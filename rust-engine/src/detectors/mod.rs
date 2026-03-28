// detectors/mod.rs — Defines the Detector trait and the pipeline that
// runs every raw packet through all detectors in sequence.
//
// Each detector gets the parsed Ethernet frame and returns an optional
// ThreatEvent. If it returns Some(...), the event is sent upstream to Go.

pub mod arp;
pub mod dns;
pub mod portscan;
pub mod signature;
pub mod tls;

use crate::nethawk::{Protocol, ThreatEvent, ThreatType};
use chrono::Utc;
use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EthernetPacket, EtherTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};
use std::net::Ipv4Addr;
use tracing::trace;

// ── Helper to build a ThreatEvent ────────────────────────────────────────────
// We use this in every detector to avoid repeating boilerplate.
pub fn make_event(
    src_ip: &str,
    dst_ip: &str,
    src_mac: &str,
    dst_mac: &str,
    src_port: u32,
    dst_port: u32,
    proto: Protocol,
    threat: ThreatType,
    severity: f32,
    desc: &str,
    payload: &[u8],
    ja3: &str,
    matched_sig: &str,
) -> ThreatEvent {
    ThreatEvent {
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_mac: src_mac.to_string(),
        dst_mac: dst_mac.to_string(),
        src_port,
        dst_port,
        // Into the i32 that protobuf enums serialize as
        protocol: proto as i32,
        threat_type: threat as i32,
        severity,
        description: desc.to_string(),
        // Only copy first 256 bytes of payload — no need for more in a threat event
        raw_payload: payload[..payload.len().min(256)].to_vec(),
        // Nanoseconds since UNIX epoch — Go uses this for deduplication windows
        timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
        ja3_fingerprint: ja3.to_string(),
        matched_sig: matched_sig.to_string(),
    }
}

// ── The pipeline ──────────────────────────────────────────────────────────────
// DetectorPipeline owns all detector instances and runs them in order on
// each raw Ethernet frame received from the capture channel.
pub struct DetectorPipeline {
    pub arp: arp::ArpDetector,
    pub dns: dns::DnsDetector,
    pub tls: tls::TlsDetector,
    pub sig: signature::SignatureDetector,
    pub scan: portscan::PortScanDetector,
}

impl DetectorPipeline {
    /// Create a pipeline with the given threat signatures (for sig detector).
    pub fn new(signatures: Vec<String>) -> Self {
        Self {
            arp: arp::ArpDetector::new(),
            dns: dns::DnsDetector::new(),
            tls: tls::TlsDetector::new(),
            sig: signature::SignatureDetector::new(signatures),
            scan: portscan::PortScanDetector::new(),
        }
    }

    /// Process one raw Ethernet frame.
    /// Returns a list of ThreatEvents (0, 1, or more) detected in this frame.
    /// One frame can trigger multiple detectors simultaneously.
    pub fn process(&mut self, raw: &[u8]) -> Vec<ThreatEvent> {
        let mut events = Vec::new();

        // Parse the raw bytes as an Ethernet frame.
        // new() returns None if the slice is too short to be a valid Ethernet header.
        let eth = match EthernetPacket::new(raw) {
            Some(e) => e,
            None => {
                trace!("Received truncated/malformed Ethernet frame, skipping");
                return events;
            }
        };

        let src_mac = eth.get_source().to_string();
        let dst_mac = eth.get_destination().to_string();

        match eth.get_ethertype() {
            // ── ARP frames ───────────────────────────────────────────────────
            EtherTypes::Arp => {
                if let Some(arp_pkt) = ArpPacket::new(eth.payload()) {
                    if let Some(ev) = self.arp.inspect(&arp_pkt, &src_mac, &dst_mac) {
                        events.push(ev);
                    }
                }
            }

            // ── IPv4 frames ──────────────────────────────────────────────────
            EtherTypes::Ipv4 => {
                if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                    let src_ip = ip.get_source().to_string();
                    let dst_ip = ip.get_destination().to_string();

                    match ip.get_next_level_protocol() {
                        // TCP — check for TLS and port scanning
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                let sport = tcp.get_source() as u32;
                                let dport = tcp.get_destination() as u32;
                                let payload = tcp.payload();

                                // TLS detector: inspect TCP payloads on port 443
                                if dport == 443 || sport == 443 {
                                    if let Some(ev) = self.tls.inspect(
                                        payload, &src_ip, &dst_ip, &src_mac, &dst_mac,
                                        sport, dport,
                                    ) {
                                        events.push(ev);
                                    }
                                }

                                // Port scan detector: track SYN packets per source
                                if let Some(ev) = self.scan.inspect(
                                    &tcp, &src_ip, &dst_ip, &src_mac, &dst_mac,
                                ) {
                                    events.push(ev);
                                }

                                // Signature detector: match against raw payload
                                if let Some(ev) = self.sig.inspect(
                                    payload, &src_ip, &dst_ip, &src_mac, &dst_mac,
                                    sport, dport, Protocol::Tcp,
                                ) {
                                    events.push(ev);
                                }
                            }
                        }

                        // UDP — check for DNS anomalies
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ip.payload()) {
                                let sport = udp.get_source() as u32;
                                let dport = udp.get_destination() as u32;
                                let payload = udp.payload();

                                // DNS is port 53
                                if dport == 53 || sport == 53 {
                                    if let Some(ev) = self.dns.inspect(
                                        payload, &src_ip, &dst_ip, &src_mac, &dst_mac,
                                    ) {
                                        events.push(ev);
                                    }
                                }

                                // Signatures on UDP payloads too
                                if let Some(ev) = self.sig.inspect(
                                    payload, &src_ip, &dst_ip, &src_mac, &dst_mac,
                                    sport, dport, Protocol::Udp,
                                ) {
                                    events.push(ev);
                                }
                            }
                        }

                        _ => {}
                    }
                }
            }

            _ => {
                // IPv6, VLAN, etc. — not handled yet, skip silently
            }
        }

        events
    }
}