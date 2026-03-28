// capture.rs — Raw packet capture using libpcap.
//
// libpcap puts the NIC into promiscuous mode and gives us every Ethernet frame
// before the OS network stack processes it. This is how Wireshark, tcpdump,
// and every IDS/IPS works at layer 2.
//
// Because pcap's capture loop is BLOCKING (it parks the thread waiting for
// frames), we run it inside tokio::task::spawn_blocking so it gets its own
// OS thread and doesn't starve the async runtime.

use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};
const CHANNEL_CAPACITY: usize = 4096;

pub fn start_capture(
    interface: String,
    bpf_filter: String,
) -> Result<(mpsc::Receiver<Vec<u8>>, oneshot::Sender<()>)> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    let iface = interface.clone();
    let filter = bpf_filter.clone();

    tokio::task::spawn_blocking(move || {
        info!("Opening pcap on interface '{}' filter '{}'", iface, filter);

        let mut cap = pcap::Capture::from_device(iface.as_str())
            .context("Failed to open device — is the interface name correct?")?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
            .context("Failed to open capture — try running as root or: sudo chmod a+r /dev/bpf*")?;

        if !filter.is_empty() {
            cap.filter(&filter, true)
                .context("Invalid BPF filter expression")?;
            info!("BPF filter applied: '{}'", filter);
        }

        loop {
            match stop_rx.try_recv() {
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => {
                    info!("Capture stop signal received, shutting down pcap loop");
                    break;
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                }
            }

            match cap.next_packet() {
                Ok(packet) => {
                    let data = packet.data.to_vec();

                    if tx.blocking_send(data).is_err() {
                        info!("Packet channel closed, stopping capture");
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    continue;
                }
                Err(e) => {
                    error!("pcap error: {}", e);
                    break;
                }
            }
        }

        info!("Capture thread exited cleanly");
        Ok::<(), anyhow::Error>(())
    });

    Ok((rx, stop_tx))
}