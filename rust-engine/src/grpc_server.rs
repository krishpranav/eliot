// grpc_server.rs — Implements the SecurityEngine gRPC service.
//
// This is the bridge between the tonic gRPC framework and our detector pipeline.
// When Go calls StartCapture(), this function:
//   1. Starts the pcap capture thread (capture.rs)
//   2. Builds the detector pipeline (detectors/mod.rs)
//   3. Runs the pipeline on each packet in a loop
//   4. Streams ThreatEvents back to Go via the gRPC stream

use crate::capture;