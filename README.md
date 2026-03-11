# Sniper (XDP/eBPF Filter)

An eBPF-based network filter written in Rust using the Aya framework. It attaches to the XDP hook to evaluate and drop specific traffic (currently TCP port 80) at the driver level, before it reaches the Linux network stack.

## Architecture
- **Kernel-space (`sniper-ebpf`):** Packet parsing and filtering logic (Ring 0, `no_std`).
- **User-space (`sniper`):** eBPF program loader and telemetry logger.
- **Framework:** Aya.

## Prerequisites
- Rust stable & nightly toolchains.
- `bpf-linker`: `cargo install bpf-linker`

## Build & Run
```bash
# Compile both user-space and kernel-space programs
cargo build --release

# Note: Loading the XDP program requires root privileges.
