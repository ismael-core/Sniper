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
---

## Dev Log: Phase 2 - Structs, repr(C) & Memory Layouts

I realized today that using "magic numbers" and manual byte offsets (like adding `data + 34`) to read packets is a dead end if I want to build a real, scalable gateway. So, I spent this session laying down a solid foundation.

Instead of blindly guessing byte positions, I mapped out the actual protocol headers using Rust structs to create exact memory templates.

### What I built and learned:
* **Taming the compiler with `#[repr(C)]`:** Turns out Rust likes to reorder struct fields to optimize memory, which completely destroys eBPF programs trying to read raw network packets. Adding `#[repr(C)]` forces Rust to respect the standard C memory layout. Huge lifesaver.
* **Defining the Networking Stack (L2 to L4):**
  * `EthHdr` (14 bytes): Got the MAC addresses and the `ether_type` setup to filter L2.
  * `Ipv4Hdr` (20 bytes): Mapped out the IP header to validate L3 and check if the payload is TCP or UDP.
  * `TcpHdr` (20 bytes) & `UdpHdr` (8 bytes): The actual targets. No more guessing; now I have exact molds to read specific ports (like targeting port 80).

**Next steps:** With these blueprints ready, tomorrow I'm ripping out the old pointer arithmetic in `sniper_operations` and replacing it with safe struct casting. Time to make the sniper actually use these scopes.
---

## Dev Log: Phase 2.5 – Constants & Cleanup

Stopped coding for a sec and reviewed everything I had so far line by line. Wanted to make sure I wasn't just writing stuff that works without knowing why it works. Glad I did — caught a few gaps in my understanding around `no_main` and how the entry point actually gets called by the kernel.

Set up all the protocol constants I'll need: ether types, IP protocol numbers, and a bunch of well-known ports (HTTP, HTTPS, SSH, DNS, databases, etc). It's just reference values but having them named and organized at the top beats writing magic numbers everywhere.

Gutted `sniper_operations` completely. The old logic with `data + 36` and `data + 38` worked but it was fragile. Starting fresh with struct-based parsing using `size_of` to calculate offsets automatically.

### What changed:
* Added constants for ether types (IPv4, IPv6, ARP), protocols (TCP, UDP, ICMP), and ~15 common ports
* Stripped the old manual offset logic out of `sniper_operations`
* Picked up the `&*` zero-copy casting pattern for reading packet headers without copying bytes around

**Next:** Full layer-by-layer parsing inside `sniper_operations` — Ethernet → IPv4 → TCP/UDP using the structs instead of hardcoded offsets.
