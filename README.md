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
## Dev Log: Phase 3 – The Verifier & Full Packet Parsing

Today was the day everything clicked. Spent the first half of the session going deep on the eBPF verifier — not just "what it does" but how it actually works internally. The verifier tracks every register with an abstract state: it knows if something is a PTR_TO_PACKET, a PTR_TO_PACKET_END, or a SCALAR_VALUE, and it follows every possible code path before your program ever touches a packet. If it can't prove your memory access is safe, your program doesn't load. Period.

The big realization: bounds checks aren't just runtime safety — they're instructions to the verifier. When I write if data + 14 > data_end { return XDP_PASS }, the verifier splits into two branches and learns that in the "didn't return" branch, there are at least 14 accessible bytes. It's pattern matching, not general math — write the check in the wrong form and it rejects you even if the logic is equivalent.

Then I rewrote sniper_operations from scratch using the structs I built on day 9. Layer by layer:

1. L2 → EthHdr: Bounds check 14 bytes, cast data as *const EthHdr, read ether_type, bail if not IPv4.
2. L3 → Ipv4Hdr: Bounds check 34 bytes, cast (data + 14) as *const Ipv4Hdr, read prot to determine TCP or UDP.
3. L4 → TcpHdr / UdpHdr: Branching with if/else if — TCP gets bounds check at 54, UDP at 42. Both cast at data + 34, read dest_port with from_be, and drop if it matches PORT_HTTP.

No magic offsets. No hardcoded data + 38. Every access proven safe to the verifier.

### The moment

Loaded it into the kernel, verifier accepted it first try. Ran bpftool net show — saw eth0(2) driver id 225. Opened Safari on my iPad, hit the server IP on port 80, and watched it hang. ethtool -S eth0 | grep xdp showed 37 drops. My code killed those packets before they even reached the network stack.

### What changed:
* Replaced the old skeleton sniper_operations with full L2→L3→L4 parsing
* Proper bounds checks before every unsafe cast (verifier-safe pattern)
* TCP/UDP branching based on ipv4.prot
* XDP_DROP on TCP port 80 — confirmed working with live traffic
* Zero-copy reads using &* pointer dereferencing through #[repr(C)] structs

**Next:** Multi-port filtering (Telnet, FTP, databases), UDP-specific rules, and adding aya_log so I can actually see what's getting dropped in real time.
