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
## Dev Log: Phase 4 – Multi-Port Filtering & Live Telemetry

Up until now Sniper only blocked one port — TCP 80. Today I turned it into an actual multi-port firewall with real-time logging. The program now watches for dangerous services and tells me exactly who tried to connect and where.

### Choosing what to block

Before writing any code I had to think about which ports actually need to be blocked and on which protocol. Not every service runs on both TCP and UDP — most database and remote access services are TCP only, while stuff like SNMP and NTP are UDP. Blocking MySQL on UDP would be a rule that never fires because MySQL traffic never goes over UDP. Wasted code.

I also had to think about what’s actually dangerous to leave exposed. Database ports (MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017) are probably the worst — if someone from the internet can reach your database, they have access to everything. Redis doesn’t even require a password by default. Telnet (23) and FTP (21) send everything in plaintext. BGP (179) and LDAP (389) have no business being open on a server that isn’t a router or directory service.

One important thing I learned: blocking a port on eth0 doesn’t affect local traffic. Processes on the same server talk through the loopback interface (`lo`), not eth0. So my app can still use MySQL locally while the XDP program blocks anyone from the internet trying to reach port 3306.

### match instead of chained if statements

Rust’s `match` is way cleaner than chaining `if port == X || port == Y || port == Z`. You declare what you’re comparing once, then list the values separated by `|`:

```rust
match tcp_port {
    PORT_MYSQL | PORT_POSTGRES | PORT_REDIS | PORT_MONGODB
    | PORT_TELNET | PORT_FTP | PORT_BGP | PORT_LDAP => {
        // drop
    }
    _ => {}  // everything else passes
}
```

The `_` means “everything else” — Rust forces you to cover all possibilities. Inside match, `|` is a pattern separator (not the logical OR `||` from if statements). Caught a nasty bug here too: I typo’d `PORT_SNTP` instead of `PORT_SNMP` in the UDP match. Rust didn’t error — it treated it as a new variable name that catches ALL values. Would have silently dropped every UDP packet. The compiler warning about “variable should be snake_case” was the clue.

### aya_log — seeing what gets dropped in real time

The logging architecture has two sides. The kernel program writes to a shared buffer using `aya_log_ebpf::info!`. The userspace loader reads that buffer and prints to the terminal. The loader already had the setup code from the Aya template — I just needed to add `info!` calls in the eBPF program.

The raw IP comes out as a u32 (like 2691030871) which is useless to read. To get a human-readable IP I extract each byte with bit shifts and masking:

```rust
let b1 = ipv4.src_ip & 0xFF;           // bits 0-7
let b2 = (ipv4.src_ip >> 8) & 0xFF;    // bits 8-15
let b3 = (ipv4.src_ip >> 16) & 0xFF;   // bits 16-23
let b4 = (ipv4.src_ip >> 24) & 0xFF;   // bits 24-31
```

`0xFF` is a mask (11111111 in binary) that isolates 8 bits. The `>>` shift brings each byte down to the lowest position before masking. Now the logs show actual IPs.

### The real internet showed up

Within minutes of running the program, the logs caught a bot from a random IP trying to hit port 21 (FTP). I didn’t trigger that — it was an automated scanner just sweeping the internet looking for open FTP servers. My program blocked it and logged it. That’s exactly why multi-port filtering matters.

### What changed:

- Replaced single PORT_HTTP check with `match` blocks for multi-port filtering
- TCP blocks: MySQL, PostgreSQL, Redis, MongoDB, Telnet, FTP, BGP, LDAP
- UDP blocks: SNMP
- Added `aya_log_ebpf::info!` logging with human-readable source IP and dest port
- Extracted IPv4 bytes using bitwise shift and mask operations
- Caught real bot traffic on port 21 during testing

**Next:** Source port filtering, IP-based filtering, and continuing to build out the detection logic.
