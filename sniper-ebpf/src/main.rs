#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
#[repr(C)]
pub struct EthHdr {
    pub dst_mac: [u8; 6], // 48 bits (Destination MAC Address)
    pub src_mac: [u8; 6], // 48 bits (Source MAC Address)
    pub ether_type: u16,  // 16 bits (Protocol Type: IPv4, IPv6, ARP, etc.)
}
#[repr(C)]
pub struct Ipv4Hdr { 
    pub v_ihl: u8,       // 8 bits (Version 4 + IHL 4)
    pub tos: u8,         // 8 bits (Type of Service)
    pub tot_len: u16,    // 16 bits (Total Length)
    pub id: u16,         // 16 bits (Identification)
    pub fr_offs: u16,    // 16 bits (Flags 3 + Offset 13)
    pub ttl: u8,         // 8 bits (Time to Live)
    pub prot: u8,        // 8 bits (Protocol)
    pub hdr_check: u16,  // 16 bits (Header Checksum)
    pub src_ip: u32,     // 32 bits (Source Address)
    pub dst_ip: u32,     // 32 bits (Destination Address)
}
#[repr(C)]
pub struct TcpHdr { 
    pub source: u16,      // 16 bits (Source Port)
    pub dest_port: u16,   // 16 bits (Destination Port - NUESTRO TARGET)
    pub seq: u32,         // 32 bits (Sequence Number)
    pub ack_seq: u32,     // 32 bits (Acknowledgment Number)
    pub res1_doff: u8,    // 8 bits (Data Offset + Reserved)
    pub flags: u8,        // 8 bits (Control Flags: SYN, ACK, FIN, etc.)
    pub window: u16,      // 16 bits (Window Size)
    pub check: u16,       // 16 bits (TCP Checksum)
    pub urg_ptr: u16,     // 16 bits (Urgent Pointer)
}
#[repr(C)]
pub struct UdpHdr {
    pub src_port: u16,    // 16 bits (Source Port)
    pub dest_port: u16,   // 16 bits (Destination Port)
    pub len: u16,         // 16 bits (Length of UDP header + data)
    pub check: u16,       // 16 bits (Checksum)
}

// ═══════════════════════════════════════════
// ETHER TYPES (Layer 2 → Layer 3)
// ═══════════════════════════════════════════
const ETH_P_IPV4:  u16 = 0x0800;   // IPv4
const ETH_P_IPV6:  u16 = 0x86DD;   // IPv6
const ETH_P_ARP:   u16 = 0x0806;   // ARP (Address Resolution Protocol)

// ═══════════════════════════════════════════
// IP PROTOCOLS (Layer 3 → Layer 4)
// ═══════════════════════════════════════════
const IPPROTO_TCP:  u8 = 6;    // TCP
const IPPROTO_UDP:  u8 = 17;   // UDP
const IPPROTO_ICMP: u8 = 1;    // ICMP (ping)

// ═══════════════════════════════════════════
// TCP/UDP PORTS (Layer 4 → Services)
// ═══════════════════════════════════════════
// Web
const PORT_HTTP:       u16 = 80;
const PORT_HTTPS:      u16 = 443;

// Remote Access
const PORT_SSH:        u16 = 22;
const PORT_RDP:        u16 = 3389;   // Remote Desktop

// DNS
const PORT_DNS:        u16 = 53;

// Mail
const PORT_SMTP:       u16 = 25;     // Email sending
const PORT_IMAP:       u16 = 143;    // Email reading
const PORT_IMAPS:      u16 = 993;    // Email reading (encrypted)

// Database
const PORT_MYSQL:      u16 = 3306;
const PORT_POSTGRES:   u16 = 5432;
const PORT_REDIS:      u16 = 6379;
const PORT_MONGODB:    u16 = 27017;

// Infrastructure
const PORT_FTP:        u16 = 21;
const PORT_TELNET:     u16 = 23;     // Insecure, always block
const PORT_NTP:        u16 = 123;    // Time sync
const PORT_SNMP:       u16 = 161;    // Network monitoring
const PORT_BGP:        u16 = 179;    // Border Gateway Protocol
const PORT_LDAP:       u16 = 389;    // Directory services

#[xdp]
pub fn sniper(ctx: XdpContext) -> u32 {
    match sniper_operations(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn sniper_operations(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    return Ok(xdp_action::XDP_PASS);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


