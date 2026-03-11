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

const HTTP_PORT:u16 = 80;
if (data + 38) >  data_end {
    return Ok(xdp_action::XDP_PASS)
}
let port = unsafe { u16::from_be(*((data + 36) as *const u16))};

if port == HTTP_PORT{
   info!(&ctx, "ENEMY AT PORT ({}) HAS BEEN BLOCKED", HTTP_PORT);
   return Ok(xdp_action::XDP_DROP);
} 
return Ok(xdp_action::XDP_PASS);
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

