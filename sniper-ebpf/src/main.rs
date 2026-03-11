#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;


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

