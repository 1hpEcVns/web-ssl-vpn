#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::{HashMap, Array},
    programs::TcContext,
};
use network_types::{
    eth::EtherType,
    ip::IpProto,
};

#[map]
static BYTES_SENT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[map]
static BYTES_RECV: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[map]
static CONN_COUNT: Array<u64> = Array::with_max_entries(1, 0);

const ETH_HDR_LEN: usize = core::mem::size_of::<[u8; 14]>();
const IPV4_HDR_LEN: usize = 20;
const TCP_HDR_OFF_FLAGS: usize = 12;

const ETHER_TYPE_OFF: usize = 12;
const IP_LEN_OFF: usize = 2;
const IP_PROTO_OFF: usize = 9;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

fn read_u16_at(ctx: &TcContext, offset: usize) -> Result<u16, i64> {
    let bytes: [u8; 2] = ctx.load(offset)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u8_at(ctx: &TcContext, offset: usize) -> Result<u8, i64> {
    let byte: u8 = ctx.load(offset)?;
    Ok(byte)
}

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let Ok(ether_type) = read_u16_at(&ctx, ETH_HDR_LEN + ETHER_TYPE_OFF) else {
        return TC_ACT_OK;
    };
    if ether_type != EtherType::Ipv4 as u16 {
        return TC_ACT_OK;
    }

    let Ok(tot_len) = read_u16_at(&ctx, ETH_HDR_LEN + IP_LEN_OFF) else {
        return TC_ACT_OK;
    };
    let ip_len = tot_len as u64;

    if let Some(val) = BYTES_RECV.get_ptr_mut(&0) {
        unsafe { *val = (*val).wrapping_add(ip_len) };
    }

    let Ok(proto) = read_u8_at(&ctx, ETH_HDR_LEN + IP_PROTO_OFF) else {
        return TC_ACT_OK;
    };
    if proto == IpProto::Tcp as u8 {
        let flags_off = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_OFF_FLAGS;
        let Ok(flags_byte) = read_u8_at(&ctx, flags_off + 1) else {
            return TC_ACT_OK;
        };

        if (flags_byte & TCP_SYN) != 0 && (flags_byte & TCP_ACK) == 0 {
            if let Some(cnt) = CONN_COUNT.get_ptr_mut(0) {
                unsafe { *cnt = (*cnt).wrapping_add(1) };
            }
        }
        if (flags_byte & TCP_FIN) != 0 || (flags_byte & TCP_RST) != 0 {
            if let Some(cnt) = CONN_COUNT.get_ptr_mut(0) {
                unsafe { *cnt = (*cnt).saturating_sub(1) };
            }
        }
    }

    TC_ACT_OK
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let Ok(ether_type) = read_u16_at(&ctx, ETH_HDR_LEN + ETHER_TYPE_OFF) else {
        return TC_ACT_OK;
    };
    if ether_type != EtherType::Ipv4 as u16 {
        return TC_ACT_OK;
    }

    let Ok(tot_len) = read_u16_at(&ctx, ETH_HDR_LEN + IP_LEN_OFF) else {
        return TC_ACT_OK;
    };
    let ip_len = tot_len as u64;

    if let Some(val) = BYTES_SENT.get_ptr_mut(&0) {
        unsafe { *val = (*val).wrapping_add(ip_len) };
    }

    TC_ACT_OK
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
