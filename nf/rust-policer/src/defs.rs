use std::os::raw::c_char;
use std::os::raw::c_int;

pub type TimeT = u64;

#[repr(C)]
pub struct NetPacket {
    pub data: *mut u8,
    pub length: u64,
    pub time: TimeT,
    pub device: u16,
    pub _padding: [u8; 6],
    pub os_tag: u64
}

#[repr(C)]
pub struct NetEtherHeader {
    pub src_addr: [u8; 6],
    pub dst_addr: [u8; 6],
    pub ether_type: u16,
}

#[repr(C)]
pub struct NetIPv4Header {
    pub version_ihl: u8,
    pub type_of_service: u8,
    pub total_length: u16,
    pub packet_id: u16,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub next_proto_id: u8,
    pub hdr_checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[inline]
pub unsafe fn net_get_ether_header(packet: *mut NetPacket, out_ether_header: *mut *mut NetEtherHeader) -> bool {
    *out_ether_header = (*packet).data as *mut NetEtherHeader;
    true
}

#[inline]
pub unsafe fn net_get_ipv4_header(ether_header: *mut NetEtherHeader, out_ipv4_header: *mut *mut NetIPv4Header) -> bool {
    *out_ipv4_header = ether_header.offset(1) as *mut NetIPv4Header;
    u16::from_be((*ether_header).ether_type) == 0x0800
}

#[repr(C)]
pub struct Map {
    _private: [u8; 0],
}
#[repr(C)]
pub struct IndexPool {
    _private: [u8; 0],
}

extern "C" {
    pub fn os_config_try_get(name: *const c_char, out_value: *mut u64) -> bool;

    pub fn os_memory_alloc(count: usize, size: usize) -> *mut u8;

    pub fn net_transmit(
        packet: *mut NetPacket,
        device: u16,
        flags: c_int
    );

    pub fn map_alloc(key_size: usize, capacity: usize) -> *mut Map;
    pub fn map_get(map: *mut Map, key_ptr: *mut u8, out_value: *mut *mut u8) -> bool;
    pub fn map_set(map: *mut Map, key_ptr: *mut u8, value: *mut u8);
    pub fn map_remove(map: *mut Map, key_ptr: *mut u8);

    pub fn index_pool_alloc(size: usize, exp_time: TimeT) -> *mut IndexPool;
    pub fn index_pool_borrow(pool: *mut IndexPool, time: TimeT, out_index: *mut usize, was_used: *mut bool) -> bool;
    pub fn index_pool_refresh(pool: *mut IndexPool, time: TimeT, index: usize);
}
