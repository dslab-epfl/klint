use std::os::raw::c_char;
use std::os::raw::c_int;

pub const NET_ETHER_ADDR_SIZE: usize = 6;

pub type TimeT = i64;

#[repr(C)]
pub struct NetPacket {
    pub data: *mut u8,
    pub device: u16,
    pub length: u16,
    pub _padding: u32,
    pub os_tag: u64
}

#[repr(C)]
pub struct NetEtherHeader {
    pub src_addr: [u8; NET_ETHER_ADDR_SIZE],
    pub dst_addr: [u8; NET_ETHER_ADDR_SIZE],
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

//#[repr(C)]
//pub struct NetTcpUdpHeader {
//    pub src_port: u16,
//    pub dst_port: u16,
//}

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
pub struct OsMap {
    _private: [u8; 0],
}
#[repr(C)]
pub struct OsPool {
    _private: [u8; 0],
}

extern "C" {
    // OS API
    pub fn os_config_get_u16(name: *const c_char) -> u16;
    pub fn os_config_get_u64(name: *const c_char) -> u64;
    pub fn os_memory_alloc(count: usize, size: usize) -> *mut u8;
    pub fn os_clock_time_ns() -> TimeT;
    pub fn net_transmit(
        packet: *mut NetPacket,
        device: u16,
        flags: c_int
    );

    // Map API
    pub fn os_map_alloc(key_size: usize, capacity: usize) -> *mut OsMap;
    pub fn os_map_get(map: *mut OsMap, key_ptr: *mut u8, out_value: *mut *mut u8) -> bool;
    pub fn os_map_set(map: *mut OsMap, key_ptr: *mut u8, value: *mut u8);
    pub fn os_map_remove(map: *mut OsMap, key_ptr: *mut u8);

    // Pool API
    pub fn os_pool_alloc(size: usize) -> *mut OsPool;
    pub fn os_pool_borrow(pool: *mut OsPool, time: TimeT, out_index: *mut usize) -> bool;
    // pub fn os_pool_return(pool: *mut OsPool, index: usize);
    pub fn os_pool_refresh(pool: *mut OsPool, time: TimeT, index: usize);
    // pub fn os_pool_used(pool: *mut OsPool, index: usize, out_time: *mut TimeT) -> bool;
    pub fn os_pool_expire(pool: *mut OsPool, time: TimeT, out_index: *mut usize) -> bool;
}
