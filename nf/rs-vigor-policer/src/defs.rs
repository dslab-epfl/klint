pub const OS_NET_ETHER_ADDR_SIZE: usize = 6;

pub type TimeT = i64;

#[repr(C)]
pub struct OsNetPacket {
    pub data: *mut u8,
    pub _reserved0: u64, // DPDK buf_iova
    pub _reserved1: u16, // DPDK data_off
    pub _reserved2: u16, // DPDK refcnt
    pub _reserved3: u16, // DPDK nb_segs
    pub device: u16,
    pub _reserved4: u64, // DPDK ol_flags
    pub _reserved5: u32, // DPDK packet_type
    pub _reserved6: u32, // DPDK pkt_len
    pub length: u16,
}

#[repr(C)]
pub struct OsNetEtherHeader {
    pub src_addr: [u8; OS_NET_ETHER_ADDR_SIZE],
    pub dst_addr: [u8; OS_NET_ETHER_ADDR_SIZE],
    pub ether_type: u16,
}

#[repr(C)]
pub struct OsNetIPv4Header {
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

#[repr(C)]
pub struct OsNetTcpUdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

#[inline]
pub unsafe fn os_net_get_ether_header(packet: *mut OsNetPacket, out_ether_header: *mut *mut OsNetEtherHeader) -> bool {
    *out_ether_header = (*packet).data as *mut OsNetEtherHeader;
    true
}

#[inline]
pub unsafe fn os_net_get_ipv4_header(ether_header: *mut OsNetEtherHeader, out_ipv4_header: *mut *mut OsNetIPv4Header) -> bool {
    *out_ipv4_header = ether_header.offset(1) as *mut OsNetIPv4Header;
    true // @TODO different from C implementation: how to determine machine's endianness at compile time in Rust ?
}