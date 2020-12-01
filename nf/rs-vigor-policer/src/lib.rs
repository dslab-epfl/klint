use std::ffi::CString;
use std::mem::size_of;
use std::os::raw::c_char;
use std::ptr::null_mut;
mod defs;
use defs::*;

extern "C" {
    // OS API
    fn os_config_get_u16(name: *const c_char) -> u16;
    fn os_config_get_u64(name: *const c_char) -> u64;
    fn os_memory_alloc(count: usize, size: usize) -> *mut u8;
    fn os_clock_time() -> TimeT;
    fn os_net_transmit(
        packet: *mut OsNetPacket,
        device: u16,
        ether_header: *mut OsNetEtherHeader,
        ipv4_header: *mut OsNetIPv4Header,
        tcpudp_header: *mut OsNetTcpUdpHeader,
    );

    // Map API
    fn os_map_alloc(key_size: usize, capacity: usize) -> *mut OsMap;
    fn os_map_get(map: *mut OsMap, key_ptr: *mut u8, out_value: *mut *mut u8) -> bool;
    fn os_map_set(map: *mut OsMap, key_ptr: *mut u8, value: *mut u8);
    fn os_map_remove(map: *mut OsMap, key_ptr: *mut u8);

    // Pool API
    fn os_pool_alloc(size: usize) -> *mut OsPool;
    fn os_pool_borrow(pool: *mut OsPool, time: TimeT, out_index: *mut usize) -> bool;
    // fn os_pool_return(pool: *mut OsPool, index: usize);
    fn os_pool_refresh(pool: *mut OsPool, time: TimeT, index: usize);
    // fn os_pool_used(pool: *mut OsPool, index: usize, out_time: *mut TimeT) -> bool;
    fn os_pool_expire(pool: *mut OsPool, time: TimeT, out_index: *mut usize) -> bool;
}

#[repr(C)]
pub struct PolicerBucket {
    size: i64,
    time: TimeT,
}

#[repr(C)]
pub struct OsMap {
    _private: [u8; 0],
}
#[repr(C)]
pub struct OsPool {
    _private: [u8; 0],
}

static mut WAN_DEVICE: u16 = 0;
static mut RATE: i64 = 0;
static mut BURST: i64 = 0;
static mut MAX_FLOWS: u64 = 0;
static mut ADDRESSES: *mut u32 = null_mut();
static mut BUCKETS: *mut PolicerBucket = null_mut();
static mut MAP: *mut OsMap = null_mut();
static mut POOL: *mut OsPool = null_mut();

const ERR_BAD_C_STRING: &str = "String cannot be converted to C representation.";

#[no_mangle]
pub unsafe extern "C" fn nf_init(devices_count: u16) -> bool {
    if devices_count != 2 {
        return false;
    }
    WAN_DEVICE = {
        let device =
            os_config_get_u16(CString::new("wan device").expect(ERR_BAD_C_STRING).as_ptr());
        if device >= devices_count {
            return false;
        }
        device
    };
    RATE = {
        let rate = os_config_get_u64(CString::new("rate").expect(ERR_BAD_C_STRING).as_ptr()) as i64;
        if rate <= 0 {
            return false;
        }
        rate
    };
    BURST = {
        let burst =
            os_config_get_u64(CString::new("burst").expect(ERR_BAD_C_STRING).as_ptr()) as i64;
        if burst <= 0 {
            return false;
        }
        burst
    };
    MAX_FLOWS = {
        let max_flows = os_config_get_u64(CString::new("burst").expect(ERR_BAD_C_STRING).as_ptr());
        if max_flows == 0 || max_flows > (usize::MAX / 16 - 2) as u64 {
            return false;
        }
        max_flows
    };
    ADDRESSES = os_memory_alloc(MAX_FLOWS as usize, size_of::<u32>() as usize) as *mut u32;
    BUCKETS = os_memory_alloc(MAX_FLOWS as usize, size_of::<PolicerBucket>() as usize)
        as *mut PolicerBucket;
    MAP = os_map_alloc(size_of::<u32>(), MAX_FLOWS as usize);
    POOL = os_pool_alloc(MAX_FLOWS as usize);
    if MAP == null_mut() || POOL == null_mut() {
        return false;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn nf_handle(packet: *mut OsNetPacket) {
    let mut ether_header = null_mut();
    let mut ipv4_header = null_mut();
    if !os_net_get_ether_header(packet, &mut ether_header)
        || !os_net_get_ipv4_header(ether_header, &mut ipv4_header)
    {
        // Not IPv4 over Ethernet
        return;
    }

    if (*packet).device == WAN_DEVICE {
        let time = os_clock_time();
        let mut index: usize = 0;
        if os_map_get(
            MAP,
            (&mut (*ipv4_header).dst_addr as *mut u32) as *mut u8,
            (&mut index as *mut usize) as *mut *mut u8,
        ) {
            os_pool_refresh(POOL, time, index);
            let time_diff = time - (*BUCKETS.offset(index as isize)).time;
            if time_diff < BURST / RATE {
                (*BUCKETS.offset(index as isize)).size += time_diff * RATE;
                if (*BUCKETS.offset(index as isize)).size > BURST {
                    (*BUCKETS.offset(index as isize)).size = BURST;
                }
            } else {
                (*BUCKETS.offset(index as isize)).size = BURST;
            }
            (*BUCKETS.offset(index as isize)).time = time;

            if (*BUCKETS.offset(index as isize)).size > (*packet).length as i64 {
                (*BUCKETS.offset(index as isize)).size -= (*packet).length as i64;
            } else {
                // Packet too big
                return;
            }
        } else {
            if (*packet).length as i64 > BURST {
                // Unknown flow, length greater than burst
                return;
            }

            if os_pool_expire(POOL, time, &mut index as *mut usize) {
                os_map_remove(MAP, ADDRESSES.offset(index as isize) as *mut u8);
            }

            if os_pool_borrow(POOL, time, &mut index as *mut usize) {
                *ADDRESSES.offset(index as isize) = (*ipv4_header).dst_addr;
                os_map_set(
                    MAP,
                    ADDRESSES.offset(index as isize) as *mut u8,
                    (&mut index as *mut usize) as *mut u8,
                );
                (*BUCKETS.offset(index as isize)).size = BURST - (*packet).length as i64;
                (*BUCKETS.offset(index as isize)).time = time;
            } else {
                // No more space
                return;
            }
        }
    } // No policing for outgoing packets

    os_net_transmit(packet, 1 - (*packet).device, null_mut(), null_mut(), null_mut());
}
