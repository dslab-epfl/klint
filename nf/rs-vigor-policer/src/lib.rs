use std::mem::size_of;
use std::os::raw::c_char;
use std::ptr::null_mut;
mod defs;
use defs::*;

macro_rules! cstr {
  ($s:expr) => (
      concat!($s, "\0") as *const str as *const [c_char] as *const c_char
  );
}

#[repr(C)]
pub struct PolicerBucket {
    size: u64,
    time: TimeT,
}

static mut WAN_DEVICE: u16 = 0;
static mut RATE: u64 = 0;
static mut BURST: u64 = 0;
static mut MAX_FLOWS: u64 = 0;
static mut ADDRESSES: *mut u32 = null_mut();
static mut BUCKETS: *mut PolicerBucket = null_mut();
static mut MAP: *mut OsMap = null_mut();
static mut POOL: *mut OsPool = null_mut();

#[no_mangle]
pub unsafe extern "C" fn nf_init(devices_count: u16) -> bool {
    if devices_count != 2 {
        return false;
    }
    WAN_DEVICE = {
        let device = os_config_get_u16(cstr!("wan device"));
        if device >= devices_count {
            return false;
        }
        device
    };

    RATE = os_config_get_u64(cstr!("rate"));
    if RATE == 0 { return false; }

    BURST = os_config_get_u64(cstr!("burst"));
    if BURST == 0 { return false; }

    MAX_FLOWS = {
        let max_flows = os_config_get_u64(cstr!("max flows"));
        if max_flows == 0 || max_flows > (usize::MAX / 2 + 1) as u64 {
            return false;
        }
        max_flows
    };
    ADDRESSES = os_memory_alloc(MAX_FLOWS as usize, size_of::<u32>() as usize) as *mut u32;
    BUCKETS = os_memory_alloc(MAX_FLOWS as usize, size_of::<PolicerBucket>() as usize) as *mut PolicerBucket;
    MAP = os_map_alloc(size_of::<u32>(), MAX_FLOWS as usize);
    POOL = os_pool_alloc(MAX_FLOWS as usize, 1000000000 * BURST / RATE);

    true
}

#[no_mangle]
pub unsafe extern "C" fn nf_handle(packet: *mut NetPacket) {
    let mut ether_header = null_mut();
    let mut ipv4_header = null_mut();
    if !net_get_ether_header(packet, &mut ether_header)
        || !net_get_ipv4_header(ether_header, &mut ipv4_header)
    {
        // Not IPv4 over Ethernet
        return;
    }

    if (*packet).device == WAN_DEVICE {
        let time = os_clock_time_ns();
        let mut index: usize = 0;
        if os_map_get(
            MAP,
            (&mut (*ipv4_header).dst_addr as *mut u32) as *mut u8,
            (&mut index as *mut usize) as *mut *mut u8,
        ) {
            os_pool_refresh(POOL, time, index);
            let time_diff = (time - (*BUCKETS.offset(index as isize)).time) as u64;
            if time_diff < BURST / RATE {
                (*BUCKETS.offset(index as isize)).size += time_diff * RATE;
                if (*BUCKETS.offset(index as isize)).size > BURST {
                    (*BUCKETS.offset(index as isize)).size = BURST;
                }
            } else {
                (*BUCKETS.offset(index as isize)).size = BURST;
            }
            (*BUCKETS.offset(index as isize)).time = time;

            if (*BUCKETS.offset(index as isize)).size > (*packet).length as u64 {
                (*BUCKETS.offset(index as isize)).size -= (*packet).length as u64;
            } else {
                // Packet too big
                return;
            }
        } else {
            if (*packet).length as u64 > BURST {
                // Unknown flow, length greater than burst
                return;
            }

            let mut was_used: bool = false;
            if os_pool_borrow(POOL, time, &mut index as *mut usize, &mut was_used as *mut bool) {
                if was_used {
                  os_map_remove(MAP, ADDRESSES.offset(index as isize) as *mut u8);
                }

                *ADDRESSES.offset(index as isize) = (*ipv4_header).dst_addr;
                os_map_set(
                    MAP,
                    ADDRESSES.offset(index as isize) as *mut u8,
                    index as *mut u8,
                );
                (*BUCKETS.offset(index as isize)).size = BURST - (*packet).length as u64;
                (*BUCKETS.offset(index as isize)).time = time;
            } else {
                // No more space
                return;
            }
        }
    } // No policing for outgoing packets

    net_transmit(packet, 1 - (*packet).device, 0);
}
