#pragma once

#define os_swap16(val) ((val << 8) | (val >> 8))
#define os_swap32(val) ((val << 24) | ((val << 8) & 0xFF) | ((val >> 8) & 0xFF) | (val >> 24))
#define os_swap64(val) ((val << 56) | ((val << 40) & 0xFF) | ((val << 24) & 0xFF) | ((val << 8) & 0xFF) | ((val >> 8) & 0xFF) | ((val >> 24) & 0xFF) | ((val >> 40) & 0xFF) | (val >> 56))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define os_cpu_to_le16(x) (x)
#define os_cpu_to_le32(x) (x)
#define os_cpu_to_le64(x) (x)
#define os_cpu_to_be16(x) os_swap16(x)
#define os_cpu_to_be32(x) os_swap32(x)
#define os_cpu_to_be64(x) os_swap64(x)
#define os_le_to_cpu16(x) (x)
#define os_le_to_cpu32(x) (x)
#define os_le_to_cpu64(x) (x)
#define os_be_to_cpu16(x) os_swap16(x)
#define os_be_to_cpu32(x) os_swap32(x)
#define os_be_to_cpu64(x) os_swap64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define os_cpu_to_le16(x) os_swap16(x)
#define os_cpu_to_le32(x) os_swap32(x)
#define os_cpu_to_le64(x) os_swap64(x)
#define os_cpu_to_be16(x) (x)
#define os_cpu_to_be32(x) (x)
#define os_cpu_to_be64(x) (x)
#define os_le_to_cpu16(x) os_swap16(x)
#define os_le_to_cpu32(x) os_swap32(x)
#define os_le_to_cpu64(x) os_swap64(x)
#define os_be_to_cpu16(x) (x)
#define os_be_to_cpu32(x) (x)
#define os_be_to_cpu64(x) (x)
#else
#error Unknown endianness
#endif
