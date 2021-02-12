// This file just needs to exist so that the rest of DPDK does not import generic/rte_pause.h,
// which has a 'static inline void rte_pause(void);' that causes a compile error due to being static inline but not defined
