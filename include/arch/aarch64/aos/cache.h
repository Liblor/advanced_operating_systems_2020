/**
 * \file
 * \brief aarch64 cache maintenance functions
 * */

/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */
#ifndef LIBBARRELFISH_CACHE_H
#define LIBBARRELFISH_CACHE_H

#define	cpu_nullop()			arm64_nullop()
#define	cpufunc_nullop()		arm64_nullop()
#define	cpu_setttb(a)			arm64_setttb(a)

#define	cpu_tlb_flushID()		arm64_tlb_flushID()
#define	cpu_tlb_flushID_SE(e)		arm64_tlb_flushID_SE(e)

#define	cpu_dcache_wbinv_range(a, s)	arm64_dcache_wbinv_range((a), (s))
#define	cpu_dcache_inv_range(a, s)	arm64_dcache_inv_range((a), (s))
#define	cpu_dcache_wb_range(a, s)	arm64_dcache_wb_range((a), (s))

#define	cpu_idcache_wbinv_range(a, s)	arm64_idcache_wbinv_range((a), (s))
#define	cpu_icache_sync_range(a, s)	arm64_icache_sync_range((a), (s))

void arm64_nullop(void);
void arm64_setttb(vm_offset_t);
void arm64_tlb_flushID(void);
void arm64_tlb_flushID_SE(vm_offset_t);
void arm64_icache_sync_range(vm_offset_t, vm_size_t);
void arm64_idcache_wbinv_range(vm_offset_t, vm_size_t);
void arm64_dcache_wbinv_range(vm_offset_t, vm_size_t);
void arm64_dcache_inv_range(vm_offset_t, vm_size_t);
void arm64_dcache_wb_range(vm_offset_t, vm_size_t);

#endif
