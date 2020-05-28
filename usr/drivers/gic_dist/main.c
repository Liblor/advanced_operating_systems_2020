/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr 6, CH-8092 Zurich.
 */

#include <stdio.h>
#include <stdlib.h>
#include <aos/aos.h>
#include <drivers/gic_dist.h>
#include <dev/pl390_gic_dist_dev.h>

struct gic_dist_s {
    pl390_gic_dist_t devgic;
    uint32_t it_num_lines;
    int cpu_count;
};

enum IrqType {
    IrqType_SGI,
    IrqType_PPI,
    IrqType_SPI
};

/**
 * \brief Returns the IRQ type based on the interrupt ID
 *
 * We have three types of interrupts
 * 1) Software generated Interrupts (SGI): IDs 0-15
 * 2) Private Peripheral Interrupts (PPI): IDs 16-31
 * 3) Shared Peripheral Interrups (SPI): IDs 32-
 *
 * \return The type of the interrupt.
 */
static enum IrqType get_irq_type(uint32_t int_id)
{
    if (int_id < 16) {
        return IrqType_SGI;
    } else if (int_id < 32) {
        return IrqType_PPI;
    } else {
        return IrqType_SPI;
    }
}


void gic_dist_raise_softirq(struct gic_dist_s * gds, uint8_t cpumask, uint8_t irq)
{
    uint32_t regval = (cpumask << 16) | irq;
    pl390_gic_dist_ICDSGIR_wr(&gds->devgic, regval);
};

errval_t gic_dist_enable_interrupt(struct gic_dist_s *gds, int int_id,
    uint8_t cpu_targets, uint16_t prio)
{
    // For now, we support only edge triggered and one to one interrupts
    bool edge_triggered = 1;
    bool one_to_n = 0;
    //Disable forwarding
    pl390_gic_dist_ICDDCR_enable_wrf(&gds->devgic, 0x0);

    assert(edge_triggered);
    GIC_DIST_DEBUG("enable int=%d forwarding to cpu_mask=%d\n", int_id, cpu_targets);
    uint32_t ind = int_id / 32;
    uint32_t bit_mask = (1U << (int_id % 32));
    enum IrqType irq_type = get_irq_type(int_id);

    // We allow PPI on any core, and SPI only on instance 0
    if(!(irq_type == IrqType_SPI && int_id <= gds->it_num_lines))
    {
        GIC_DIST_DEBUG("invalid int_id=%d\n", int_id);
        return SYS_ERR_IRQ_INVALID;
    }
    
    // Enable
    // 1 Bit per interrupt
    uint32_t regval = pl390_gic_dist_ICDISER_rd(&gds->devgic, ind);
    regval |= bit_mask;
    pl390_gic_dist_ICDISER_wr(&gds->devgic, ind, regval);

    // TODO: cleanup pl390 mackerel file so that we don't need bit magic
    // here.  -SG, 2012/12/13

    // Priority
    // 8 Bit per interrupt
    // chp 4.3.10
    ind = int_id/4;
    // XXX: check that priorities work properly, -SG, 2012/12/13
    prio = (prio & 0xF)<<4;
    switch(int_id % 4) {
    case 0:
        pl390_gic_dist_ICDIPR_prio_off0_wrf(&gds->devgic, ind, prio);
        break;
    case 1:
        pl390_gic_dist_ICDIPR_prio_off1_wrf(&gds->devgic, ind, prio);
        break;
    case 2:
        pl390_gic_dist_ICDIPR_prio_off2_wrf(&gds->devgic, ind, prio);
        break;
    case 3:
        pl390_gic_dist_ICDIPR_prio_off3_wrf(&gds->devgic, ind, prio);
        break;
    }

    // Target processors (only SPIs)
    // 8 Bit per interrupt
    ind = int_id/4;
    if (irq_type == IrqType_SPI) { // rest is ro
        switch (int_id % 4) {
        case 0:
            pl390_gic_dist_ICDIPTR_targets_off0_wrf(&gds->devgic, ind, cpu_targets);
            break;
        case 1:
            pl390_gic_dist_ICDIPTR_targets_off1_wrf(&gds->devgic, ind, cpu_targets);
            break;
        case 2:
            pl390_gic_dist_ICDIPTR_targets_off2_wrf(&gds->devgic, ind, cpu_targets);
            break;
        case 3:
            pl390_gic_dist_ICDIPTR_targets_off3_wrf(&gds->devgic, ind, cpu_targets);
            break;
        }
    }

    // Configuration registers
    // 2 Bit per IRQ
    ind = int_id/16;
    uint8_t val = ((edge_triggered&0x1) << 1) | (one_to_n&0x1);
    switch (int_id % 16) {
    case 0:
        pl390_gic_dist_ICDICR_conf0_wrf(&gds->devgic, ind, val);
        break;
    case 1:
        pl390_gic_dist_ICDICR_conf1_wrf(&gds->devgic, ind, val);
        break;
    case 2:
        pl390_gic_dist_ICDICR_conf2_wrf(&gds->devgic, ind, val);
        break;
    case 3:
        pl390_gic_dist_ICDICR_conf3_wrf(&gds->devgic, ind, val);
        break;
    case 4:
        pl390_gic_dist_ICDICR_conf4_wrf(&gds->devgic, ind, val);
        break;
    case 5:
        pl390_gic_dist_ICDICR_conf5_wrf(&gds->devgic, ind, val);
        break;
    case 6:
        pl390_gic_dist_ICDICR_conf6_wrf(&gds->devgic, ind, val);
        break;
    case 7:
        pl390_gic_dist_ICDICR_conf7_wrf(&gds->devgic, ind, val);
        break;
    case 8:
        pl390_gic_dist_ICDICR_conf8_wrf(&gds->devgic, ind, val);
        break;
    case 9:
        pl390_gic_dist_ICDICR_conf9_wrf(&gds->devgic, ind, val);
        break;
    case 10:
        pl390_gic_dist_ICDICR_conf10_wrf(&gds->devgic, ind, val);
        break;
    case 11:
        pl390_gic_dist_ICDICR_conf11_wrf(&gds->devgic, ind, val);
        break;
    case 12:
        pl390_gic_dist_ICDICR_conf12_wrf(&gds->devgic, ind, val);
        break;
    case 13:
        pl390_gic_dist_ICDICR_conf13_wrf(&gds->devgic, ind, val);
        break;
    case 14:
        pl390_gic_dist_ICDICR_conf14_wrf(&gds->devgic, ind, val);
        break;
    case 15:
        pl390_gic_dist_ICDICR_conf15_wrf(&gds->devgic, ind, val);
        break;
    }

    //Re-enable forwarding
    pl390_gic_dist_ICDDCR_enable_wrf(&gds->devgic, 0x1);

    return SYS_ERR_OK;
}

errval_t gic_dist_init(struct gic_dist_s** gds_ret, void* base) {
    GIC_DIST_DEBUG("Driver init\n");
    
    assert(gds_ret != NULL);
    assert(base != NULL);

    struct gic_dist_s * gds = calloc(sizeof(struct gic_dist_s), 1);
    assert(gds);
    *gds_ret = gds;

    // Hardware init
    pl390_gic_dist_initialize(&gds->devgic, base);

    // read GIC configuration
    pl390_gic_dist_ICDICTR_t gic_config = pl390_gic_dist_ICDICTR_rd(&gds->devgic);

    // ARM GIC 2.0 TRM, Table 4-6
    // This is the number of ICDISERs, i.e. #SPIs
    // Number of SGIs (0-15) and PPIs (16-31) is fixed
    uint32_t it_num_lines_tmp =
        pl390_gic_dist_ICDICTR_it_lines_num_extract(gic_config);
    gds->it_num_lines = 32*(it_num_lines_tmp + 1);
    gds->cpu_count = pl390_gic_dist_ICDICTR_cpu_number_extract(gic_config) + 1;

    GIC_DIST_DEBUG("interrupt lines = %d, cpu_count = %d\n", gds->it_num_lines,
            gds->cpu_count);

    // enable interrupt forwarding from distributor to cpu interface
    pl390_gic_dist_ICDDCR_enable_wrf(&gds->devgic, 0x1);

    return SYS_ERR_OK;
}
