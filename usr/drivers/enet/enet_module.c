/**
 * \file
 * \brief imx8 NIC driver module
 */
/*
 * Copyright (c) 2019, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>
#include <netutil/etharp.h>


#include "enet.h"

#define PHY_ID 0x2

static errval_t enet_write_mdio(struct enet_driver_state* st, int8_t phyaddr,
                                int8_t regaddr, int16_t data)
{
    
    // Some protocol ...

    enet_mmfr_t reg = 0;
    reg = enet_mmfr_pa_insert(reg, phyaddr);
    reg = enet_mmfr_ra_insert(reg, regaddr);
    reg = enet_mmfr_data_insert(reg, data);   
    reg = enet_mmfr_st_insert(reg, 0x1);   
    reg = enet_mmfr_ta_insert(reg, 0x2);   

    // 1 is write 2 is read
    reg = enet_mmfr_op_insert(reg, 0x1);   
 
    ENET_DEBUG("Write MDIO: write cmd %lx \n", reg);

    enet_mmfr_wr(st->d, reg);

    uint16_t tries = 1000;
    while (!(enet_eir_mii_rdf(st->d) & 0x1)) {
        tries--;
        //barrelfish_usleep(10);
        if (tries == 0) {
            return ENET_ERR_MDIO_WRITE;
        }
    }
   
    enet_eir_mii_wrf(st->d, 0x1);
    return SYS_ERR_OK;
}

static errval_t enet_read_mdio(struct enet_driver_state* st, int8_t phyaddr,
                               int8_t regaddr, int16_t *data)
{
    
    // Some protocol ...
    enet_eir_mii_wrf(st->d, 0x1);

    enet_mmfr_t reg = 0;
    reg = enet_mmfr_pa_insert(reg, phyaddr);
    reg = enet_mmfr_ra_insert(reg, regaddr);
    reg = enet_mmfr_st_insert(reg, 0x1);   
    reg = enet_mmfr_ta_insert(reg, 0x2);   
    // 1 is write 2 is read
    reg = enet_mmfr_op_insert(reg, 0x2);   

    enet_mmfr_wr(st->d, reg);
    
    ENET_DEBUG("Read MDIO: read cmd %lx \n", reg);

    uint16_t tries = 1000;
    while (!(enet_eir_mii_rdf(st->d) & 0x1)) {
        barrelfish_usleep(10);
        tries--;
        if (tries == 0) {
            return ENET_ERR_MDIO_WRITE;
        }
    }
    
    enet_eir_mii_wrf(st->d, 0x1);
    *data = enet_mmfr_data_rdf(st->d);
    
    return SYS_ERR_OK;
}

static errval_t enet_get_phy_id(struct enet_driver_state* st)
{
    errval_t err;
    int16_t data; 
    uint32_t phy_id;

    // get phy ID1
    err = enet_read_mdio(st, PHY_ID,  0x2, &data);
    if (err_is_fail(err))  {
        return err;
    }   
    phy_id = data << 16;

    // get phy ID2
    err = enet_read_mdio(st, PHY_ID,  0x3, &data);
    if (err_is_fail(err))  {
        return err;
    }   

    phy_id |= data;
    st->phy_id = phy_id;    
    return err;
}

#define PHY_RESET 0x8000

#define PHY_RESET_CMD 0x0
#define PHY_STATUS_CMD 0x1
#define PHY_AUTONEG_CMD 0x4
#define PHY_LPA_CMD 0x5
#define PHY_CTRL1000_CMD 0x09
#define PHY_STAT1000_CMD 0x0a

static errval_t enet_reset_phy(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_write_mdio(st, PHY_ID, PHY_RESET_CMD, PHY_RESET);
    if (err_is_fail(err))  {
        return err;
    }   

    int16_t data;
    err = enet_read_mdio(st, PHY_ID, PHY_RESET_CMD, &data);
    if (err_is_fail(err))  {
        return err;
    }   
    
    int timeout = 500;
    while ((data & PHY_RESET) && timeout > 0) {
        err = enet_read_mdio(st, PHY_ID, PHY_RESET_CMD, &data);
        if (err_is_fail(err))  {
            return err;
        }   
    
        barrelfish_usleep(1000);
        timeout--;
    }

    if (data & PHY_RESET) {
        return ENET_ERR_PHY_RESET;
    }

    return SYS_ERR_OK;
}

static errval_t enet_setup_autoneg(struct enet_driver_state* st)
{
    errval_t err;
    int16_t status;
    int16_t autoneg;

    // Read BASIC MODE status register
    err = enet_read_mdio(st, PHY_ID, 0x1, &status);
    if (err_is_fail(err))  {
        return err;
    }   

    // READ autoneg status
    err = enet_read_mdio(st, PHY_ID, PHY_AUTONEG_CMD, &autoneg);
    if (err_is_fail(err))  {
        return err;
    }   
    
    // Read BASIC contorl register
    err = enet_read_mdio(st, PHY_ID, PHY_RESET_CMD, &status);
    if (err_is_fail(err))  {
        return err;
    }   

    return SYS_ERR_OK;
}

#define AUTONEG_100FULL 0x0100
#define AUTONEG_100HALF 0x0080
#define AUTONEG_10FULL  0x0040
#define AUTONEG_10HALF  0x0020
#define AUTONEG_PSB_802_3 0x0001

#define AUTONEG_ENABLE 0x1000
#define AUTONEG_RESTART 0x0200
static errval_t enet_restart_autoneg(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_write_mdio(st, PHY_ID, PHY_RESET_CMD, PHY_RESET);
    if (err_is_fail(err)) {
        return err;
    }

    barrelfish_usleep(1000);
    //barrelfish_usleep(1000);

    err = enet_write_mdio(st, PHY_ID, PHY_AUTONEG_CMD, 
                          AUTONEG_100FULL | AUTONEG_100HALF | AUTONEG_10FULL |
                          AUTONEG_10HALF | AUTONEG_PSB_802_3);
    if (err_is_fail(err)) {
        return err;
    }
 
    err = enet_write_mdio(st, PHY_ID, PHY_RESET_CMD, 
                          AUTONEG_ENABLE | AUTONEG_RESTART);
    if (err_is_fail(err)) {
        return err;
    }
   
    return SYS_ERR_OK;
}


static errval_t enet_init_phy(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_get_phy_id(st);
    if (err_is_fail(err))  {
        return err;
    }   
 
    err = enet_reset_phy(st);
    if (err_is_fail(err))  {
        return err;
    }   
   
    // board_phy_config in uboot driver. Don't know what
    // this actually does ...
    err = enet_write_mdio(st, PHY_ID, 0x1d, 0x1f);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1e, 0x8);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1d, 0x00);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1e, 0x82ee);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1d, 0x05);
    assert(err_is_ok(err));
    err = enet_write_mdio(st, PHY_ID, 0x1e, 0x100);
    assert(err_is_ok(err));

    err = enet_setup_autoneg(st);
    if (err_is_fail(err))  {
        return err;
    }   

    return SYS_ERR_OK;
}



#define PHY_STATUS_LSTATUS 0x0004
#define PHY_STATUS_ANEG_COMP 0x0020
#define PHY_STATUS_ESTAT 0x0100
#define PHY_STATUS_ERCAP 0x0001


#define PHY_LPA_100HALF  0x0080
#define PHY_LPA_100FULL 0x0100
#define PHY_LPA_10FULL  0x0040
// TODO check for rest of link capabilities
static void enet_parse_link(struct enet_driver_state* st)
{
    // just a sanity check if values are ok
    errval_t err;
    int16_t status;
    err = enet_read_mdio(st, PHY_ID, PHY_STAT1000_CMD, &status);
    assert(err_is_ok(err));

    int16_t mii_reg;
    err = enet_read_mdio(st, PHY_ID, PHY_STATUS_CMD, &mii_reg);
    assert(err_is_ok(err));

    if (status < 0) {   
        debug_printf("ENET not capable of 1G \n");
        return;
    } else {
        err = enet_read_mdio(st, PHY_ID, PHY_CTRL1000_CMD, &status);
        assert(err_is_ok(err));
        
        if (status == 0) {
            int16_t lpa, lpa2;   
            err = enet_read_mdio(st, PHY_ID, PHY_AUTONEG_CMD, &lpa);
            assert(err_is_ok(err));

            err = enet_read_mdio(st, PHY_ID, PHY_LPA_CMD, &lpa2);
            assert(err_is_ok(err));
        
            lpa &= lpa2;
            if (lpa & (PHY_LPA_100FULL | PHY_LPA_100HALF)) {
                if (lpa & PHY_LPA_100FULL) {
                    debug_printf("LINK 100 Mbit/s FULL duplex \n");
                } else {
                    debug_printf("LINK 100 Mbit/s half\n");
                }
            }
        }
    }

}

static errval_t enet_phy_startup(struct enet_driver_state* st)
{
    errval_t err;
    // board_phy_config in uboot driver. Don't know what
    // this actually does ...
    int16_t mii_reg;
    err = enet_read_mdio(st, PHY_ID, PHY_STATUS_CMD, &mii_reg);
    assert(err_is_ok(err));

    if (mii_reg & PHY_STATUS_LSTATUS) {
        debug_printf("LINK already UP\n");
        return SYS_ERR_OK;
    }
    
    if (!(mii_reg & PHY_STATUS_ANEG_COMP)) {

        debug_printf("[enet] Starting autonegotiation \n");
        while(!(mii_reg & PHY_STATUS_ANEG_COMP))  {
            err = enet_read_mdio(st, PHY_ID, PHY_STATUS_CMD, &mii_reg);
            assert(err_is_ok(err));
            barrelfish_usleep(1000);
        }
        
        ENET_DEBUG("Autonegotation done\n");
    }
    
    enet_parse_link(st);
    
    return SYS_ERR_OK;
}

// bool promiscous for promiscous mode. 
// This will also set it so that all multicast packets will also be received!
/*
static void enet_init_multicast_filt(struct enet_driver_state* st, bool promisc)
{
    if (promisc) {
        enet_rcr_prom_wrf(st->d, 1);
        return;
    }

    enet_rcr_prom_wrf(st->d, 0);
    
    // TODO Catching all multicast packets for now
    enet_gaur_wr(st->d, 0xFFFFFFFF);
    enet_galr_wr(st->d, 0xFFFFFFFF);
    // TODO if we do not catch all multicast packet then do this:
    // crc32 value of mac address
    #if 0
    unsigned int crc = 0xffffffff;
    unsigned char hash;
    unsigned int hash_high = 0, hash_low = 0;
    for (int i = 0; i < 6; i++) {
        unsigned char data = ((uint8_t*) &st->mac)[i];

        for (int bit = 0; bit < 8; bit++, data >>= 1) {
            crc = (crc >> 1) ^ (((crc ^ data) & 1) ? ENET_CRC32_POLY : 0);  
        }
        
        hash = (crc >> (32 - ENET_HASH_BITS)) & 0x3f;  
        
        if (hash > 31) {
            hash_high |= 1 << (hash - 32);
        } else {
            hash_low |= 1 << hash;
        }
    } 
  
    enet_gaur_gaddr_wrf(st->d, hash_high);
    enet_galr_gaddr_wrf(st->d, hash_low);
    #endif
    // TODO if this is M5272 then set the hash table entries to 0 ...
}
*/

static void enet_read_mac(struct enet_driver_state* st)
{
    uint64_t lower = enet_palr_paddr1_rdf(st->d);
    uint64_t upper = enet_paur_paddr2_rdf(st->d);
    // this is weird lower seems to be the upper part of the address ..
    uint64_t mac = (lower << 16) | upper;

    ENET_DEBUG("MAC %lx \n", mac);
    st->mac = mac;  
}

static void enet_write_mac(struct enet_driver_state* st)
{
    
    uint64_t lower = st->mac >> 16;
    uint32_t upper = st->mac & 0xFFFF;

    enet_palr_paddr1_wrf(st->d, lower);
    enet_paur_paddr2_wrf(st->d, upper);
}

static errval_t enet_reset(struct enet_driver_state* st)
{
    // reset device
    ENET_DEBUG("Reset device\n");
    
    uint64_t ecr = enet_ecr_rd(st->d);
    enet_ecr_wr(st->d, ecr | 0x1);
    int timeout = 500;
    while ((enet_ecr_rd(st->d) & 0x1) && timeout > 0) {
        barrelfish_usleep(10);
        // TODO timeout
    }

    if (timeout <= 0) {
        return ENET_ERR_DEV_RESET;
    }
   
    return SYS_ERR_OK;
}

static void enet_reg_setup(struct enet_driver_state* st)
{
    // Set interrupt mask register
    ENET_DEBUG("Set interrupt mask register\n");
    enet_eimr_wr(st->d, 0x0);
    // Clear outstanding interrupts
    ENET_DEBUG("Clear outstanding interrupts\n");
    enet_eir_wr(st->d, 0xFFFFFFFF);
    
    uint64_t reg; 
    // TODO see if other fields are required, not in dump
    reg = enet_rcr_rd(st->d);
    reg = enet_rcr_loop_insert(reg, 0x0);
    reg = enet_rcr_rmii_mode_insert(reg, 0x1);
    reg = enet_rcr_mii_mode_insert(reg, 0x1);
    reg = enet_rcr_fce_insert(reg, 0x1);
    reg = enet_rcr_max_fl_insert(reg, 1522);
    //reg = enet_rcr_prom_insert(reg, 1);
    enet_rcr_wr(st->d, reg);   
}

static errval_t enet_open(struct enet_driver_state *st)
{
    errval_t err = SYS_ERR_OK;
    // Enable full duplex, disable heartbeet
    enet_tcr_fden_wrf(st->d, 0x1);

    // Enable HW endian swap
    enet_ecr_dbswp_wrf(st->d, 0x1);
    enet_ecr_en1588_wrf(st->d, 0x0);
    // Enable store and forward mode
    enet_tfwr_strfwd_wrf(st->d, 0x1);
    // Enable controler
    enet_ecr_etheren_wrf(st->d, 0x1);

    // TODO don't think this is MX25/MX53 or MX6SL
    // Startup PHY
    err = enet_phy_startup(st);
    if (err_is_fail(err))  {
        return err;
    } 

    uint8_t speed = enet_ecr_speed_rdf(st->d);
    
    if (!speed) {
        enet_rcr_rmii_10t_wrf(st->d, 0x0);
    }

    //enet_activate_rx_ring(st);
    ENET_DEBUG("Init done! \n");
    return err;
}

static errval_t enet_init(struct enet_driver_state* st)
{
    errval_t err = SYS_ERR_OK;
    // set HW addreses
    enet_iaur_wr(st->d, 0);
    enet_ialr_wr(st->d, 0);
    enet_gaur_wr(st->d, 0);
    enet_galr_wr(st->d, 0);
    enet_write_mac(st);

    enet_reg_setup(st);

    uint64_t reg; 
    // Set MII speed, do not drop preamble and set hold time to 10ns
    reg = enet_mscr_rd(st->d);
    reg = enet_mscr_mii_speed_insert(reg, 0x18);
    reg = enet_mscr_hold_time_insert(reg, 0x1);
    enet_mscr_wr(st->d, reg);

    // Set Opcode and Pause duration
    enet_opd_wr(st->d, 0x00010020);
    enet_tfwr_tfwr_wrf(st->d, 0x2);

    // Set multicast addr filter
    enet_gaur_wr(st->d, 0);
    enet_galr_wr(st->d, 0);

    // Max pkt size rewrite ...
    enet_mrbr_wr(st->d, 0x600);

    // Tell card beginning of rx/tx rings
    //enet_rdsr_wr(st->d, st->rxq->desc_mem.devaddr);
    //enet_tdsr_wr(st->d, st->txq->desc_mem.devaddr);

    err = enet_restart_autoneg(st);
    if (err_is_fail(err)) {
        return err;
    }

    err = enet_open(st);
    if (err_is_fail(err)) {
        // TODO cleanup
        return err;
    }

    return err;
}

static errval_t enet_probe(struct enet_driver_state* st)
{
    errval_t err;
    err = enet_reset(st);
    if (err_is_fail(err)) {
        return err;
    }
 
    enet_reg_setup(st);
   
    uint64_t reg; 
    // Set MII speed, do not drop preamble and set hold time to 10ns
    reg = enet_mscr_rd(st->d);
    reg = enet_mscr_mii_speed_insert(reg, 0x18);
    reg = enet_mscr_hold_time_insert(reg, 0x1);
    enet_mscr_wr(st->d, reg);

    err = enet_init_phy(st);
    if (err_is_fail(err))  {
        debug_printf("Failed PHY reset\n");
        return err;
    }   

    // Write back mac again
    ENET_DEBUG("Reset MAC\n");
    // TODO do this later? NOT in dump
    enet_write_mac(st);
    enet_read_mac(st);

    // TODO checked dump until here! 
    return SYS_ERR_OK;
}


int main(int argc, char *argv[]) {
    errval_t err;

    debug_printf("Enet driver started \n");
    struct enet_driver_state * st = (struct enet_driver_state*) 
                                    calloc(1, sizeof(struct enet_driver_state));    
    assert(st != NULL);

    /* TODO Net Project: get the capability to the register region
     * and then map it so it is accessible. 
     * TODO set st->d_vaddr to the memory mapped register region */
    if (st->d_vaddr == NULL) {
        USER_PANIC("ENET: No register region mapped \N");
    }

    /* Initialize Mackerel binding */
    st->d = (enet_t *) malloc(sizeof(enet_t));
    enet_initialize(st->d, (void *) st->d_vaddr);

    assert(st->d != NULL);
    enet_read_mac(st);

    err = enet_probe(st);
    if (err_is_fail(err)) {
        // TODO cleanup
        return err;
    }

    err = enet_init(st);
    if (err_is_fail(err)) {
        // TODO cleanup
        return err;
    }

    debug_printf("Enet driver init done \n");
    
    debug_printf("Creating devqs \n");
   
    err = enet_rx_queue_create(&st->rxq, st->d);
    if (err_is_fail(err)) {
        debug_printf("Failed creating RX devq \n");
        return err;
    }

    err = enet_tx_queue_create(&st->txq, st->d);
    if (err_is_fail(err)) {
        debug_printf("Failed creating RX devq \n");
        return err;
    }

    // Add some memory to receive stuffa
    err = frame_alloc(&st->rx_mem, 512*2048, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    regionid_t rid;
    err = devq_register((struct devq*) st->rxq, st->rx_mem, &rid);
    if (err_is_fail(err)) {
        return err;
    }

    // Enqueue buffers
    for (int i = 0; i < st->rxq->size-1; i++) {
        err = devq_enqueue((struct devq*) st->rxq, rid, i*(2048), 2048,
                            0, 2048, 0);
        if (err_is_fail(err)) {
            return err;
        }
    }

    err = frame_alloc(&st->tx_mem, 512*2048, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    err = devq_register((struct devq*) st->txq, st->tx_mem, &rid);
    if (err_is_fail(err)) {
        return err;
    }
    struct devq_buf buf;
    while(true) {
        err = devq_dequeue((struct devq*) st->rxq, &buf.rid, &buf.offset,
                           &buf.length, &buf.valid_data, &buf.valid_length,
                           &buf.flags);
        if (err_is_ok(err)) {
            debug_printf("Received Packet of size %lu \n", buf.valid_length);
            err = devq_enqueue((struct devq*) st->rxq, buf.rid, buf.offset,
                               buf.length, buf.valid_data, buf.valid_length,
                               buf.flags);
            assert(err_is_ok(err));
        }
    }
}
