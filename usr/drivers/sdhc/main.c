/**
 * \file
 * \brief IMX8x uSDHC Digital Host Controller Driver
 */

/*
 * Copyright (c) 2007, 2008, 2010, 2011, 2012,2020 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstrasse 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

/*
 * In U-boot drivers/mmc/fsl_esdhc.c is talking to the
 * same controller. This driver follows the i.MX 8DualXPlus/8QuadXPlus
 * Applications Processor Reference Manual register definitions and
 * descriptions, except for the vendor specific register, which is
 * used differently in U-Boot, and that seems the correct way.
 *
 * Card detection on Toradex boards:
 * ===========
 * The Toradex boards dont break out the SDHC card detection pin, instead
 * a GPIO (Bank4, Pin22) has to be checked for card present. Currently,
 * this driver simply assumes a card is present.
 */

#include <aos/aos.h>
#include <drivers/sdhc.h>
#include <aos/deferred.h>
#include <dev/imx8x/sdhc_dev.h>

//#define DEBUG_ON

#if defined(DEBUG_ON) || defined(GLOBAL_DEBUG)
#    define DEBUG(x...) debug_printf(x)
#else
#    define DEBUG(x...) ((void)0)
#endif

#define MMC_CMD_GO_IDLE_STATE       0
#define MMC_CMD_SEND_OP_COND        1
#define MMC_CMD_ALL_SEND_CID        2
#define MMC_CMD_SET_RELATIVE_ADDR   3
#define MMC_CMD_SET_DSR         4
#define MMC_CMD_SWITCH          6
#define MMC_CMD_SELECT_CARD     7
#define MMC_CMD_SEND_EXT_CSD        8
#define MMC_CMD_SEND_CSD        9
#define MMC_CMD_SEND_CID        10
#define MMC_CMD_STOP_TRANSMISSION   12
#define MMC_CMD_SEND_STATUS     13
#define MMC_CMD_SET_BLOCKLEN        16
#define MMC_CMD_READ_SINGLE_BLOCK   17
#define MMC_CMD_READ_MULTIPLE_BLOCK 18
#define MMC_CMD_SEND_TUNING_BLOCK       19
#define MMC_CMD_SEND_TUNING_BLOCK_HS200 21
#define MMC_CMD_SET_BLOCK_COUNT         23
#define MMC_CMD_WRITE_SINGLE_BLOCK  24
#define MMC_CMD_WRITE_MULTIPLE_BLOCK    25
#define MMC_CMD_ERASE_GROUP_START   35
#define MMC_CMD_ERASE_GROUP_END     36
#define MMC_CMD_ERASE           38
#define MMC_CMD_APP_CMD         55
#define MMC_CMD_SPI_READ_OCR        58
#define MMC_CMD_SPI_CRC_ON_OFF      59
#define MMC_CMD_RES_MAN         62

#define SD_CMD_SEND_RELATIVE_ADDR   3
#define SD_CMD_SWITCH_FUNC      6
#define SD_CMD_SEND_IF_COND     8
#define SD_CMD_SWITCH_UHS18V        11
#define SD_CMD_APP_SET_BUS_WIDTH    6
#define SD_CMD_APP_SD_STATUS        13
#define SD_CMD_ERASE_WR_BLK_START   32
#define SD_CMD_ERASE_WR_BLK_END     33
#define SD_CMD_APP_SEND_OP_COND     41
#define SD_CMD_APP_SEND_SCR     51


#define MMC_RSP_PRESENT (1 << 0)
#define MMC_RSP_136 (1 << 1)        /* 136 bit response */
#define MMC_RSP_CRC (1 << 2)        /* expect valid crc */
#define MMC_RSP_BUSY    (1 << 3)        /* card may send busy */
#define MMC_RSP_OPCODE  (1 << 4)        /* response contains opcode */

#define MMC_RSP_NONE    (0)
#define MMC_RSP_R1  (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R1b (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE| \
            MMC_RSP_BUSY)
#define MMC_RSP_R2  (MMC_RSP_PRESENT|MMC_RSP_136|MMC_RSP_CRC)
#define MMC_RSP_R3  (MMC_RSP_PRESENT)
#define MMC_RSP_R4  (MMC_RSP_PRESENT)
#define MMC_RSP_R5  (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R6  (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R7  (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)

#define OCR_BUSY        0x80000000
#define OCR_HCS         0x40000000
#define OCR_S18R        0x1000000

struct sdhc_s {
    sdhc_t dev;
    uintptr_t vbase;
    uint32_t caps;

    // Card properties
    uint8_t cid[16];
    uint32_t csd[4];
    uint16_t rca;
    int high_capacity;

    uint64_t read_bl_len;
    uint64_t write_bl_len ;
    uint64_t capacity_user;
};


struct cmd {
    uint16_t     cmdidx;
    unsigned int cmdarg;
    unsigned int resp_type;
    unsigned int response[4]; // The response of the command
    genpaddr_t   dma_base;    // If a data transfer is necessary, use this
                              // physical base address for read/write.
};

#define dump(sd) do {\
        char buf[1024];\
        sdhc_int_status_pr(buf, 1024, &sd->dev);\
        DEBUG("%s:%d: %s\n", __FUNCTION__, __LINE__, buf);\
    } while(0)

static errval_t software_reset(struct sdhc_s *sd){
    sdhc_sys_ctrl_rsta_wrf(&sd->dev, 1); 
    uint64_t timeout  = 1000;
    while(sdhc_sys_ctrl_rsta_rdf(&sd->dev)){
        if(--timeout == 0){
            DEBUG("Reset TIMEOUT!\n");
            return SDHC_ERR_RESET_TIMEOUT;
        }
        barrelfish_usleep(1000);
    }

    // Set sensible defaults
    sdhc_mmc_boot_rawwr(&sd->dev, 0);
    sdhc_mix_ctrl_rawwr(&sd->dev, 0);
    sdhc_clk_tune_ctrl_status_rawwr(&sd->dev, 0);
    sdhc_dll_rawwr(&sd->dev, 0);

    sdhc_vend_spec_t vs = 0;
    vs = sdhc_vend_spec_ipgen_insert(vs, 1);
    vs = sdhc_vend_spec_hcken_insert(vs, 1);
    sdhc_vend_spec_wr(&sd->dev, vs);
    
    DEBUG("Reset complete!\n");

    sd->caps = sdhc_host_ctrl_cap_rawrd(&sd->dev);

    //Setting clock to initial 40mhz
    sdhc_vend_spec_cken_wrf(&sd->dev, 0);

    sdhc_sys_ctrl_t s = 0;
    s = sdhc_sys_ctrl_dvs_insert(s, 0xf);
    s = sdhc_sys_ctrl_sdclkfs_insert(s, 0x10);
    s = sdhc_sys_ctrl_dtocv_insert(s, 0xc);
    sdhc_sys_ctrl_wr(&sd->dev, s);

    barrelfish_usleep(10000);
    vs = sdhc_vend_spec_rd(&sd->dev);
    vs = sdhc_vend_spec_peren_insert(vs, 1);
    vs = sdhc_vend_spec_cken_insert(vs, 1);
    sdhc_vend_spec_wr(&sd->dev, vs);

    sdhc_prot_ctrl_dtw_wrf(&sd->dev, 0); // Bus width: 1-bit mode
    sdhc_prot_ctrl_emode_wrf(&sd->dev, 0x2); // Little endian mode
    sdhc_sys_ctrl_dtocv_wrf(&sd->dev, 0xe);

    return SYS_ERR_OK;
}

static sdhc_cmd_xfr_typ_t xfr_typ_for_cmd(struct cmd *cmd){
    sdhc_cmd_xfr_typ_t c = 0;

    if(cmd->cmdidx == MMC_CMD_READ_SINGLE_BLOCK ||
       cmd->cmdidx == MMC_CMD_WRITE_SINGLE_BLOCK)
    {
        c = sdhc_cmd_xfr_typ_dpsel_insert(c, 1);
    }

    c = sdhc_cmd_xfr_typ_cmdinx_insert(c, cmd->cmdidx);
    if (cmd->resp_type & MMC_RSP_CRC)
        c = sdhc_cmd_xfr_typ_cccen_insert(c, 1);
    if (cmd->resp_type & MMC_RSP_OPCODE)
        c = sdhc_cmd_xfr_typ_cicen_insert(c, 1);

    
    c = sdhc_cmd_xfr_typ_rsptyp_insert(c, sdhc_rsp_tp_none);
    if (cmd->resp_type & MMC_RSP_136)
        c = sdhc_cmd_xfr_typ_rsptyp_insert(c, sdhc_rsp_tp_136);
    else if (cmd->resp_type & MMC_RSP_BUSY)
        c = sdhc_cmd_xfr_typ_rsptyp_insert(c, sdhc_rsp_tp_48cb);
    else if (cmd->resp_type & MMC_RSP_PRESENT)
        c = sdhc_cmd_xfr_typ_rsptyp_insert(c, sdhc_rsp_tp_48);
                                          
    c = sdhc_cmd_xfr_typ_cmdtyp_insert(c, sdhc_cmd_tp_norm);
    if (cmd->cmdidx == MMC_CMD_STOP_TRANSMISSION)
        c = sdhc_cmd_xfr_typ_cmdtyp_insert(c, sdhc_cmd_tp_abrt);

    return c;
}

static errval_t sdhc_send_cmd(struct sdhc_s * sd, struct cmd * cmd) {
    DEBUG("sdhc_send_cmd: cmdidx=%d,cmdarg=%d\n", cmd->cmdidx, cmd->cmdarg);

    uint32_t mask; // TODO: in some cases we don't need to wait for all
    if(cmd->cmdidx == MMC_CMD_STOP_TRANSMISSION) {
       mask = 1;
    } else {
       mask = 3;
    }
    while(sdhc_pres_state_rawrd(&sd->dev) & mask){
        DEBUG("Card busy!\n");
    }
    DEBUG("Card ready (data & cmd inhibit are clear)!\n");
    barrelfish_usleep(10000);

    // Clear interrupts
    sdhc_int_status_rawwr(&sd->dev, ~0x0);

    // Mask interrupts.
    sdhc_int_signal_en_rawwr(&sd->dev, 0);

    // CMD argument
    sdhc_cmd_arg_wr(&sd->dev, cmd->cmdarg);

    // Mixer controler
    int is_read = cmd->cmdidx == MMC_CMD_READ_SINGLE_BLOCK;
    int is_write = cmd->cmdidx == MMC_CMD_WRITE_SINGLE_BLOCK;
    sdhc_mix_ctrl_wr(&sd->dev, 0); 
    sdhc_mix_ctrl_dmaen_wrf(&sd->dev, is_read || is_write);
    sdhc_mix_ctrl_dtdsel_wrf(&sd->dev, is_read);

    if(is_read || is_write){
        // DMA address setup
        assert((cmd->dma_base >> 32) == 0);
        sdhc_vend_spec2_acmd23_argu2_en_wrf(&sd->dev, 0);
        sdhc_ds_addr_wr(&sd->dev, cmd->dma_base);

        //Set watermark
        sdhc_wtmk_lvl_rd_wml_wrf(&sd->dev, 16);
        sdhc_wtmk_lvl_wr_wml_wrf(&sd->dev, 16);
    }

    sdhc_cmd_xfr_typ_t c = xfr_typ_for_cmd(cmd);
    sdhc_cmd_xfr_typ_wr(&sd->dev, c);

    //DEBUG("%s:%d: Wait until irq_stat.tc || irq_stat.cc \n", __FUNCTION__, __LINE__);
    uint32_t tc = 0;
    uint32_t cc = 0;
    size_t i = 0;
    do {
        uint32_t ctoe = sdhc_int_status_ctoe_rdf(&sd->dev);
        uint32_t cce = sdhc_int_status_cce_rdf(&sd->dev);
        tc = sdhc_int_status_tc_rdf(&sd->dev);
        cc = sdhc_int_status_cc_rdf(&sd->dev);

        if (ctoe == 0x1 && cce == 0x1) {
            DEBUG("%s:%d: ctoe = 1 ccrc = 1: Conflict on cmd line.\n",
                    __FUNCTION__, __LINE__);
            dump(sd);
            return SDHC_ERR_CMD_CONFLICT;
        }
        if (ctoe == 0x1 && cce == 0x0) {
            DEBUG("%s:%d: cto = 1 ccrc = 0: Abort.\n", __FUNCTION__, __LINE__);
            dump(sd);
            return SDHC_ERR_CMD_TIMEOUT;
        }

        if (i++ > 1000) {
            dump(sd);
            USER_PANIC("Command not Ackd?");
        }
        barrelfish_usleep(100);
        if(tc || cc) break;
    } while (true);
    DEBUG("Command complete!\n");

    if(cmd->resp_type & MMC_RSP_136){
        uint32_t r0 = sdhc_cmd_rsp0_rd(&sd->dev);
        uint32_t r1 = sdhc_cmd_rsp1_rd(&sd->dev);
        uint32_t r2 = sdhc_cmd_rsp2_rd(&sd->dev);
        uint32_t r3 = sdhc_cmd_rsp3_rd(&sd->dev);
        cmd->response[0] = (r3 << 8) | (r2 >> 24);
        cmd->response[1] = (r2 << 8) | (r1 >> 24);
        cmd->response[2] = (r1 << 8) | (r0 >> 24);
        cmd->response[3] = (r0 << 8);
    } else {
        cmd->response[0] = sdhc_cmd_rsp0_rd(&sd->dev);
    }
    return SYS_ERR_OK;
}

static errval_t sdhc_go_idle(struct sdhc_s *sd) {
    errval_t err;
    struct cmd init = {
        .cmdidx = MMC_CMD_GO_IDLE_STATE,
        .cmdarg = 0,
        .resp_type = MMC_RSP_NONE
    };
    err = sdhc_send_cmd(sd, &init);
    if(err_is_ok(err)){
        DEBUG("Successfully sent GO_IDLE transaction\n");
    }
    barrelfish_usleep(2000);
    return err;
}

static errval_t sdhc_send_if_cond(struct sdhc_s *sd) {
    errval_t err;
    uint32_t pattern = 0xde;
    struct cmd cmd = {
        .cmdidx = SD_CMD_SEND_IF_COND,
        .cmdarg = 0x100 | pattern, // Offer 3V voltage followed by pattern
        .resp_type = MMC_RSP_R7
    };

    err = sdhc_send_cmd(sd, &cmd);
    if(err_is_ok(err)){
        if(cmd.response[0] == (0x100 | pattern)){
            DEBUG("IF_COND: Success! Got (at least) SD Version 2\n");
            return SYS_ERR_OK;
        } else {
            DEBUG("IF_COND: Legacy cards not supported!\n");
            err = SDHC_ERR_CMD_TIMEOUT;
        }
    }
    return err;
}

/*
 * This function queries the card to determine operating voltage/standard
 * etc. It does not perform a card initialization.
 */
static errval_t sdhc_get_ocr(struct sdhc_s *sd){
    errval_t err; 
    uint32_t ocr=0;

    while(1){
        struct cmd app_cmd = {
            .cmdidx = MMC_CMD_APP_CMD,
            .cmdarg = 0,
            .resp_type = MMC_RSP_R1
        };

        err = sdhc_send_cmd(sd, &app_cmd);
        if(err_is_fail(err)){
            DEBUG_ERR(err, "send app_cmd");
            return err;
        }

        struct cmd op_cond_cmd = {
            .cmdidx = SD_CMD_APP_SEND_OP_COND,
            .cmdarg = 0x40300000,  // Have OCS and default voltages 
            .resp_type = MMC_RSP_R3
        };
        err = sdhc_send_cmd(sd, &op_cond_cmd);
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "send op_cond_cmd");
            return err;
        }

        if(op_cond_cmd.response[0] & OCR_BUSY) {
            ocr = op_cond_cmd.response[0];
            break;
        }

        barrelfish_usleep(10000);
    }

    DEBUG("Received OCR! ocr=0x%"PRIx32"\n", ocr);

    if((ocr & OCR_HCS) == OCR_HCS){
        DEBUG("High capacity card found!\n");
        sd->high_capacity = 1;
    } else {
        DEBUG("Non high capacity card. NOT TESTED\n");
        sd->high_capacity = 0;
    }
    sd->rca = 0;
    return SYS_ERR_OK;
}



/** 
 * Here we perform the actual card initialization
 */
static errval_t sdhc_card_init(struct sdhc_s* sd){
    errval_t err;
    // Put card in identify mode
    struct cmd cid = {
        .cmdidx = MMC_CMD_ALL_SEND_CID,
        .resp_type = MMC_RSP_R2,
        .cmdarg = 0
    };
    err = sdhc_send_cmd(sd, &cid);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "cid command");
    }
    memcpy(sd->cid, cid.response, 16);

    struct cmd send_addr = {
        .cmdidx = SD_CMD_SEND_RELATIVE_ADDR,
        .cmdarg = sd->rca << 16,
        .resp_type = MMC_RSP_R6
    };

    err = sdhc_send_cmd(sd, &send_addr);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "send addr command");
    }
    sd->rca = send_addr.response[0] >> 16 & 0xffff;
    DEBUG("Determined RCA=0x%"PRIx16".\n", sd->rca);

    struct cmd send_csd = {
        .cmdidx = MMC_CMD_SEND_CSD,
        .resp_type = MMC_RSP_R2,
        .cmdarg = sd->rca << 16
    };
    err = sdhc_send_cmd(sd, &send_csd);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "send csd command");
    }
    sd->csd[0] = send_csd.response[0];
    sd->csd[1] = send_csd.response[1];
    sd->csd[2] = send_csd.response[2];
    sd->csd[3] = send_csd.response[3];
    DEBUG("CSD: [0]=%"PRIx32", [1]=%"PRIx32", [2]=%"PRIx32", [3]=%"PRIx32"\n",
            sd->csd[0], sd->csd[1], sd->csd[2], sd->csd[3]);
    sd->read_bl_len = 1 << ((sd->csd[1]>>16) & 0xf);
    DEBUG("SD read_bl_len: %"PRIx64"\n", sd->read_bl_len);
    sd->write_bl_len = sd->read_bl_len;

    if(sd->high_capacity) {
        unsigned int csize, cmult;
        csize = (sd->csd[1] & 0x3f) << 16 | (sd->csd[2] & 0xffff0000) >> 16;
        cmult = 8;
        sd->capacity_user = ((csize + 1) << (cmult + 2)) * sd->read_bl_len;
        DEBUG("SD capacity: %"PRIx64"\n", sd->capacity_user);
    }

    // Select the card, this puts it into the "transfer" state
    struct cmd select_card = {
        .cmdidx = MMC_CMD_SELECT_CARD,
        .resp_type = MMC_RSP_R1,
        .cmdarg = sd->rca << 16
    };
    err = sdhc_send_cmd(sd, &select_card);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "select_card cmd");
        return err;
    }      

    return SYS_ERR_OK;
}

errval_t sdhc_read_block(struct sdhc_s* sd, int index, lpaddr_t dest)
{
    errval_t err;

    struct cmd set_blocklen = {
        .cmdidx = MMC_CMD_SET_BLOCKLEN,
        .cmdarg = SDHC_BLOCK_SIZE,
        .resp_type = MMC_RSP_R1
    };
    err = sdhc_send_cmd(sd, &set_blocklen);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "set_blocklen");
        return err;
    }

    struct cmd read_block = {
        .cmdidx = MMC_CMD_READ_SINGLE_BLOCK,
        .cmdarg = index,
        .resp_type = MMC_RSP_R1,
        .dma_base = dest

    };
    err = sdhc_send_cmd(sd, &read_block);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "read_block");
        return err;
    }

    return SYS_ERR_OK;
}

errval_t sdhc_write_block(struct sdhc_s* sd, int index, lpaddr_t source){
    errval_t err;

    struct cmd set_blocklen = {
        .cmdidx = MMC_CMD_SET_BLOCKLEN,
        .cmdarg = SDHC_BLOCK_SIZE,
        .resp_type = MMC_RSP_R1
    };
    err = sdhc_send_cmd(sd, &set_blocklen);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "set_blocklen");
        return err;
    }

    struct cmd write_block = {
        .cmdidx = MMC_CMD_WRITE_SINGLE_BLOCK,
        .cmdarg = index,
        .resp_type = MMC_RSP_R1,
        .dma_base = source 

    };
    err = sdhc_send_cmd(sd, &write_block);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "read_block");
        return err;
    }

    return SYS_ERR_OK;
}

static errval_t card_init(struct sdhc_s * sd){
    //Initialize and identify the card. Roughly following SDHC specification,
    //3.6 Card Initialization and Identification.
    errval_t err;
    
    DEBUG("Sending go idle transaction...\n"); err = sdhc_go_idle(sd);
    if(err_is_fail(err)) return err;

    DEBUG("Sending if_cond transaction...\n");
    err = sdhc_send_if_cond(sd);
    if(err_is_fail(err)) return err;

    DEBUG("Query OCR (CMD 55/41)...\n");
    err = sdhc_get_ocr(sd);
    if(err_is_fail(err)) return err;

    DEBUG("Card initialization...\n");
    err = sdhc_card_init(sd);
    if(err_is_fail(err)) return err;

    DEBUG("Card in transfer state!");

    return SYS_ERR_OK;
}

errval_t sdhc_test(struct sdhc_s *sd, void* scratch, lpaddr_t scratch_p)
{
    errval_t err;

    // Write, read and verify some test data
    char test_data[] = {0x01,0x02,0x03,0xff,0x0};
    for(int i=0; test_data[i]; i++){
        ((char*)scratch)[i] = test_data[i];
    }

    err = sdhc_write_block(sd, SDHC_TEST_BLOCK, scratch_p);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "write block");
        return err;
    }

    memset(scratch, 0, 0x1000);

    err = sdhc_read_block(sd, SDHC_TEST_BLOCK, scratch_p);
    if(err_is_fail(err)){
        DEBUG_ERR(err, "read block");
        return err;
    }

    for(int i=0; test_data[i]; i++){
        char c = ((char*)scratch)[i];
        printf("Byte [%d] = %x\n", i, c);
        if(c != test_data[i]) return SDHC_ERR_TEST_FAILED;
    }

    return SYS_ERR_OK;
}

errval_t sdhc_init(struct sdhc_s** sd_ret, void *base)
{
    DEBUG("sdhc_init: enter\n");
    errval_t err;

    struct sdhc_s * sd = calloc(sizeof(struct sdhc_s), 1);
    *sd_ret = sd;

    sdhc_initialize(&sd->dev, base);

    err = software_reset(sd);
    if (err_is_fail(err)) {
       DEBUG_ERR(err, "software reset failed");
       return err;
    }
    DEBUG("reset done.\n");

    err = card_init(sd);
    if (err_is_fail(err)) {
       DEBUG_ERR(err, "card init failed (No card present?)");
       return err;
    }

    return SYS_ERR_OK;
}

