/**
 * \file
 * \brief Serial port driver.
 */

/*
 * Copyright (c) 2020, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstrasse 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <drivers/lpuart.h>
#include <dev/lpuart_dev.h>

struct lpuart_s {
    struct event_closure int_handler;
    struct lpuart_t dev;
};


static void hw_init(struct lpuart_s *s)
{  
    // Disable transceiver
    lpuart_ctrl_t ctrl = lpuart_ctrl_rawrd(&s->dev);
    ctrl = lpuart_ctrl_te_insert(ctrl, 0);
    ctrl = lpuart_ctrl_re_insert(ctrl, 0);
    lpuart_ctrl_rawwr(&s->dev, ctrl);

    // Set baudrate
    // baudrate = clock rate / (over sampling rate * SBR)
    // TODO: Currently we assume UART clock is set to 8MHz
    lpuart_baud_t baud = lpuart_baud_default;
    baud = lpuart_baud_osr_insert(baud, lpuart_ratio5);

    // OSR of 5 needs bothedge set
    baud = lpuart_baud_bothedge_insert(baud, 1);
    baud = lpuart_baud_sbr_insert(baud, 139);
    lpuart_baud_rawwr(&s->dev, baud);

    // enable FIFOs
    ctrl = lpuart_ctrl_default;
    ctrl = lpuart_ctrl_te_insert(ctrl, 0);
    ctrl = lpuart_ctrl_re_insert(ctrl, 0);
    lpuart_ctrl_rawwr(&s->dev, ctrl);
    lpuart_fifo_t fcr = lpuart_fifo_default;
    fcr = lpuart_fifo_rxfe_insert(fcr, 1);
    lpuart_fifo_rawwr(&s->dev, fcr);
    fcr = lpuart_fifo_txfe_insert(fcr, 1);
    lpuart_fifo_rawwr(&s->dev, fcr);
    // Set both watermarks to 0 (and also reset their counts)
    lpuart_water_rawwr(&s->dev, 0);

    // Enable transceiver
    ctrl = lpuart_ctrl_default;
    ctrl = lpuart_ctrl_te_insert(ctrl, 1);
    ctrl = lpuart_ctrl_re_insert(ctrl, 1);
    lpuart_ctrl_rawwr(&s->dev, ctrl);
}

errval_t lpuart_init(struct lpuart_s** s_ret, void *base)
{
    LPUART_DEBUG("Driver init\n");

    assert(s_ret != NULL);
    assert(base != NULL);

    struct lpuart_s *s = calloc(1, sizeof(struct lpuart_s));
    assert(s);
    *s_ret = s;
    
    lpuart_initialize(&s->dev, base);

    uint8_t major = lpuart_verid_major_rdf(&s->dev); 
    uint8_t minor = lpuart_verid_minor_rdf(&s->dev); 
    LPUART_DEBUG("Read version major=%d, minor=%d\n", major, minor);
    if(major != 4 || minor != 1){
       return LPUART_ERR_INVALID_DEV; 
    }

    LPUART_DEBUG("Initializing hw...");
    hw_init(s);
    return SYS_ERR_OK;
}

errval_t lpuart_getchar(struct lpuart_s *s, char *c)
{
    if (lpuart_stat_or_rdf(&s->dev)) {
        lpuart_stat_or_wrf(&s->dev, 1);
        return LPUART_ERR_RCV_OVERRUN;
    }

    if (lpuart_stat_rdrf_rdf(&s->dev) == 0) {
        return LPUART_ERR_NO_DATA;
    }

    *c = lpuart_rxdata_buf_rdf(&s->dev);
    return SYS_ERR_OK;
}


errval_t lpuart_enable_interrupt(struct lpuart_s *s)
{
    // Receive interrupt enable
    lpuart_ctrl_rie_wrf(&s->dev,1);
    return SYS_ERR_OK;
}

errval_t lpuart_putchar(struct lpuart_s *s, char c)
{
    lpuart_t *u = &s->dev;
    assert(u->base != 0);

    while (lpuart_stat_tdre_rdf(u) == 0)
        ;
    lpuart_txdata_wr(u, c);
    return SYS_ERR_OK;
}
