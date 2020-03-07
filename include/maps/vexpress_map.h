/**
 * \file
 * \brief Physical memory map for the Versatile Express motherboard
 *
 */

/*
 * Copyright (c) 2012, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstrasse 6, CH-8092 Zurich.
 * Attn: Systems Group.
 */

#ifndef VEXPRESS_MAP_H
#define VEXPRESS_MAP_H

/*
 * For more information, see the ARM Motherboard Express μATX
 * Technical Reference Manual V2M-P1. Section numbers below refer to this.
 */

/*
 * Chip select addresses: see S.4.2.2.  This is the setup used by the
 * CoreTile Express A15x2 daughterboard, which is what GEM5 seems to
 * be emulating (mostly).
 */
#define VEXPRESS_MAP_CS0        0x00000000
#define VEXPRESS_MAP_CS1        0x14000000
#define VEXPRESS_MAP_CS2        0x18000000
#define VEXPRESS_MAP_CS3        0x1C000000
#define VEXPRESS_MAP_CS4        0x0C000000
#define VEXPRESS_MAP_CS5        0x10000000

#define VEXPRESS_MAP_NOR_FLASH_0    (VEXPRESS_MAP_CS0 + 0)
#define VEXPRESS_MAP_NOR_FLASH_0_SIZE   0x4000000
#define VEXPRESS_MAP_NOR_FLASH_1    (VEXPRESS_MAP_CS4 + 0)
#define VEXPRESS_MAP_NOR_FLASH_1_SIZE   0x4000000
#define VEXPRESS_MAP_USER_SRAM      (VEXPRESS_MAP_CS1 + 0)
#define VEXPRESS_MAP_USER_SRAM_SIZE 0x4000000
#define VEXPRESS_MAP_VRAM       (VEXPRESS_MAP_CS2 + 0)
#define VEXPRESS_MAP_VRAM_SIZE      0x2000000
#define VEXPRESS_MAP_LAN        (VEXPRESS_MAP_CS2 + 0x02000000)
#define VEXPRESS_MAP_LAN_SIZE       0x10000
#define VEXPRESS_MAP_USB        (VEXPRESS_MAP_CS2 + 0x03000000)
#define VEXPRESS_MAP_USB_SIZE       0x20000

#define VEXPRESS_MAP_DAP_ROM        (VEXPRESS_MAP_CS3 + 0x00000000)
#define VEXPRESS_MAP_DAP_ROM_SIZE   0x10000
#define VEXPRESS_MAP_SYSREG     (VEXPRESS_MAP_CS3 + 0x00010000)
#define VEXPRESS_MAP_SYSREG_SIZE    0x10000
#define VEXPRESS_MAP_SP810      (VEXPRESS_MAP_CS3 + 0x00020000)
#define VEXPRESS_MAP_SP810_SIZE     0x10000
#define VEXPRESS_MAP_SERIAL_PCI     (VEXPRESS_MAP_CS3 + 0x00030000)
#define VEXPRESS_MAP_SERIAL_PCI_SIZE    0x10000
#define VEXPRESS_MAP_AACI       (VEXPRESS_MAP_CS3 + 0x00040000) // PL041
#define VEXPRESS_MAP_AACI_SIZE      0x10000
#define VEXPRESS_MAP_MMCI       (VEXPRESS_MAP_CS3 + 0x00050000) // PL180
#define VEXPRESS_MAP_MMCI_SIZE      0x10000
#define VEXPRESS_MAP_KMI0       (VEXPRESS_MAP_CS3 + 0x00060000) // PL050
#define VEXPRESS_MAP_KMI0_SIZE      0x10000
#define VEXPRESS_MAP_KMI1       (VEXPRESS_MAP_CS3 + 0x00070000) // PL050
#define VEXPRESS_MAP_KMI1_SIZE      0x10000
#define VEXPRESS_MAP_ENERGY_CTRL    (VEXPRESS_MAP_CS3 + 0x00080000) // ??? GEM5
#define VEXPRESS_MAP_ENERGY_CTRL_SIZE   0x10000
#define VEXPRESS_MAP_UART0      (VEXPRESS_MAP_CS3 + 0x00090000) // PL011
#define VEXPRESS_MAP_UART0_SIZE     0x10000
#define VEXPRESS_MAP_UART1      (VEXPRESS_MAP_CS3 + 0x000A0000) // PL011
#define VEXPRESS_MAP_UART1_SIZE     0x10000
#define VEXPRESS_MAP_UART2      (VEXPRESS_MAP_CS3 + 0x000B0000) // PL011
#define VEXPRESS_MAP_UART2_SIZE     0x10000
#define VEXPRESS_MAP_UART3      (VEXPRESS_MAP_CS3 + 0x000C0000) // PL011
#define VEXPRESS_MAP_UART3_SIZE     0x10000
#define VEXPRESS_MAP_WATCHDOG       (VEXPRESS_MAP_CS3 + 0x000F0000) // SP805
#define VEXPRESS_MAP_WATCHDOG_SIZE  0x10000
#define VEXPRESS_MAP_TIMER01        (VEXPRESS_MAP_CS3 + 0x00110000) // SP801
#define VEXPRESS_MAP_TIMER01_SIZE   0x10000
#define VEXPRESS_MAP_TIMER23        (VEXPRESS_MAP_CS3 + 0x00120000) // SP801
#define VEXPRESS_MAP_TIMER23_SIZE   0x10000
#define VEXPRESS_MAP_RTC        (VEXPRESS_MAP_CS3 + 0x00170000) // PL031
#define VEXPRESS_MAP_RTC_SIZE       0x10000
#define VEXPRESS_MAP_IDE_BAR0       (VEXPRESS_MAP_CS3 + 0x001A0000) // ??? GEM5
#define VEXPRESS_MAP_IDE_BAR0_SIZE  0x100
#define VEXPRESS_MAP_IDE_BAR1       (VEXPRESS_MAP_CS3 + 0x001A0100) // ??? GEM5
#define VEXPRESS_MAP_IDE_BAR1_SIZE  0x1000
#define VEXPRESS_MAP_UART4      (VEXPRESS_MAP_CS3 + 0x001B0000) // PL011
#define VEXPRESS_MAP_UART4_SIZE     0x10000
#define VEXPRESS_MAP_CLCD       (VEXPRESS_MAP_CS3 + 0x001F0000) // PL111
#define VEXPRESS_MAP_CLCD_SIZE      0x10000

/*
 * This is the daughterboard memory map
 *
 * For this, see the CoreTile Express™ A15x2 Cortex™-A15 MPCore
 * (V2P-CA15) Technical Reference Manual, S.3.2.3
 */

#define VEXPRESS_MAP_CORESIGHT            0x20000000
#define VEXPRESS_MAP_CORESIGHT_SIZE       0x8000000
#define VEXPRESS_MAP_AXI_NIC              0x2A000000
#define VEXPRESS_MAP_AXI_NIC_SIZE         0x100000 // NIC-301
#define VEXPRESS_MAP_SCC                  0x2A420000
#define VEXPRESS_MAP_SCC_SIZE             0x10000
#define VEXPRESS_MAP_SYS_COUNT            0x2A430000
#define VEXPRESS_MAP_SYS_COUNT_SIZE       20
#define VEXPRESS_MAP_HDLCD                0x2B000000
#define VEXPRESS_MAP_HDLCD_SIZE           592
#define VEXPRESS_MAP_SYS_WDG              0x2B060000 // SP805 (not same as abv)
#define VEXPRESS_MAP_SYS_WDG_SIZE         0x1000
#define VEXPRESS_MAP_DMC_CONFIG           0x2B0A0000 // PL341
#define VEXPRESS_MAP_DMC_CONFIG_SIZE      0x1000
#define VEXPRESS_MAP_GIC_DIST             0x2C001000 // PL390
#define VEXPRESS_MAP_GIC_DIST_SIZE        0x1000
#define VEXPRESS_MAP_GIC_CPU              0x2C002000 // PL390
#define VEXPRESS_MAP_GIC_CPU_SIZE         0x100
#define VEXPRESS_MAP_VGIC_HV              0x2C004000
#define VEXPRESS_MAP_VGIC_HV_SIZE         0x1000
#define VEXPRESS_MAP_VGIC_VCPU            0x2C006000
#define VEXPRESS_MAP_VGIC_VCPU_SIZE       0x1000
#define VEXPRESS_MAP_LOCAL_CPU_TIMER      0x2C080000
#define VEXPRESS_MAP_LOCAL_CPU_TIMER_SIZE 0x1000
#define VEXPRESS_MAP_L2X0                 0x2C100000
#define VEXPRESS_MAP_L2X0_SIZE            0x1000

#define VEXPRESS_MAP_PCI_CFG              0x30000000
#define VEXPRESS_MAP_PCI_CFG_SIZE         0x10000000

/* These are the VE system registers, as offsets from VEXPRESS_MAP_SYSREG. See
 * ARM Motherboard Express μATX TRM Table 4-3. */

#define VEXPRESS_SYS_ID         0x0000
#define VEXPRESS_SYS_SW         0x0004
#define VEXPRESS_SYS_LED        0x0008
#define VEXPRESS_SYS_100HZ      0x0024
#define VEXPRESS_SYS_FLAGS      0x0030
#define VEXPRESS_SYS_FLAGSSET   0x0030
#define VEXPRESS_SYS_FLAGSCLR   0x0034
#define VEXPRESS_SYS_NVFLAGS    0x0038
#define VEXPRESS_SYS_NVFLAGSSET 0x0038
#define VEXPRESS_SYS_NVFLAGSCLR 0x003C
#define VEXPRESS_SYS_MCI        0x0048
#define VEXPRESS_SYS_FLASH      0x004C
#define VEXPRESS_SYS_CFGSW      0x0058
#define VEXPRESS_SYS_24MHZ      0x005C
#define VEXPRESS_SYS_MISC       0x0060
#define VEXPRESS_SYS_DMA        0x0064
#define VEXPRESS_SYS_PROCID0    0x0084
#define VEXPRESS_SYS_PROCID1    0x0088
#define VEXPRESS_SYS_CFGDATA    0x00A0
#define VEXPRESS_SYS_CFGCTRL    0x00A4
#define VEXPRESS_SYS_CFGSTAT    0x00A8

#endif // VEXPRESS_MAP_H
