#ifndef _ICMP_H_
#define _ICMP_H_

#include <stddef.h>
#include <stdint.h>
#include <aos/aos.h>

//#define ICMP_DEBUG_OPTION 1

#if defined(ICMP_DEBUG_OPTION)
#define ICMP_DEBUG(x...) debug_printf("[ip] " x);
#else
#define ICMP_DEBUG(fmt, ...) ((void)0)
#endif


#define ICMP_ER   0    /* echo reply */
#define ICMP_DUR  3    /* destination unreachable */
#define ICMP_SQ   4    /* source quench */
#define ICMP_RD   5    /* redirect */
#define ICMP_ECHO 8    /* echo */
#define ICMP_TE  11    /* time exceeded */
#define ICMP_PP  12    /* parameter problem */
#define ICMP_TS  13    /* timestamp */
#define ICMP_TSR 14    /* timestamp reply */
#define ICMP_IRQ 15    /* information request */
#define ICMP_IR  16    /* information reply */

enum icmp_dur_type {
  ICMP_DUR_NET   = 0,  /* net unreachable */
  ICMP_DUR_HOST  = 1,  /* host unreachable */
  ICMP_DUR_PROTO = 2,  /* protocol unreachable */
  ICMP_DUR_PORT  = 3,  /* port unreachable */
  ICMP_DUR_FRAG  = 4,  /* fragmentation needed and DF set */
  ICMP_DUR_SR    = 5   /* source route failed */
};

enum icmp_te_type {
  ICMP_TE_TTL  = 0,    /* time to live exceeded in transit */
  ICMP_TE_FRAG = 1     /* fragment reassembly time exceeded */
};


/** This is the standard ICMP header only that the u32_t data
 *  is splitted to two u16_t like ICMP echo needs it.
 *  This header is also used for other ICMP types that do not
 *  use the data part.
 */
#define ICMP_HLEN 8 

struct icmp_echo_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t chksum;
  uint16_t id;
  uint16_t seqno;
} __attribute__((__packed__)) ;

#define ICMPH_TYPE(hdr) ((hdr)->type)
#define ICMPH_CODE(hdr) ((hdr)->code)

/** Combines type and code to an u16_t */
#define ICMPH_TYPE_SET(hdr, t) ((hdr)->type = (t))
#define ICMPH_CODE_SET(hdr, c) ((hdr)->code = (c))


#endif
