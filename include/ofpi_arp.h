/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef __OFPI_ARP_H__
#define __OFPI_ARP_H__

#include <odp_api.h>

#include "ofpi_pkt_processing.h" /* return codes, i.e.: OFP_DROP */
#include "ofpi.h"

struct arp_key {
	uint32_t vrf;
	uint32_t ipv4_addr;
};

#ifdef OFP_USE_LIBCK
#include <ck_queue.h>

struct arp_entry {
	struct arp_key key;
	/* Keep ifx/timestamp/state together in the same word! */
	uint16_t ifx;
	uint8_t state;
	uint8_t slowpath_keepalive_timer_armed;
	uint64_t macaddr;
	uint16_t timer_armed; /* Slowpath neigh update timer */
	CK_SLIST_ENTRY(arp_entry) next;
};

#else /* ! OFP_USE_LIBCK */
#include "ofpi_queue.h"

struct pkt_entry {
	odp_packet_t pkt;
	struct ofp_nh_entry *nh;
	OFP_SLIST_ENTRY(pkt_entry) next;
};

struct pkt_list {
	struct pkt_entry *slh_first;
}; /* OFP_SLIST_HEAD */

struct arp_entry {
	struct arp_key key;

	odp_time_t usetime;
	odp_timer_t usetime_upd_tmo;
	odp_rwlock_t usetime_rwlock;

	uint64_t macaddr;
	struct pkt_list pkt_list_head;
	odp_timer_t pkt_tmo;
	OFP_STAILQ_ENTRY(arp_entry) next;
} ODP_ALIGNED_CACHE;
#endif /* OFP_USE_LIBCK */

struct arp_cache {
	odp_atomic_u32_t entry_idx;
};

#define ARP_IS_CACHE_HIT(_entry, _key) \
	(((_key)->vrf == (_entry)->key.vrf) && \
	 ((_key)->ipv4_addr == (_entry)->key.ipv4_addr))

#define ARP_GET_CACHE(_cache) \
	(&(shm->arp.entries[odp_atomic_load_u32(&(_cache)->entry_idx)]))

#define ARP_SET_CACHE(_cache, _entry) \
	odp_atomic_store_u32(&(_cache)->entry_idx, \
			     (_entry) - &(shm->arp.entries[0]))

#define ARP_DEL_CACHE(_cache) \
	odp_atomic_store_u32(&(_cache)->entry_idx, 0)

int ofp_arp_lookup_shared_memory(void);
void ofp_arp_init_prepare(void);
int ofp_arp_init_global(void);
int ofp_arp_term_global(void);
int ofp_arp_init_local(void);
void ofp_arp_term_local(void);

int ofp_arp_ipv4_insert(uint32_t ipv4_addr, unsigned char *ll_addr,
			struct ofp_ifnet *dev);
int ofp_arp_ipv4_remove(uint32_t ipv4_addr, struct ofp_ifnet *dev);
int ofp_ipv4_lookup_mac(uint32_t ipv4_addr, unsigned char *ll_addr,
			struct ofp_ifnet *dev);
enum ofp_return_code ofp_arp_save_ipv4_pkt(odp_packet_t pkt, struct ofp_nh_entry *nh_param,
				uint32_t ipv4_addr, struct ofp_ifnet *dev);

void ofp_arp_show_table(int fd);
void ofp_arp_show_saved_packets(int fd);
void ofp_arp_age_cb(void *arg);
int ofp_arp_init_tables(void);

#endif /* __OFPI_ARP_H__ */
