/*
 * ip_vs_xmit.c: various packet transmitters for IPVS
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Julian Anastasov <ja@ssi.bg>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include "ofp_vs.h"

static inline void
ipv4_cksum(struct iphdr *iphdr, struct rte_mbuf *skb)
{
        (void)skb;
        iphdr->check = 0;
        if (sysctl_ip_vs_csum_offload) {
                /* Use hardware csum offload */
#ifdef OFP_PERFORMANCE
                skb->ol_flags |= PKT_TX_IP_CKSUM;
#endif
        } else {
#ifdef OFP_PERFORMANCE
                iphdr->check = ofp_vs_ipv4_cksum(iphdr);
#endif
        }
}

static struct ofp_nh_entry *ip_vs_get_out_rt(struct rte_mbuf *skb,
                         __be32 daddr)
{
        uint32_t flags;
        uint32_t vrf;
        struct ofp_ifnet *send_ctx = odp_packet_user_ptr((odp_packet_t)skb);
        struct ofp_nh_entry *nh = NULL;

        vrf = send_ctx ? send_ctx->vrf : 0;
        nh = ofp_get_next_hop(vrf, daddr, &flags);
        if (nh) {
            IP_VS_DBG(12, "%s dst:"
                  PRINT_IP_FORMAT" gw:"
                  PRINT_IP_FORMAT
                  " port:%d vlan:%d\n",
                  __func__,
                  PRINT_NIP(daddr),
                  PRINT_NIP(nh->gw),
                  nh->port,
                  nh->vlan);
        }
        return nh;
}


/*
 *      FULLNAT transmitter (only for outside-to-inside fullnat forwarding)
 *      Not used for related ICMP
 */
int
ip_vs_fnat_xmit(struct rte_mbuf *skb, struct ip_vs_conn *cp,
                struct ip_vs_protocol *pp)
{
        int ret;
        struct iphdr *iphdr = ip_hdr(skb);
        
        EnterFunction(10);
        /* check if it is a connection of no-client-port */
        if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
                __be16 *p;
                p = (__be16 *)((unsigned char *)iphdr + iphdr->ihl * 4);
                if (p == NULL)
                        goto tx_error;
                ip_vs_conn_fill_cport(cp, *p);
                IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
        }

        iphdr->saddr = cp->laddr.ip;
        iphdr->daddr = cp->daddr.ip;

        ipv4_cksum(iphdr, skb);

        if (pp->fnat_in_handler && !pp->fnat_in_handler(skb, pp, cp))
                goto tx_error;

        if (!cp->in_nh && sysctl_ip_vs_fast_xmit_inside) {
                cp->in_nh = ip_vs_get_out_rt(skb, iphdr->daddr);
        }
        
        ret = ofp_ip_send((odp_packet_t)skb, cp->in_nh);
        LeaveFunction(10);
        return ret;
                
tx_error:
        LeaveFunction(10);
        return NF_DROP;
}

/* Response transmit to client
 * Used for FULLNAT.
 */
int
ip_vs_fnat_response_xmit(struct rte_mbuf *skb, struct ip_vs_protocol *pp,
                         struct ip_vs_conn *cp, int ihl)
{
        int ret;
        struct iphdr *iphdr = ip_hdr(skb);
        (void)ihl;

        EnterFunction(10);

        iphdr->saddr = cp->vaddr.ip;
        iphdr->daddr = cp->caddr.ip;
        ipv4_cksum(iphdr, skb);

        if (pp->fnat_out_handler && !pp->fnat_out_handler(skb, pp, cp))
                goto err;

        if (!cp->out_nh && sysctl_ip_vs_fast_xmit) {
                cp->out_nh = ip_vs_get_out_rt(skb, iphdr->daddr);
        }
        
        ret = ofp_ip_send((odp_packet_t)skb, cp->out_nh);
        LeaveFunction(10);
        return ret;

err:
        LeaveFunction(10);
        return NF_DROP;
}

int
ip_vs_nat_xmit(struct rte_mbuf *skb, struct ip_vs_conn *cp,
               struct ip_vs_protocol *pp)
{
        struct iphdr *iphdr = ip_hdr(skb);

        EnterFunction(10);

        /* check if it is a connection of no-client-port */
        if (unlikely(cp->flags & IP_VS_CONN_F_NO_CPORT)) {
                __be16 *p;
                p = (__be16 *)((unsigned char *)iphdr + iphdr->ihl * 4);
                if (p == NULL)
                        goto tx_error;
                ip_vs_conn_fill_cport(cp, *p);
                IP_VS_DBG(10, "filled cport=%d\n", ntohs(*p));
        }

        
        iphdr->daddr = cp->daddr.ip;

        ipv4_cksum(iphdr, skb);

        /* mangle the packet */
        if (pp->dnat_handler && !pp->dnat_handler(skb, pp, cp))
                goto tx_error;

        IP_VS_DBG_PKT(10, pp, skb, 0, "After DNAT");

        LeaveFunction(10);
        return ofp_ip_send((odp_packet_t)skb, NULL);

tx_error:
        LeaveFunction(10);
        return NF_DROP;
}

/* Response transmit to client
 * Used for NAT/Local.
 */
int
ip_vs_normal_response_xmit(struct rte_mbuf *skb, struct ip_vs_protocol *pp,
                           struct ip_vs_conn *cp, int ihl)
{
        struct iphdr *iphdr = ip_hdr(skb);
        (void)ihl;

        EnterFunction(10);

        iphdr->saddr = cp->vaddr.ip;

        ipv4_cksum(iphdr, skb);

        /* mangle the packet */
        if (pp->snat_handler && !pp->snat_handler(skb, pp, cp))
                goto drop;

        return ofp_ip_send((odp_packet_t)skb, NULL);

drop:
        LeaveFunction(10);
        return NF_DROP;
}

/*
 *      Direct Routing transmitter
 *      Used for ANY protocol
 */
int
ip_vs_dr_xmit(struct rte_mbuf *skb, struct ip_vs_conn *cp,
              struct ip_vs_protocol *pp)
{
        int ret;
        (void)pp;

        EnterFunction(10);

        if (!cp->in_nh && sysctl_ip_vs_fast_xmit_inside) {
            cp->in_nh = ip_vs_get_out_rt(skb, cp->daddr.ip);
        }

        ret = ofp_ip_send((odp_packet_t)skb, cp->in_nh);
        LeaveFunction(10);
        return ret;        
}
