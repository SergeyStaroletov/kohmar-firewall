/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Staroletov, Chudov
 */

#ifndef DEBUG_UTILS_H_
#define DEBUG_UTILS_H_

char *protocol_from_number(int n) {
  switch (n) {
  case 0:
    return "tcp_dummy";
  case 1:
    return "icmp";
  case 2:
    return "igmp";
  case 4:
    return "ipip";
  case 6:
    return "tcp";
  case 8:
    return "egp";
  case 12:
    return "pup";
  case 17:
    return "udp";
  case 22:
    return "idp";
  case 29:
    return "tp";
  case 41:
    return "ipv6_header";
  case 43:
    return "ipv6_routing";
  case 44:
    return "ipv6_fragment";
  case 46:
    return "vsvp";
  case 47:
    return "gre";
  case 50:
    return "esp";
  case 51:
    return "ah";
  case 58:
    return "icmpv6";
  case 59:
    return "ipv6_none";
  case 60:
    return "ipv6_dstopts";
  case 92:
    return "mtp";
  case 98:
    return "encap";
  case 103:
    return "pim";
  case 108:
    return "comp";
  case 132:
    return "sctp";
  case 255:
    return "raw";
  }

  return "unknown";
}

void print_packet(struct sk_buff *skb) {
  int dadd, sadd, bit1, bit2, bit3, bit4;

  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  printk("len=%d ", skb->len);
  printk("data_len=%d ", skb->data_len);
  printk("truesize=%d ", skb->truesize);
  printk("frt_id=%d ", ((ip_header->id)));
  printk("frt_offset=%d ", ((ip_header->frag_off)));
  printk("fr_xf=%d ", (ntohs(ip_header->frag_off) & IP_CE) > 0);
  printk("frt_df=%d ", (ntohs(ip_header->frag_off) & IP_DF) > 0);
  printk("fr_mf=%d ", (ntohs(ip_header->frag_off) & IP_MF) > 0);
  printk("\n");

  if (ip_header->protocol == 6) {
    struct tcphdr *tc = (struct tcphdr *)skb_transport_header(skb);
    printk("tcp flags: ack= %d ack_seq= %d doff=%d fin=%d seq=%d syn=%d\n",
           tc->ack, tc->ack_seq, tc->doff, tc->fin, tc->seq, tc->syn);
  }

  dadd = ip_header->daddr;
  sadd = ip_header->saddr;
  bit1 = 255 & sadd;
  bit2 = (0xff00 & sadd) >> 8;
  bit3 = (0xff0000 & sadd) >> 16;
  bit4 = (0xff000000 & sadd) >> 24;
  printk(" %d.%d.%d.%d -> ", bit1, bit2, bit3, bit4);
  bit1 = 255 & dadd;
  bit2 = (0xff00 & dadd) >> 8;
  bit3 = (0xff0000 & dadd) >> 16;
  bit4 = (0xff000000 & dadd) >> 24;
  // tcp_header = tcp_hdr(skb);
  printk("-> %d.%d.%d.%d  proto %s\n", bit1, bit2, bit3, bit4,
         protocol_from_number(ip_header->protocol));
}

#endif /* DEBUG_UTILS_H_ */
