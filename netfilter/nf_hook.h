/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Staroletov, Chudov
 */

// A Netfilter hook. Provides sniffer capabilities, drop packets and mime
// filtering
#ifndef NF_HOOK_H_
#define NF_HOOK_H_

unsigned int port_str_to_int(char *port_str);
unsigned int ip_str_to_hl(char *ip_str);
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask);

inline int get_raw_data(struct sk_buff *skb, char *buf) {
  int i, offset;
  char *uk;
  i = 0;
  uk = skb->head;

  if (!uk) {
    return 0;
  }

  //#ifdef _LP64
  // 64 bit has another definition of skb pointers. they are store offset
  //    offset = skb_mac_header(skb) - skb->head;
  //   uk += offset;
  //   uk += skb->mac_len; //we don't want to collect mac header
  //   memcpy(buf, uk, skb->len);

  //#else
  offset = skb_mac_header(skb) - skb->head;
  uk += offset;
  uk += skb->mac_len;
  memcpy(buf, uk, skb->len);

  //#endif

  // if (isLogging) printk("mac len=%d skb_len=%d\n",skb->mac_len,skb->len) ;
  // if (isLogging) print_packet(skb);

  return skb->len;
}

//
// 1 -> found "bad" content type
// 2 -> found "good" content-type
// 0 -> no content-type in frame
//
inline int find_content_type(char *raw_data, int raw_size) {
  int hlen;
  int copyed;
  char ct_word[100];
  int f, h;
  bool flag;
  char *p;

  hlen = sizeof(struct tcphdr);
  hlen += sizeof(struct iphdr);
  p = hlen + raw_data;
  for (h = hlen; h < raw_size - 14; h++) {
    int curpos = h + 14;
    // for fast processing:)
    if (raw_data[h] == 'C')
      if (raw_data[h + 1] == 'o')
        if (raw_data[h + 2] == 'n')
          if (raw_data[h + 3] == 't')
            if (raw_data[h + 4] == 'e')
              if (raw_data[h + 5] == 'n')
                if (raw_data[h + 6] == 't')
                  if (raw_data[h + 7] == '-')
                    if (raw_data[h + 8] == 't' || raw_data[h + 8] == 'T')
                      if (raw_data[h + 9] == 'y')
                        if (raw_data[h + 10] == 'p')
                          if (raw_data[h + 11] == 'e') {
                            if (raw_size > curpos) {
                              log("content-type found");
                              // copy to string end or to ' ' or to '/r' '/n'
                              // h+14..
                              copyed = 0;
                              while ((curpos < raw_size) &&
                                     !((raw[curpos] == ' ') ||
                                       (raw[curpos] == '\r') ||
                                       (raw[curpos] == '\n') ||
                                       (raw[curpos] == ';'))) {
                                ct_word[copyed++] = raw_data[curpos++];
                                if (copyed >= 98)
                                  break;
                              }
                              ct_word[copyed] = 0;
                              log("content-type is:");
                              log(ct_word);
                              flag = 0;

                              // check the classes - by substring
                              for (f = 0; f < filter_classes_count; f++) {
                                if (strstr(ct_word, filter_classes[f]))
                                  flag = 1;
                                break;
                              }
                              // check the types - by equal
                              if (!flag)
                                for (f = 0; f < filter_types_count; f++) {
                                  if (!strcmp(ct_word, filter_types[f]))
                                    flag = 1;
                                  break;
                                }

                              if (flag == 1)
                                return 1;

                              return 2;
                            }
                          }
  }

  return 0;
}

/*
 * HOOK FUNCTION
 */

/* Function prototype in <linux/netfilter> */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22)
unsigned int main_hook(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) {
#else
unsigned int main_hook(unsigned int hooknum, struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) {
#endif

  // struct tcphdr *tcp_header;
  struct iphdr *ip_header;

  int gp;
  struct sk_buff *sock_buff;
  int raw_size = 0;
  void *next_packet;

  int mtu = 1500;
  if (out)
    mtu = out->mtu;
  if (in)
    mtu = in->mtu;

  if (in && strcmp(in->name, ifdev)) {
    return NF_ACCEPT; // in device!= we select
  } else if (!in && out && strcmp(out->name, ifdev)) {
    return NF_ACCEPT;
  } else if (!in && !out) {
    return NF_ACCEPT;
  }

  if (!skb) {
    return NF_ACCEPT;
  }

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22)
  // sock_buff = skb_copy(skb, GFP_ATOMIC);
  sock_buff = skb;
#else
  // sock_buff = skb_copy(*skb, GFP_ATOMIC);
  sock_buff = *skb;
#endif

  if (!sock_buff) {
    printk("!sock_buff\n");
    return NF_ACCEPT;
  }

  ip_header = (struct iphdr *)skb_network_header(sock_buff);

  if (!ip_header) {
    printk("!! no ip header!\n");
    return NF_ACCEPT;
  }

  raw_size = sock_buff->len;

  if (raw_size <= 0 || raw_size > MAX_BUFFERED_LEN) {
    printk("!!!wrong raw size! %d\n", raw_size);
    return NF_ACCEPT;
  }

  if ((raw_size < min_packet_size)) { // size is too small
    log("size if too small, accepted without compressor");
    return NF_ACCEPT;
  }

  // mime types - commented
  /*if (isFiltering && (ip_header->protocol == 6)) //tcp
          {
      //we can check data here

      con.ip1 = ip_header->daddr;
      con.ip2 = ip_header->saddr;

      tcp_header = (struct tcphdr*) skb_transport_header(sock_buff);
      con.port1 = tcp_header->source;
      con.port2 = tcp_header->dest;
      hlen = sizeof(struct tcphdr);

      if (connection_rb_search(&the_root, &con)) {
          //connection found in tree

          if (skb->len < mtu) {
              //this is last packet --> remove
              log("\nlast packet. remove connection if exists");
              connection_rb_erase(&the_root, &con);
          } else if (isMultiFiltering) {

              raw_size = get_raw_data(sock_buff, raw);

              if (find_content_type(raw, raw_size) == 2) {
                  //old connections was bad ,new is good
                  log("\nnew content type in connection detection. remove
  connection if exists"); connection_rb_erase(&the_root, &con); } else {
                  //skip of compression - forward direct
                  log("connection with compression disabled found in tree.
  PASS"); logconnection(&con); atomic_inc(&filtered_packets); return NF_ACCEPT;
              }
          }
      } else {
          //connection not found in tree
          //try to find content-type
          raw_size = get_raw_data(sock_buff, raw);
          if ((atomic_read(&tracked_connections) < max_tracked_connections) &&
  find_content_type(raw, raw_size) == 1) {
              //create node if we have mem
              log("New connection, compression disabled found. PASS and register
  in tree"); conn = kmalloc(sizeof(struct connection), GFP_ATOMIC); //gfp_kernel
  may cause sleeping while atomic if (conn == NULL) { log("!!! kmalloc failed on
  adding to connection tree"); } else { memcpy(conn, &con, sizeof(struct
  connection));
                  //add it to three
                  log("insert new connection to tree");
                  logconnection(conn);
                  connection_rb_insert(&the_root, conn);
                  atomic_inc(&filtered_packets);
                  return NF_ACCEPT;
              }
          } else {
              //not found - > pass to compressor
          }
      }
  } else */
  { raw_size = get_raw_data(sock_buff, raw); }

  // copy to shmem
  next_packet = mmap_get_next_pointer(mmap_rx);
  if (next_packet) {
    memcpy(next_packet + sizeof(struct new_packet_header), raw, raw_size);

    ((struct new_packet_header *)next_packet)->size = raw_size;
    ((struct new_packet_header *)next_packet)->flag_ready = 1;
  } else {
    printk("[sniffer] bug!");
  }

  atomic_inc(&got_p);
  gp = atomic_read(&got_p);

  if (!drop)
    return NF_ACCEPT;
  else
    return NF_DROP;
}

//=================IN_OUT HOOKS======================

// the hook function itself: regsitered for filtering outgoing packets
unsigned int hook_func_out(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state) {

  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  struct udphdr *udp_header;
  struct tcphdr *tcp_header;

  struct list_head *p_l;
  struct RuleListItem *a_rule;
  int i = 0;

  struct net_device *in = state->in;
  struct net_device *out = state->out;

  int gp;
  struct sk_buff *sock_buff;
  int raw_size = 0;
  void *next_packet;

  unsigned int src_ip;
  unsigned int dest_ip;
  unsigned int src_port = 0;
  unsigned int dest_port = 0;
  int act = 1;

  if (in && strcmp(in->name, ifdev)) {
    return NF_ACCEPT; // in device!= we select
  } else if (!in && out && strcmp(out->name, ifdev)) {
    return NF_ACCEPT;
  } else if (!in && !out) {
    return NF_ACCEPT;
  }

  sock_buff = skb;

  if (!sock_buff) {
    printk("!skb!\n");
    return NF_ACCEPT;
  }

  raw_size = sock_buff->len;

  if (raw_size <= 0 || raw_size > MAX_BUFFERED_LEN) {
    return NF_ACCEPT;
  }

  if ((raw_size < min_packet_size)) {
    // size is too small, accepted
    return NF_ACCEPT;
  }

  raw_size = get_raw_data(sock_buff, raw);

  // get src and dest ip addresses
  src_ip = (unsigned int)ip_header->saddr;
  dest_ip = (unsigned int)ip_header->daddr;
  src_port = 0;
  dest_port = 0;
  act = 1;

  // get src and dest port number
  if (ip_header->protocol == _UDP) {
    udp_header = (struct udphdr *)skb_transport_header(skb);
    src_port = (unsigned int)ntohs(udp_header->source);
    dest_port = (unsigned int)ntohs(udp_header->dest);
  } else if (ip_header->protocol == _TCP) {
    tcp_header = (struct tcphdr *)skb_transport_header(skb);
    src_port = (unsigned int)ntohs(tcp_header->source);
    dest_port = (unsigned int)ntohs(tcp_header->dest);
  } else if (ip_header->protocol == _ICMP) {
  }

  // go through the firewall list and check if there is a match
  // in case there are multiple matches, take the first one

  list_for_each(p_l, &policy_list.list) {
    i++;
    a_rule = list_entry(p_l, struct RuleListItem, list);

    // if a rule doesn't specify as "out", skip it
    if (a_rule->in_out != 2) {
      continue;
    } else {
      // check the protocol
      if ((a_rule->proto == 1) && (ip_header->protocol != _TCP)) {
        continue;
      } else if ((a_rule->proto == 2) && (ip_header->protocol != _UDP)) {
        continue;
      } else if ((a_rule->proto == 3) && (ip_header->protocol != _ICMP)) {
        continue;
      }

      // check the ip address
      if (a_rule->src_ip == 0) {
        // rule doesn't specify ip: match
      } else {
        if (!check_ip(src_ip, a_rule->src_ip, 0)) {
          continue;
        }
      }
      if (a_rule->dest_ip == 0) {
        // rule doesn't specify ip: match
      } else {
        if (!check_ip(dest_ip, a_rule->dest_ip, 0)) {
          continue;
        }
      }
      // check the port number
      if (a_rule->src_port == -1) {
        // rule doesn't specify src port: match
      } else if (src_port != a_rule->src_port) {
        continue;
      }
      if (a_rule->dest_port == -1) {
        // rule doens't specify dest port: match
      } else if (dest_port != a_rule->dest_port) {
        continue;
      }

      // a match is found: take action
      if (a_rule->action == 0) {
        printk(KERN_INFO "Firewall: a match is found: DROP the packet\n");
        // return NF_DROP;
        act = 0;
        break;
      } else {
        printk(KERN_INFO "Firewall: a match is found: ACCEPT the packet\n");
        // return NF_ACCEPT;
        act = 1;
        break;
      }
    }
  }

  // no matching is found, accept the packet\n");

  if (act == 1) {
    // copy to shmem
    next_packet = mmap_get_next_pointer(mmap_rx);
    if (next_packet) {
      memcpy(next_packet + sizeof(struct new_packet_header), raw, raw_size);

      ((struct new_packet_header *)next_packet)->size = raw_size;
      ((struct new_packet_header *)next_packet)->flag_ready = 1;
    } else {
      printk("[sniffer] bug!");
    }

    atomic_inc(&got_p);
    gp = atomic_read(&got_p);

    return NF_ACCEPT;
  } else {
    return NF_DROP;
  }
}

// the hook function itself: registered for filtering incoming packets

unsigned int hook_func_in(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state) {

  /* get src address, src netmask, src port, dest ip, dest netmask, dest port,
   * protocol*/

  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  struct udphdr *udp_header;
  struct tcphdr *tcp_header;

  struct list_head *p_l;
  struct RuleListItem *a_rule;
  int i = 0;
  const struct net_device *in = state->in;
  struct net_device *out = state->out;

  int gp;
  struct sk_buff *sock_buff;
  int raw_size = 0;
  void *next_packet;
  unsigned int src_ip;
  unsigned int dest_ip;
  unsigned int src_port = 0;
  unsigned int dest_port = 0;
  int act = 1;

  if (in && strcmp(in->name, ifdev)) {
    return NF_ACCEPT; // in device!= we select
  } else if (!in && out && strcmp(out->name, ifdev)) {
    return NF_ACCEPT;
  } else if (!in && !out) {
    return NF_ACCEPT;
  }

  sock_buff = skb;

  if (!sock_buff) {
    return NF_ACCEPT;
  }

  raw_size = sock_buff->len;

  if (raw_size <= 0 || raw_size > MAX_BUFFERED_LEN) {
    // printk("wrong raw size! %d\n", raw_size);
    return NF_ACCEPT;
  }

  if ((raw_size < min_packet_size)) { // size is too small
    // size is too small, accepted
    return NF_ACCEPT;
  }

  // if(!run_pause) return NF_ACCEPT;

  raw_size = get_raw_data(sock_buff, raw);

  // get src and dest ip addresses
  src_ip = (unsigned int)ip_header->saddr;
  dest_ip = (unsigned int)ip_header->daddr;
  src_port = 0;
  dest_port = 0;
  act = 1;

  // get src and dest port number
  if (ip_header->protocol == 17) {
    udp_header = (struct udphdr *)(skb_transport_header(skb) + 20);
    src_port = (unsigned int)ntohs(udp_header->source);
    dest_port = (unsigned int)ntohs(udp_header->dest);
  } else if (ip_header->protocol == 6) {
    tcp_header = (struct tcphdr *)(skb_transport_header(skb) + 20);
    src_port = (unsigned int)ntohs(tcp_header->source);
    dest_port = (unsigned int)ntohs(tcp_header->dest);
  }

  // go through the firewall list and check if there is a match
  // in case there are multiple matches, take the first one

  list_for_each(p_l, &policy_list.list) {
    i++;
    a_rule = list_entry(p_l, struct RuleListItem, list);

    // if a rule doesn't specify as "in", skip it
    if (a_rule->in_out != 1) {
      continue;
    } else {
      // check the protocol
      if ((a_rule->proto == 1) && (ip_header->protocol != 6)) {
        continue;
      } else if ((a_rule->proto == 2) && (ip_header->protocol != 17)) {
        continue;
      }
      // check the ip address
      if (a_rule->src_ip == 0) {
        //
      } else {
        if (!check_ip(src_ip, a_rule->src_ip, 0)) {
          continue;
        }
      }
      if (a_rule->dest_ip == 0) {
        //
      } else {
        if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
          continue;
        }
      }
      // check the port number
      if (a_rule->src_port == -1) {
        // rule doesn't specify src port: match
      } else if (src_port != a_rule->src_port) {
        continue;
      }
      if (a_rule->dest_port == -1) {
        // rule doens't specify dest port: match
      } else if (dest_port != a_rule->dest_port) {
        continue;
      }
      // a match is found: take action
      if (a_rule->action == 0) {
        // return NF_DROP;
        act = 0;
        break;
      } else {
        // return NF_ACCEPT;
        act = 1;
        break;
      }
    }
  }

  // no matching is found, accept the packet

  if (act == 1) {
    // copy to shmem
    next_packet = mmap_get_next_pointer(mmap_rx);
    if (next_packet) {
      memcpy(next_packet + sizeof(struct new_packet_header), raw, raw_size);

      ((struct new_packet_header *)next_packet)->size = raw_size;
      ((struct new_packet_header *)next_packet)->flag_ready = 1;
    } else {
      printk("[sniffer] bug!");
    }

    atomic_inc(&got_p);
    gp = atomic_read(&got_p);

    return NF_ACCEPT;
  } else {
    return NF_DROP;
  }
}

#endif /* NF_HOOK_H_ */
