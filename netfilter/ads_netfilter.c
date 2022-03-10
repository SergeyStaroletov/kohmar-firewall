/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Staroletov, Chudov
 */

#ifndef KERNEL_NETFILTER
#define KERNEL_NETFILTER

#include "../config.h"

#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
//#include <asm/current.h>
//#include <asm/segment.h>
//#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <net/ip.h>
#include <net/sock.h>

#if DEBUG
#define log(S)                                                                 \
  if (isLogging) {                                                             \
    printk("[ads_drv] %s\n", S);                                               \
  }
#else
#define log(S) ;
#endif

#define MAX_BUFFERED_LEN 2000

/* Own family for netlink socket */
#define NETLINK_USER 31

/* To send true/false */
#define MSG_SIZE_BOOL sizeof(bool)
#define MSG_SIZE_INT sizeof(int)
#define MSG_SIZE_DYN_RULE sizeof(struct DynamicRuleFromKernel)

struct machdr {
  unsigned char dst[6], src[6];
  char type[2]; /* mac type */
};

static struct nf_hook_ops netfilter_ops_out; /* NF_IP_POST_ROUTING */
struct net_device *dev;

atomic_t got_p;
atomic_t tracked_connections;
int max_tracked_connections = 100000;
atomic_t filtered_packets;

int max_filter_rules = 200;
int filter_classes_count = 0;
int filter_types_count = 0;
int min_packet_size = 0;

char **filter_classes;
char **filter_types;
char *raw;

short drop;
short isLogging = 1;
short isFiltering = 0;
short isMultiFiltering = 0;

short isResender = 0;
short isSniffer = 0;

char ifdev[20];

long buf_size = 3 * 1024 * 1024;
long resender_buf_size = 3 * 1024 * 1024;

char user_data[80]; /* our device */

struct Rule *RECVED_RULE;
struct Command *RECEVED_COMMAND;
struct sock *netlink_sock;
static bool run_pause = true;

static struct RuleListItem policy_list;
static int dyn_rules_count = 0;

// the structure used to register the function
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

//============Our includes ===========
#include "../Common/structs.h"
#include "debug_utils.h"
#include "mmap_utils.h"
#include "nf_hook.h"
#include "proc_fs.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-ai-firewall");
MODULE_AUTHOR("sergey_staroletov, roman_chudov");

//=============FUNCTIONS================================

unsigned int port_str_to_int(char *port_str) {
  unsigned int port = 0;
  int i = 0;
  if (port_str == NULL) {
    return 0;
  }
  while (port_str[i] != '\0') {
    port = port * 10 + (port_str[i] - '0');
    ++i;
  }
  return port;
}

/* convert the string to byte array first, e.g.: from "131.132.162.25" to
 * [131][132][162][25] */
unsigned int ip_str_to_hl(char *ip_str) {
  unsigned char ip_array[4];
  int i = 0;
  unsigned int ip = 0;
  if (ip_str == NULL) {
    return 0;
  }
  memset(ip_array, 0, 4);
  while (ip_str[i] != '.') {
    ip_array[0] = ip_array[0] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '.') {
    ip_array[1] = ip_array[1] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '.') {
    ip_array[2] = ip_array[2] * 10 + (ip_str[i++] - '0');
  }
  ++i;
  while (ip_str[i] != '\0') {
    ip_array[3] = ip_array[3] * 10 + (ip_str[i++] - '0');
  }
  /* convert from byte array to host long integer format */
  ip = (ip_array[0] << 24);
  ip = (ip | (ip_array[1] << 16));
  ip = (ip | (ip_array[2] << 8));
  ip = (ip | ip_array[3]);
  // printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
  return ip;
}

/* check the two input IP addresses, if they match, only the first few bits
 * (masked bits) are compared */
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
  unsigned int tmp = ntohl(ip); // network to host long
  int cmp_len = 32;
  int i = 0, j = 0;
  if (mask != 0) {
    cmp_len = 0;
    for (i = 0; i < 32; ++i) {
      if (mask & (1 << (32 - 1 - i)))
        cmp_len++;
      else
        break;
    }
  }

  /* compare the two IP addresses for the first cmp_len bits */
  for (i = 31, j = 0; j < cmp_len; --i, ++j) {
    if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
      // printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
      return false;
    }
  }
  return true;
}

void allocate_memory(void) {
  log("try to alloc buffer");
  raw = NULL;
  raw = (char *)kmalloc(MAX_BUFFERED_LEN, GFP_ATOMIC);
  if (!raw) {
    log("ERROR in memory allocating");
  } else {
    log("allocated memory OK");
  }
}

void free_memory(void) {
  int f;
  log("free mem");
  if (raw)
    kfree(raw);
  raw = NULL;

  for (f = 0; f < filter_classes_count; f++)
    kfree(filter_classes[f]);
  if (filter_classes)
    kfree(filter_classes);

  filter_classes = NULL;

  for (f = 0; f < filter_types_count; f++)
    kfree(filter_types[f]);
  if (filter_types)
    kfree(filter_types);
  filter_types = NULL;

  filter_classes_count = 0;
  filter_types_count = 0;
}


void change_targert(const char *targert) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 22)
  if (!strcmp(targert, "pre_routing"))
    netfilter_ops_out.hooknum = NF_INET_PRE_ROUTING;
  if (!strcmp(targert, "local_in"))
    netfilter_ops_out.hooknum = NF_INET_LOCAL_IN;
  if (!strcmp(targert, "forward"))
    netfilter_ops_out.hooknum = NF_INET_FORWARD;
  if (!strcmp(targert, "local_out"))
    netfilter_ops_out.hooknum = NF_INET_LOCAL_OUT;
  if (!strcmp(targert, "post_routing"))
    netfilter_ops_out.hooknum = NF_INET_POST_ROUTING;
  if (!strcmp(targert, "numhooks"))
    netfilter_ops_out.hooknum = NF_INET_NUMHOOKS;
#else
  if (!strcmp(targert, "pre_routing"))
    netfilter_ops_out.hooknum = NF_IP_PRE_ROUTING;
  if (!strcmp(targert, "local_in"))
    netfilter_ops_out.hooknum = NF_IP_LOCAL_IN;
  if (!strcmp(targert, "forward"))
    netfilter_ops_out.hooknum = NF_IP_FORWARD;
  if (!strcmp(targert, "local_out"))
    netfilter_ops_out.hooknum = NF_IP_LOCAL_OUT;
  if (!strcmp(targert, "post_routing"))
    netfilter_ops_out.hooknum = NF_IP_POST_ROUTING;
  if (!strcmp(targert, "numhooks"))
    netfilter_ops_out.hooknum = NF_IP_NUMHOOKS;
#endif
}

void change_priority(const char *priority) {
  if (!strcmp(priority, "first"))
    netfilter_ops_out.priority = NF_IP_PRI_FIRST;
  if (!strcmp(priority, "conntrack_defrag"))
    netfilter_ops_out.priority = NF_IP_PRI_CONNTRACK_DEFRAG;
  if (!strcmp(priority, "raw"))
    netfilter_ops_out.priority = NF_IP_PRI_RAW;
  if (!strcmp(priority, "selinux_first"))
    netfilter_ops_out.priority = NF_IP_PRI_SELINUX_FIRST;
  if (!strcmp(priority, "conntrack"))
    netfilter_ops_out.priority = NF_IP_PRI_CONNTRACK;
  if (!strcmp(priority, "mangle"))
    netfilter_ops_out.priority = NF_IP_PRI_MANGLE;
  if (!strcmp(priority, "nat_dst"))
    netfilter_ops_out.priority = NF_IP_PRI_NAT_DST;
  if (!strcmp(priority, "filter"))
    netfilter_ops_out.priority = NF_IP_PRI_FILTER;
  if (!strcmp(priority, "security"))
    netfilter_ops_out.priority = NF_IP_PRI_SECURITY;
  if (!strcmp(priority, "nat_src"))
    netfilter_ops_out.priority = NF_IP_PRI_NAT_SRC;
  if (!strcmp(priority, "selinux_last"))
    netfilter_ops_out.priority = NF_IP_PRI_SELINUX_LAST;
  if (!strcmp(priority, "conntrack_confirm"))
    netfilter_ops_out.priority = NF_IP_PRI_CONNTRACK_CONFIRM;
  if (!strcmp(priority, "last"))
    netfilter_ops_out.priority = NF_IP_PRI_LAST;
}

void init_run_sniffer(void);

int sniffer_dev_open(struct inode *inode, struct file *filep);
int sniffer_dev_release(struct inode *inode, struct file *filep);
ssize_t sniffer_dev_read(struct file *filep, char *buff, size_t count,
                         loff_t *offp);
ssize_t sniffer_dev_write(struct file *filep, const char *buff, size_t count,
                          loff_t *offp);

struct file_operations dev_fops = {
  open : sniffer_dev_open,
  read : sniffer_dev_read,
  write : sniffer_dev_write,
  release : sniffer_dev_release,
};

int sniffer_dev_open(struct inode *inode, struct file *filep) { return 0; }
int sniffer_dev_release(struct inode *inode, struct file *filep) { return 0; }
ssize_t sniffer_dev_read(struct file *filep, char *buff, size_t count,
                         loff_t *offp) { return 0; }

/*
 * Handles parameters passing: user echo ... >/dev/ads_sniffer
 */
ssize_t sniffer_dev_write(struct file *filep, const char *buff, size_t count,
                          loff_t *offp) {
  char saveif[20];
  char buffer[30];
  int l;

  strcpy(saveif, ifdev);
  strcpy(ifdev, "null");

  log("dev_write");

  /* function to copy user space buffer to kernel space*/
  if (count > 79)
    count = 79;
  if (copy_from_user(user_data, buff, count) != 0)
    log("Userspace -> kernel copy failed!\n");

  user_data[count] = 0;

  for (l = 0; l < count; l++)
    if (user_data[l] == '\r' || user_data[l] == '\n') {
      user_data[l] = 0;
      break;
    }
  log("user sent:");
  log(user_data);

  // start sniffer by request
  if (!strcmp(user_data, "sniffer")) {
    isSniffer = 1;
    init_run_sniffer();
    strcpy(ifdev, saveif);
    return count;
  }

  // setup parameters
  if (!strcmp(user_data, "drop_packets")) {
    drop = 1;
    log("enabled packets drop");
  } else if (!strcmp(user_data, "pass_packets")) {
    drop = 0;
    log("disabled packets drop");
  }

  if (!strcmp(user_data, "logging")) {
    isLogging = 1;
  }

  if (!strcmp(user_data, "nologging")) {
    isLogging = 0;
  }

  //some commands known to the userspace starter app

  if (user_data[0] == 'i' && user_data[1] == 'f') {
    memset(saveif, 0, sizeof(saveif));
    strcpy(saveif, user_data + 3);
    printk("set up drop interface: '%s'\n", saveif);
  }

  // enable mime filtering?
  if (user_data[0] == 'm' && user_data[1] == 'f') {
    if (user_data[3] == '1') {
      isFiltering = 1;
      log("packet filtering with mime enabled");
    } else {
      isFiltering = 0;
      log("packet filtering with mime disabled");
    }
  }

  if (user_data[0] == 'm' && user_data[1] == 'g') {
    if (user_data[3] == '1') {
      isMultiFiltering = 1;
      log("multi connection filtering with mime enabled");
    } else {
      isMultiFiltering = 0;
      log("multi connection filtering with mime disabled");
    }
  }

  if (user_data[0] == 'p' && user_data[1] == 'r') {
    strcpy(buffer, user_data + 3);
    log("change priority to");
    log(buffer);
    change_priority(buffer);
  }

  if (user_data[0] == 't' && user_data[1] == 't') {
    strcpy(buffer, user_data + 3);
    log("change targert to");
    log(buffer);
    change_targert(buffer);
  }

  if (user_data[0] == 'm' && user_data[1] == 's') {
    strcpy(buffer, user_data + 3);
    min_packet_size = simple_strtol(buffer, NULL, 10);
    printk("set up min packet size: %d\n", min_packet_size);
  }

  if (user_data[0] == 'b' && user_data[1] == 'f') {
    // set buffer size
    strcpy(buffer, user_data + 3);
    buf_size = simple_strtol(buffer, NULL, 10);
  }

  if (user_data[0] == 'c' && user_data[1] == 'c') {
    char word[50];
    strcpy(word, user_data + 3);
    if (filter_classes_count < max_filter_rules) {
      filter_classes[filter_classes_count] = kmalloc(50, GFP_ATOMIC);
      strcpy(filter_classes[filter_classes_count], word);
      log("added rule:");
      log(filter_classes[filter_classes_count]);
      filter_classes_count++;
    } else {
      log("too many filter rules!");
    }
  }

  if (user_data[0] == 'c' && user_data[1] == 't') {
    char word[50];
    strcpy(word, user_data + 3);
    if (filter_types_count < max_filter_rules) {
      filter_types[filter_types_count] = kmalloc(50, GFP_ATOMIC);
      strcpy(filter_types[filter_types_count], word);
      log("added rule:");
      log(filter_types[filter_types_count]);
      filter_types_count++;
    } else {
      log("too many filter rules!");
    }
  }

  memset(user_data, 0, sizeof(user_data));
  strcpy(ifdev, saveif);

  return count;
}


void init_run_sniffer(void) {
  log("init ads_sniffer\n");

  allocate_memory();
  mmap_rx = kmalloc(sizeof(struct pkt_mmap), GFP_ATOMIC);

  init_mmap_all(buf_size, "ads_sniff_mmap", mmap_rx, &packet_mmap_ops_rx,
                &mmap_fops_rx);

  atomic_set(&mmap_rx->number_atomic, 1);
  atomic_set(&got_p, 0);
  atomic_set(&tracked_connections, 0);
  atomic_set(&filtered_packets, 0);

  // fill in the hook structure for incoming packet hook
  nfho.hook = hook_func_in;
  nfho.hooknum = NF_INET_LOCAL_IN; // NF_INET_PRE_ROUTING;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho); // Register the hook

  // fill in the hook structure for outgoing packet hook
  nfho_out.hook = hook_func_out;
  nfho_out.hooknum = NF_INET_LOCAL_OUT; // NF_INET_POST_ROUTING;
  nfho_out.pf = PF_INET;
  nfho_out.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho_out); // Register the hook

  log("init ads sniffer done");
}

/*
 * FOR RULES
 */

int add_a_rule(struct Rule *a_rule_desp) {
  struct RuleListItem *a_rule;
  struct list_head *p;
  struct RuleListItem *each_rule;
  unsigned int ip_src_desp = ip_str_to_hl(a_rule_desp->ip_src);
  unsigned int ip_dest_desp = ip_str_to_hl(a_rule_desp->ip_dest);

  list_for_each(p, &policy_list.list) {
    each_rule = list_entry(p, struct RuleListItem, list);

    if (each_rule->in_out == a_rule_desp->in_out)
      if (each_rule->src_ip == ip_src_desp)
        if (each_rule->dest_ip == ip_dest_desp)
          if (each_rule->src_port == a_rule_desp->port_src)
            if (each_rule->dest_port == a_rule_desp->port_dest)
              if (each_rule->proto == a_rule_desp->proto)
                if (each_rule->action == a_rule_desp->action)
                  return 0;
  }

  a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);

  if (a_rule == NULL) {
    printk(KERN_INFO
           "Firewall: error: cannot allocate memory for a_new_rule\n");
    return 0;
  }

  a_rule->id_rule = a_rule_desp->id_rule;
  a_rule->in_out = a_rule_desp->in_out;
  a_rule->src_ip = ip_src_desp;
  a_rule->dest_ip = ip_dest_desp;
  a_rule->src_port = a_rule_desp->port_src;
  a_rule->dest_port = a_rule_desp->port_dest;
  a_rule->proto = a_rule_desp->proto;
  a_rule->action = a_rule_desp->action;
  // a_rule->src_netmask = ip_str_to_hl(a_rule_desp->src_netmask);
  // a_rule->dest_netmask = ip_str_to_hl(a_rule_desp->dest_netmask);
  printk(KERN_INFO "Firewall: add_a_rule: in_out=%u, src_ip=%u, src_port=%d, "
                   "dest_ip=%u, dest_port=%d, proto=%u, action=%u\n",
         a_rule->in_out, a_rule->src_ip, a_rule->src_port, a_rule->dest_ip,
         a_rule->dest_port, a_rule->proto, a_rule->action);

  // down_write(&rw_sem);
  // spin_lock(&lock);

  INIT_LIST_HEAD(&(a_rule->list));
  list_add_tail(&(a_rule->list), &(policy_list.list));

  if (a_rule_desp->id_rule < 0)
    dyn_rules_count++;
  // up_write(&rw_sem);
  // spin_unlock(&lock);

  return 1;
}


void delete_a_rule(struct Rule *a_rule_desp) {
  //int i = 0;
  struct list_head *p, *q;
  struct RuleListItem *a_rule;

  // down_write(&rw_sem);
  // spin_lock(&lock);

  list_for_each_safe(p, q, &policy_list.list) {
    a_rule = list_entry(p, struct RuleListItem, list);
    if (a_rule->id_rule == a_rule_desp->id_rule) {
      if (a_rule->id_rule < 0)
        dyn_rules_count--;

      list_del(p);
      kfree(a_rule);
      log("rule deleted");
      return;
    }
  }

  // up_write(&rw_sem);
  // spin_unlock(&lock);
}

void update_a_rule(struct Rule *a_rule_desp) {
  struct list_head *p, *q;
  struct RuleListItem *a_rule;

  // down_write(&rw_sem);
  // spin_lock(&lock);

  list_for_each_safe(p, q, &policy_list.list) {
    a_rule = list_entry(p, struct RuleListItem, list);
    if (a_rule->id_rule == a_rule_desp->id_rule) {
      a_rule->in_out = a_rule_desp->in_out;
      a_rule->src_ip = a_rule_desp->ip_src;
      a_rule->src_port = a_rule_desp->port_src;
      a_rule->dest_ip = a_rule_desp->ip_dest;
      a_rule->dest_port = a_rule_desp->port_dest;
      a_rule->proto = a_rule_desp->proto;
      a_rule->action = a_rule_desp->action;

      kfree(a_rule);
      log("rule updated");
      return;
    }
  }

  // up_write(&rw_sem);
  // spin_unlock(&lock);
}

void return_count_dyn_rules(void) {}

/* Called when data arrives at the netlink socket, the network packet containing
 * the netlink message is passed in the parameters */
void netlink_Read_Msg(struct sk_buff *skb_in) {

  // pointer to a netlink message
  struct nlmsghdr *nl_msg;

  // network packet to send response
  struct sk_buff *skb_out;

  // auxiliary variables
  int pid;
  bool res = true;

  struct DynamicRuleFromKernel *to_user_space;
  struct list_head *p;
  struct RuleListItem *each_rule;

  // retrieving a netlink message from a network packet
  nl_msg = (struct nlmsghdr *)skb_in->data;

  RECEVED_COMMAND = (struct Command *)nlmsg_data(nl_msg);

  if (RECEVED_COMMAND == NULL)
    res = false;

  // store the ID of the process that sent this message
  pid = nl_msg->nlmsg_pid;

  //=================================================================================
  if (res) {
    switch (RECEVED_COMMAND->action) {
    case ADD_RULE_COMMAND: {
      res = add_a_rule(RECEVED_COMMAND->rule);
      log("rule added");
    } break;
    case DELETE_RULE_COMMAND: {
      delete_a_rule(RECEVED_COMMAND->rule);
    } break;
    case UPDATE_RULE_COMMAND: {
      update_a_rule(RECEVED_COMMAND->rule);
    } break;
    case START_COMMAND: {
      run_pause = true;
    } break;
    case PAUSE_COMMAND: {
      run_pause = false;
    } break;
    case GET_DYNAMIC_RULES_COMMAND: {
      printk(KERN_ERR "Firewall: count of dynamic rules = %d\n",
             dyn_rules_count);
      // we create a network packet to place a Netlink message in it for a response
      skb_out = nlmsg_new(MSG_SIZE_INT, 0);
      if (!skb_out) {
        printk(KERN_ERR "Firewall: Failed to allocate new skb\n");
        res = 0;
      }

      // we create a netlink message with data of size MSG_SIZE in skb_out
      nl_msg = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, MSG_SIZE_INT, 0);
      // write to the data area of the response netlink message
      *((int *)nlmsg_data(nl_msg)) = dyn_rules_count;
      // we send a network packet to the specified process (pid) via a netlink socket
      nlmsg_unicast(netlink_sock, skb_out, pid);

      list_for_each(p, &policy_list.list) {
        each_rule = list_entry(p, struct RuleListItem, list);

        if (each_rule->id_rule < 0) {
          to_user_space = kmalloc(MSG_SIZE_DYN_RULE, GFP_KERNEL);
          to_user_space->id_rule = each_rule->id_rule;
          to_user_space->in_out = each_rule->in_out;
          to_user_space->src_ip = each_rule->src_ip;
          to_user_space->src_port = each_rule->src_port;
          to_user_space->dest_ip = each_rule->dest_ip;
          to_user_space->dest_port = each_rule->dest_port;
          to_user_space->proto = each_rule->proto;
          to_user_space->action = each_rule->action;

          // we create a network packet to place a Netlink message in it for a response
          skb_out = nlmsg_new(MSG_SIZE_DYN_RULE, 0);
          if (!skb_out) {
            printk(KERN_ERR "Firewall: Failed to allocate new skb\n");
            // return;
            res = 0;
          }

          // we create a netlink message with data of size MSG_SIZE in skb_out
          nl_msg = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, MSG_SIZE_DYN_RULE, 0);
          // write to the data area of the response netlink message
          *((struct DynamicRuleFromKernel *)nlmsg_data(nl_msg)) =
              *to_user_space;
          // we send a network packet to the specified process (pid) via a netlink socket
          nlmsg_unicast(netlink_sock, skb_out, pid);
        }
      }
    } break;
    default:
      break;
    }
  }

  if (RECEVED_COMMAND->action != GET_DYNAMIC_RULES_COMMAND) {
    // we create a network packet to place a Netlink message in it for a response
    skb_out = nlmsg_new(MSG_SIZE_BOOL, 0);
    if (!skb_out) {
      printk(KERN_ERR "Firewall: Failed to allocate new skb\n");
      res = false;
    }

    // we create a netlink message with data of size MSG_SIZE in skb_out
    nl_msg = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, MSG_SIZE_BOOL, 0);
    // write to the data area of the response netlink message
    *((bool *)nlmsg_data(nl_msg)) = res;
    // we send a network packet to the specified process (pid) via a netlink socket
    nlmsg_unicast(netlink_sock, skb_out, pid);
  }
}


/* Initialization routine */

int init_module() {

  struct netlink_kernel_cfg cfg = {
     .input = netlink_Read_Msg,
  };

  int dev_num = 232;

  log("INIT...");

  INIT_LIST_HEAD(&(policy_list.list));

  log("creating device");

  if (register_chrdev(dev_num, "ads_sniffer", &dev_fops)) {
    printk("failed to register character device, num = %d\n", 232);
    return 1;
  }

  filter_classes = NULL;
  filter_types = NULL;
  filter_classes = kmalloc(max_filter_rules * sizeof(char *), GFP_ATOMIC);
  filter_types = kmalloc(max_filter_rules * sizeof(char *), GFP_ATOMIC);

  if (!filter_classes || !filter_types) {
    log("ERROR memory allocating for types/classes");
  };

  init_procfs();

  netlink_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);

  if (netlink_sock == NULL)
    printk(KERN_ERR "Firewall: Error creating netlink socket.\n");

  log("INIT done");

  return 0;
}

void cleanup(void) { nf_unregister_net_hook(&init_net, &netfilter_ops_out); }


/* main cleanup routine */
void cleanup_module() {
  struct list_head *p, *q;
  struct RuleListItem *a_rule;

  printk("unloading ads_drv...");

  remove_proc();

  if (isSniffer) {
    // nf_unregister_hook(&netfilter_ops_out);
    nf_unregister_net_hook(&init_net, &nfho);
    nf_unregister_net_hook(&init_net, &nfho_out);

    mmap_clear_all(mmap_rx);
    free_memory();
  }

  unregister_chrdev(232, "ads_sniffer");

  printk(KERN_INFO "Firewall: free policy list\n");

  list_for_each_safe(p, q, &policy_list.list) {
    printk(KERN_INFO "Firewall: free one\n");
    a_rule = list_entry(p, struct RuleListItem, list);
    list_del(p);
    kfree(a_rule);
  }

  netlink_kernel_release(netlink_sock);

  printk(KERN_INFO "Firewall: kernel module UNLOADED.\n");
}

int hex_to_int(char c) {
  int first = c / 16 - 3;
  int second = c % 16;
  int result = first * 10 + second;
  if (result > 9)
    result--;
  return result;
}

int hex_to_ascii(char c, char d) {
  int high = hex_to_int(c) * 16;
  int low = hex_to_int(d);
  return high + low;
}

#endif // KERNEL_NETFILTER
