/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef STRUCTS_H
#define STRUCTS_H

#define DELETE_RULE_COMMAND 0
#define ADD_RULE_COMMAND 1
#define UPDATE_RULE_COMMAND 2
#define GET_DYNAMIC_RULES_COMMAND 3
#define PAUSE_COMMAND 4
#define START_COMMAND 5

#define TCP_DROP_ALL_PORTS 1
#define TCP_DROP_SRC_PORT_ONLY 2
#define TCP_DROP_DEST_PORT_ONLY 3

#define _ICMP 1
#define _TCP 6
#define _UDP 17

#define LEARN_HTTP 1
#define LEARN_HTTPS 2
#define LEARN_FTP 3
#define LEARN_SSH 4
#define LEARN_TELNET 5
#define LEARN_ALL 6

#define _DROP 0
#define _ACCEPT 1

struct MyPacket {
  unsigned int in_out;
  unsigned int src_ip;
  unsigned int dest_ip;
  int src_port; // 0~2^32
  int dest_port;
  unsigned int proto; // 0: all, 1: tcp, 2: udp 3: icmp

  bool urg;
  bool ack;
  bool syn;
  bool fin;
  bool rst;
  bool psh;
};

struct DynamicRuleFromKernel {
  int id_rule;
  unsigned int in_out;
  unsigned int src_ip; //
  int src_port;        // 0~2^32
  unsigned int dest_ip;
  int dest_port;
  unsigned int proto;  // 0: all, 1: tcp, 2: udp
  unsigned int action; // 0: for block, 1: for unblock
};

#ifdef KERNEL_NETFILTER

#include <linux/list.h>

struct Rule {
  int id_rule;
  unsigned int in_out;
  char *ip_src;
  char *ip_dest;
  int port_src;
  int port_dest;
  unsigned int proto;
  unsigned int action;
};

struct Command {
  int action;
  struct Rule *rule;
};

/*structure for firewall policies*/
struct RuleListItem {
  int id_rule;
  unsigned int in_out;
  unsigned int src_ip;      //
  unsigned int src_netmask; //
  int src_port;             // 0~2^32
  unsigned int dest_ip;
  unsigned int dest_netmask;
  int dest_port;
  unsigned int proto;  // 0: all, 1: tcp, 2: udp
  unsigned int action; // 0: for block, 1: for unblock
  struct list_head list;
};

#endif // KERNEL_NETFILTER

#ifndef KERNEL_NETFILTER

struct RuleToKernel {
  int id_rule;
  unsigned int in_out;
  char *ip_src;
  char *ip_dest;
  int port_src;
  int port_dest;
  unsigned int proto;
  unsigned int action;
};

struct Command {
  int action;
  struct RuleToKernel *rule;
};

struct CommandToAds {
  int command;
  unsigned int in_out;
  char ip_src[15];
  char ip_dest[15];
  char host_src[100];
  char host_dest[100];
  int port_src;
  int port_dest;
  unsigned int proto;
  unsigned int action;
  int id_rule;
};

//#ifdef ADS_QT

#include <QString>

struct Rule {
  int id_rule;
  unsigned int in_out;
  QString ip_src;
  QString ip_dest;
  int port_src;
  int port_dest;
  unsigned int proto;
  unsigned int action;
  QString host_name_dest;
  QString host_name_src;
};
//#endif

#include "utils/UnixSemaphore.h"
#include <vector>

struct AnomalyNodeTCP {
  unsigned int src_ip;
  unsigned int dest_ip;
  int src_port;
  int dest_port;
  unsigned int proto;
  double anomaly;
  int predictor;
  char *states;
};

struct AnomalyNodeFlow {
  double flow_size_average;
  int flow_new_tcp_conn_count;
  double flow_udp_count;
  double flow_icmp_count;
  int flow_diff_ip_src_count;
  double flow_low_active_conn_count;
  int flow_little_count;
  int flow_big_count;
  // int flow_diff_ports_count;
  double anomaly;
  //
  int winner; // for som visualization
};

struct ConnectionTreeNode {
  // int key;
  unsigned int ip_src;
  unsigned int ip_dest;
  unsigned int port_src;
  unsigned int port_dest;
  ConnectionTreeNode *left;
  ConnectionTreeNode *right;

  char *states;
  // std::vector<char*> learning_strings;
  char *learning_string;
  // bool learned;
  // int last_l_str;

  UnixSemaphore *sem;

  long packs_transmitted;

  int bal;

  int id;
};

//#endif // ADS_QT

#endif // KERNEL_NETFILTER

#endif // STRUCTS_H
