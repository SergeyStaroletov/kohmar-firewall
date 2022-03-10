/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef NETLINKMANAGER_H
#define NETLINKMANAGER_H

#ifndef ADS_DAEMON
#include <QDebug>
#include <QList>
#include <QMessageBox>
#include <QString>
#endif // ADS_DAEMON

#include "structs.h"
#include <fcntl.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define MSG_SIZE_SEND sizeof(struct Command)
#define MSG_SIZE_READ sizeof(bool)
#define MSG_SIZE_READ_DYN_COUNT sizeof(int)
#define MSG_SIZE_READ_DYN_RULE sizeof(struct DynamicRuleFromKernel)

/* Own family for netlink socket */
#define NETLINK_USER 31

class NetLinkManager {
public:
  NetLinkManager(int group);
  ~NetLinkManager();
  void closeNetlinkSocket();
  bool sendCommand(struct Command com);
  void sendRuleToKernel(Rule *r);
  void deleteRuleFromKernel(Rule *r);
  void updateRuleInKernel(Rule *r);

#ifndef ADS_DAEMON
  void getDynamicRulesFromKernel(QList<Rule *> *dyn_rules);
  QString getStrIp(unsigned int ip);
#endif

private:
  /* Netlink socket for communication with the module */
  int netlink_sock;

  /* Address to bind the socket to receive data addressed to us */
  struct sockaddr_nl nl_src_addr;

  /* Address of the module to indicate to whom the data is intended */
  struct sockaddr_nl nl_dest_addr;

  /* Two messages for sending and receiving netlink messages */
  struct msghdr MSG_Read, MSG_Send, MSG_Read_count, MSG_Read_rule;
  struct iovec iov_read, iov_send, iov_read_count, iov_read_rule;

  /* Two Netlink messages to send and receive */
  struct nlmsghdr *nlmsg_read, *nlmsg_send, *nlmsg_read_count, *nlmsg_read_rule;

  struct Command *SEND_MSG;

  bool *RECV_FLAG;
  int *RECV_COUNT;
  struct DynamicRuleFromKernel *RECV_DYN_RULE;
};

#endif // NETLINKMANAGER_H
