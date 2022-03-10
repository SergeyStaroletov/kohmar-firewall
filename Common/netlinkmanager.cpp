/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "netlinkmanager.h"

NetLinkManager::NetLinkManager(int group) {
#ifndef ADS_DAEMON
  QMessageBox msgBox;
#endif // ADS_DAEMON

  int res;

  /* We create a Netlink socket, specify our own family (NETLINK_USER) */
  if ((netlink_sock = socket(PF_NETLINK, SOCK_RAW, group)) < 0) {
// perror("Netlink Socket");
#ifndef ADS_DAEMON
    msgBox.setText("NetLink socket creation error");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "NetLink socket creation error";
    return;
  }

  /* Specify our process ID in the address and associate the address with the
   * socket
   */
  memset(&nl_src_addr, 0, sizeof(nl_src_addr));
  nl_src_addr.nl_family = AF_NETLINK;
  nl_src_addr.nl_pid =
      getpid(); // pthread_self() << 16 | getpid();//pthread_self();//(pid_t)
                // syscall (SYS_gettid);
  nl_src_addr.nl_groups = 0;

  res =
      bind(netlink_sock, (struct sockaddr *)&nl_src_addr, sizeof(nl_src_addr));
  if (res < 0) {
#ifndef ADS_DAEMON
    msgBox.setText("NetLink socket bind error");
    msgBox.exec();
#endif // ADS_DAEMON

    qDebug() << "NetLink socket bind error";
    return;
  }

  /* Fill in the address for sending messages to the kernel module */
  nl_dest_addr.nl_family = AF_NETLINK;
  nl_dest_addr.nl_pid = 0;
  nl_dest_addr.nl_groups = 0;

  /* We allocate memory for the netlink header of the message and the
   * transmitted data */
  nlmsg_send = (struct nlmsghdr *)malloc(NLMSG_SPACE(MSG_SIZE_SEND));

  if (nlmsg_send == NULL) {
#ifndef ADS_DAEMON
    msgBox.setText("Memory allocation error for NetLink socket");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "Memory allocation error for NetLink socket";
    return;
  }

  /* Specify the size of the message, and who sends it */
  nlmsg_send->nlmsg_len = NLMSG_SPACE(MSG_SIZE_SEND);
  nlmsg_send->nlmsg_pid = getpid();
  nlmsg_send->nlmsg_flags = 0;

  /* Filling iovec for the msghdr structure */
  iov_send.iov_base = (void *)nlmsg_send;
  iov_send.iov_len = nlmsg_send->nlmsg_len;

  /* We form a message: indicate to whom to send and what to send */
  MSG_Send.msg_name = (void *)&nl_dest_addr;
  MSG_Send.msg_namelen = sizeof(nl_dest_addr);
  MSG_Send.msg_iov = &iov_send;
  MSG_Send.msg_iovlen = 1;

  /* Allocate memory for receiving netlink messages */
  nlmsg_read = (struct nlmsghdr *)malloc(NLMSG_SPACE(MSG_SIZE_READ));

  if (nlmsg_read == NULL) {
#ifndef ADS_DAEMON
    msgBox.setText("Memory allocation error for NetLink socket");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "Memory allocation error for NetLink socket";
    return;
  }

  /* We form a message for receiving: specify the size and where to save the
   * data */
  nlmsg_read->nlmsg_len = NLMSG_SPACE(MSG_SIZE_READ);
  iov_read.iov_base = (void *)nlmsg_read;
  iov_read.iov_len = nlmsg_read->nlmsg_len;
  MSG_Read.msg_iov = &iov_read;
  MSG_Read.msg_iovlen = 1;

  /* We define pointers for convenient work with received and sent data */
  SEND_MSG = (struct Command *)NLMSG_DATA(nlmsg_send);
  RECV_FLAG = (bool *)NLMSG_DATA(nlmsg_read);
}

void NetLinkManager::closeNetlinkSocket() {
  close(netlink_sock);
  // free((void *)nlmsg_send);
  // free((void *)nlmsg_read);
  // free((void *)SEND_MSG);
}

bool NetLinkManager::sendCommand(struct Command com) {
  memcpy(SEND_MSG, &com, sizeof(com));
  /* Send a message to the module */
  sendmsg(netlink_sock, &MSG_Send, 0);

  // QMessageBox msgBox;
  // msgBox.setText("Command Sended To Kernel");
  // msgBox.exec();
  qDebug() << "Sent to Kernel";

  recvmsg(netlink_sock, &MSG_Read, 0);

  // msgBox.setText("Received From Kernel");
  // msgBox.exec();
  // printf("\nRecived: %d\n", *RECV_FLAG);*/
  qDebug() << "Answer received from Kernel";
  return *RECV_FLAG;
}

void NetLinkManager::sendRuleToKernel(Rule *r) {
#ifndef ADS_DAEMON
  QMessageBox msgBox;
#endif // ADS_DAEMON

  qDebug() << "[Netlink - qstring] ip_src=" + r->ip_src +
                  " ip_dest=" + r->ip_dest;
  char __ip_src[16];
  char __ip_dest[16];
  strcpy(__ip_src, r->ip_src.toStdString().c_str());
  strcpy(__ip_dest, r->ip_dest.toStdString().c_str());

  struct RuleToKernel rule_to_kernel;
  struct Command command;

  // rule_to_kernel = new RuleToKernel;

  rule_to_kernel.id_rule = r->id_rule;
  rule_to_kernel.in_out = r->in_out;

  if (r->ip_src == "-")
    rule_to_kernel.ip_src = NULL;
  else {
    // qDebug() << "[NetlinkManager] ip_src...";
    rule_to_kernel.ip_src = __ip_src;
  }

  rule_to_kernel.port_src = r->port_src;

  if (r->ip_dest == "-")
    rule_to_kernel.ip_dest = NULL;
  else {
    // qDebug() << "[NetlinkManager] ip_dest...";
    rule_to_kernel.ip_dest = __ip_dest; // r->ip_dest.toUtf8().data();
  }

  rule_to_kernel.port_dest = r->port_dest;
  rule_to_kernel.proto = r->proto;
  rule_to_kernel.action = r->action;

  qDebug() << "[Netlink - char] ip_src=" +
                  QString::fromUtf8(rule_to_kernel.ip_src) +
                  " ip_dest=" + QString::fromUtf8(rule_to_kernel.ip_dest);

  // command = new Command;
  command.action = ADD_RULE_COMMAND;
  command.rule = &rule_to_kernel;

  if (!sendCommand(command)) {
#ifndef ADS_DAEMON
    // msgBox.setText("Error! Rule was not added!");
    // msgBox.exec();
#endif // ADS_DAEMON

    qDebug() << "Error! Rule was not added!";
  }
}

void NetLinkManager::deleteRuleFromKernel(Rule *r) {
#ifndef ADS_DAEMON
  QMessageBox msgBox;
#endif // ADS_DAEMON

  struct RuleToKernel rule_to_kernel;
  struct Command command;

  rule_to_kernel.id_rule = r->id_rule;
  rule_to_kernel.in_out = r->in_out;

  if (r->ip_src == "-")
    rule_to_kernel.ip_src = NULL;
  else
    rule_to_kernel.ip_src = r->ip_src.toUtf8().data();

  rule_to_kernel.port_src = r->port_src;

  if (r->ip_dest == "-")
    rule_to_kernel.ip_dest = NULL;
  else
    rule_to_kernel.ip_dest = r->ip_dest.toUtf8().data();

  rule_to_kernel.port_dest = r->port_dest;
  rule_to_kernel.proto = r->proto;
  rule_to_kernel.action = r->action;

  // command = new Command;
  command.action = DELETE_RULE_COMMAND;
  command.rule = &rule_to_kernel;

  if (!sendCommand(command)) {
#ifndef ADS_DAEMON
    msgBox.setText("Error! Rule was not deleted!");
    msgBox.exec();
#endif // ADS_DAEMON

    qDebug() << "Error! Rule was not deleted!";
  }
}

void NetLinkManager::updateRuleInKernel(Rule *r) {
#ifndef ADS_DAEMON
  QMessageBox msgBox;
#endif // ADS_DAEMON

  struct RuleToKernel rule_to_kernel;
  struct Command command;

  rule_to_kernel.id_rule = r->id_rule;
  rule_to_kernel.in_out = r->in_out;

  if (r->ip_src == "-")
    rule_to_kernel.ip_src = NULL;
  else
    rule_to_kernel.ip_src = r->ip_src.toUtf8().data();

  rule_to_kernel.port_src = r->port_src;

  if (r->ip_dest == "-")
    rule_to_kernel.ip_dest = NULL;
  else
    rule_to_kernel.ip_dest = r->ip_dest.toUtf8().data();

  rule_to_kernel.port_dest = r->port_dest;
  rule_to_kernel.proto = r->proto;
  rule_to_kernel.action = r->action;

  // command = new Command;
  command.action = UPDATE_RULE_COMMAND;
  command.rule = &rule_to_kernel;

  if (!sendCommand(command)) {
#ifndef ADS_DAEMON
    msgBox.setText("Error! Rule was not changed!");
    msgBox.exec();
#endif // ADS_DAEMON

    qDebug() << "Error! Rule was not changed!";
  }
}

NetLinkManager::~NetLinkManager() {
  this->closeNetlinkSocket();

  delete nlmsg_send;
  nlmsg_send = NULL;
  delete nlmsg_read;
  nlmsg_read = NULL;
  delete SEND_MSG;
  SEND_MSG = NULL;
}

#ifndef ADS_DAEMON
void NetLinkManager::getDynamicRulesFromKernel(QList<Rule *> *dyn_rules) {
  struct Command com;
  struct Rule *rule;
  com.action = GET_DYNAMIC_RULES_COMMAND;

  /* Allocate memory for receiving netlink messages */
  nlmsg_read_count =
      (struct nlmsghdr *)malloc(NLMSG_SPACE(MSG_SIZE_READ_DYN_COUNT));
  if (nlmsg_read_count == NULL) {
    qDebug() << "Memory allocation error for NetLink socket";
    exit(0);
  }

  /* Allocate memory for receiving netlink messages */
  nlmsg_read_rule =
      (struct nlmsghdr *)malloc(NLMSG_SPACE(MSG_SIZE_READ_DYN_RULE));
  if (nlmsg_read_rule == NULL) {
    qDebug() << "Memory allocation error for NetLink socket";
    exit(0);
  }

  /* We form a message for receiving: specify the size and where to save the
   * data */
  nlmsg_read_count->nlmsg_len = NLMSG_SPACE(MSG_SIZE_READ_DYN_COUNT);
  iov_read_count.iov_base = (void *)nlmsg_read_count;
  iov_read_count.iov_len = nlmsg_read_count->nlmsg_len;
  MSG_Read_count.msg_iov = &iov_read_count;
  MSG_Read_count.msg_iovlen = 1;
  RECV_COUNT = (int *)NLMSG_DATA(nlmsg_read_count);

  /* We form a message for receiving: specify the size and where to save the
   * data */
  nlmsg_read_rule->nlmsg_len = NLMSG_SPACE(MSG_SIZE_READ_DYN_RULE);
  iov_read_rule.iov_base = (void *)nlmsg_read_rule;
  iov_read_rule.iov_len = nlmsg_read_rule->nlmsg_len;
  MSG_Read_rule.msg_iov = &iov_read_rule;
  MSG_Read_rule.msg_iovlen = 1;
  RECV_DYN_RULE = (struct DynamicRuleFromKernel *)NLMSG_DATA(nlmsg_read_rule);

  memcpy(SEND_MSG, &com, sizeof(com));
  /* Send the message to the module */
  sendmsg(netlink_sock, &MSG_Send, 0);

  recvmsg(netlink_sock, &MSG_Read_count, 0);
  qDebug() << "dyn_count=" << QString::number(*RECV_COUNT);

  for (int i = 0; i < *RECV_COUNT; i++) {
    recvmsg(netlink_sock, &MSG_Read_rule, 0);
    qDebug() << "dyn_id_rule=" << QString::number(RECV_DYN_RULE->id_rule);

    rule = new Rule;
    rule->action = RECV_DYN_RULE->action;
    rule->host_name_dest = "-";
    rule->host_name_src = "-";
    rule->id_rule = RECV_DYN_RULE->id_rule;
    rule->in_out = RECV_DYN_RULE->in_out;
    rule->port_dest = RECV_DYN_RULE->dest_port;
    rule->port_src = RECV_DYN_RULE->src_port;
    rule->proto = RECV_DYN_RULE->proto;
    rule->ip_dest = getStrIp(RECV_DYN_RULE->dest_ip);
    rule->ip_src = getStrIp(RECV_DYN_RULE->src_ip);

    dyn_rules->append(rule);
  }
}

QString NetLinkManager::getStrIp(unsigned int ip) {
  int bit1, bit2, bit3, bit4;

  bit1 = 255 & ip;
  bit2 = (0xff00 & ip) >> 8;
  bit3 = (0xff0000 & ip) >> 16;
  bit4 = (0xff000000 & ip) >> 24;

  QString res;

  res = QString::number(bit4) + "." + QString::number(bit3) + "." +
        QString::number(bit2) + "." + QString::number(bit1);

  return res;
}
#endif
