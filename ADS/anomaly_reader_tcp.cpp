/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "anomaly_reader_tcp.h"

AnomalyReaderTcp::AnomalyReaderTcp(
    QObject *parent, QTableWidget *_anomalies_table, QTableWidget *_rules_table,
    PacksReceiver *_receiver, AnomalyTcpFrame *_painter, QList<Rule *> *_rules,
    NetLinkManager *_nlMngr, int *_limit_tcp, UnixSemaphore *_sem_dynamic_rules,
    bool *_gen_rules, UnixSemaphore *_sem_settings, int *_tcp_drop_ports,
    int *_id_rules_dyn)
    : QThread(parent) {

  anomalies_table = _anomalies_table;
  rules_table = _rules_table;
  receiver = _receiver;
  painter = _painter;

  sem_rules = _sem_dynamic_rules;
  sem_settings = _sem_settings;

  rules = _rules;
  nlManager = _nlMngr;

  limit_tcp = _limit_tcp;
  gen_rules = _gen_rules;
  tcp_drop_ports = _tcp_drop_ports;

  id_rule = _id_rules_dyn;
  __id = -1;
  col_rules = 0;
  col_anomalies = 0;
}

void AnomalyReaderTcp::run() {
  AnomalyNodeTCP anomaly_node;
  QString ip_src_str, ip_dest_str, port_src_str, port_dest_str;
  QTableWidgetItem *timeItem, *numItem, *ipSrcItem, *ipDestItem, *portSrcItem,
      *portDestItem, *valItem, *statesItem, *predictorItem;

  while (true) {
    if (receiver->getTcpAnomalyFromQueue(&anomaly_node)) {
      painter->addPoint(anomaly_node.anomaly);
      painter->paintGraphic();

      sem_settings->wait();

      if (anomaly_node.anomaly >= *limit_tcp) {

        timeItem = new QTableWidgetItem();
        valItem = new QTableWidgetItem();
        ipSrcItem = new QTableWidgetItem();
        ipDestItem = new QTableWidgetItem();
        portDestItem = new QTableWidgetItem();
        portSrcItem = new QTableWidgetItem();
        statesItem = new QTableWidgetItem();
        predictorItem = new QTableWidgetItem();

        timeItem->setText(QTime::currentTime().toString("hh:mm:ss"));
        valItem->setText(QString::number(anomaly_node.anomaly));
        ipSrcItem->setText(getStrIp(anomaly_node.src_ip));
        ipDestItem->setText(getStrIp(anomaly_node.dest_ip));
        portDestItem->setText(QString::number(anomaly_node.dest_port));
        portSrcItem->setText(QString::number(anomaly_node.src_port));
        statesItem->setText(QString::fromUtf8(anomaly_node.states));
        predictorItem->setText(QString::number(anomaly_node.predictor));

        anomalies_table->insertRow(col_anomalies);
        anomalies_table->setItem(col_anomalies, 0, timeItem);
        anomalies_table->setItem(col_anomalies, 1, valItem);
        anomalies_table->setItem(col_anomalies, 2, ipSrcItem);
        anomalies_table->setItem(col_anomalies, 3, portSrcItem);
        anomalies_table->setItem(col_anomalies, 4, ipDestItem);
        anomalies_table->setItem(col_anomalies, 5, portDestItem);
        anomalies_table->setItem(col_anomalies, 6, statesItem);
        anomalies_table->setItem(col_anomalies, 7, predictorItem);
        col_anomalies++;

        if (*gen_rules) {
          Rule *rule_new = new Rule;

          rule_new->action = _DROP;
          rule_new->host_name_dest = "-";
          rule_new->host_name_src = "-";
          rule_new->proto = 1;
          rule_new->ip_dest = getStrIp(anomaly_node.dest_ip);
          rule_new->ip_src = getStrIp(anomaly_node.src_ip);

          rule_new->in_out = 1;

          if (*tcp_drop_ports == TCP_DROP_ALL_PORTS) {
            rule_new->port_dest = -1;
            rule_new->port_src = -1;
            port_dest_str = "Any";
            port_src_str = "Any";
          } else if (*tcp_drop_ports == TCP_DROP_SRC_PORT_ONLY) {
            rule_new->port_dest = -1;
            rule_new->port_src = anomaly_node.src_port;
            port_dest_str = "Any";
            port_src_str = QString::number(anomaly_node.src_port);
          } else if (*tcp_drop_ports == TCP_DROP_DEST_PORT_ONLY) {
            rule_new->port_dest = anomaly_node.dest_port;
            rule_new->port_src = -1;
            port_src_str = "Any";
            port_dest_str = QString::number(anomaly_node.dest_port);
          }

          sem_rules->wait();

          rule_new->id_rule = *(id_rule);

          if (!isRuleExist(rule_new)) {
            rules->append(rule_new);
            nlManager->sendRuleToKernel(rule_new);

            timeItem = new QTableWidgetItem();
            numItem = new QTableWidgetItem();
            ipSrcItem = new QTableWidgetItem();
            ipDestItem = new QTableWidgetItem();
            portDestItem = new QTableWidgetItem();
            portSrcItem = new QTableWidgetItem();

            timeItem->setText(QTime::currentTime().toString("hh:mm:ss"));
            numItem->setText(QString::number(-1 * (*id_rule)));
            ipSrcItem->setText(rule_new->ip_src);
            ipDestItem->setText(rule_new->ip_dest);
            portDestItem->setText(port_dest_str);
            portSrcItem->setText(port_src_str);

            rules_table->insertRow(col_rules);
            rules_table->setItem(col_rules, 0, numItem);
            rules_table->setItem(col_rules, 1, timeItem);
            rules_table->setItem(col_rules, 2, ipSrcItem);
            rules_table->setItem(col_rules, 3, portSrcItem);
            rules_table->setItem(col_rules, 4, ipDestItem);
            rules_table->setItem(col_rules, 5, portDestItem);

            col_rules++;
            (*id_rule)--;

          } else
            delete rule_new;

          sem_rules->post();
        }
      }

      sem_settings->post();

    } else { // pause
      this->msleep(5);
    }
  }
}

QString AnomalyReaderTcp::getStrIp(unsigned int ip) {
  int bit1, bit2, bit3, bit4;

  bit1 = 255 & ip;
  bit2 = (0xff00 & ip) >> 8;
  bit3 = (0xff0000 & ip) >> 16;
  bit4 = (0xff000000 & ip) >> 24;

  QString res;

  res = QString::number(bit1) + "." + QString::number(bit2) + "." +
        QString::number(bit3) + "." + QString::number(bit4);

  return res;
}

bool AnomalyReaderTcp::isIpFromLAN(unsigned int ip) {
  bool res = false;

  int bit1, bit2 /*, bit3, bit4*/;

  bit1 = 255 & ip;
  bit2 = (0xff00 & ip) >> 8;
  // bit3 = (0xff0000 & ip) >> 16;
  // bit4 = (0xff000000 & ip) >> 24;

  if ((bit1 == 10) || ((bit1 == 172) && ((bit2 >= 16) && (bit2 <= 31))) ||
      ((bit1 == 192) && (bit2 == 168)))
    res = true;

  return res;
}

bool AnomalyReaderTcp::isRuleExist(Rule *rule_to_check) {
  Rule *r;
  foreach (r, *rules) {
    if (r->action == rule_to_check->action &&
        r->in_out == rule_to_check->in_out &&
        r->ip_dest == rule_to_check->ip_dest &&
        r->ip_src == rule_to_check->ip_src &&
        r->port_dest == rule_to_check->port_dest &&
        r->port_src == rule_to_check->port_src)
      return true;
  }

  return false;
}
