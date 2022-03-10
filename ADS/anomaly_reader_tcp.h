/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef ANOMALYREADER_H
#define ANOMALYREADER_H

#include <QDebug>
#include <QListWidget>
#include <QTableWidget>
#include <QThread>
#include <QTime>

#include "anomaly_frame.h"

#include "../Common/netlinkmanager.h"
#include "../Common/packsreceiver.h"
#include "../Common/structs.h"
#include "../Common/utils/UnixSemaphore.h"

class AnomalyReaderTcp : public QThread {
  Q_OBJECT
public:
  explicit AnomalyReaderTcp(
      QObject *parent = 0, QTableWidget *_anomalies_table = 0,
      QTableWidget *_rules_table = 0, PacksReceiver *_receiver = 0,
      AnomalyTcpFrame *_painter = 0, QList<Rule *> *_rules = 0,
      NetLinkManager *_nlMngr = 0, int *_limit_tcp = 0,
      UnixSemaphore *_sem_dynamic_rules = 0, bool *_gen_rules = 0,
      UnixSemaphore *_sem_settings = 0, int *_tcp_drop_ports = 0,
      int *_id_rules_dyn = 0);

  void run();

private:
  QListWidget *alist;
  QTableWidget *anomalies_table;
  QTableWidget *rules_table;
  PacksReceiver *receiver;
  AnomalyTcpFrame *painter;
  QList<Rule *> *rules;
  NetLinkManager *nlManager;
  int *limit_tcp;
  bool *gen_rules;
  int *tcp_drop_ports;

  int *id_rule;
  int __id;
  int col_rules;
  int col_anomalies;

  UnixSemaphore *sem_rules;
  UnixSemaphore *sem_settings;

  QString getStrIp(unsigned int ip);
  bool isIpFromLAN(unsigned int ip);
  bool isRuleExist(Rule *rule_to_check);

signals:

public slots:
};

#endif // ANOMALYREADER_H
