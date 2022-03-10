#ifndef ANOMALY_READER_FLOW_H
#define ANOMALY_READER_FLOW_H
/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

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
#include "../SOM/samplesom.h"

class AnomalyReaderFlow : public QThread {
  Q_OBJECT
public:
  explicit AnomalyReaderFlow(
      QObject *parent = 0, QTableWidget *_som_table = 0,
      QTableWidget *_anomalies_table = 0, QTableWidget *_rules_table = 0,
      PacksReceiver *_receiver = 0, AnomalyTcpFrame *_painter = 0,
      QList<Rule *> *_rules = 0, NetLinkManager *_nlMngr = 0,
      int *_limit_flow = 0, UnixSemaphore *_sem_dynamic_rules = 0,
      bool *_gen_rules = 0, UnixSemaphore *_sem_settings = 0,
      int *_flow_drop_ports = 0, int *_id_rules_dyn = 0);
  void run();
  SampleSom *getSample(int ind);

signals:

public slots:

private:
  QListWidget *alist;
  QTableWidget *rules_table;
  QTableWidget *anomalies_table;
  QTableWidget *som_table;
  PacksReceiver *receiver;
  AnomalyTcpFrame *painter;
  QList<Rule *> *rules;
  NetLinkManager *nlManager;
  int *limit_flow;
  bool *gen_rules;
  int *flow_drop_ports;

  int *id_rule;
  int col_rules;
  int col_anomalies;

  UnixSemaphore *sem_rules;
  UnixSemaphore *sem_settings;

  QList<SampleSom *> samples;

  QString getStrIp(unsigned int ip);
  bool isIpFromLAN(unsigned int ip);
  bool isRuleExist(Rule *rule_to_check);
};

#endif // ANOMALY_READER_FLOW_H
