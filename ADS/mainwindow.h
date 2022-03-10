/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QGridLayout>
#include <QMainWindow>
#include <QMessageBox>

#include <stdio.h>
#include <string.h>

#include "ads_settings_dialog.h"
#include "anomaly_frame.h"
#include "learning_flow_dialog.h"
#include "learning_tcp_dialog.h"
#include "rulesform.h"

#include "anomaly_reader_flow.h"
#include "anomaly_reader_tcp.h"

#include "../Common/netlinkmanager.h"
#include "../Common/packsreceiver.h"
#include "../Common/structs.h"
//#include "../Common/ConnectionTree.h"
//#include "../Common/adressresolver.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  explicit MainWindow(QWidget *parent = 0, NetLinkManager *mng = 0,
                      PacksReceiver *_packs_receiver = 0);
  ~MainWindow();

private slots:
  void showRulesForm();
  void learnTcp();
  void learnFlow();
  void showSettings();
  void run_pause_firewall();
  void showAbout();
  void on_MainWindow_destroyed();
  void on_pushButtonFalseAlarm_clicked();
  void on_pushButtonFalseAlarmFlow_clicked();
  void on_tableWidgetSOM_cellClicked(int row, int column);

private:
  Ui::MainWindow *ui;
  // QSqlDatabase dBase;
  QList<Rule *> *user_rules;
  QList<Rule *> *ads_rules;
  NetLinkManager *nlManager;
  PacksReceiver *packs_receiver;
  void loadRulesToKernel();
  bool isLearnTcp;
  bool run_pause;

  AnomalyReaderTcp *tcp_anomaly_reader;
  AnomalyReaderFlow *flow_anomaly_reader;

  AnomalyTcpFrame *tcp_anomaly_frame;
  AnomalyTcpFrame *flow_anomaly_frame;
  QGridLayout *tcp_layout;

  UnixSemaphore *sem_dynamic_rules;
  UnixSemaphore *sem_settings_tcp;

  int tcp_depth;
  int tcp_anomaly_limit;
  int tcp_drop_ports;
  bool tcp_gen_rules;

  int flow_packs_max_count;
  int flow_min_count_packs_in_conn;
  int flow_anomaly_limit;
  int flow_drop_ports;
  bool flow_gen_rules;

  int id_rule_dynamic;
};

#endif // MAINWINDOW_H
