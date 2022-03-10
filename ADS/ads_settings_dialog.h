/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef ADS_SETTINGS_DIALOG_H
#define ADS_SETTINGS_DIALOG_H

#include "../Common/structs.h"
#include <QDialog>

namespace Ui {
class AdsSettingsDialog;
}

class AdsSettingsDialog : public QDialog {
  Q_OBJECT

public:
  explicit AdsSettingsDialog(QWidget *parent = 0,
                             UnixSemaphore *_sem_settings_tcp = 0,
                             int *_tcp_depth = 0, int *_tcp_limit = 0,
                             bool *_tcp_gen_rules = 0, int *_tcp_ports = 0,
                             int *_flow_limit = 0, bool *_flow_gen_rules = 0,
                             int *_flow_max_packs = 0);
  ~AdsSettingsDialog();

private slots:
  void on_buttonBox_accepted();

private:
  Ui::AdsSettingsDialog *ui;
  int *tcp_depth;
  int *tcp_limit;
  int *tcp_ports;
  bool *tcp_gen_rules;

  int *flow_limit;
  int *flow_max_packs;
  bool *flow_gen_rules;

  UnixSemaphore *sem_settings_tcp;
};

#endif // ADS_SETTINGS_DIALOG_H
