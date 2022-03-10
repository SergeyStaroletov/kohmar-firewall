/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "ads_settings_dialog.h"
#include "ui_ads_settings_dialog.h"

AdsSettingsDialog::AdsSettingsDialog(QWidget *parent,
                                     UnixSemaphore *_sem_settings_tcp,
                                     int *_tcp_depth, int *_tcp_limit,
                                     bool *_tcp_gen_rules, int *_tcp_ports,
                                     int *_flow_limit, bool *_flow_gen_rules,
                                     int *_flow_max_packs)
    : QDialog(parent), ui(new Ui::AdsSettingsDialog) {
  ui->setupUi(this);

  tcp_depth = _tcp_depth;
  tcp_limit = _tcp_limit;
  tcp_gen_rules = _tcp_gen_rules;
  tcp_ports = _tcp_ports;

  flow_gen_rules = _flow_gen_rules;
  flow_limit = _flow_limit;
  flow_max_packs = _flow_max_packs;

  sem_settings_tcp = _sem_settings_tcp;

  ui->spinBoxDepth->setValue(*tcp_depth);
  ui->spinBoxAnomalyThr->setValue(*tcp_limit);
  ui->checkBoxTCPGenRule->setChecked(*tcp_gen_rules);

  ui->spinBoxStreamSize->setValue(*flow_max_packs);
  ui->spinBoxFlowAnomTh->setValue(*flow_limit);
  ui->checkBoxGenRuleFlow->setChecked(*flow_gen_rules);

  if (*tcp_ports == TCP_DROP_ALL_PORTS)
    ui->radioButtonBlockAll->setChecked(true);
  else if (*tcp_ports == TCP_DROP_SRC_PORT_ONLY)
    ui->radioButtonBlockOut->setChecked(true);
  else if (*tcp_ports == TCP_DROP_DEST_PORT_ONLY)
    ui->radioButtonBlockInc->setChecked(true);
}

AdsSettingsDialog::~AdsSettingsDialog() { delete ui; }

void AdsSettingsDialog::on_buttonBox_accepted() {
  // sem_settings_tcp->wait();

  *tcp_depth = ui->spinBoxDepth->value();
  *tcp_limit = ui->spinBoxAnomalyThr->value();
  *tcp_gen_rules = ui->checkBoxTCPGenRule->isChecked();

  *flow_gen_rules = ui->checkBoxGenRuleFlow->isChecked();
  *flow_limit = ui->spinBoxFlowAnomTh->value();
  *flow_max_packs = ui->spinBoxStreamSize->value();

  if (ui->radioButtonBlockAll->isChecked())
    *tcp_ports = TCP_DROP_ALL_PORTS;
  else if (ui->radioButtonBlockOut->isChecked())
    *tcp_ports = TCP_DROP_SRC_PORT_ONLY;
  if (ui->radioButtonBlockInc->isChecked())
    *tcp_ports = TCP_DROP_DEST_PORT_ONLY;

  // sem_settings_tcp->post();
}
