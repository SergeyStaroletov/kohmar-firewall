/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "addruleform.h"
#include "ui_addruleform.h"

AddRuleForm::AddRuleForm(QWidget *parent, QList<Rule *> *_list, Rule *_rule)
    : QDialog(parent), ui(new Ui::AddRuleForm) {
  ui->setupUi(this);

  rule = _rule;
  rList = _list;
  okay_flag = false;

  if (rule == NULL /*rule->ip_src == "-1"*/) {
    this->setWindowTitle("Add a rule");
    flag_add_edit = true;
  } else {
    this->setWindowTitle("Modify a rule");
    flag_add_edit = false;

    if (rule->in_out == 1)
      ui->comboBoxTrafficType->setCurrentIndex(0);
    else
      ui->comboBoxTrafficType->setCurrentIndex(1);

    if (rule->ip_src != "-") {
      ui->lineEditSrcAddr->setText(rule->ip_src);
      ui->checkBoxSrcAdrAny->setChecked(false);
    } else {
      ui->lineEditSrcAddr->setEnabled(false);
      ui->checkBoxSrcAdrAny->setChecked(true);
    }

    if (rule->ip_dest != "-") {
      ui->lineEditDstAddr->setText(rule->ip_dest);
      ui->checkBoxDstAAny->setChecked(false);
    } else {
      ui->lineEditDstAddr->setEnabled(false);
      ui->checkBoxDstAAny->setChecked(true);
    }

    if (rule->port_src != -1) {
      ui->spinBoxSrcPort->setValue(rule->port_src);
      ui->checkBoxSrcPortAny->setChecked(false);
    } else {
      ui->spinBoxSrcPort->setEnabled(false);
      ui->checkBoxSrcPortAny->setChecked(true);
    }

    if (rule->port_dest != -1) {
      ui->spinBoxDstPort->setValue(rule->port_dest);
      ui->checkBoxDstPortAny->setChecked(false);
    } else {
      ui->spinBoxDstPort->setEnabled(false);
      ui->checkBoxDstPortAny->setChecked(true);
    }

    ui->comboBoxProtocol->setCurrentIndex(rule->proto);
    ui->comboBoxAction->setCurrentIndex(rule->action);
  }
}

AddRuleForm::~AddRuleForm() { delete ui; }

void AddRuleForm::on_pushButtonOk_clicked() {
  QMessageBox msg;
  // QUrl url;
  QList<QHostAddress> src_adrs;
  QList<QHostAddress> dest_adrs;
  bool srcIsName = false;
  bool destIsName = false;

  unsigned int in_out;
  QString ip_src;
  QString ip_dest;
  int port_src;
  int port_dest;
  unsigned int proto;
  unsigned int action;

  int result;
  struct sockaddr_in sa;

  if (ui->comboBoxTrafficType->currentIndex() == 0)
    in_out = 1;
  else
    in_out = 2;

  if (ui->checkBoxSrcPortAny->isChecked())
    port_src = -1;
  else
    port_src = ui->spinBoxSrcPort->value();

  if (ui->checkBoxDstPortAny->isChecked())
    port_dest = -1;
  else
    port_dest = ui->spinBoxDstPort->value();

  proto = ui->comboBoxProtocol->currentIndex();

  action = ui->comboBoxAction->currentIndex();

  if (ui->checkBoxSrcAdrAny->isChecked())
    ip_src = "-";
  else
    ip_src = ui->lineEditSrcAddr->text().trimmed();

  if (ui->checkBoxDstAAny->isChecked())
    ip_dest = "-";
  else
    ip_dest = ui->lineEditDstAddr->text().trimmed();

  if (ip_src != "-") {
    result = inet_pton(AF_INET, ip_src.toUtf8().data(), &(sa.sin_addr));

    if (!result) {
      if (rule == NULL) {
        QUrl url = QUrl::fromUserInput(ip_src);

        if (url == QUrl()) {
          msg.setText("Source address is incorrect!");
          msg.exec();
          return;
        } else {
          src_adrs = AdressResolver::resolve(ip_src);

          if (src_adrs.count()) {
            srcIsName = true;
          } else {
            msg.setText("Source address: no such address!");
            msg.exec();
            return;
          }
        }
      } else {
        msg.setText("Source IP specified is incorrect! (when changing, only "
                    "the IP address can be specified)");
        msg.exec();
        return;
      }
    }
  }

  if (ip_dest != "-") {
    result = inet_pton(AF_INET, ip_dest.toUtf8().data(), &(sa.sin_addr));

    if (!result) {
      if (rule == NULL) {
        QUrl url = QUrl::fromUserInput(ip_dest);

        if (url == QUrl()) {
          msg.setText("Dst address is incorrect!");
          msg.exec();
          return;
        } else {
          dest_adrs = AdressResolver::resolve(ip_dest);

          if (dest_adrs.count()) {
            destIsName = true;
          } else {
            msg.setText("Dst address: no such address!");
            msg.exec();
            return;
          }
        }
      } else {
        msg.setText("Dst IP specified is incorrect! (when changing, only the "
                    "IP address can be specified)");
        msg.exec();
        return;
      }
    }
  }

  if (rule != NULL) {
    rule->action = action;
    rule->in_out = in_out;
    rule->ip_dest = ip_dest;
    rule->ip_src = ip_src;
    rule->port_dest = port_dest;
    rule->port_src = port_src;
    rule->proto = proto;
  } else {
    if (srcIsName && destIsName) {
      foreach (const QHostAddress &src_address, src_adrs) {
        foreach (const QHostAddress &dest_address, dest_adrs) {
          rule = new Rule;

          rule->action = action;
          rule->in_out = in_out;
          rule->ip_dest = dest_address.toString();
          rule->ip_src = src_address.toString();
          rule->port_dest = port_dest;
          rule->port_src = port_src;
          rule->proto = proto;
          rule->host_name_src = ip_src;
          rule->host_name_dest = ip_dest;

          rList->append(rule);
        }
      }
    } else {
      if (srcIsName) {
        foreach (const QHostAddress &src_address, src_adrs) {
          rule = new Rule;

          rule->action = action;
          rule->in_out = in_out;
          rule->ip_dest = ip_dest;
          rule->ip_src = src_address.toString();
          rule->port_dest = port_dest;
          rule->port_src = port_src;
          rule->proto = proto;
          rule->host_name_src = ip_src;
          rule->host_name_dest = "-";

          rList->append(rule);
        }
      } else {
        if (destIsName) {
          foreach (const QHostAddress &dest_address, dest_adrs) {
            rule = new Rule;

            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = dest_address.toString();
            rule->ip_src = ip_src;
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_dest = ip_dest;
            rule->host_name_src = "-";

            rList->append(rule);
          }
        } else {
          rule = new Rule;

          rule->action = action;
          rule->in_out = in_out;
          rule->ip_dest = ip_dest;
          rule->ip_src = ip_src;
          rule->port_dest = port_dest;
          rule->port_src = port_src;
          rule->proto = proto;
          rule->host_name_src = "-";
          rule->host_name_dest = "-";

          rList->append(rule);
        }
      }
    }
  }

  this->setResult(1);
  this->accept();
  okay_flag = true;
  this->close();
}

void AddRuleForm::on_pushButtonCancel_clicked() {
  this->setResult(0);
  this->reject();
  okay_flag = false;
  this->close();
}

void AddRuleForm::on_checkBoxSrcAdrAny_clicked() {
  if (ui->checkBoxSrcAdrAny->isChecked())
    ui->lineEditSrcAddr->setEnabled(false);
  else
    ui->lineEditSrcAddr->setEnabled(true);
}

void AddRuleForm::on_checkBoxDstAAny_clicked() {
  if (ui->checkBoxDstAAny->isChecked())
    ui->lineEditDstAddr->setEnabled(false);
  else
    ui->lineEditDstAddr->setEnabled(true);
}

void AddRuleForm::on_checkBoxSrcPortAny_clicked() {
  if (ui->checkBoxSrcPortAny->isChecked())
    ui->spinBoxSrcPort->setEnabled(false);
  else
    ui->spinBoxSrcPort->setEnabled(true);
}

void AddRuleForm::on_checkBoxDstPortAny_clicked() {
  if (ui->checkBoxDstPortAny->isChecked())
    ui->spinBoxDstPort->setEnabled(false);
  else
    ui->spinBoxDstPort->setEnabled(true);
}
