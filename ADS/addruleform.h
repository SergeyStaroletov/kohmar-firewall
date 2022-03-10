/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef ADDRULEFORM_H
#define ADDRULEFORM_H

#include "../Common/adressresolver.h"
#include "../Common/structs.h"
#include <QDialog>
#include <QHostInfo>
#include <QMessageBox>
#include <QUrl>
#include <arpa/inet.h>

namespace Ui {
class AddRuleForm;
}

class AddRuleForm : public QDialog {
  Q_OBJECT

public:
  explicit AddRuleForm(QWidget *parent = 0, QList<Rule *> *_list = NULL,
                       Rule *_rule = NULL);
  ~AddRuleForm();

  bool okay_flag;

private slots:
  void on_pushButtonOk_clicked();
  void on_pushButtonCancel_clicked();
  void on_checkBoxSrcAdrAny_clicked();
  void on_checkBoxDstAAny_clicked();
  void on_checkBoxSrcPortAny_clicked();
  void on_checkBoxDstPortAny_clicked();

private:
  Ui::AddRuleForm *ui;
  bool flag_add_edit;
  Rule *rule;
  QList<Rule *> *rList;
};

#endif // ADDRULEFORM_H
