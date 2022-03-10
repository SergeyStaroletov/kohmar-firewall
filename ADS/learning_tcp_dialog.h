/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef LEARNING_TCP_DIALOG_H
#define LEARNING_TCP_DIALOG_H

#include <QDialog>
#include <QMessageBox>

#include "../Common/packsreceiver.h"
#include "../Common/structs.h"

namespace Ui {
class LearningTcpDialog;
}

class LearningTcpDialog : public QDialog {
  Q_OBJECT

public:
  explicit LearningTcpDialog(QWidget *parent = 0,
                             PacksReceiver *_packs_receiver = 0);
  ~LearningTcpDialog();

private slots:
  void on_pushButton_clicked();
  void on_pushButton_2_clicked();
  void on_pushButton_3_clicked();

private:
  Ui::LearningTcpDialog *ui;
  int learned_protocol;
  bool isLearn;
  PacksReceiver *packs_receiver;

  void closeEvent(QCloseEvent *event);
};

#endif // LEARNING_TCP_DIALOG_H
