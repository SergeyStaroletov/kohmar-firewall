/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef LEARNING_FLOW_DIALOG_H
#define LEARNING_FLOW_DIALOG_H

#include <QDialog>
#include <QMessageBox>

#include <stdio.h>

#include "../Common/packsreceiver.h"
#include "../Common/structs.h"

namespace Ui {
class LearningFlowDialog;
}

class LearningFlowDialog : public QDialog {
  Q_OBJECT

public:
  explicit LearningFlowDialog(QWidget *parent = 0,
                              PacksReceiver *_packs_receiver = 0);
  ~LearningFlowDialog();

private slots:
  void on_pushButton_clicked();
  void on_pushButton_2_clicked();
  void on_pushButton_3_clicked();
  void on_pushButton_4_clicked();
  void on_horizontalSlider_valueChanged(int value);

private:
  Ui::LearningFlowDialog *ui;

  bool isLearn;
  PacksReceiver *packs_receiver;
  int cur_anomaly_level;
  QList<SampleSom *> samples;
};

#endif // LEARNING_FLOW_DIALOG_H
