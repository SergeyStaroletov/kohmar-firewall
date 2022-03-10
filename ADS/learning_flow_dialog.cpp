/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "learning_flow_dialog.h"
#include "ui_learning_flow_dialog.h"

LearningFlowDialog::LearningFlowDialog(QWidget *parent,
                                       PacksReceiver *_packs_receiver)
    : QDialog(parent), ui(new Ui::LearningFlowDialog) {
  ui->setupUi(this);

  ui->pushButton->setEnabled(true);
  ui->pushButton_2->setEnabled(false);
  ui->pushButton_3->setEnabled(false);

  packs_receiver = _packs_receiver;
  isLearn = false;
}

LearningFlowDialog::~LearningFlowDialog() { delete ui; }

void LearningFlowDialog::on_pushButton_clicked() {
  ui->pushButton->setEnabled(false);
  ui->pushButton_2->setEnabled(true);
  cur_anomaly_level = ui->horizontalSlider->value();
  isLearn = true;
  packs_receiver->setCurFlowAnomaly(cur_anomaly_level);
  packs_receiver->setIsLearnFlow(true);
}

void LearningFlowDialog::on_pushButton_2_clicked() {
  ui->pushButton_2->setEnabled(false);

  isLearn = false;
  packs_receiver->setIsLearnFlow(false);

  QList<SampleSom *> cur_samples =
      packs_receiver->getFlowLearningSamplesFromQueue();

  SampleSom *s;
  foreach (s, cur_samples) { samples.append(s); }

  packs_receiver->clearFlowLearningSamples();

  ui->pushButton->setEnabled(true);
  ui->pushButton_3->setEnabled(true);
}

void LearningFlowDialog::on_pushButton_3_clicked() {
  QMessageBox msgBox;
  bool retrain;
  char file_mode[2];

  if (ui->radioButton_5->isChecked()) {
    retrain = true;
    file_mode[0] = 'w';
  } else {
    retrain = false;
    file_mode[0] = 'a';
  }
  file_mode[1] = '\0';

  if (samples.count() == 0) {
    msgBox.setText("Null training set!");
    msgBox.exec();
    return;
  }

  int dim, i;
  FILE *file = fopen("flow.samples", file_mode);

  if (!file) {
    msgBox.setText("Unable to open the file for saving!");
    msgBox.exec();
    return;
  }

  dim = samples[0]->getDimension();

  if (retrain)
    fprintf(file, "%d\n\n", dim);

  SampleSom *s;
  foreach (s, samples) {
    fprintf(file, "%lf\n", s->getAnomaly());

    for (i = 0; i < dim; i++) {
      fprintf(file, "%lf\n", s->getKoeff(i));
    }

    fprintf(file, "\n");
    delete s;
  }

  fclose(file);

  msgBox.setText(
      "The training set has been saved!\nFor the changes to take effect, "
      "\nyou need to restart the program!");
  msgBox.exec();
  this->close();
}

void LearningFlowDialog::on_pushButton_4_clicked() {
  if (isLearn) {
    QMessageBox msgBox;
    msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Ok);
    msgBox.setText("We are training now! Do you really want to close?");
    int ret = msgBox.exec();

    switch (ret) {
    case QMessageBox::Cancel:
      return;
      break;
    case QMessageBox::Ok: {
      isLearn = false;
      packs_receiver->setIsLearnFlow(false);
      packs_receiver->clearFlowLearningSamples();
      this->close();
    } break;
    default:
      return;
    }
  } else
    this->close();
}

void LearningFlowDialog::on_horizontalSlider_valueChanged(int value) {
  ui->label_5->setText(QString::number(value));
}
