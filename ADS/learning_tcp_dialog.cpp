/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "learning_tcp_dialog.h"
#include "ui_learning_tcp_dialog.h"

LearningTcpDialog::LearningTcpDialog(QWidget *parent,
                                     PacksReceiver *_packs_receiver)
    : QDialog(parent), ui(new Ui::LearningTcpDialog) {
  ui->setupUi(this);
  ui->pushButton->setEnabled(true);
  ui->pushButton_2->setEnabled(false);

  packs_receiver = _packs_receiver;
  isLearn = false;
}

LearningTcpDialog::~LearningTcpDialog() { delete ui; }

void LearningTcpDialog::on_pushButton_clicked() {
  ui->pushButton->setEnabled(false);
  ui->pushButton_2->setEnabled(true);

  if (ui->radioButton->isChecked())
    learned_protocol = LEARN_HTTP;

  if (ui->radioButton_2->isChecked())
    learned_protocol = LEARN_FTP;

  if (ui->radioButton_3->isChecked())
    learned_protocol = LEARN_SSH;

  if (ui->radioButton_4->isChecked())
    learned_protocol = LEARN_ALL;

  if (isLearn == false) {
    isLearn = true;
    packs_receiver->setIsLearnTcp(true, learned_protocol);
  } else {
  }
}

void LearningTcpDialog::on_pushButton_2_clicked() {
  QMessageBox msgBox;
  int max_len = 0;
  // bool retrain = false;
  char file_mode[2];

  isLearn = false;
  packs_receiver->setIsLearnTcp(false, learned_protocol);
  QList<char *> strings =
      packs_receiver->getLerningStrings(learned_protocol, &max_len);
  char *tn;

  if (ui->radioButton_5->isChecked()) {
    // retrain = true;
    file_mode[0] = 'w';
  } else {
    // retrain = false;
    file_mode[0] = 'a';
  }
  file_mode[1] = '\0';

  if (max_len) {
    char file_name[15];

    if (learned_protocol == LEARN_HTTP) {
      strcpy(file_name, "http.samples");
    } else if (learned_protocol == LEARN_FTP) {
      strcpy(file_name, "ftp.samples");
    } else if (learned_protocol == LEARN_SSH) {
      strcpy(file_name, "ssh.samples");
    } else if (learned_protocol == LEARN_ALL) {
      strcpy(file_name, "common.samples");
    }

    FILE *file = fopen(file_name, file_mode); //"w"

    if (!file) {
      qDebug() << "Error! File not opened!";
      msgBox.setText("The file to save the results is not open!");
      msgBox.exec();
      return;
    }

    // if(retrain)
    // fprintf(file, "%d\n", max_len+1);

    foreach (tn, strings) {
      qDebug() << tn;
      fprintf(file, "%s\n", tn);
    }

    fclose(file);
  } else {
    qDebug() << "max_len=0";
    msgBox.setText("The training sample was not formed!");
    msgBox.exec();
  }

  ui->pushButton_2->setEnabled(false);
  ui->pushButton->setEnabled(true);

  msgBox.setText("The training sample has been formed!\nFor the changes to "
                 "take effect,\nyou need to restart the program!");
  msgBox.exec();
  this->close();
}

void LearningTcpDialog::closeEvent(QCloseEvent *event) {
  (void)event;

  if (this->isLearn)
    return;
}

void LearningTcpDialog::on_pushButton_3_clicked() {
  if (isLearn) {
    QMessageBox msgBox;
    msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Ok);
    msgBox.setText("We are training! Do you really want to close?");
    int ret = msgBox.exec();

    switch (ret) {
    case QMessageBox::Cancel:
      return;
      break;
    case QMessageBox::Ok: {
      isLearn = false;
      packs_receiver->setIsLearnTcp(false, learned_protocol);
      packs_receiver->clearLearningStrings();
      this->close();
    } break;
    default:
      return;
    }
  } else
    this->close();
}
