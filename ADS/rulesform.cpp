/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "rulesform.h"
#include "ui_rulesform.h"

RulesForm::RulesForm(QWidget *parent, QList<Rule *> *_user_rules,
                     QList<Rule *> *_dyn_rules, NetLinkManager *mng,
                     UnixSemaphore *_sem_dyn_rules)
    : QWidget(parent), ui(new Ui::RulesForm) {
  ui->setupUi(this);
  ui->tableWidget->setColumnWidth(2, 140);
  ui->tableWidget->setColumnWidth(3, 120);
  ui->tableWidget->setColumnWidth(4, 140);
  ui->tableWidget->setColumnWidth(5, 120);
  ui->tableWidget->setColumnWidth(8, 145);
  ui->tableWidget->setColumnWidth(9, 145);
  ui->tableWidget_2->setColumnWidth(3, 120);
  ui->tableWidget_2->setColumnWidth(5, 120);
  ui->tableWidget_2->setColumnWidth(8, 145);
  ui->tableWidget_2->setColumnWidth(9, 145);

  user_rules = _user_rules;
  dynamic_rules = _dyn_rules;

  nlManager = mng;
  sem_dyn_rules = _sem_dyn_rules;

  ui->tableWidget->setColumnHidden(0, true);
  // ui->tableWidget_2->setColumnHidden(0, true);

  fillUserGrid();
  fillDynamicGrid();
}

RulesForm::~RulesForm() { delete ui; }

void RulesForm::fillUserGrid() {
  QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem, *ipDestItem,
      *portDestItem, *protoItem, *actItem, *hostNameSrc, *hostNameDest;
  int count = 0;
  Rule *r;

  foreach (r, *user_rules) {
    idItem = new QTableWidgetItem();
    inOutItem = new QTableWidgetItem();
    ipSrcItem = new QTableWidgetItem();
    portSrcItem = new QTableWidgetItem();
    ipDestItem = new QTableWidgetItem();
    portDestItem = new QTableWidgetItem();
    protoItem = new QTableWidgetItem();
    actItem = new QTableWidgetItem();
    hostNameSrc = new QTableWidgetItem();
    hostNameDest = new QTableWidgetItem();

    idItem->setText(QString::number(r->id_rule));

    if (r->in_out == 1)
      inOutItem->setText("Input");
    else
      inOutItem->setText("Output");

    if (r->ip_src == "-")
      ipSrcItem->setText("Any");
    else
      ipSrcItem->setText(r->ip_src);

    if (r->port_src == -1)
      portSrcItem->setText("Any");
    else
      portSrcItem->setText(QString::number(r->port_src));

    if (r->ip_dest == "-")
      ipDestItem->setText("Any");
    else
      ipDestItem->setText(r->ip_dest);

    if (r->port_dest == -1)
      portDestItem->setText("Any");
    else
      portDestItem->setText(QString::number(r->port_dest));

    switch (r->proto) {
    case 0: {
      protoItem->setText("Any");
    } break;
    case 1: {
      protoItem->setText("TCP");
    } break;
    case 2: {
      protoItem->setText("UDP");
    } break;
    case 3: {
      protoItem->setText("ICMP");
    } break;
    default:
      break;
    }

    if (r->action == 0)
      actItem->setText("Deny");
    else
      actItem->setText("Accept");

    hostNameSrc->setText(r->host_name_src);
    hostNameDest->setText(r->host_name_dest);

    ui->tableWidget->insertRow(count);
    ui->tableWidget->setItem(count, 0, idItem);
    ui->tableWidget->setItem(count, 1, inOutItem);
    ui->tableWidget->setItem(count, 2, ipSrcItem);
    ui->tableWidget->setItem(count, 3, portSrcItem);
    ui->tableWidget->setItem(count, 4, ipDestItem);
    ui->tableWidget->setItem(count, 5, portDestItem);
    ui->tableWidget->setItem(count, 6, protoItem);
    ui->tableWidget->setItem(count, 7, actItem);
    ui->tableWidget->setItem(count, 8, hostNameSrc);
    ui->tableWidget->setItem(count, 9, hostNameDest);
  }
}

void RulesForm::fillDynamicGrid() {
  QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem, *ipDestItem,
      *portDestItem, *protoItem, *actItem, *hostNameSrc, *hostNameDest;
  int count = 0;
  Rule *r;

  sem_dyn_rules->wait();

  foreach (r, *dynamic_rules) {
    idItem = new QTableWidgetItem();
    inOutItem = new QTableWidgetItem();
    ipSrcItem = new QTableWidgetItem();
    portSrcItem = new QTableWidgetItem();
    ipDestItem = new QTableWidgetItem();
    portDestItem = new QTableWidgetItem();
    protoItem = new QTableWidgetItem();
    actItem = new QTableWidgetItem();
    hostNameSrc = new QTableWidgetItem();
    hostNameDest = new QTableWidgetItem();

    idItem->setText(QString::number(-1 * (r->id_rule)));

    if (r->in_out == 1)
      inOutItem->setText("Input");
    else
      inOutItem->setText("Output");

    if (r->ip_src == "-")
      ipSrcItem->setText("Any");
    else
      ipSrcItem->setText(r->ip_src);

    if (r->port_src == -1)
      portSrcItem->setText("Any");
    else
      portSrcItem->setText(QString::number(r->port_src));

    if (r->ip_dest == "-")
      ipDestItem->setText("Any");
    else
      ipDestItem->setText(r->ip_dest);

    if (r->port_dest == -1)
      portDestItem->setText("Any");
    else
      portDestItem->setText(QString::number(r->port_dest));

    switch (r->proto) {
    case 0: {
      protoItem->setText("Any");
    } break;
    case 1: {
      protoItem->setText("TCP");
    } break;
    case 2: {
      protoItem->setText("UDP");
    } break;
    case 3: {
      protoItem->setText("ICMP");
    } break;
    default:
      break;
    }

    if (r->action == 0)
      actItem->setText("Deny");
    else
      actItem->setText("Accept");

    hostNameSrc->setText(r->host_name_src);
    hostNameDest->setText(r->host_name_dest);

    ui->tableWidget_2->insertRow(count);
    ui->tableWidget_2->setItem(count, 0, idItem);
    ui->tableWidget_2->setItem(count, 1, inOutItem);
    ui->tableWidget_2->setItem(count, 2, ipSrcItem);
    ui->tableWidget_2->setItem(count, 3, portSrcItem);
    ui->tableWidget_2->setItem(count, 4, ipDestItem);
    ui->tableWidget_2->setItem(count, 5, portDestItem);
    ui->tableWidget_2->setItem(count, 6, protoItem);
    ui->tableWidget_2->setItem(count, 7, actItem);
    ui->tableWidget_2->setItem(count, 8, hostNameSrc);
    ui->tableWidget_2->setItem(count, 9, hostNameDest);
  }

  sem_dyn_rules->post();
}

void RulesForm::addToGrid(Rule *r) {
  QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem, *ipDestItem,
      *portDestItem, *protoItem, *actItem, *hostNameSrc, *hostNameDest;
  int count = ui->tableWidget->rowCount();

  idItem = new QTableWidgetItem();
  inOutItem = new QTableWidgetItem();
  ipSrcItem = new QTableWidgetItem();
  portSrcItem = new QTableWidgetItem();
  ipDestItem = new QTableWidgetItem();
  portDestItem = new QTableWidgetItem();
  protoItem = new QTableWidgetItem();
  actItem = new QTableWidgetItem();
  hostNameSrc = new QTableWidgetItem();
  hostNameDest = new QTableWidgetItem();

  idItem->setText(QString::number(r->id_rule));

  if (r->in_out == 1)
    inOutItem->setText("Input");
  else
    inOutItem->setText("Output");

  // ipSrcItem->setText(r->ip_src);
  if (r->ip_src == "-")
    ipSrcItem->setText("Any");
  else
    ipSrcItem->setText(r->ip_src);

  if (r->port_src == -1)
    portSrcItem->setText("Any");
  else
    portSrcItem->setText(QString::number(r->port_src));

  // ipDestItem->setText(r->ip_dest);
  if (r->ip_dest == "-")
    ipDestItem->setText("Any");
  else
    ipDestItem->setText(r->ip_dest);

  if (r->port_dest == -1)
    portDestItem->setText("Any");
  else
    portDestItem->setText(QString::number(r->port_dest));

  switch (r->proto) {
  case 0: {
    protoItem->setText("Any");
  } break;
  case 1: {
    protoItem->setText("TCP");
  } break;
  case 2: {
    protoItem->setText("UDP");
  } break;
  case 3: {
    protoItem->setText("ICMP");
  } break;
  default:
    break;
  }

  if (r->action == 0)
    actItem->setText("Deny");
  else
    actItem->setText("Accept");

  hostNameSrc->setText(r->host_name_src);
  hostNameDest->setText(r->host_name_dest);

  ui->tableWidget->insertRow(count);
  ui->tableWidget->setItem(count, 0, idItem);
  ui->tableWidget->setItem(count, 1, inOutItem);
  ui->tableWidget->setItem(count, 2, ipSrcItem);
  ui->tableWidget->setItem(count, 3, portSrcItem);
  ui->tableWidget->setItem(count, 4, ipDestItem);
  ui->tableWidget->setItem(count, 5, portDestItem);
  ui->tableWidget->setItem(count, 6, protoItem);
  ui->tableWidget->setItem(count, 7, actItem);
  ui->tableWidget->setItem(count, 8, hostNameSrc);
  ui->tableWidget->setItem(count, 9, hostNameDest);
}

void RulesForm::on_pushButton_clicked() {
  QList<Rule *> *list = new QList<Rule *>();

  // Rule * rule_new = new Rule;
  // rule_new->ip_src = "-1";

  AddRuleForm *form = new AddRuleForm(0, list, NULL);
  form->setWindowFlags(((form->windowFlags() | Qt::CustomizeWindowHint) &
                        ~Qt::WindowMaximizeButtonHint));
  form->setFixedSize(form->size());
  form->setModal(true);
  form->exec();

  if (form->okay_flag) {
    Rule *rule_new = new Rule;

    foreach (rule_new, *list) {
      if (!isExist(rule_new)) {
        DbManager::addToDb(rule_new);
        addToGrid(rule_new);
        nlManager->sendRuleToKernel(rule_new);
        user_rules->append(rule_new);
      } else {
        qDebug() << "rule already exist!";
        QMessageBox msgBox;
        msgBox.setText("The rule already exists!");
        msgBox.exec();
      }
    }
  } else {
    delete list;
  }
}

void RulesForm::on_pushButton_2_clicked() {
  qDebug() << "EDITING";
  int cur_row = ui->tableWidget->currentRow();

  if (cur_row >= 0) {

    QString id_str = ui->tableWidget->item(cur_row, 0)->text();

    int id = id_str.toInt();

    Rule *rr;
    Rule *rule_to_edit = nullptr;

    // Rule copy = *rule_to_edit;

    foreach (rr, *user_rules) {
      if (rr->id_rule == id) {
        rule_to_edit = rr;
        break;
      }
    }

    if (!rule_to_edit)
      return;

    AddRuleForm *form = new AddRuleForm(0, NULL, rule_to_edit);
    form->setWindowFlags(((form->windowFlags() | Qt::CustomizeWindowHint) &
                          ~Qt::WindowMaximizeButtonHint));
    form->setFixedSize(form->size());
    form->setModal(true);
    form->exec();

    if (form->okay_flag) {
      if (!isExist(rule_to_edit)) {
        DbManager::updateInDb(rule_to_edit);
        updateInGrid(cur_row, rule_to_edit);
        //---nlManager->updateRuleInKernel(rule_to_edit);
        nlManager->deleteRuleFromKernel(rule_to_edit);
        nlManager->sendRuleToKernel(rule_to_edit);
      } else {
        qDebug() << "rule already exist!";
        QMessageBox msgBox;
        msgBox.setText("The rule already exists!");
        msgBox.exec();

        form->exec();

        //*rule_to_edit = copy;
      }
    }
  }
}

void RulesForm::on_pushButton_3_clicked() {
  qDebug() << "DELETING";
  int cur_row = ui->tableWidget->currentRow();

  if (cur_row >= 0) {
    QMessageBox msgBox;
    msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Ok);
    msgBox.setText("Are you sure to delete the rule #" +
                   QString::number(cur_row + 1) + "?");
    int ret = msgBox.exec();

    switch (ret) {
    case QMessageBox::Cancel:
      return;
      break;
    case QMessageBox::Ok: {

      QString id_str = ui->tableWidget->item(cur_row, 0)->text();
      int id = id_str.toInt();

      qDebug() << "DELETE OK";

      Rule *rr, *r;

      foreach (rr, *user_rules) {
        if (rr->id_rule == id) {
          r = rr;
          break;
        }
      }

      DbManager::removeFromDb(r->id_rule);
      nlManager->deleteRuleFromKernel(r);

      ui->tableWidget->removeRow(cur_row);

      // user_rules->removeAt(remove_ind);
      user_rules->removeOne(r);
    } break;
    default:
      break;
    }
  }
}

void RulesForm::updateInGrid(int row, Rule *r) {
  if (r->ip_dest == "-")
    ui->tableWidget->item(row, 4)->setText("Any");
  else
    ui->tableWidget->item(row, 4)->setText(r->ip_dest);

  if (r->ip_src == "-")
    ui->tableWidget->item(row, 2)->setText("Any");
  else
    ui->tableWidget->item(row, 2)->setText(r->ip_src);

  ui->tableWidget->item(row, 8)->setText(r->host_name_src);
  ui->tableWidget->item(row, 9)->setText(r->host_name_dest);
  // ui->tableWidget->item(row, 1)->setText(QString::number(r->in_out));
  // ui->tableWidget->item(row, 3)->setText(QString::number(r->port_src));
  // ui->tableWidget->item(row, 5)->setText(QString::number(r->port_dest));
  // ui->tableWidget->item(row, 6)->setText(QString::number(r->proto));
  // ui->tableWidget->item(row, 7)->setText(QString::number(r->action));

  if (r->in_out == 1)
    ui->tableWidget->item(row, 1)->setText("Input");
  else
    ui->tableWidget->item(row, 1)->setText("Output");

  if (r->port_src == -1)
    ui->tableWidget->item(row, 3)->setText("Any");
  else
    ui->tableWidget->item(row, 3)->setText(QString::number(r->port_src));

  if (r->port_dest == -1)
    ui->tableWidget->item(row, 5)->setText("Any");
  else
    ui->tableWidget->item(row, 5)->setText(QString::number(r->port_dest));

  switch (r->proto) {
  case 0: {
    ui->tableWidget->item(row, 6)->setText("Any");
  } break;
  case 1: {
    ui->tableWidget->item(row, 6)->setText("TCP");
  } break;
  case 2: {
    ui->tableWidget->item(row, 6)->setText("UDP");
  } break;
  case 3: {
    ui->tableWidget->item(row, 6)->setText("ICMP");
  } break;
  default:
    break;
  }

  if (r->action == 0)
    ui->tableWidget->item(row, 7)->setText("Deny");
  else
    ui->tableWidget->item(row, 7)->setText("Accept");
}

bool RulesForm::isExist(Rule *toCheck) {
  Rule *r = new Rule;
  bool res = false;

  foreach (r, *user_rules) {
    if (r->action == toCheck->action)
      if (r->in_out == toCheck->in_out)
        if (r->ip_dest == toCheck->ip_dest)
          if (r->ip_src == toCheck->ip_src)
            if (r->port_dest == toCheck->port_dest)
              if (r->port_src == toCheck->port_src)
                if (r->proto == toCheck->proto)
                  if (r->id_rule != toCheck->id_rule) {
                    res = true;
                    break;
                  }
  }

  return res;
}

void RulesForm::on_pushButton_5_clicked() {}

void RulesForm::on_pushButton_6_clicked() {
  int cur_row = ui->tableWidget_2->currentRow();

  if (cur_row >= 0) {
    QMessageBox msgBox;
    msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Ok);
    msgBox.setText("Are you sure to delete the rule #" +
                   QString::number(cur_row + 1) + "?");
    int ret = msgBox.exec();

    switch (ret) {
    case QMessageBox::Cancel:
      return;
      break;
    case QMessageBox::Ok: {

      QString id_str = ui->tableWidget_2->item(cur_row, 0)->text();
      int id = id_str.toInt();
      id *= -1;

      // msgBox.setText(id);
      // msgBox.exec();

      Rule *rr, *r;

      foreach (rr, *dynamic_rules) {
        if (rr->id_rule == id) {
          r = rr;
          break;
        }
      }

      if (r) {
        nlManager->deleteRuleFromKernel(r);

        ui->tableWidget_2->removeRow(cur_row);

        sem_dyn_rules->wait();
        dynamic_rules->removeOne(r);
        sem_dyn_rules->post();
      }
    } break;
    default:
      break;
    }
  }
}
