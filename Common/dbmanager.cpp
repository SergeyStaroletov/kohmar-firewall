/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "dbmanager.h"

DbManager::DbManager() {}

void DbManager::addToDb(Rule *r) {
#ifndef ADS_DAEMON
  QMessageBox msgBox;
#endif // ADS_DAEMON

  QSqlDatabase dBase;

  try {
    dBase = QSqlDatabase::addDatabase("QSQLITE");
    dBase.setDatabaseName("../Common/db_firewall.sqlite");

    if (!dBase.open()) {
#ifndef ADS_DAEMON
      msgBox.setText("Error connecting to database!");
      msgBox.exec();
#endif // ADS_DAEMON
      qDebug() << "Error connecting to database!";
      dBase.close();
      return;
    }

    // get data
    QSqlQuery query;
    QString sql = "INSERT INTO rule(in_out, ip_src, ip_dest, port_src, "
                  "port_dest, proto, action, src_name, dest_name) values('" +
                  QString::number(r->in_out) + "', '" + r->ip_src + "', '" +
                  r->ip_dest + "', '" + QString::number(r->port_src) + "', '" +
                  QString::number(r->port_dest) + "', '" +
                  QString::number(r->proto) + "', '" +
                  QString::number(r->action) + "', '" + r->host_name_src +
                  "', '" + r->host_name_dest + "')";

    // query.prepare(sql);
    // query.bindValue(":field1", QString::number(r->in_out));

    if (!query.exec(sql)) {
#ifndef ADS_DAEMON
      msgBox.setText("DB insert error!");
      msgBox.exec();
#endif // ADS_DAEMON
      qDebug() << "DB insert error!";
      dBase.close();
      // return;
    }

    r->id_rule = query.lastInsertId().toUInt();

    dBase.close();
  } catch (...) {
#ifndef ADS_DAEMON
    msgBox.setText("Error!");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "error1";
  }

  try {
    dBase.close();
  } catch (...) {
  }
}

void DbManager::removeFromDb(int id) {
#ifndef ADS_DAEMON
  QMessageBox msgBox;
  // msgBox.exec();
#endif // ADS_DAEMON

  QSqlDatabase dBase;

  try {
    qDebug() << "Remove from DB: id=" + QString::number(id);
    dBase = QSqlDatabase::addDatabase("QSQLITE");
    dBase.setDatabaseName("../Common/db_firewall.sqlite");

    if (!dBase.open()) {
#ifndef ADS_DAEMON
      msgBox.setText("Error connecting to database");
      msgBox.exec();
#endif // ADS_DAEMON
      qDebug() << "Error connecting to database!";
      dBase.close();
      return;
    }

    // get data
    QSqlQuery query;
    QString sql = "DELETE FROM rule WHERE id_rule=" + QString::number(id);

    if (!query.exec(sql)) {
#ifndef ADS_DAEMON
      msgBox.setText("Deletion error from database!");
      msgBox.exec();
#endif // ADS_DAEMON
      qDebug() << "Deletion error from database!";
      dBase.close();
      // return;
    }

    dBase.close();
  } catch (...) {
#ifndef ADS_DAEMON
    msgBox.setText("Error!");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "error2";
  }

  try {
    dBase.close();
  } catch (...) {
  }
}

void DbManager::updateInDb(Rule *r) {
#ifndef ADS_DAEMON
  QMessageBox msgBox;
  // msgBox.exec();
#endif // ADS_DAEMON

  QSqlDatabase dBase;

  try {
    qDebug() << "Update in DB: id=" + QString::number(r->id_rule);
    dBase = QSqlDatabase::addDatabase("QSQLITE");
    dBase.setDatabaseName("../Common/db_firewall.sqlite");

    if (!dBase.open()) {
#ifndef ADS_DAEMON
      msgBox.setText("Error connecting to database!");
      msgBox.exec();
#endif // ADS_DAEMON
      qDebug() << "Error connecting to database!";
      dBase.close();
      return;
    }

    // get data
    QSqlQuery query;
    QString sql = "UPDATE rule SET in_out='" + QString::number(r->in_out) +
                  "', ip_src='" + r->ip_src + "', ip_dest='" + r->ip_dest +
                  "', port_src='" + QString::number(r->port_src) +
                  "', port_dest='" + QString::number(r->port_dest) +
                  "', proto='" + QString::number(r->proto) + "', action='" +
                  QString::number(r->action) + "', src_name='" +
                  r->host_name_src + "', dest_name='" + r->host_name_dest +
                  "' WHERE id_rule='" + QString::number(r->id_rule) + "'";

    if (!query.exec(sql)) {
#ifndef ADS_DAEMON
      msgBox.setText("Database update error!");
      msgBox.exec();
#endif // ADS_DAEMON
      qDebug() << "Database update error!";
      dBase.close();
      // return;
    }

    dBase.close();
  } catch (...) {
#ifndef ADS_DAEMON
    msgBox.setText("Error!");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "error3";
  }

  try {
    dBase.close();
  } catch (...) {
  }
}

QList<Rule *> *DbManager::getRulesFromDb() {
  QList<Rule *> *user_rules = new QList<Rule *>();

  // connect to DB
  QSqlDatabase dBase;
  dBase = QSqlDatabase::addDatabase("QSQLITE");
  dBase.setDatabaseName("../Common/db_firewall.sqlite");

  if (!dBase.open()) {
#ifndef ADS_DAEMON
    QMessageBox msgBox;
    msgBox.setText("Error connecting to database!");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "Error connecting to database!";
    qApp->quit();
  }

  // get data
  QSqlQuery query;

  if (!query.exec("SELECT * FROM rule ORDER BY id_rule DESC")) {
#ifndef ADS_DAEMON
    QMessageBox msgBox;
    msgBox.setText("Database read error!");
    msgBox.exec();
#endif // ADS_DAEMON
    qDebug() << "Database read error!";
    qApp->quit();
  }

  QSqlRecord rec = query.record();

  int id_rule, in_out, proto, action, port_dest, port_src;
  QString ip_src, ip_dest, src_name, dest_name;
  // QTableWidgetItem *idItem, *inOutItem, *ipSrcItem, *portSrcItem,
  // *ipDestItem, *portDestItem, *protoItem, *actItem;
  Rule *rule;

  // append to user_rules
  while (query.next()) {
    id_rule = query.value(rec.indexOf("id_rule")).toInt();
    in_out = query.value(rec.indexOf("in_out")).toUInt();
    ip_src = query.value(rec.indexOf("ip_src")).toString();
    port_src = query.value(rec.indexOf("port_src")).toInt();
    ip_dest = query.value(rec.indexOf("ip_dest")).toString();
    port_dest = query.value(rec.indexOf("port_dest")).toInt();
    proto = query.value(rec.indexOf("proto")).toUInt();
    action = query.value(rec.indexOf("action")).toUInt();
    src_name = query.value(rec.indexOf("src_name")).toString();
    dest_name = query.value(rec.indexOf("dest_name")).toString();

    if (src_name != "-" && dest_name != "-") {
      QList<QHostAddress> src_adrs = AdressResolver::resolve(src_name);
      QList<QHostAddress> dest_adrs = AdressResolver::resolve(dest_name);

      if (src_adrs.count() != 0 && dest_adrs.count() != 0) {
        foreach (const QHostAddress &src_address, src_adrs) {
          foreach (const QHostAddress &dest_address, dest_adrs) {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = dest_address.toString();
            rule->ip_src = src_address.toString();
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = dest_name;

            user_rules->append(rule);
          }
        }
      } else {
        if (src_adrs.count() == 0 && dest_adrs.count() != 0) {
          foreach (const QHostAddress &dest_address, dest_adrs) {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = dest_address.toString();
            rule->ip_src = ip_src;
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = dest_name;

            user_rules->append(rule);
          }
        } else {
          if (src_adrs.count() != 0 && dest_adrs.count() == 0) {
            foreach (const QHostAddress &src_address, src_adrs) {
              rule = new Rule;

              rule->id_rule = id_rule;
              rule->action = action;
              rule->in_out = in_out;
              rule->ip_dest = ip_dest;
              rule->ip_src = src_address.toString();
              rule->port_dest = port_dest;
              rule->port_src = port_src;
              rule->proto = proto;
              rule->host_name_src = src_name;
              rule->host_name_dest = dest_name;

              user_rules->append(rule);
            }
          } else {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = ip_dest;
            rule->ip_src = ip_src;
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = dest_name;

            user_rules->append(rule);
          }
        }
      }
    } else {
      if (src_name != "-") {
        QList<QHostAddress> src_adrs = AdressResolver::resolve(src_name);

        if (src_adrs.count() != 0) {
          foreach (const QHostAddress &src_address, src_adrs) {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = ip_dest;
            rule->ip_src = src_address.toString();
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_src = src_name;
            rule->host_name_dest = "-";

            user_rules->append(rule);
          }
        } else {
          rule = new Rule;

          rule->id_rule = id_rule;
          rule->action = action;
          rule->in_out = in_out;
          rule->ip_dest = ip_dest;
          rule->ip_src = ip_src;
          rule->port_dest = port_dest;
          rule->port_src = port_src;
          rule->proto = proto;
          rule->host_name_src = src_name;
          rule->host_name_dest = "-";

          user_rules->append(rule);
        }
      } else {
        if (dest_name != "-") {
          QList<QHostAddress> dest_adrs = AdressResolver::resolve(dest_name);

          if (dest_adrs.count() != 0) {
            foreach (const QHostAddress &dest_address, dest_adrs) {
              rule = new Rule;

              rule->id_rule = id_rule;
              rule->action = action;
              rule->in_out = in_out;
              rule->ip_dest = dest_address.toString();
              rule->ip_src = ip_src;
              rule->port_dest = port_dest;
              rule->port_src = port_src;
              rule->proto = proto;
              rule->host_name_dest = dest_name;
              rule->host_name_src = "-";

              user_rules->append(rule);
            }
          } else {
            rule = new Rule;

            rule->id_rule = id_rule;
            rule->action = action;
            rule->in_out = in_out;
            rule->ip_dest = ip_dest;
            rule->ip_src = ip_src;
            rule->port_dest = port_dest;
            rule->port_src = port_src;
            rule->proto = proto;
            rule->host_name_dest = dest_name;
            rule->host_name_src = "-";

            user_rules->append(rule);
          }
        } else {
          rule = new Rule;

          rule->id_rule = id_rule;
          rule->in_out = in_out;
          rule->ip_src = ip_src;
          rule->port_src = port_src;
          rule->ip_dest = ip_dest;
          rule->port_dest = port_dest;
          rule->proto = proto;
          rule->action = action;
          rule->host_name_src = "-";
          rule->host_name_dest = "-";

          user_rules->append(rule);
        }
      }
    }

    // nlManager->sendRuleToKernel(rule);

    // count++;
  }

  dBase.close();

  return user_rules;
}
