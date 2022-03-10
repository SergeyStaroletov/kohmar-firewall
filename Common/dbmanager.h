/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef DBMANAGER_H
#define DBMANAGER_H

#ifndef ADS_DAEMON
#include <QMessageBox>
#endif // ADS_DAEMON

#include "QtSql"
#include "adressresolver.h"
#include "structs.h"

class DbManager {
public:
  DbManager();
  static void addToDb(Rule *r);
  static void updateInDb(Rule *r);
  static void removeFromDb(int id);
  static QList<Rule *> *getRulesFromDb();
};

#endif // DBMANAGER_H
