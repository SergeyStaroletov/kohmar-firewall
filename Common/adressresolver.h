/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef ADRESSRESOLVER_H
#define ADRESSRESOLVER_H

#include <QHostInfo>
#include <QList>
#include <QString>
#include <QStringList>

class AdressResolver {
public:
  AdressResolver();
  static QList<QHostAddress> resolve(QString hostName);
};

#endif // ADRESSRESOLVER_H
