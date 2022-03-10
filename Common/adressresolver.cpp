/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "adressresolver.h"

AdressResolver::AdressResolver() {}

QList<QHostAddress> AdressResolver::resolve(QString hostName) {
  QHostInfo hInfo = QHostInfo::fromName(hostName);
  QList<QHostAddress> adrs = hInfo.addresses();
  return adrs;
}
