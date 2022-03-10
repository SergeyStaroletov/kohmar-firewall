/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef NEURON_H
#define NEURON_H

#include <QObject>

class Neuron : public QObject {
  Q_OBJECT

private:
  int dimension;
  double *koeffs;
  double anomaly;

public:
  explicit Neuron(int _dimension, QObject *parent = 0);
  bool setKoeffs(double *_koeffs);
  bool setKoeff(int index, double value);
  int getDimension();
  double *getKoeffs();
  double getKoeff(int index);
  void setAnomaly(double _anomaly);
  double getAnomaly();

signals:

public slots:
};

#endif // NEURON_H
