/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef SELFORGANIZEDMAP_H
#define SELFORGANIZEDMAP_H

#include "neuron.h"
#include "samplesom.h"
#include <QObject>
#include <qmath.h>

class SelfOrganizedMap : public QObject {
  Q_OBJECT
private:
  int N;
  int M;
  int dimension;
  int Iters;
  double R;
  double G;
  double lambda;
  double eta;
  QList<Neuron *> network;
  QList<SampleSom *> *samples;

public:
  explicit SelfOrganizedMap(int n, int m, int _dimension, int _Iters = 100,
                            double _R = 2, double _G = 2, double _lambda = 2,
                            double _eta = 2, QObject *parent = 0);
  void learn(QList<SampleSom *> *_samples);
  int recognize(SampleSom *sample);
  Neuron *getNeuron(int i, int j);
  int getN() { return N; }
  int getM() { return M; }

private:
  int getWinnerFor(SampleSom *sample);
  double distance(SampleSom *x1, Neuron *x2);
  double distanceNeurons(int a, int b);

signals:

public slots:
};

#endif // SELFORGANIZEDMAP_H
