/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "selforganizedmap.h"

SelfOrganizedMap::SelfOrganizedMap(int n, int m, int _dimension, int _Iters,
                                   double _R, double _G, double _lambda,
                                   double _eta, QObject *parent)
    : QObject(parent) {
  dimension = _dimension;
  Iters = _Iters;
  R = _R;
  G = _G;
  lambda = _lambda;
  eta = _eta;
  N = n;
  M = m;

  for (int i = 0; i < N * M; i++)
    network.append(new Neuron(dimension));
}

void SelfOrganizedMap::learn(QList<SampleSom *> *_samples) {
  int winner;
  double etaMin;
  double etaMax;
  double rMin;
  double rMax;

  etaMin = 0.2;
  etaMax = 0.9;
  rMin = 1;
  rMax = 3;

  samples = _samples;

  for (int iter = 0; iter < Iters; iter++) {
    for (int i = 0; i < samples->count(); i++) {
      // get Winner
      winner = getWinnerFor(samples->at(i));
      // modif neurons
      double d0 = distance(
          samples->at(i),
          network[winner]); // distance from the winning neuron to the image
      double d;

      for (int n = 0; n < N * M; n++) {
        if (distanceNeurons(
                winner, n) /*distance((SampleSom*)network[winner], network[n])*/
            <= R) {
          d = distance(samples->at(i),
                       network[n]); // distance from the current neuron inside
                                    // the circle to the image

          G = exp((double)-1 * ((d0 - d) * (d0 - d) / (lambda * lambda)));
          // GArray[n] = G;
          network[n]->setAnomaly(
              network[n]->getAnomaly() +
              eta * G *
                  (samples->at(i)->getAnomaly() - network[n]->getAnomaly()));

          for (int j = 0; j < dimension; j++) {
            network[n]->setKoeff(j, network[n]->getKoeff(j) +
                                        eta * G *
                                            (samples->at(i)->getKoeff(j) -
                                             network[n]->getKoeff(j)));

            if (network[n]->getAnomaly() > 100)
              network[n]->setAnomaly(100);
          }
        } else {
        }
      }
    }
    // modify coefficients
    eta = etaMax * pow(etaMin / etaMax, iter / Iters);
    R = rMax * pow(rMin / rMax, iter / Iters);
  }
}

int SelfOrganizedMap::getWinnerFor(SampleSom *sample) {
  double d;
  int winner = -1;
  int min = -1;

  for (int i = 0; i < N * M; i++) {
    d = distance(sample, network[i]);

    if (winner == -1 || min > d) {
      min = d;
      winner = i;
    }
  }

  return winner;
}

double SelfOrganizedMap::distance(SampleSom *x1, Neuron *x2) {
  double sum = 0;

  for (int i = 0; i < dimension; i++) {
    sum += (x1->getKoeff(i) - x2->getKoeff(i)) *
           (x1->getKoeff(i) - x2->getKoeff(i));
  }

  return sqrt(sum);
}

double SelfOrganizedMap::distanceNeurons(int a, int b) {
  int x1 = a / N;
  int x2 = b / N;

  int y1 = a % N;
  int y2 = b % N;

  double res = (x2 - x1) * (x2 - x1) + (y2 - y1) * (y2 - y1);
  return sqrt(res);
}

Neuron *SelfOrganizedMap::getNeuron(int i, int j) { return network[i * M + j]; }

int SelfOrganizedMap::recognize(SampleSom *sample) {
  int winner = getWinnerFor(sample);
  return winner;
}
