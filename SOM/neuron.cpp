/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "neuron.h"

Neuron::Neuron(int _dimension, QObject *parent) : QObject(parent) {
  dimension = _dimension;
  koeffs = new double[dimension];
  anomaly = 0;

  for (int i = 0; i < dimension; i++)
    koeffs[i] = (double)rand() / (double)RAND_MAX;
}

bool Neuron::setKoeff(int index, double value) {
  bool res = true;

  if (index < dimension)
    koeffs[index] = value;
  else
    res = false;

  return res;
}

bool Neuron::setKoeffs(double *_koeffs) {
  bool res = true;

  if (sizeof(*_koeffs) / sizeof(double) == dimension) {
    for (int i = 0; i < dimension; i++) {
      koeffs[i] = _koeffs[i];
    }
  } else {
    res = false;
  }

  return res;
}

int Neuron::getDimension() { return dimension; }

double *Neuron::getKoeffs() { return koeffs; }

double Neuron::getKoeff(int index) {
  if (index < dimension) {
    return koeffs[index];
  } else
    return 0;
}

void Neuron::setAnomaly(double _anomaly) { anomaly = _anomaly; }

double Neuron::getAnomaly() { return anomaly; }
