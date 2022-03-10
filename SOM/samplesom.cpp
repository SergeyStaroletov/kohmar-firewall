/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "samplesom.h"
#include <fstream>

SampleSom::SampleSom(int _dimension) : Neuron(_dimension) {}

QList<SampleSom *> SampleSom::loadFromFile(QString file_name) {
  QMessageBox msgBox;
  QList<SampleSom *> res;
  SampleSom *sample = NULL;
  int dim = 9;
  int i;
  double anomaly;

  std::fstream file("flow.samples", std::ios::in);

  if (!file.is_open()) {
    msgBox.setText("The file containing the training sample for the traffic "
                   "flow system is not open!");
    msgBox.exec();
    return res;
  }

  file >> dim;
  int max = 100000;

  while (file >> anomaly, !file.eof()) {
    sample = new SampleSom(dim);
    sample->setAnomaly(anomaly);
    for (i = 0; i < dim; i++) {
      double koeff;
      file >> koeff;
      sample->setKoeff(i, koeff);
    }
    res.append(sample);
    max--;
    if (max == 0)
      break;
  }

  file.close();
  return res;
}
