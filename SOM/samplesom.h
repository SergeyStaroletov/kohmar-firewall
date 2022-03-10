/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef SAMPLESOM_H
#define SAMPLESOM_H

#include <QDebug>
#include <QFile>
#include <QMessageBox>
#include <QObject>
#include <QTextStream>
#include <QXmlStreamReader>

#include <stdio.h>

#include "neuron.h"

class SampleSom : public Neuron {
  Q_OBJECT

public:
  explicit SampleSom(int _dimension);
  static QList<SampleSom *> loadFromFile(QString file_name);

signals:

public slots:
};

#endif // SAMPLESOM_H
