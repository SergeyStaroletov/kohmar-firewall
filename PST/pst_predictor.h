/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef PSTPREDICTOR_H
#define PSTPREDICTOR_H

#include "pst_arithpredictor.h"
#include "pst_builder.h"
#include "pst_common.h"
#include "pst_node.h"
#include "pst_samples.h"
#include <QString>
#include <math.h>

class PstPredictor {
protected:
  double NEGATIVE_INVERSE_LOG_2;
  constexpr static const double MAX_VAL = 100;
  int abSize;
  double pMin;
  double alpha;
  double gamma;
  double r;
  int vmmOrder;
  double retrainKoeff;
  QString fname;

public:
  PstNode *root;
  PstPredictor();
  void init(int _abSize, double _pMin, double _alpha, double _gamma, double _r,
            int _vmmOrder, double _retrainKoeff);
  void learn(char *trainingSequence);
  void learn(Samples *smps);
  void retrainForSeq(char *seq);
  // double predict(int symbol, char *context);
  double logEval(char *testSequence);
  double predict(char c, char *str);
  void setName(QString fname) { this->fname = fname; }
};

#endif // PSTPREDICTOR_H
