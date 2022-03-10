/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "pst_predictor.h"
#include <QDebug>

PstPredictor::PstPredictor() {
  root = NULL;
  NEGATIVE_INVERSE_LOG_2 = -((double)1 / log(2.0));
}

void PstPredictor::init(int _abSize, double _pMin, double _alpha, double _gamma,
                        double _r, int _vmmOrder, double _retrainKoeff) {
  this->abSize = _abSize;
  this->pMin = _pMin;
  this->alpha = _alpha;
  this->gamma = _gamma;
  this->r = _r;
  this->vmmOrder = _vmmOrder;
  this->retrainKoeff = _retrainKoeff;
}

void PstPredictor::learn(char *trainingSequence) {
  PstBuilder *builder = new PstBuilder(abSize);
  Samples *samples = new Samples();
  samples->add(trainingSequence);
  root = builder->build(samples, pMin, alpha, gamma, r, vmmOrder);
}

void PstPredictor::learn(Samples *smps) {
  PstBuilder *builder = new PstBuilder(abSize);
  root = builder->build(smps, pMin, alpha, gamma, r, vmmOrder);

  QString s = root->printMe();
  FILE *f = fopen((this->fname + ".dot").toLocal8Bit(), "w");
  fwrite(s.toLocal8Bit(), s.size(), 1, f);
  fclose(f);
}

double PstPredictor::logEval(char *seq) {
  double *pArr = new double[abSize];
  double eval = 0.0;
  int seqLength = strlen(seq);

  PstArithPredictor *pstPredictor = new PstArithPredictor(root);

  for (int i = 0, sym = -1; i < seqLength; i++) {
    sym = (int)seq[i];
    pstPredictor->predict(pArr);
    eval += log(pArr[sym]);
    pstPredictor->increment(sym);
  }

  delete pstPredictor;

  // eval *= NEGTIVE_INVERSE_LOG_2;
  eval *= -1.0;

  if (eval > MAX_VAL)
    eval = MAX_VAL;

  delete[] pArr;

  return eval;
}

double PstPredictor::predict(char c, char *seq) {
  double *pArr = new double[abSize];
  int seqLength = strlen(seq);

  PstArithPredictor *pstPredictor = new PstArithPredictor(root);

  for (int i = 0, sym = -1; i < seqLength; i++) {
    sym = (int)seq[i];
    pstPredictor->predict(pArr);
    pstPredictor->increment(sym);
    // pstPredictor->predict(pArr);
  }

  pstPredictor->predict(pArr);
  return pArr[(int)c];
}

void PstPredictor::retrainForSeq(char *seq) {
  double *pArr = new double[abSize];
  double addKoeff;
  int seqLength = strlen(seq);
  PstNode *node;

  PstArithPredictor *pstPredictor = new PstArithPredictor(root);

  for (int i = 0, sym = -1; i < seqLength; i++) {
    sym = (int)seq[i];
    node = pstPredictor->predict(pArr);

    addKoeff = pArr[sym] * retrainKoeff;

    node->retrainProbs(addKoeff, sym);

    pstPredictor->increment(sym);
  }
}
