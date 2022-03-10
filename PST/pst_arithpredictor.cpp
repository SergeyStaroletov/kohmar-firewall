/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "pst_arithpredictor.h"

PstArithPredictor::PstArithPredictor(PstNode *node) {
  pst = node;
  context = new Context(pst->subTreeHeight());
}

PstArithPredictor::~PstArithPredictor() { delete context; }

PstNode *PstArithPredictor::predict(double *prediction) {
  PstNode *contextNode = pst->get(context->getIterator());
  contextNode->predict(prediction);
  return contextNode;
}

void PstArithPredictor::increment(int symbol) { context->add(symbol); }

int PstArithPredictor::alphabetSize() { return pst->getAlphabetSize(); }
