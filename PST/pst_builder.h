/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef PSTBUILDER_H
#define PSTBUILDER_H

#include "pst_node.h"
#include "pst_samples.h"
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

class PstBuilder {
protected:
  int ALPHABET_RANGE;
  int S_INITIAL_SIZE;
  // int UNSIGNED_BYTE_MASK = 0xFF;

  int alphabetSize;
  bool *seenAlphabet;
  int strHits;
  int *strCharHits;
  int *charStrHits;
  int *charStrHitsPerSample;

  Samples *samples;

  std::vector<std::string> queryStrs;
  std::vector<double *> suffStrNextSymProb;
  PstNode *pstRoot;

  PstNode *createPstRoot(double *nextSymProb);
  void init(double pMin, double nextSymProbMin);
  void updateQueryStrs(std::string &str, double *nextSymProb, double pMin);
  void addToTree(std::string &str, double *strNSymProb, double nextSymProbMin);
  void initHitCounts(std::string &str);
  bool isConditionB(double *StrNSymProb, double *suffStrNSymProb, double alpha,
                    double nextSymProbMin, double addedValThreshold);
  double *smooth(double *prob, double nsMinP);
  double *computeNextSymProb();

public:
  PstBuilder();
  PstBuilder(int abSize);
  PstNode *build(Samples *_samples, double pMin, double alpha,
                 double nextSymProbMin, double addedValThreshold,
                 int strMaxLength);
};

#endif // PSTBUILDER_H
