/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef PSTNODE_H
#define PSTNODE_H

#include "pst_context.h"
#include <QString>
#include <math.h>
#include <stdio.h>
#include <string.h>

class PstNode {
protected:
  int ABSIZE;
  double *nextSymProbability;
  PstNode **childrens;
  bool isLeaf;
  int absize;
  char *idStr;

public:
  PstNode();
  PstNode(int abSize);
  PstNode(char *idStr, double *_nextSymProbability, int alphabetSize);
  PstNode *get(char *str);
  PstNode *get(char symbol);
  PstNode *get(Context *context);
  char *getString();
  void insert(char symbol, double *_nextSymProbability);
  QString printMe();
  void printRecursively(int parent, double prob);
  void predict(double *pArr);
  int getAlphabetSize();
  int subTreeHeight();
  void retrainProbs(double addKoeff, int index);
};

#endif // PSTNODE_H
