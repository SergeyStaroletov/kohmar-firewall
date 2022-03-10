/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef CONTEXT_H_
#define CONTEXT_H_

#include <stdio.h>

class Context {
private:
  const static int ILL_INDEX = -1;

  // Context collection, a symbol is access by its int id.
  int *context;
  int nextAddIndex;
  int length;

  /* Indicates the size of the population in context[] */
  int population;

  /* Iteration index */
  int iterInd;
  int iterCount;

  int indexBefore(int index);
  bool isFull();

public:
  Context(int maxlength);
  virtual ~Context();

  void add(int symbol);
  bool hasNext();
  int nextSymbol();
  Context *getIterator();
};

#endif /* CONTEXT_H_ */
