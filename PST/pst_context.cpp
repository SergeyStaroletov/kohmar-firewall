/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "pst_context.h"

Context::Context(int maxlength) {
  context = new int[maxlength];
  nextAddIndex = 0;
  population = 0;
  iterInd = 0;
  iterCount = 0;
  length = maxlength;
}

Context::~Context() {}

void Context::add(int symbol) {
  context[nextAddIndex] = symbol;
  nextAddIndex = (nextAddIndex + 1) % length;
  population = isFull() ? population : population + 1;
}

bool Context::hasNext() { return iterCount != population; }

int Context::nextSymbol() {
  int sym = context[iterInd];
  iterInd = indexBefore(iterInd);
  iterCount++;
  return sym;
}

int Context::indexBefore(int index) {
  return (index == 0) ? length - 1 : (index - 1);
}

bool Context::isFull() { return (population == length); }

Context *Context::getIterator() {
  iterInd = indexBefore(nextAddIndex);
  iterCount = 0;
  return this;
}
