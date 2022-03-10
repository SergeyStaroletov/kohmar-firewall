/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "pst_samples.h"

Samples::Samples() {}

void Samples::add(char *smp) { samples.push_back(smp); }

BYTE Samples::getElem(int sampleIndex, int index) {
  BYTE res = -1;

  if (sampleIndex < this->numOfSamples()) {
    if (index < this->sizeSample(sampleIndex)) {
      res = samples[sampleIndex][index];
    }
  }

  return res;
}

int Samples::sizeSample(int sampleIndex) {
  int res = -1;

  if (sampleIndex < this->numOfSamples()) {
    res = strlen(samples[sampleIndex]);
  }

  return res;
}

int Samples::numOfSamples() { return samples.size(); }

int Samples::sizeAll() {
  int res = 0;

  for (int i = 0; i < this->numOfSamples(); i++) {
    res += this->sizeSample(i);
  }

  return res;
}

int Samples::loadFromFile(const char *filename) {
  int res = -1;
  int MAX_ARRAY_LEN = 400;
  FILE *file = fopen(filename, "r");

  if (!file) {
    return -1;
  }

  try {
    int maxlen = 0;
    int len;
    // fscanf(file, "%d\n", &len);

    // len++;
    // res = len;

    char *smp;
    int read_flag;

    while (true) {
      smp = new char[MAX_ARRAY_LEN];

      read_flag = fscanf(file, "%s\n", smp);
      smp[MAX_ARRAY_LEN - 1] = '\0';

      if (read_flag != EOF) {
        printf("%s\n", smp);
        this->add(smp);
        res++;

        len = strlen(smp);

        if (len > maxlen)
          maxlen = len;

      } else
        break;
    }

  } catch (...) {
    res = -1;
  }

  fclose(file);
  return res + 1;
}

char *Samples::getSample(int index) { return this->samples[index]; }
