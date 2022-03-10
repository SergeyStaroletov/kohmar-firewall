/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "pst_builder.h"

PstBuilder::PstBuilder() {
  ALPHABET_RANGE = 256;
  S_INITIAL_SIZE = 1024;
  strHits = 0;
  alphabetSize = ALPHABET_RANGE;
  seenAlphabet = new bool[ALPHABET_RANGE];
  strCharHits = new int[ALPHABET_RANGE];
  charStrHits = new int[ALPHABET_RANGE];
  charStrHitsPerSample = new int[ALPHABET_RANGE];
  samples = NULL;
  pstRoot = NULL;
}

PstBuilder::PstBuilder(int abSize) {
  strHits = 0;
  alphabetSize = abSize;
  ALPHABET_RANGE = abSize;
  S_INITIAL_SIZE = 1024;
  seenAlphabet = new bool[alphabetSize];
  strCharHits = new int[alphabetSize];
  charStrHits = new int[alphabetSize];
  charStrHitsPerSample = new int[alphabetSize];
  samples = NULL;
  pstRoot = NULL;
}

PstNode *PstBuilder::build(Samples *_samples, double pMin, double alpha,
                           double nextSymProbMin, double addedValThreshold,
                           int strMaxLength) {
  samples = _samples;
  init(pMin, nextSymProbMin);

  // start building the PST
  char *str = new char[256];
  double *strNSymProb;
  double suffStrNSymProb[alphabetSize];

  while (queryStrs.size() > 0) {
    strcpy(str, queryStrs[0]);
    queryStrs.erase(queryStrs.begin());

    for (int i = 0; i < alphabetSize; i++) {
      suffStrNSymProb[i] = suffStrNextSymProb[0][i];
    }

    suffStrNextSymProb.erase(suffStrNextSymProb.begin());

    initHitCounts(str);
    strNSymProb = computeNextSymProb();

    if (isConditionB(strNSymProb, suffStrNSymProb, alpha, nextSymProbMin,
                     addedValThreshold)) {
      addToTree(str, strNSymProb, nextSymProbMin);
    }

    if ((int)strlen(str) < strMaxLength)
      updateQueryStrs(str, strNSymProb, pMin);
  }

  return pstRoot;
}

void PstBuilder::init(double pMin, double nextSymProbMin) {
  if (nextSymProbMin * alphabetSize > 1) {
    return;
  }

  int numOfSamples = samples->numOfSamples();
  int allLength = samples->sizeAll();

  for (int i = 0; i < alphabetSize; i++)
    strCharHits[i] = 0;

  for (int val = 0, sampleSize = 0, sampleID = 0; sampleID < numOfSamples;
       sampleID++) {
    sampleSize = samples->sizeSample(sampleID);

    for (int i = 0; i < sampleSize; i++) {
      val = samples->getElem(sampleID, i);
      seenAlphabet[val] = true;
      strCharHits[val]++;
    }
  }

  // init seenALPHABET & queryStrs
  double *prob = new double[alphabetSize];

  for (int i = 0; i < alphabetSize; i++) {
    // if(seenAlphabet[i]) alphabetSize++;
    prob[i] = strCharHits[i] / (double)allLength;

    if (prob[i] > pMin) {
      char *ch = new char[2];
      ch[0] = (char)i;
      ch[1] = '\0';

      queryStrs.push_back(ch);
      suffStrNextSymProb.push_back(prob);
    }
  }

  double *rootsProb = new double[alphabetSize];

  for (int i = 0; i < alphabetSize; i++)
    rootsProb[i] = prob[i];

  pstRoot = createPstRoot(smooth(rootsProb, nextSymProbMin));
}

double *PstBuilder::smooth(double *prob, double nsMinP) {
  double factor = 1 - alphabetSize * nsMinP;

  for (int i = 0; i < alphabetSize; ++i) {
    if (seenAlphabet[i]) {
      prob[i] = factor * prob[i] + nsMinP;
    }
  }

  return prob;
}

PstNode *PstBuilder::createPstRoot(double *nextSymProb) {
  char *str = new char[10];
  strcpy(str, "");

  PstNode *root = new PstNode(str, nextSymProb, alphabetSize); //!!
  return root;
}

void PstBuilder::initHitCounts(char *str) {
  for (int i = 0; i < alphabetSize; i++) {
    strCharHits[i] = 0;
    charStrHits[i] = 0;
    charStrHitsPerSample[i] = 0;
  }

  strHits = 0;

  bool *isUpdatePerSample = new bool[alphabetSize];
  int sampleSize, loopTest, strSize = strlen(str);

  // BYTE * strBytes;
  for (int sampleID = 0, numOfSamples = samples->numOfSamples();
       sampleID < numOfSamples; sampleID++) {
    for (int i = 0; i < alphabetSize; i++)
      isUpdatePerSample[i] = true;

    sampleSize = samples->sizeSample(sampleID);
    loopTest = sampleSize - strSize;

    for (int i = 0, j = 0; i < loopTest; i++) {
      for (j = 0; j < strSize; j++) {
        if (samples->getElem(sampleID, i + j) != str[j])
          break;
      }

      if (j == strSize) {
        strHits++;

        if (i + j < sampleSize)
          strCharHits[(int)samples->getElem(sampleID, i + j)]++;

        if (i > 0) {
          int charId = samples->getElem(sampleID, i - 1);
          charStrHits[charId]++;
          if (isUpdatePerSample[charId]) {
            isUpdatePerSample[charId] = false;
            charStrHitsPerSample[charId]++;
          }
        }
      }
    }
  }
}

double *PstBuilder::computeNextSymProb() {
  double *retVal = new double[alphabetSize];

  int strCharAll = 0;

  for (int i = 0; i < alphabetSize; i++) {
    strCharAll += strCharHits[i];
  }

  for (int i = 0; i < alphabetSize; ++i) {
    retVal[i] = (double)strCharHits[i] / strCharAll;
  }
  return retVal;
}

bool PstBuilder::isConditionB(double *StrNSymProb, double *suffStrNSymProb,
                              double alpha, double nextSymProbMin,
                              double addedValThreshold) {
  double factor = 0;

  for (int i = 0; i < alphabetSize; i++) {
    if (StrNSymProb[i] >= (1 + alpha) * nextSymProbMin) {
      factor = StrNSymProb[i] / suffStrNSymProb[i];

      if ((factor >= addedValThreshold) || (factor <= 1 / addedValThreshold)) {
        return true;
      }
    }
  }

  return false;
}

void PstBuilder::updateQueryStrs(char *str, double *nextSymProb, double pMin) {
  int allPossibleMatches = 0;
  int test = samples->numOfSamples();
  int chStrLen = strlen(str) + 1;

  for (int i = 0; i < test; i++) {
    allPossibleMatches += samples->sizeSample(i) - chStrLen + 1;
  }

  for (int i = 0; i < alphabetSize; i++) {
    if (((double)charStrHits[i] / allPossibleMatches) >= pMin) {
      // char * ch = new char[2];
      char ch[200] = {0};
      ch[0] = (char)i;
      ch[1] = '\0';

      queryStrs.push_back(strcat(ch, str));
      suffStrNextSymProb.push_back(nextSymProb);
    }
  }
}

void PstBuilder::addToTree(char *str, double *strNSymProb,
                           double nextSymProbMin) {
  PstNode *deepestNode = pstRoot->get(str);
  int str_length = strlen(str);
  int deep_length = 0;
  if (deepestNode->getString() != NULL)
    deep_length = strlen(deepestNode->getString());

  if (deep_length == str_length - 1) {
    deepestNode->insert(str[0], smooth(strNSymProb, nextSymProbMin));
  } else {
    int *savedStrChHits = new int[alphabetSize];
    int *savedChStrHits = new int[alphabetSize];

    for (int i = 0; i < alphabetSize; i++) {
      savedChStrHits[i] = charStrHits[i];
      savedStrChHits[i] = strCharHits[i];
    }

    double *prob;

    for (int i = str_length - deep_length - 1; i > -1; i--) {
      initHitCounts(&str[i]);
      prob = computeNextSymProb();
      deepestNode->insert(str[i], smooth(prob, nextSymProbMin));
    }

    for (int i = 0; i < alphabetSize; i++) {
      charStrHits[i] = savedChStrHits[i];
      strCharHits[i] = savedStrChHits[i];
    }

    // deepestNode = deepestNode->get(str[i]);//
  }
}
