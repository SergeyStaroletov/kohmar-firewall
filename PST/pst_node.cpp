/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "pst_node.h"
#include <QDebug>
using namespace std;

static int node_id = 0;
static QString treeDot;

PstNode::PstNode() {
  ABSIZE = 256;
  absize = ABSIZE;
  nextSymProbability = new double[ABSIZE];
  childrens = new PstNode *[ABSIZE];

  for (int i = 0; i < absize; i++)
    childrens[i] = NULL;

  isLeaf = true;

  string str;
  // strcpy(str, "");
  idStr = str;
}

PstNode::PstNode(int alphabetSize) {
  ABSIZE = alphabetSize;
  string str;
  idStr = str;

  absize = alphabetSize;
  nextSymProbability = new double[absize];
  childrens = new PstNode *[absize];

  for (int i = 0; i < absize; i++)
    childrens[i] = NULL;

  isLeaf = true;
}

PstNode::PstNode(string _idStr, double *_nextSymProbability, int alphabetSize) {
  isLeaf = true;
  ABSIZE = alphabetSize;
  idStr = _idStr;
  // strcpy(idStr, _idStr);
  nextSymProbability = _nextSymProbability;
  absize = alphabetSize;
  childrens = new PstNode *[absize];

  for (int i = 0; i < absize; i++)
    childrens[i] = NULL;
}

PstNode *PstNode::get(string str) {
  int strLen = str.size();

  if (strLen == 0) {
    return this;
  } else {
    int nextSymIndex = str[strLen - 1];
    char ch = str[strLen - 1]; // last
    // str.erase(strLen - 1);
    str[strLen - 1] = '\0'; // LEAVE?

    if (childrens[nextSymIndex] != NULL) {
      PstNode *ret = childrens[nextSymIndex]->get(str);
      str[strLen - 1] = ch;
      return ret;
    } else { // therefore this corresponds to the largest suffix
      str[strLen - 1] = ch;
      return this;
    }
  }
}

PstNode *PstNode::get(char symbol) { return childrens[(int)symbol]; }

PstNode *PstNode::get(Context *context) {
  if (context->hasNext()) {
    int symbol = context->nextSymbol();
    return (childrens[symbol] != NULL) ? childrens[symbol]->get(context) : this;
  } else {
    return this;
  }
}

string PstNode::getString() { return idStr; }

void PstNode::insert(char symbol, double *_nextSymProbability) {
  if (isLeaf) {
    isLeaf = false;
    childrens = new PstNode *[absize];
    for (int i = 0; i < absize; i++)
      childrens[i] = NULL;
  }

  // char strDest = new char[2];
  string strDest = "0";
  strDest[0] = symbol;

  strDest = strDest + idStr;

  PstNode *newNode = new PstNode(strDest, _nextSymProbability, absize);
  childrens[(int)symbol] = newNode;
}

QString str2flags(string str) {
  QString rez;
  for (unsigned int i = 0; i < str.size(); i++) {
    char cur_state = str[i];
    int cur_state2 = (int)cur_state - 48;
    int fin2 = (cur_state2 / 32);
    cur_state2 -= fin2 * 32;
    int urg2 = (cur_state2 / 16);
    cur_state2 -= urg2 * 16;
    int rst2 = (cur_state2 / 8);
    cur_state2 -= rst2 * 8;
    int psh2 = (cur_state2 / 4);
    cur_state2 -= psh2 * 4;
    int ack2 = (cur_state2 / 2);
    cur_state2 -= ack2 * 2;
    int syn2 = cur_state2;

    rez += "ack:" + QString::number(ack2) + " syn:" + QString::number(syn2) +
           " fin:" + QString::number(fin2) + " psh:" + QString::number(psh2) +
           " urg:" + QString::number(urg2) + " rst:" + QString::number(rst2) +
           "\\n";
  }
  return rez;
}

QString PstNode::printMe() {
  qDebug() << "Printing PST = \n\n" << idStr.c_str() << "\n";
  node_id = 0;
  treeDot = "digraph g {\n";
  this->printRecursively(0, 0);
  treeDot += "}";
  return treeDot;
}

void PstNode::printRecursively(int parent, double prob) {

  node_id++;
  int my_node = node_id;

  if (idStr != "") {

    treeDot += "node" + QString::number(node_id) + "[label =\"[" +
               QString::fromStdString(idStr) + "]" + "\n" + str2flags(idStr) +
               "\"];\n";
  } else {
    treeDot += "node" + QString::number(node_id) + "[label =\"[-]\"];\n";
  }
  if (parent != 0) {
    treeDot += "node" + QString::number(parent) + "->" + "node" +
               QString::number(node_id) + " [label = \"" +
               QString::number(prob) + "\"];" + "\n";
  }

  for (int i = 0; i < absize; i++) {
    if (childrens[i]) {
      childrens[i]->printRecursively(my_node, nextSymProbability[i]);
    }
  }

  // for (int i = 0; i < absize; i++) {
  //  if (childrens[i]) {
  // childrens[i]->printRecursively();
  //  }
  // }
}

int PstNode::getAlphabetSize() { return absize; }

int PstNode::subTreeHeight() {
  int height = 0;

  if (isLeaf) {
    return 0;
  } else {

    for (int i = 0, childH; i < absize; ++i) {
      if (childrens[i] != NULL) {
        childH = childrens[i]->subTreeHeight();
        height = (height > childH) ? height : childH;
      }
    }

    return height + 1;
  }
}

void PstNode::predict(double *pArr) {
  for (int i = 0; i < absize; i++)
    pArr[i] = nextSymProbability[i];
}

void PstNode::retrainProbs(double addKoeff, int index) {
  nextSymProbability[index] += addKoeff;

  for (int i = 0; i < absize; i++) {
    if (i != index)
      nextSymProbability[i] -= (double)addKoeff / (absize - 1);
  }
}
