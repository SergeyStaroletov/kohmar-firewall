/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "../Common/utils/UnixSemaphore.h"
#include <QDebug>
#include <QString>
#include <stdio.h>
#include <vector>

struct ConnectionTreeNode {
  // int key;
  unsigned int ip_src;
  unsigned int ip_dest;
  unsigned int port_src;
  unsigned int port_dest;
  ConnectionTreeNode *left;
  ConnectionTreeNode *right;

  char *states;
  char *learning_string;

  UnixSemaphore *sem;

  int bal;
  int id;
};

class ConnectionTree {
public:
protected:
  int count;
  ConnectionTreeNode *root;

public:
  ConnectionTree(void);
  // ConnetctionTree(FILE* file);
  void insertLeaf(unsigned int _ip_src, unsigned int _ip_dest,
                  unsigned int _port_src, unsigned int _port_dest);
  ConnectionTreeNode *traverse(bool deleteall);
  ConnectionTreeNode *find(unsigned int _ip_src, unsigned int _ip_dest,
                           unsigned int _port_src, unsigned int _port_dest);
  void del(unsigned int _ip_src, unsigned int _ip_dest, unsigned int _port_src,
           unsigned int _port_dest);
  void leftRootRight(void);
  void print(void);
  void move(bool right, ConnectionTreeNode *tn, ConnectionTreeNode *father);
  int height(ConnectionTreeNode *_root);
  int balanceCount(ConnectionTreeNode *_root);
  bool isEqual(ConnectionTreeNode *n1, ConnectionTreeNode *n2);
  bool isGreather(ConnectionTreeNode *n1, ConnectionTreeNode *n2);
  virtual ~ConnectionTree(void);
};
