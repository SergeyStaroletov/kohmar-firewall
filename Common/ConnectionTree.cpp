/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "../Common/ConnectionTree.h"
#define MAX 60

ConnectionTree::ConnectionTree(void) {
  root = NULL;
  count = 0;
}

ConnectionTree::~ConnectionTree(void) {
  traverse(true);
  //~kol;
}

void ConnectionTree::insertLeaf(unsigned int _ip_src, unsigned int _ip_dest,
                                unsigned int _port_src,
                                unsigned int _port_dest) {
  ConnectionTreeNode *sta[MAX];
  bool exist = 0;
  int UV = -1;
  ConnectionTreeNode *tn = new ConnectionTreeNode;
  // tn->key=ZN;
  tn->ip_src = _ip_src;
  tn->ip_dest = _ip_dest;
  tn->port_src = _port_src;
  tn->port_dest = _port_dest;
  tn->left = NULL;
  tn->right = NULL;
  tn->bal = 0;
  tn->id = count;

  if (root == NULL) {
    root = tn;
    count++;
    qDebug() << "+first+ connection added to con_tree";
  } else {
    bool PR = 1;
    ConnectionTreeNode *t = root;
    while (PR) {
      // UV++;
      // sta[UV]=t;
      if (isEqual(tn, t)) {
        exist = true;
        break;
      }

      sta[++UV] = t;

      if (isGreather(t, tn)) {
        if (t->left != NULL) {
          t = t->left;
        } else {
          t->left = tn;
          PR = 0;
        }
      } else {
        if (isGreather(tn, t)) {
          if (t->right != NULL) {
            t = t->right;
          } else {
            t->right = tn;
            PR = 0;
          }
        }
      }
    }
    if (!exist) {
      count++;
      ConnectionTreeNode *tt, *t, *par;
      bool flag = true;
      if (UV == -1)
        t = NULL;
      else {
        tt = tn;
        t = sta[UV];
        UV--;
        if (UV == -1)
          par = NULL;
        else
          par = sta[UV];
      }
      while (flag) {

        if (t == NULL)
          flag = false;
        else {
          if (tt == t->left)
            t->bal++;
          else
            t->bal--;
          if (t->bal == 0)
            flag = false;
          if (t->bal == 2) {
            switch (tt->bal) {
            case 1: {
              move(true, t, par);
              flag = false;
              break;
            }
            case -1: {
              move(false, tt, t);
              move(true, t, par);
              flag = false;
            }
            }
          }
          if (t->bal == -2) {
            switch (tt->bal) {
            case -1: {
              move(false, t, par);
              flag = false;
              break;
            }
            case 1: {
              move(true, tt, t);
              move(false, t, par);
              flag = false;
            }
            }
          }
        }
        if (UV == -1)
          t = NULL;
        else {
          tt = t;
          t = sta[UV];
          UV--;
          if (UV == -1)
            par = NULL;
          else
            par = sta[UV];
        }
      }

      qDebug() << "connection added to con_tree";
    } else {
      delete tn;
      tn = NULL;
      qDebug() << "connection already exists!";
    }
  }
}

ConnectionTreeNode *ConnectionTree::traverse(bool deleteall) {
  int sk = 0;
  ConnectionTreeNode *result = root;
  ConnectionTreeNode *sta[MAX];
  int stp[MAX];
  int UV = -1;
  for (int i = 0; i < MAX; i++)
    stp[i] = 0;
  ConnectionTreeNode *tn = root;
  UV++;
  sta[UV] = tn;
  stp[UV]++;
  sk++;

  while (tn) {
    UV++;
    tn = tn->left;
    sta[UV] = tn;
    stp[UV] = 1;
  }

  while (1) // LPK
  {
    if (tn != NULL) {
      if (stp[UV] == 3) {
        if (sk == count / 2)
          result = tn;
        sk++;
        if (deleteall) {
          delete tn;
          tn = NULL;
        }
        UV--;
        if (UV == -1)
          break;
        else {
          stp[UV]++;
          tn = sta[UV];
        }
      } else {
        if (stp[UV] == 2) {
          tn = tn->right;
          UV++;
          sta[UV] = tn;
          stp[UV] = 1;
        } else {
          if (stp[UV] == 1) {
            tn = tn->left;
            UV++;
            sta[UV] = tn;
            stp[UV] = 1;
          }
        }
      }
    } else {
      UV--;
      stp[UV]++;
    }
    tn = sta[UV];
  }

  return result;
}

void ConnectionTree::del(unsigned int _ip_src, unsigned int _ip_dest,
                         unsigned int _port_src, unsigned int _port_dest) {
  ConnectionTreeNode *to_del = new ConnectionTreeNode;
  to_del->ip_src = _ip_src;
  to_del->ip_dest = _ip_dest;
  to_del->port_dest = _port_dest;
  to_del->port_src = _port_src;

  if (count == 1 && isEqual(root, to_del)) {
    delete root;
    root = NULL;
    count = 0;
    delete to_del;
    return;
  }

  ConnectionTreeNode *tn = root;
  bool flag = true, isNode = true, left = false, right = false;
  int UV = -1;
  ConnectionTreeNode *st[MAX];

  while (flag) {
    if (tn != NULL) {
      if (!isEqual(tn, to_del)) {
        UV++;
        st[UV] = tn;
        if (isGreather(to_del, tn)) {
          tn = tn->right;
          right = true;
          left = false;
        } else if (isGreather(tn, to_del)) {
          tn = tn->left;
          right = false;
          left = true;
        }
      } else {
        flag = false;
        /*UV++; st[UV]=tn;*/
      }
    } else
      flag = false;
  }
  if (tn == NULL) {
    // not found
  } else {
    count--;
    if (tn->left == NULL && tn->right == NULL) {
      isNode = false;
      if (tn == root) {
        delete tn;
        root = NULL;
      } else {
        delete tn;
        tn = st[UV];
        if (left) {
          tn->left = NULL; /*st[UV]->bal-=1;*/
        } else {
          tn->right = NULL; /*st[UV]->bal+=1;*/
        }
      }
    } else {
      if (tn->left == NULL) {
        if (tn->right->left == NULL && tn->right->right == NULL) {
          isNode = false;
          // tn->key=tn->right->key;
          tn->ip_dest = tn->right->ip_dest;
          tn->ip_src = tn->right->ip_src;
          tn->port_dest = tn->right->port_dest;
          tn->port_src = tn->right->port_src;

          delete tn->right;
          tn->right = NULL;
          tn->bal = 0;
        }
      } else {
        if (tn->right == NULL) {
          if (tn->left->left == NULL && tn->left->right == NULL) {
            isNode = false;
            // tn->key=tn->left->key;
            tn->ip_dest = tn->left->ip_dest;
            tn->ip_src = tn->left->ip_src;
            tn->port_dest = tn->left->port_dest;
            tn->port_src = tn->left->port_src;

            delete tn->left;
            tn->left = NULL;
            tn->bal = 0;
          }
        }
      }
      if (isNode) {
        ConnectionTreeNode *tn1 = tn->left;
        right = false;
        left = true;
        st[++UV] = tn;
        while (tn1->right) {
          st[++UV] = tn1;
          tn1 = tn1->right;
          right = true;
          left = false;
        }
        // int key=tn1->key;
        // tn->key=key;
        tn->ip_dest = tn1->ip_dest;
        tn->ip_src = tn1->ip_src;
        tn->port_dest = tn1->port_dest;
        tn->port_src = tn1->port_src;
        // DEL tn1
        ConnectionTreeNode *p;
        if (tn1->left == NULL && tn1->right == NULL) {
          if (tn1 == root) {
            root = NULL;
            delete tn1;
          } else {
            p = st[UV]; //--];
            if (tn1 == p->left)
              p->left = NULL;
            if (tn1 == p->right)
              p->right = NULL;
            delete tn1;
          }
        } else {
          if (tn1->left == NULL || tn1->right == NULL) {
            if (tn1->right == NULL) {
              if (tn1 == root)
                root = tn1->left;
              else {
                p = st[UV]; //--];
                if (tn1 == p->left)
                  p->left = tn1->left;
                if (tn1 == p->right)
                  p->right = tn1->left;
              }
              delete tn1;
            }
            if (tn1->left == NULL) {
              if (tn1 == root)
                root = tn1->right;
              else {
                p = st[UV]; //--];
                if (tn1 == p->left)
                  p->left = tn1->right;
                if (tn1 == p->right)
                  p->right = tn1->right;
              }
              delete tn1;
            }
          }
        }
      }
    }
    // right=false,left=false;
    ConnectionTreeNode *t0, *par, *t;

    flag = true;
    if (UV == -1)
      t0 = NULL;
    else {
      t0 = st[UV--];
      if (UV == -1)
        par = NULL;
      else
        par = st[UV];
    }

    while (flag) {
      if (t0 == NULL)
        flag = false;
      else {
        int pred = t0->bal;

        if (left)
          t0->bal--;
        if (right)
          t0->bal++;
        balanceCount(root);
        if (pred == 0 && (t0->bal == -1 || t0->bal == 1))
          flag = false;
        if (t0->bal == 2) {
          switch (t0->left->bal) {
          case 0:
          case 1: {
            move(1, t0, par);
            if (par)
              t0 = par->right;
            else
              t0 = 0; /*flag=false*/
            break;
          }
          case -1: {
            move(0, t0->left, t0);
            move(1, t0, par);
            if (par)
              t0 = par->right;
            else
              t0 = 0; /*flag=false*/
            ;
            break;
          }
          }
        }
        if (t0->bal == -2) {
          switch (t0->right->bal) {
          case 0:
          case -1: {
            move(0, t0, par); /*flag=false*/
            if (par)
              t0 = par->left;
            else
              t0 = 0;
            break;
          }
          case 1: {
            move(1, t0->right, t0);
            move(0, t0, par); /*flag=false*/
            if (par)
              t0 = par->left;
            else
              t0 = 0;
            break;
          }
          }
        }
      }
      if (UV == -1)
        t0 = NULL;
      else {
        t = t0;
        t0 = st[UV--];
        if (UV == -1)
          par = NULL;
        else
          par = st[UV];
        if (t0 != NULL) {
          if (t == t0->right) {
            right = true;
            left = false;
          }
          if (t == t0->left) {
            left = true;
            right = false;
          }
        }
      }
    }
  }
  // balanceCount(root);
}

void ConnectionTree::move(bool right, ConnectionTreeNode *tn,
                          ConnectionTreeNode *father) {
  ConnectionTreeNode *y;

  if (right) {
    y = tn->left;
    if (father != NULL) {
      if (tn == father->left)
        father->left = y;
      else
        father->right = y;
    } else
      root = y;
    tn->left = y->right;
    y->right = tn;

    if (tn->bal == 2 && y->bal == 1) {
      tn->bal = 0;
      y->bal = 0;
    }
    if (tn->bal == 2 && y->bal == 2) {
      tn->bal = -1;
      y->bal = 0;
    }
    if (tn->bal == 1 && y->bal == 1) {
      tn->bal = -1;
      y->bal = -1;
    }
    if (tn->bal == 1 && y->bal == -1) {
      tn->bal = 0;
      y->bal = -2;
    }
    if (tn->bal == 1 && y->bal == 0) {
      tn->bal = 0;
      y->bal = -1;
    }
    if (tn->bal == 2 && y->bal == 0) {
      tn->bal = 1;
      y->bal = -1;
    }
  }

  else {
    y = tn->right;
    if (father != NULL) {
      if (tn == father->left)
        father->left = y;
      else
        father->right = y;

    } else
      root = y;
    tn->right = y->left;
    y->left = tn;

    if (tn->bal == -2 && y->bal == -1) {
      tn->bal = 0;
      y->bal = 0;
    }
    if (tn->bal == -2 && y->bal == -2) {
      tn->bal = 1;
      y->bal = 0;
    }
    if (tn->bal == -1 && y->bal == -1) {
      tn->bal = 1;
      y->bal = 1;
    }
    if (tn->bal == -1 && y->bal == 1) {
      tn->bal = 0;
      y->bal = 2;
    }
    if (tn->bal == -1 && y->bal == 0) {
      tn->bal = 0;
      y->bal = 1;
    }
    if (tn->bal == -2 && y->bal == 0) {
      tn->bal = -1;
      y->bal = 1;
    }
  }
}

void ConnectionTree::leftRootRight(void) {
  ConnectionTreeNode *sta[MAX];
  int stp[MAX];
  int UV = -1;
  for (int i = 0; i < MAX; i++)
    stp[i] = 0;
  ConnectionTreeNode *tn = root;
  UV++;
  sta[UV] = tn;
  stp[UV] = 1;

  while (tn) {

    UV++;
    tn = tn->left;
    sta[UV] = tn;
    stp[UV] = 1;
  }

  while (1) {
    if (tn != NULL) {
      if (stp[UV] == 3) {
        UV--;
        if (UV == -1)
          break;
        else
          stp[UV]++;
      } else {
        if (stp[UV] == 2) {
          tn = tn->right;
          UV++;
          sta[UV] = tn;
          stp[UV] = 1;
        } else {
          if (stp[UV] == 1) {
            tn = tn->left;
            UV++;
            sta[UV] = tn;
            stp[UV] = 1;
          }
        }
      }
    } else {
      UV--;
      stp[UV]++;
    }
    tn = sta[UV];
  }
}

void ConnectionTree::print(void) {
  ConnectionTreeNode *tn = root;
  bool flag = true;
  int UV = -1;
  ConnectionTreeNode *st[MAX];
  int left_id, right_id;
  // printf("\n-------------------------");
  // printf("\n|  K  | Bal |  L  |  P  |");
  while (flag) // KLP
  {
    if (tn == NULL) {
      if (UV == -1)
        flag = false;
      else {
        tn = st[UV--];
        tn = tn->right;
      }
    } else {
      // printf("\n|%5d",tn->key);
      // printf("|%5d",tn->bal);
      // if(tn->left) printf("|%5d",tn->left->key);
      // else printf("|  -  ");
      // if(tn->right) printf("|%5d|",tn->right->key);
      // else printf("|  -  |");

      if (tn->left)
        left_id = tn->left->id;
      else
        left_id = -1;

      if (tn->right)
        right_id = tn->right->id;
      else
        right_id = -1;

      qDebug() << QString::number(tn->ip_src) << ":"
               << QString::number(tn->port_src) << " -> "
               << QString::number(tn->ip_dest) << ":"
               << QString::number(tn->port_dest)
               << "   id=" << QString::number(tn->id)
               << " left=" << QString::number(left_id)
               << " right=" << QString::number(right_id);
      st[++UV] = tn;
      tn = tn->left;
    }
  }
}

ConnectionTreeNode *ConnectionTree::find(unsigned int _ip_src,
                                         unsigned int _ip_dest,
                                         unsigned int _port_src,
                                         unsigned int _port_dest) {
  if (root == NULL)
    return NULL;

  ConnectionTreeNode *res = NULL;
  ConnectionTreeNode *t = root;
  ConnectionTreeNode *tn = new ConnectionTreeNode;

  tn->ip_dest = _ip_dest;
  tn->ip_src = _ip_src;
  tn->port_dest = _port_dest;
  tn->port_src = _port_src;

  bool PR = 1;

  while (PR) {
    if (isEqual(tn, t)) {
      res = t;
      break;
    }

    if (isGreather(t, tn)) {
      if (t->left != NULL) {
        t = t->left;
      } else {
        t->left = tn;
        PR = 0;
      }
    } else {
      if (isGreather(tn, t)) {
        if (t->right != NULL) {
          t = t->right;
        } else {
          t->right = tn;
          PR = 0;
        }
      }
    }
  }
  delete tn;
  tn = NULL;
  return res;
}

int ConnectionTree::height(ConnectionTreeNode *_root) {
  if (_root == NULL) {
    return 0;
  } else {
    return 1 + (height(_root->left) > height(_root->right)
                    ? height(_root->left)
                    : height(_root->right));
  }
}

int ConnectionTree::balanceCount(ConnectionTreeNode *_root) {
  int need = 0;
  ConnectionTreeNode *t = _root;
  int end = 0;
  int uv = -1;
  ConnectionTreeNode *st[100];
  while (!end) {
    if (t == NULL) {
      if (uv == -1) {
        end = 1;
      } else {
        t = st[uv--];
        t = t->right;
      }
    } else {
      t->bal = height(t->left) - height(t->right);
      if (t->bal == 2)
        need++;
      st[++uv] = t;
      t = t->left;
    }
  }
  return need;
}

bool ConnectionTree::isEqual(ConnectionTreeNode *n1, ConnectionTreeNode *n2) {
  if ((n1->ip_src == n2->ip_src) && (n1->ip_dest == n2->ip_dest) &&
      (n1->port_src == n2->port_src) && (n1->port_dest == n2->port_dest))
    return true;
  else
    return false;
}

bool ConnectionTree::isGreather(ConnectionTreeNode *n1,
                                ConnectionTreeNode *n2) // n1 > n2 ?
{
  if (n1->ip_src > n2->ip_src)
    return 1;
  else if (n1->ip_src < n2->ip_src)
    return 0;
  else {
    if (n1->ip_dest > n2->ip_dest)
      return 1;
    else if (n1->ip_dest < n2->ip_dest)
      return 0;
    else {
      if (n1->port_src > n2->port_src)
        return 1;
      else if (n1->port_src < n2->port_src)
        return 0;
      else {
        if (n1->port_dest > n2->port_dest)
          return 1;
        else
          return 0;
      }
    }
  }
}
