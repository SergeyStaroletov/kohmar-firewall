#include "LowLevelSocket.h"
#include <stdlib.h>
#include <string.h>

/* send a string by using convertion to char * and length of string */
int LowLevelSocket::send(std::string buf) {
  return send(buf.c_str(), buf.length());
}

/* receive to a string */
int LowLevelSocket::receive(std::string &buf) {
  char charbuf[1024];
  memset(charbuf, 0, sizeof(charbuf));
  // receive from charbuf and return it as string
  int r = receive(charbuf, 1023);
  buf = charbuf;
  return r;
}

LowLevelSocket::LowLevelSocket() {
  //
}

LowLevelSocket::~LowLevelSocket() {
  //
}
