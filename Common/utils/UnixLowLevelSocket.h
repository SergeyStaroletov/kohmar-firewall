#ifndef UNIXLOWLEVELSOCKET_H_
#define UNIXLOWLEVELSOCKET_H_

#include "LowLevelSocket.h"
#include "UnixSemaphore.h"

/*
 * Realization of abstract base class as unix socket
 */
class UnixLowLevelSocket : public LowLevelSocket {
public:
  UnixLowLevelSocket();
  UnixLowLevelSocket(int descriptor, std::string addr) {
    this->sd = descriptor;
    this->addr = addr;
    sem = new UnixSemaphore();
  };
  void initialize(int domain, int type, int protocol);

  void setSendBufSize(int buf);
  void setRcvBufSize(int buf);

  void connect(std::string address, int port, int protocol);
  void bindAndListen(int address, int port, int protocol, int queueSize);
  void bindAndListen(std::string address, int port, int protocol,
                     int queueSize);
  UnixLowLevelSocket *accept();

  int send(const char *buf, int size);

  int receive(char *buf, int size);

  void setUnblocking(bool unblocking);

  void close();

  std::string &getAddress() { return addr; }

  virtual ~UnixLowLevelSocket();

private:
  int sd;
  bool reuse;
  std::string addr;
  UnixSemaphore *sem;
};

#endif /* UNIXLOWLEVELSOCKET_H_ */
