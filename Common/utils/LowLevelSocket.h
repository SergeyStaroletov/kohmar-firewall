#ifndef LOWLEVELSOCKET_H_
#define LOWLEVELSOCKET_H_

#include <ios>
#include <string>

/* class for socket exceptions with string message of diagnostics */

class SocketException : public std::ios_base::failure {
public:
  SocketException(const std::string &str)
      : std::ios_base::failure(str) { // str=user message
  }
};

/*
 * Abstract class for implementing socket in-out capabilities. Supports
 * send/receive, sync/async, blocking socket descriptor
 *
 * Successors must implement these methods
 */

class LowLevelSocket {
public:
  // type of our socket
  static const int AF_INET_ = 0;
  static const int AF_UNIX_ = 1;

  static const int SOCK_STREAM_ = 100;
  // type of in address
  static const int INADDR_ANY_ = 200;

  LowLevelSocket();

  // init
  virtual void setSendBufSize(int buf) = 0;
  virtual void setRcvBufSize(int buf) = 0;

  virtual void initialize(int domain, int type, int protocol) = 0;
  // connect
  virtual void connect(std::string address, int port, int protocol) = 0;
  // bind and listen
  virtual void bindAndListen(int address, int port, int protocol,
                             int queueSize) = 0;
  virtual void bindAndListen(std::string address, int port, int protocol,
                             int queueSize) = 0;
  // accept
  virtual LowLevelSocket *accept() = 0;
  // send
  virtual int send(const char *buf, int size) = 0;
  int send(std::string buf);
  // receive
  virtual int receive(char *buf, int size) = 0;
  int receive(std::string &buf);
  // getmyaddress
  virtual std::string &getAddress() = 0;
  // set reuse socket
  void setReuse(bool reuse) { this->reuse = reuse; }
  // close
  virtual void close() = 0;
  // set socket to unblocking mode
  virtual void setUnblocking(bool unblocking) = 0;
  virtual ~LowLevelSocket();

protected:
  bool unblocking;
  bool reuse;
};

#endif /* LOWLEVELSOCKET_H_ */
