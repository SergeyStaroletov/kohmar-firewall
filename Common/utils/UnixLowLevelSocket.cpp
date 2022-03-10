#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>

#include <iostream>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "UnixLowLevelSocket.h"

#include "Logger.h"
#include <ctime>
#include <fcntl.h>

UnixLowLevelSocket::UnixLowLevelSocket() { reuse = false; }

void UnixLowLevelSocket::setSendBufSize(int buf) {
  int sndsize = buf;
  setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&sndsize, (int)sizeof(sndsize));
}
void UnixLowLevelSocket::setRcvBufSize(int buf) {
  int sndsize = buf;
  setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&sndsize, (int)sizeof(sndsize));
}

/* send the data by socket */
int UnixLowLevelSocket::send(const char *buf, int size) {

  // sem->wait() ;
  // std::cout<<"send() calling\n" ;
  int r;

  if (sd > 0)
    r = ::send(sd, buf, size, 0);
  else
    r = -1;

  // std::cout<<"send() called\n" ;
  // sem->post() ;
  if (r <= 0) {
    //	std::cout<<"send throw\n" ;
    throw SocketException("send");
  }
  // std::cout<<"return r\n" ;
  return r;
}

/* bind and listen in one method */
void UnixLowLevelSocket::bindAndListen(std::string address, int port,
                                       int protocol, int queueSize) {

  // if reuse is set
  if (reuse) {
    const int on = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  }
  // create unix domain socket or tcp socket
  switch (protocol) {
  case LowLevelSocket::AF_INET_: {
    // inet=tcp socket

    struct sockaddr_in my_addr;
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);

    my_addr.sin_addr.s_addr = inet_addr(address.c_str());

    bzero(&(my_addr.sin_zero), 8);
    if (bind(sd, (struct sockaddr *)(&my_addr), sizeof(struct sockaddr)) == -1)
      throw SocketException("bind");
  } break;
  case LowLevelSocket::AF_UNIX_: {
    // unix socket
    struct sockaddr_un saun;
    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, address.c_str());
    unlink(address.c_str());
    int len = sizeof(saun.sun_family) + strlen(saun.sun_path);
    if (bind(sd, (struct sockaddr *)(&saun), len) < 0)
      throw SocketException("bind");
  } break;
    //....
  default:
    throw SocketException("bind_unknown_protocol");
  }

  // listen
  if (listen(sd, queueSize) == -1) {
    throw SocketException("listen");
  }
}

/*
 * accept new socket connection and return client socket
 */
UnixLowLevelSocket *UnixLowLevelSocket::accept() {
  socklen_t sin_size;
  struct sockaddr_in their_addr;
  sin_size = sizeof(struct sockaddr_in);
  int newsd;
  if ((newsd = ::accept(sd, (struct sockaddr *)((&their_addr)), &sin_size)) ==
      -1)
    throw SocketException("accept");
  // if ((newsd = ::accept(sd, NULL,NULL)) ==-1) throw
  // SocketException(strerror(errno));

  // return socket with given descriptor
  return new UnixLowLevelSocket(newsd, inet_ntoa(their_addr.sin_addr));
}

/*
 * connect to scoket
 */
void UnixLowLevelSocket::connect(std::string address, int port, int protocol) {
  int tries = 10;
  in_addr *inaddr = NULL;
  hostent *host = NULL;

  // if reuse
  if (reuse) {
    const int on = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  }

  // connect to unix or inet socket
  switch (protocol) {
  case LowLevelSocket::AF_INET_: {
    host = gethostbyname(address.c_str());
    if (host == NULL)
      throw SocketException("gethostbyname");
    inaddr = (in_addr *)host->h_addr;
    struct sockaddr_in addr;
    addr.sin_addr = *inaddr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    // try for tries
    for (int i = 0; i < tries; i++) {
      if (::connect(sd, (struct sockaddr *)((&addr)), sizeof(addr)) >= 0)
        break;
      sleep(1);
      if (i == tries - 1)
        throw SocketException("connect");
      this->addr = inet_ntoa(addr.sin_addr);
    }
    break;
  case LowLevelSocket::AF_UNIX_: {
    struct sockaddr_un addr;
    strcpy(addr.sun_path, address.c_str());
    addr.sun_family = AF_UNIX;
    for (int i = 0; i < tries; i++) {
      if (::connect(sd, (struct sockaddr *)((&addr)), sizeof(addr)) >= 0)
        break;
      usleep(10);
      if (i == tries - 1)
        throw SocketException("connect");
    }

    this->addr = address.c_str(); //

  } break;

  //....
  default:
    throw SocketException("bad_socket_protocol");
  }
  }
}

/*
 * receive the data
 */
int UnixLowLevelSocket::receive(char *buf, int size) {

  int r;
  if (!this->unblocking) {
    // blocking
    r = recv(sd, buf, size, 0);
    if (r <= 0)
      throw SocketException("recv"); // if blocking mode -1 throw exeption
                                     // in unblocking -1 is no data means
  } else {
    // unblocking  - we can do it safety
    sem->wait();
    r = recv(sd, buf, size, 0);
    sem->post();
  }
  return r;
}

/*
 * set unblocking or sync mode (default)
 */
void UnixLowLevelSocket::setUnblocking(bool unblocking) {
  if (unblocking)
    fcntl(sd, F_SETFL, O_NONBLOCK);
  else
    fcntl(sd, F_SETFL, O_SYNC);

  this->unblocking = unblocking;
}

/*
 *bind and listen with int address (can listen to all interfaces) - see string
 *version
 */
void UnixLowLevelSocket::bindAndListen(int address, int port, int protocol,
                                       int queueSize) {
  // reuse
  if (reuse) {
    const int on = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  }

  switch (protocol) {
  case LowLevelSocket::AF_INET_: {
    struct sockaddr_in my_addr;
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    switch (address) {
    case LowLevelSocket::INADDR_ANY_:
      my_addr.sin_addr.s_addr = INADDR_ANY;
      break;
    default:
      my_addr.sin_addr.s_addr = address;
    }
    bzero(&(my_addr.sin_zero), 8);
    if (bind(sd, (struct sockaddr *)((&my_addr)), sizeof(struct sockaddr)) ==
        -1)
      throw SocketException("bind");
  } break;
  case LowLevelSocket::AF_UNIX_: {
    throw SocketException("not implemented");
  } break;
    //....
  default:
    throw SocketException("bind_unknown_protocol");
  }

  if (listen(sd, queueSize) == -1) {
    throw SocketException("listen");
  }
}

/*
 * init socket
 */
void UnixLowLevelSocket::initialize(int domain, int type, int protocol) {

  // create semaphore - we can use platform factory-but we work on unix version
  // now
  sem = new UnixSemaphore();
  sem->open();

  unblocking = false;

  int sdomain, stype;

  // set params
  switch (domain) {
  case LowLevelSocket::AF_INET_:
    sdomain = AF_INET;
    break;
  case LowLevelSocket::AF_UNIX_:
    sdomain = AF_UNIX;

    break;
    //...
  default:
    sdomain = AF_INET;
  }

  switch (type) {
  case LowLevelSocket::SOCK_STREAM_:
    stype = SOCK_STREAM;
    break;
  default:
    stype = SOCK_STREAM;
  }

  sd = socket(sdomain, stype, protocol);
  if (sd <= 0)
    throw SocketException("socket");

  const int on = 1;
  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}
/*
 * close socket
 */
void UnixLowLevelSocket::close() { ::close(sd); }

UnixLowLevelSocket::~UnixLowLevelSocket() {
  // TODO Auto-generated destructor stub
}
