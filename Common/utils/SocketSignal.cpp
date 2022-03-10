#include "SocketSignal.h"
#include "PlatformFactory.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>

/* Constructor of SocketSignal. Creates new SocketSignal and sets
 * its name that will be used as part of the name of the socket and
 * the role (waiter or sender)
 * */
SocketSignal::SocketSignal(std::string name, bool role) : Signal(name, role) {

  if (role == ROLE_WAITER) {
    // if the role is waiter - create new socket from factory,set params and do
    // listening
    socket = PlatformFactory::getInstance()->createLowLevelSocket();
    socket->initialize(LowLevelSocket::AF_UNIX_, LowLevelSocket::SOCK_STREAM_,
                       0);
    socket->setReuse(true);
    // name is used for create path to socket map in filesystem
    socket->bindAndListen("/tmp/signal_" + name, 0, LowLevelSocket::AF_UNIX_,
                          10);
  }
}
/* Make a signal to asleep waitor  */
void SocketSignal::signal() {
  try {
    // for each signaling create new socket. its reuse is a problem
    socket = PlatformFactory::getInstance()->createLowLevelSocket();
    socket->initialize(LowLevelSocket::AF_UNIX_, LowLevelSocket::SOCK_STREAM_,
                       0);
    socket->setReuse(true);
    // connect makes waitor asleep
    socket->connect(std::string("/tmp/signal_" + name), 0,
                    LowLevelSocket::AF_UNIX_);
    socket->close();
    delete socket;
  } catch (SocketException &e) {
    std::cout << "signal_signal" << e.what() << std::endl;
    perror("signal");
  }
}

/* Wait for signal = waiting for accepting connection  */
void SocketSignal::wait() {
  try {
    // accept new connection
    LowLevelSocket *s = socket->accept();
    s->close();
    // and close it
    delete s;

  } catch (SocketException &e) {
    std::cout << "signal_wait:" << e.what() << std::endl;
    perror("wait");
  }
}

SocketSignal::~SocketSignal() { delete socket; }
