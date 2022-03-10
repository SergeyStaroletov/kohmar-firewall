

#ifndef SOCKETSIGNAL_H_
#define SOCKETSIGNAL_H_

#include "LowLevelSocket.h"
#include "Signal.h"
#include <string>

/* Class that represents a realization of abstract class Signal by using unix
 * sockets  */
class SocketSignal : public Signal {
public:
  SocketSignal(std::string name, bool role);
  void signal();
  void wait();
  virtual ~SocketSignal();

private:
  LowLevelSocket *socket;
};

#endif /* SOCKETSIGNAL_H_ */
