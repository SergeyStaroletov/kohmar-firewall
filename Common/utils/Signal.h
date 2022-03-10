

#ifndef SIGNAL_H_
#define SIGNAL_H_

#include <string>

/*
 * Abstract class for providing signal capabilities
 */
class Signal {
public:
  static const bool ROLE_WAITER = false; // we are waiting for a signal
  static const bool ROLE_SENDER = true;  // we are sending the signal

  Signal(std::string name, bool role) {
    this->name = name;
    this->role = role;
  }
  virtual void signal() = 0; // do signal
  virtual void wait() = 0;   // wait signal
  virtual ~Signal();

protected:
  std::string name;
  bool role;
};

#endif /* SIGNAL_H_ */
