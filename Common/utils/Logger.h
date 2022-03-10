#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>
#include <string>

/*
 * Abstract class for logging capabilities
 */
class Logger {
public:
  Logger();
  virtual void log(std::string logMessage) = 0; // log the data - virtual
  virtual ~Logger();
  void setName(std::string name) { this->name = name; }
  std::string &getName() { return name; }

  /* static method to convert integer to a std::string*/
  static std::string itos(int data) {
    char buf[10];
    sprintf(buf, "%d", data);
    return buf;
  }

protected:
  std::string name;
};

#endif /* LOGGER_H_ */
