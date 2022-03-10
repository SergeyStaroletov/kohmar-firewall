#ifndef NULLLOGGER_H_
#define NULLLOGGER_H_

#include "Logger.h"

class NullLogger : public Logger {
public:
  NullLogger();
  void log(std::string logMessage) { (void)logMessage; }
  virtual ~NullLogger();
};

#endif /* NULLLOGGER_H_ */
