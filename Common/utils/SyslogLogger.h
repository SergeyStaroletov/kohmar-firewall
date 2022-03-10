#ifndef SYSLOGLOGGER_H_
#define SYSLOGLOGGER_H_

#include "Logger.h"

/*
 * Realization of logging using syslog
 */
class SyslogLogger : public Logger {
public:
  SyslogLogger();
  void log(std::string logMessage);
  void setName(std::string name);
  virtual ~SyslogLogger();
};

#endif /* SYSLOGLOGGER_H_ */
