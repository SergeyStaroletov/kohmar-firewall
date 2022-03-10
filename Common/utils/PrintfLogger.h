#ifndef PRINTFLOGGER_H_
#define PRINTFLOGGER_H_

#include "Logger.h"

/*
 *Realization of the abstract class Logger which uses std::cout
 */
class PrintfLogger : public Logger {
public:
  PrintfLogger();
  void log(std::string logMessage); // log() realization with cout
  void log_n(char c);               // log() realization with cout

  virtual ~PrintfLogger();
};

#endif /* PRINTFLOGGER_H_ */
