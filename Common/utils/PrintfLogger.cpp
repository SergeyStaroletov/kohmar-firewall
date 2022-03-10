#include "PrintfLogger.h"
#include <iostream>

PrintfLogger::PrintfLogger() {
  // TODO Auto-generated constructor stub
}

/*
 * log() realization with cout
 */
void PrintfLogger::log(std::string logMessage) {

  std::cout << logMessage << std::endl;
}
void PrintfLogger::log_n(char c) { std::cout << c; }

PrintfLogger::~PrintfLogger() {
  // TODO Auto-generated destructor stub
}
