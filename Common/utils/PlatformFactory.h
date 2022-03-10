#ifndef PLATFORMFACTORY_H_
#define PLATFORMFACTORY_H_

#include <string>

#include "LowLevelSocket.h"
#include "LowLevelThread.h"

#include "Semaphore.h"
#include "Service.h"

/*
 * Singleton class to provide plarform-dependent actions
 * Works as a factory to create current platform subclasses of abstract classes
 */
class PlatformFactory {
public:
  // factory for creating threads
  LowLevelThread *createLowLevelThread();
  // factory for creating sockets
  LowLevelSocket *createLowLevelSocket();

  // singleton with lazy init
  static PlatformFactory *getInstance() {
    if (instance == NULL)
      return instance = new PlatformFactory();
    return instance;
  }
  // checks if the process is already running
  bool checkRunningAndSavePID(std::string processName);
  bool checkRunningAndSavePID(std::string processName, int pid);
  // finds pid in a pid file by given process
  int findPID(std::string processName);

  // kills process by a pid
  void kill(int pid);
  void killWithSignal(int pid, int sig);

  // factory for creating a service
  Service *createService();
  // factory for creating a semaphore
  Semaphore *createSemaphore();

private:
  static PlatformFactory *instance;
  PlatformFactory();

  std::string calculateFilenameToStorePID(std::string processName);

  virtual ~PlatformFactory();
};

#endif /* PLATFORMFACTORY_H_ */
