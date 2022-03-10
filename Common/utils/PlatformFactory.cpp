#include "PlatformFactory.h"

using namespace std;

// platform specific UNIX includes
#if defined(__GNUC__) && defined(__unix__)
#include "DaemonService.h"
#include "PosixThread.h"
#include "UnixLowLevelSocket.h"
#include "UnixSemaphore.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

// windows includes - not implemented
#elif defined(WIN32)
// include something else
#endif

// instance of this
PlatformFactory *PlatformFactory::instance = NULL;

PlatformFactory::PlatformFactory() {}

/*
 * factory to create new lowlevel thread
 */
LowLevelThread *PlatformFactory::createLowLevelThread() {

#if defined(__GNUC__) && defined(__unix__)
  return new PosixThread();
#elif defined(WIN32)
  // return something else
#endif
}

/*
 * factory to create low level socket
 */
LowLevelSocket *PlatformFactory::createLowLevelSocket() {

#if defined(__GNUC__) && defined(__unix__)
  return new UnixLowLevelSocket();
#elif defined(WIN32)
  // return something else
#endif
}
/*
 * factory to create semaphore
 */

Semaphore *PlatformFactory::createSemaphore() {

#if defined(__GNUC__) && defined(__unix__)

  return new UnixSemaphore();

#elif defined(WIN32)
  // return something else
#endif
}

/* how can we calculate a file for pid storing? */
std::string
PlatformFactory::calculateFilenameToStorePID(std::string processName) {
  return "/var/run/" + processName + ".pid";
}

/*
 *  create a platform specific background service - for *nix it is a daemon
 */
Service *PlatformFactory::createService() {

#if defined(__GNUC__) && defined(__unix__)

  return new DaemonService();

#elif defined(WIN32)
  // need to implement someday
  return NULL;
#endif
}

/*
 * check weather the program is run
 */
bool PlatformFactory::checkRunningAndSavePID(std::string processName) {
#if defined(__GNUC__) && defined(__unix__)
  // get name
  std::string pidFile = calculateFilenameToStorePID(processName);
  // try to open file
  int fd = open(pidFile.c_str(), O_RDWR | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  if (fd < 0) {
    throw ServiceException("can`t open PID file " + pidFile);
  }

  // try to lock it
  if (lockf(fd, F_TLOCK, 0)) {
    if (errno == EACCES || errno == EAGAIN) {
      close(fd);
      return 1; // already locked - by another process instance
    }
    throw ServiceException("can`t lock PID file");
  }

  int r = 0;
  r = ftruncate(fd, 0);
  char buf[255];
  sprintf(buf, "%d", (int)getpid());
  r = write(fd, buf, strlen(buf));
  (void)r;
  return 0;

#elif defined(WIN32)
  // need to implement someday
  return false;
#endif
}

/*
 * check weather the program is run
 */
bool PlatformFactory::checkRunningAndSavePID(std::string processName, int pid) {
#if defined(__GNUC__) && defined(__unix__)
  // get name
  std::string pidFile = calculateFilenameToStorePID(processName);
  // try to open file
  int fd = open(pidFile.c_str(), O_RDWR | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  if (fd < 0) {
    throw ServiceException("can`t open PID file " + pidFile);
  }

  // try to lock it
  if (lockf(fd, F_TLOCK, 0)) {
    if (errno == EACCES || errno == EAGAIN) {
      close(fd);
      return 1; // already locked - by another process instance
    }
    throw ServiceException("can`t lock PID file");
  }

  int r = 0;
  r = ftruncate(fd, 0);
  char buf[255];
  sprintf(buf, "%d", pid);
  r = write(fd, buf, strlen(buf));
  (void)r;
  return 0;

#elif defined(WIN32)
  // need to implement someday
  return false;
#endif
}

/*
 * return pid for process name
 */
int PlatformFactory::findPID(std::string processName) {
#if defined(__GNUC__) && defined(__unix__)

  std::string pidFile = calculateFilenameToStorePID(processName);
  // read pid from file
  int fd = open(pidFile.c_str(), O_RDWR | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0) {
    throw ServiceException("can`t open PID file");
  }
  char buf[255];
  memset(buf, 0, sizeof(buf));
  if (read(fd, buf, sizeof(buf)) <= 0)
    return -1;
  close(fd);

  return atoi(buf);

#elif defined(WIN32)
  // need to implement someday
  return 0;
#endif
}

/*
 * kill process by pid
 */
void PlatformFactory::kill(int pid) {
#if defined(__GNUC__) && defined(__unix__)
  ::kill(pid, SIGTERM);
#endif
}

void PlatformFactory::killWithSignal(int pid, int sig) {
#if defined(__GNUC__) && defined(__unix__)
  ::kill(pid, sig);
#endif
}

PlatformFactory::~PlatformFactory() {
  // TODO Auto-generated destructor stub
}
