#ifndef DAEMONSERVICE_H_
#define DAEMONSERVICE_H_

#include "Logger.h"
#include "Service.h"
#include <signal.h>

/*
 * successor of Service. Can install a new service as a daemon or stop it
 */
class DaemonService : public Service {
public:
  DaemonService();
  void setLogger(Logger *logger) { this->logger = logger; }
  void setup();
  void stop();
  void stopWorker();
  void sendUserSignalToWorker();
  void startWithMonitoring(int (*startFunc)(void), int (*stopFunc)(void),
                           int (*rereadCfgFun)(void));

  const static int CHILD_NEED_RESTART = 1;
  const static int CHILD_NEED_TERMINATE = 2;

  virtual ~DaemonService();
  // private:
  static void signal_handler(int sig, siginfo_t *si, void *ptr);
  // static void  signal_handler(int sig) ;

  int workProc();
  static int (*startFunc)(void);
  static int (*stopFunc)(void);
  static int (*rereadCfgFun)(void);

  static Logger *logger;
  static Logger *sysLogger;
};

#endif /* DAEMONSERVICE_H_ */
