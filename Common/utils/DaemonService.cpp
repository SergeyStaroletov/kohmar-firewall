#include "DaemonService.h"
#include "SyslogLogger.h"

#include "Logger.h"
#include "PlatformFactory.h"
#include "PrintfLogger.h"

#include <errno.h>
#include <execinfo.h>
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
#include <wait.h>

using namespace std;

#include "DaemonService.h"

int (*DaemonService::startFunc)() = NULL;
int (*DaemonService::stopFunc)() = NULL;
int (*DaemonService::rereadCfgFun)() = NULL;
Logger *DaemonService::logger = NULL;
Logger *DaemonService::sysLogger = NULL;

void DaemonService::signal_handler(int sig, siginfo_t *si, void *ptr) {
  void *ErrorAddr;
  void *Trace[16];
  int x;
  int TraceSize;
  char **Messages;
  (void)si;

  sysLogger->log("Caught signal:" + string(strsignal(sig)));

  if (sig == SIGUSR1) {
    sysLogger->log("Received user signal.");
    if (rereadCfgFun != NULL)
      (*rereadCfgFun)();

    return;
  }

  if (sig == SIGTERM) {
    sysLogger->log("Received sigterm signal. Stopping...");
    if (stopFunc != NULL)
      (*stopFunc)();
    exit(CHILD_NEED_TERMINATE);
  }

  // found error address
#if __WORDSIZE == 64
  ErrorAddr = (void *)((ucontext_t *)ptr)->uc_mcontext.regs[0];
#else
  ErrorAddr = (void *)((ucontext_t *)ptr)->uc_mcontext.gregs[REG_EIP];
#endif
  // backtrace
  TraceSize = backtrace(Trace, 16);
  Trace[1] = ErrorAddr;
  // know more
  Messages = backtrace_symbols(Trace, TraceSize);
  if (Messages) {
    sysLogger->log("== Backtrace ==");
    for (x = 1; x < TraceSize; x++) {
      sysLogger->log(Messages[x]);
    }
    sysLogger->log("== End Backtrace ==");
    free(Messages);
  }
  sysLogger->log("Stopped");

  if (stopFunc != NULL)
    (*stopFunc)();
  // we need a child restart
  exit(CHILD_NEED_RESTART);
}

DaemonService::DaemonService() {
  // TODO Auto-generated constructor stub
}

/*
 * Demonize the current process.
 */
void DaemonService::setup() {

  sysLogger = new SyslogLogger();
  sysLogger->setName(logger->getName());

  sysLogger->log("Configuring daemon...");

  pid_t pid;
  struct rlimit limits;
  struct sigaction sa;

  umask(0);

  if (getrlimit(RLIMIT_NOFILE, &limits) < 0) {
    throw ServiceException("can`t get RLIMIT_NOFILE");
  }

  // fork process and disconnect it from parent
  if ((pid = fork()) < 0) {
    throw ServiceException("fork error");

  } else if (0 != pid) {
    exit(0); // stop parent process
  }

  // create seance
  if ((setsid()) == (pid_t)-1) {
    throw ServiceException("setsig error");
  }
  // ignoring sighup
  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGHUP, &sa, NULL) < 0) {
    throw ServiceException("can`t ignore SIGHUP");
  }

  // fork again
  if ((pid = fork()) < 0) {
    throw ServiceException("fork error");

  } else if (0 != pid) {
    exit(0);
  }

  // chdir to /
  if (chdir("/") < 0) {
    throw ServiceException("can`t chdir() to /");
  }
  // close all resources
  if (limits.rlim_max == RLIM_INFINITY)
    limits.rlim_max = 1024;

  u_int32_t idx;
  for (idx = 0; idx < limits.rlim_max; ++idx) {
    close(idx);
  }
  // reopen stdout to /dev/null and another strems to it
  int fd0 = open("/dev/null", O_RDWR);
  int fd1 = dup(0);
  int fd2 = dup(0);

  if (fd0 != 0 || fd1 != 1 || fd2 != 2) {
    throw ServiceException("bad file descriptors");
  }

  sysLogger->log("Prepare to be daemon ok");

  // check the running - and save new! pid
  if (PlatformFactory::getInstance()->checkRunningAndSavePID(getName())) {
    sysLogger->log("Daemon is already running");
    throw ServiceException("Error. Daemon is already running");
  }

  // set handler to signal
  // signal(SIGTERM, signal_handler);
  sysLogger->log("Daemonize done");
}

/*
 * stops the daemon service
 */

void DaemonService::stop() {

  // get pid from pid file of running daemon
  int pid = PlatformFactory::getInstance()->findPID(this->getName());
  // check running
  if (pid == -1) {
    sysLogger->log("Error. Daemon is not running");
    throw ServiceException("Daemon is not running");

  } else
    // kill it
    PlatformFactory::getInstance()->kill(pid);
}

void DaemonService::stopWorker() {

  // get pid from pid file of running daemon
  int pid =
      PlatformFactory::getInstance()->findPID(this->getName() + "_worker");
  // check running
  if (pid == -1) {
    sysLogger->log("Error. Worker daemon is not running");
    throw ServiceException("Worker daemon is not running");
  } else
    // kill it
    PlatformFactory::getInstance()->kill(pid);
}

void DaemonService::sendUserSignalToWorker() {

  // get pid from pid file of running daemon
  int pid =
      PlatformFactory::getInstance()->findPID(this->getName() + "_worker");
  // check running
  if (pid == -1) {
    sysLogger->log("Error. Worker daemon is not running");
    throw ServiceException("Worker daemon is not running");

  } else
    // kill it
    PlatformFactory::getInstance()->killWithSignal(pid, SIGUSR1);
}

DaemonService::~DaemonService() {
  // TODO Auto-generated destructor stub
}

int DaemonService::workProc() {
  struct sigaction sigact;
  sigset_t sigset;
  int signo;
  int status;
  sigact.sa_flags = SA_SIGINFO;
  sigact.sa_sigaction = signal_handler;
  sigemptyset(&sigact.sa_mask);

  sigaction(SIGFPE, &sigact, 0);  // FPU
  sigaction(SIGILL, &sigact, 0);  // wrong instruction
  sigaction(SIGSEGV, &sigact, 0); // segfault
  sigaction(SIGBUS, &sigact, 0);  // bus memory error
  sigaction(SIGTERM, &sigact, 0);
  sigaction(SIGUSR1, &sigact, 0);

  sigemptyset(&sigset);

  // sigaddset(&sigset, SIGQUIT);
  // sigaddset(&sigset, SIGINT);
  // sigaddset(&sigset, SIGTERM);
  // sigprocmask(SIG_BLOCK, &sigset, NULL);

  struct rlimit lim;
#define FD_LIMIT 1024 * 10

  lim.rlim_cur = FD_LIMIT;
  lim.rlim_max = FD_LIMIT;
  setrlimit(RLIMIT_NOFILE, &lim);

  sysLogger->log("Starting work process...");
  // start the threads
  status = (*startFunc)();
  sysLogger->log("Start work process done");

  if (!status) {
    for (;;) {
      sigwait(&sigset, &signo);

      if (signo == SIGUSR1) {
        // reread config
        if (rereadCfgFun != NULL)
          (*rereadCfgFun)();
      } else {
        break;
      }
    }

    // close all
    //	SenderDaemonStopWork() ;
  } else {
    sysLogger->log("Create work thread failed");
  }

  sysLogger->log("[DAEMON] Stopped");
  return CHILD_NEED_TERMINATE;
}

void DaemonService::startWithMonitoring(int (*startFunc)(void),
                                        int (*stopFunc)(void),
                                        int (*rereadCfgFun)(void)) {

  this->startFunc = startFunc;
  this->stopFunc = stopFunc;
  this->rereadCfgFun = rereadCfgFun;

  int pid = 0;
  int status = 0;
  int need_start = 1;
  sigset_t sigset;
  siginfo_t siginfo;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGQUIT);
  sigaddset(&sigset, SIGINT);
  // sigaddset(&sigset, SIGTERM);
  // sigaddset(&sigset, SIGCHLD);
  sigaddset(&sigset, SIGCHLD);
  sigprocmask(SIG_BLOCK, &sigset, NULL);

  for (;;) {
    if (need_start) {
      pid = fork();
      if (pid != 0) {
        sysLogger->log("Fork with pid=" + PrintfLogger::itos(pid));

        if (PlatformFactory::getInstance()->checkRunningAndSavePID(
                getName() + "_worker", pid)) {
          sysLogger->log("worker daemon is already running");
          exit(CHILD_NEED_TERMINATE);
        }
      }
    }
    need_start = 1;
    if (pid == -1) {
      sysLogger->log("Monitor: fork failed with " + string(strerror(errno)));
    } else if (!pid) {
      // we are child
      status = this->workProc();
      exit(status);
    } else // parent
    {
      sigwaitinfo(&sigset, &siginfo);
      sysLogger->log("Monitor: wait status...");
      if (siginfo.si_signo == SIGCHLD) {

        sysLogger->log("Monitor: got child status...");
        wait(&status);

        sysLogger->log("Monitor: got exit status");

        status = WEXITSTATUS(status);
        if (status == CHILD_NEED_TERMINATE) {
          sysLogger->log("Monitor: children stopped");
          break;
        } else if (status == CHILD_NEED_RESTART) // restart
        {
          sysLogger->log("Monitor: children restart");
        }
      } else if (siginfo.si_signo == SIGUSR1) // reread config
      {
        sysLogger->log("Monitor: resend signal to pid=" +
                       PrintfLogger::itos(pid));
        kill(pid, SIGUSR1); // resend signal
        need_start = 0;     // don't restart
      } else {
        sysLogger->log("Monitor: signal " +
                       string(strsignal(siginfo.si_signo)));
        // kill child
        kill(pid, SIGTERM);
        status = 0;
        break;
      }
    }
  }
  sysLogger->log("Monitor: stopped");
  // delete pid file
  // unlink(PlatformFactory::getInstance()->calculateFilenameToStorePID(this->getName()));
}
