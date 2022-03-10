#ifndef POSIXTHREAD_H_
#define POSIXTHREAD_H_

#include "LowLevelThread.h"

#include <pthread.h>

/*
 * Posix thread realization of LovLevel Thread
 */
class PosixThread : public LowLevelThread {
public:
  PosixThread();
  void create(void *(*threadFunc)(void *), void *param) {
    pthread_create(&thread, NULL, threadFunc, param);
  }
  void join() { pthread_join(thread, NULL); }

  virtual ~PosixThread();

private:
  pthread_t thread;
};

#endif /* POSIXTHREAD_H_ */
