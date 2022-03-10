#ifndef UNIXSEMAPHORE_H_
#define UNIXSEMAPHORE_H_

#include "Semaphore.h"

#include <pthread.h>
#include <semaphore.h>
#include <string.h>

/*
 * Posix mutex realization of abstract semaphore (post and wait only)
 */
class UnixSemaphore : public Semaphore {
public:
  UnixSemaphore();
  void open(std::string name);
  void open() {}

  void post();
  void wait();
  void close();
  virtual ~UnixSemaphore();

private:
  sem_t *sem;
  pthread_mutex_t cs_mutex;
};

#endif /* UNIXSEMAPHORE_H_ */
