#include "UnixSemaphore.h"

#include <fcntl.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
/*
 * create mutex
 */
UnixSemaphore::UnixSemaphore() {
  // TODO Auto-generated constructor stub
  pthread_mutex_init(&cs_mutex, NULL);
}

/*
 *  post=mutex unlock
 */
void UnixSemaphore::post() {
  if (pthread_mutex_unlock(&cs_mutex) != 0)
    perror("nutex_unlock");
}

void UnixSemaphore::close() {}

void UnixSemaphore::open(std::string name) { (void)name; }

/*
 * wait = mutex lock
 */
void UnixSemaphore::wait() {
  if (pthread_mutex_lock(&cs_mutex) != 0)
    perror("mutex_lock");
}

UnixSemaphore::~UnixSemaphore() {
  // TODO Auto-generated destructor stub
}
