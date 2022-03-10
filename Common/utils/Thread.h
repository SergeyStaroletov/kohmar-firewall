#ifndef THREAD_H_
#define THREAD_H_

#include "LowLevelThread.h"
#include "PlatformFactory.h"

#include <pthread.h>

/*
 * Class for provide mylti-threading
 */
class Thread {
protected:
  // Thread(const Thread& copy);         // copy constructor denied

  // thread function - static wrapper
  static void *ThreadFunc(void *d) {
    ((Thread *)d)->run(); // execute run of thread received from parameter
    return NULL;
  }

private:
  LowLevelThread *systemThread; // lov level thread which does actual threading
public:
  Thread() {
    // get low level thread from a platform
    systemThread = PlatformFactory::getInstance()->createLowLevelThread();
  }
  virtual ~Thread();

  virtual void run() = 0; // run is abstract

  void start() {
    // create a thread
    systemThread->create(ThreadFunc, (void *)this);
  }

  void wait() {
    // wait
    systemThread->join();
  }
};

#endif /* THREAD_H_ */
