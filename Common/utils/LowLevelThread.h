#ifndef LOWLEVELTHREAD_H_
#define LOWLEVELTHREAD_H_

/*
 * Abstract class for a low level thread, which is used by Thread as a composite
 * class to provide realization of a platform-specific thread
 */

class LowLevelThread {
public:
  LowLevelThread();
  virtual void create(void *(*threadFunc)(void *),
                      void *param) = 0; // create a thread with the specified
                                        // function and params
  virtual void join() = 0;              // join, wait

  virtual ~LowLevelThread();

protected:
};

#endif /* LOWLEVELTHREAD_H_ */
