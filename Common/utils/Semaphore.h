#ifndef SEMAPHORE_H_
#define SEMAPHORE_H_

#include <string>

/*
 * Abstract class for providing semaphore locking
 */
class Semaphore {
public:
  Semaphore();
  virtual void open(std::string name) = 0; // open named semaphore
  virtual void open() = 0;                 // open unnnamed
  virtual void post() = 0;                 // post = V() operation
  virtual void wait() = 0;                 // wait = P() operation
  virtual void close() = 0;                // close semaphore
  virtual ~Semaphore();
};

#endif /* SEMAPHORE_H_ */
