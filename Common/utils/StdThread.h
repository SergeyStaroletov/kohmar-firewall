#ifndef STDTHREAD_H
#define STDTHREAD_H

#include "Thread.h"
#include <QObject>
#include <thread>

/*
 * A QT-friendly wrapper for std::thread
 */
class StdThread : public QObject {
  Q_OBJECT
public:
  StdThread();
  virtual ~StdThread();

  inline void start() {
    is_stopped = false;
    threadik.reset(new std::thread(StdThread::exec, this));
  }

  inline void wait() {
    if (threadik != nullptr) {
      threadik->join();
      threadik = nullptr;
    }
  }
  inline void terminate() { is_stopped = true; }

protected:
  virtual void run() = 0;
  bool is_stopped;

private:
  std::unique_ptr<std::thread> threadik = nullptr;
  static void exec(StdThread *stdThread) { stdThread->run(); }
};

#endif // STDTHREAD_H
