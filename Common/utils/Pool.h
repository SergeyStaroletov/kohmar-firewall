
#include <iostream>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <vector>

using namespace std;
/*
WorkerThread class
This class needs to be sobclassed by the user.
*/
class Task {
public:
  int taskNum;

  unsigned virtual run(int coreNum) {
    (void)coreNum;
    return 0;
  }

  Task(int taskNum) : taskNum(taskNum) {}
  virtual ~Task() {}
};

/*
ThreadPool class manages all the ThreadPool related activities. This includes
keeping track of idle threads and ynchronizations between all threads.
*/
class TaskPool {
public:
  TaskPool();
  TaskPool(int maxTasksCount);
  virtual ~TaskPool();

  void stopAllTasks(int maxPollSecs);

  bool addTask(Task *task);
  bool fetchWork(Task **task);

  void initialize();

  static void *run(void *param);

  static pthread_mutex_t mutexSyncTasks;
  static pthread_mutex_t mutexTaskComplete;

private:
  int maxTasks;

  pthread_cond_t condCrit;
  sem_t availableWork;
  sem_t availableTasks;

  // WorkerThread ** workerQueue;
  vector<Task *> tasksQueue;

  int topIndex;
  int bottomIndex;

  int incompleteWork;

  int queueSize;
};
