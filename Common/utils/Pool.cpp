#include "Pool.h"
#include <stdlib.h>

using namespace std;

pthread_mutex_t TaskPool::mutexSyncTasks = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TaskPool::mutexTaskComplete = PTHREAD_MUTEX_INITIALIZER;

struct Param2 {
  TaskPool *pool;
  int num;
};

TaskPool::TaskPool() { TaskPool(2); }

TaskPool::TaskPool(int maxThreads) {
  if (maxThreads < 1)
    maxThreads = 1;

  // mutexSync = PTHREAD_MUTEX_INITIALIZER;
  // mutexWorkCompletion = PTHREAD_MUTEX_INITIALIZER;

  pthread_mutex_lock(&mutexSyncTasks);
  this->maxTasks = maxThreads;
  this->queueSize = maxThreads;
  // workerQueue = new WorkerThread *[maxThreads];
  tasksQueue.resize(maxThreads, NULL);
  topIndex = 0;
  bottomIndex = 0;
  incompleteWork = 0;
  sem_init(&availableWork, 0, 0);
  sem_init(&availableTasks, 0, queueSize);
  pthread_mutex_unlock(&mutexSyncTasks);
}

void TaskPool::initialize() {
  for (int i = 0; i < maxTasks; ++i) {
    pthread_t tempThread;
    Param2 *param = new Param2;

    param->num = i;
    param->pool = this;
    pthread_create(&tempThread, NULL, &TaskPool::run, (void *)param);
    // threadIdVec[i] = tempThread;
  }
}

TaskPool::~TaskPool() { tasksQueue.clear(); }

void TaskPool::stopAllTasks(int maxPollSecs = 2) {
  while (incompleteWork > 0) {
    sleep(maxPollSecs);
  }
  // cout << "All Done!! Wow! That was a lot of work!" << endl;
  sem_destroy(&availableWork);
  sem_destroy(&availableTasks);
  pthread_mutex_destroy(&mutexSyncTasks);
  pthread_mutex_destroy(&mutexTaskComplete);
}

bool TaskPool::addTask(Task *workerThread) {
  pthread_mutex_lock(&mutexTaskComplete);
  incompleteWork++;
  // cout << "assignWork...incomapleteWork=" << incompleteWork << endl;
  pthread_mutex_unlock(&mutexTaskComplete);

  sem_wait(&availableTasks);

  pthread_mutex_lock(&mutexSyncTasks);
  // workerVec[topIndex] = workerThread;
  tasksQueue[topIndex] = workerThread;
  // cout << "Assigning Worker[" << workerThread->id << "] Address:[" <<
  // workerThread << "] to Queue index [" << topIndex << "]" << endl;
  if (queueSize != 1)
    topIndex = (topIndex + 1) % (queueSize - 1);
  sem_post(&availableWork);
  pthread_mutex_unlock(&mutexSyncTasks);
  return true;
}

bool TaskPool::fetchWork(Task **workerArg) {
  sem_wait(&availableWork);

  pthread_mutex_lock(&mutexSyncTasks);
  Task *workerThread = tasksQueue[bottomIndex];
  tasksQueue[bottomIndex] = NULL;
  *workerArg = workerThread;
  if (queueSize != 1)
    bottomIndex = (bottomIndex + 1) % (queueSize - 1);
  sem_post(&availableTasks);
  pthread_mutex_unlock(&mutexSyncTasks);
  return true;
}

void *TaskPool::run(void *param) {
  Param2 *passedParam = (Param2 *)param;
  Task *worker = NULL;

  while (((TaskPool *)passedParam->pool)->fetchWork(&worker)) {
    if (worker) {
      worker->run(passedParam->num);

      delete worker;
      worker = NULL;
    }

    pthread_mutex_lock(&(((TaskPool *)passedParam->pool)->mutexTaskComplete));
    // cout << "Thread " << pthread_self() << " has completed a Job !" << endl;
    ((TaskPool *)passedParam->pool)->incompleteWork--;
    pthread_mutex_unlock(&(((TaskPool *)passedParam->pool)->mutexTaskComplete));
  }
  return 0;
}
