#include "PosixThread.h"


/*
void pthread_sleep(int ms) {
	struct timespec timetoexpire;
	struct timeval today;
	int sec = ms / 1000;
	int msec = ms % 1000;
	gettimeofday(&today, NULL);
	timetoexpire.tv_sec = today.tv_sec + sec;
	long nano = (long) today.tv_usec * 1000 + (long) msec * 1000000;
	if (nano > 999999999) {
		timetoexpire.tv_sec += 1;
		timetoexpire.tv_nsec = nano - 999999999;
	} else {
		timetoexpire.tv_nsec = nano;
	}
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	//(void) pthread_mutex_lock(&mutex);
	do {
		pthread_cond_timedwait(&cond, &mutex, &timetoexpire);
		gettimeofday(&today, NULL);
		if (today.tv_sec > timetoexpire.tv_sec)
			break;
		else {
			if (today.tv_sec == timetoexpire.tv_sec)
				if (today.tv_usec * 1000000 > timetoexpire.tv_nsec)
					break;
		}
	} while (true);
	//(void) pthread_mutex_unlock(&mutex);
}
*/


PosixThread::PosixThread() {
	// TODO Auto-generated constructor stub

}

PosixThread::~PosixThread() {
	// TODO Auto-generated destructor stub
}
