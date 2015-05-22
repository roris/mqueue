#ifndef MQUEUE_H
#define MQUEUE_H

/* not defined by windows */
#ifndef MQ_NO_NONBLOCK
#define O_NONBLOCK	0x10000000L
#endif

#ifndef MQ_NO_O_PRIVATE
#define O_PRIVATE	0x40000000L
#endif

#ifndef MQ_NO_SIGEVENT

#include <pthread.h>

#define SIGEV_NONE	0x1
#define SIGEV_SIGNAL	0x2
#define SIGEV_THREAD	0x4

union sigval {
	int sival_int;
	void *sival_ptr;
};

struct sigevent {
	int sigev_notify;
	int sigev_signo;
	union sigval sigev_value;
	void (__cdecl * sigev_notify_function);
	void *sigev_notify_attributes;
};
#endif

/* MQ constants */
#define MQ_OPEN_MAX	128	/* maximum number of open message queues */
#define MQ_MSG_SIZE	512	/* maximum message size */
#define MQ_MAX_MSG	256	/* maximum number of messages per queue */
#define MQ_PRIO_MAX	16	/* number of priorities */

typedef int mqd_t;

struct mq_attr {
	long mq_flags;
	long mq_maxmsg;
	long mq_msgsize;
	long mq_curmsg;
	long mq_sleepdur;	/* sleep duration in ms */
};

int mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	    unsigned msg_prio);
int mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio);
mqd_t mq_open(const char *name, int oflag, ...);
int mq_close(mqd_t mqdes);

#endif
