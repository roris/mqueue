#include "mqueue.h"

struct message {
	int next;		/* index of the next message */
	int prev;		/* index of the previous message */
	short flags;
	unsigned int size;
	char buffer[1];
};

struct mqueue {
	long curmsg;
	long msgsize;		/* sizeof(message) - 1 + msg_size */
	long maxmsg;
	int free_tail;
	int free_head;
	int prio_tail[MQ_PRIO_MAX];
	int prio_head[MQ_PRIO_MAX];
	long namelen;
	wchar_t name[MAX_PATH];
	char buffer[1];
};

struct mqd {
	HANDLE mutex;
	HANDLE map;		/* handle to the shared memory */
	HANDLE tid;
	HANDLE not_full;
	HANDLE not_empty;
	HANDLE not_empty_prio[MQ_PRIO_MAX];
	volatile struct mqueue *queue;
	struct mqd *next;	/* next queue descriptor */
	struct mqd *prev;	/* previous queue descriptor */
	struct mq_attr attr;	/* flags for the current queue */
	int flags;		/* private flags */
	int eflags;
};

struct mqdtable {
	CRITICAL_SECTION lock;
	struct mqd_list {
		struct mqd *tail;
		struct mqd *head;
	} free_mqd, open_mqd;
	int curopen;
	struct mqd desc[MQ_OPEN_MAX];
};
