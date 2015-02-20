#include "mqueue.h"

struct message {
	int		next;		/* index of the next message */
	int		prev;		/* index of the previous message */
	short		flags;
	unsigned int	size;
	char		buffer[1];
};

struct mqueue {
	int		curmsg;
	int		msgsize;	/* sizeof(message) - 1 + msg_size */
	int		maxmsg;
	int		free_tail;
	int		free_head;
	int		prio_tail[MQ_PRIO_MAX];
	int		prio_head[MQ_PRIO_MAX];
	wchar_t		name[MAX_PATH];
	struct message	buffer[1];
};

struct mqd {
	HANDLE			 mutex;
	HANDLE			 map;	/* handle to the shared memory */
	HANDLE			 not_full;
	HANDLE			 not_empty;
	HANDLE			 not_empty_prio[MQ_PRIO_MAX];
	volatile struct mqueue	*queue;
	struct mqd	      	*next;	/* next queue descriptor */
	struct mqd	      	*prev;	/* previous queue descriptor */
	struct mq_attr		 attr;	/* flags for the current queue */
	int			 flags;	/* private flags */
	int			 eflags;
};

struct mqdtable {
	CRITICAL_SECTION lock;
	struct {
		struct mqd	*tail;
		struct mqd	*head;
	} free_mqd, live_mqd;
	int		 	 curopen;
	struct mqd	 	 desc[MQ_OPEN_MAX];
};
