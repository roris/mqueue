#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include "mqueue.h"

#define SIZE_TO_WLEN(s)	((s) / sizeof(wchar_t) - 1)
#define MQ_MSG_ALIVE	0x1
#define MQ_MQD_ALIVE	0x1
#define MQ_PREFIX	L"/mq/"
#define MQ_LOCK_SUFFIX	L".lock"
#define MQ_LOCK_LEN	(SIZE_TO_WLEN(sizeof(MQ_LOCK_SUFFIX)))
#define MQ_PREFIX_LEN	(SIZE_TO_WLEN(sizeof(MQ_PREFIX)))
#define MQ_NAME_MAX	((MAX_PATH - MQ_LOCK_LEN) - MQ_PREFIX_LEN)

struct message {
	int	next;		/* index of the next message */
	int	prev;		/* index of the previous message */
	short	flags;
	int	size;
	char	buffer[1];
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
	union {
		HANDLE	 mutex;
		CRITICAL_SECTION critical_section;
	} lock;
	HANDLE		 map;	/* handle to the shared memory */
	union {
		volatile struct mqueue *queue;
		void	*view;
	} mqd_u;
	struct mqd	*next;	/* next queue descriptor */
	struct mqd	*prev;	/* previous queue descriptor */
	struct mq_attr	 attr;	/* flags for the current queue */
	int		 flags;	/* private flags */
	int		 eflags;/* extended flags */
};

struct mqdtable {
	CRITICAL_SECTION lock;
	struct mqdtable	*parent;
	struct {
		struct mqd	*tail;
		struct mqd	*head;
	} free_mqd, live_mqd;
	int		 curqueues;
	struct mqd	 desc[MQ_OPEN_MAX];
};

static struct mqdtable *mqdtab;

static int mqdtable_init()
{
	if(mqdtab == NULL)
		mqdtab = calloc(1, sizeof(struct mqdtable));

	if(mqdtab != NULL) {
		/* create a lock */
		int i = 1;
		InitializeCriticalSection(&mqdtab->lock);
		EnterCriticalSection(&mqdtab->lock);
		for(; i < MQ_OPEN_MAX; ++i) {
			mqdtab->desc[i - 1].next = &mqdtab->desc[i];
			mqdtab->desc[i].prev = &mqdtab->desc[i - 1];
		}
		mqdtab->free_mqd.head = mqdtab->desc;
		LeaveCriticalSection(&mqdtab->lock);
		return 0;
	}
	return -1;
}

static void mqdtable_lock(struct mqdtable *t)
{
	EnterCriticalSection(&t->lock);
}

static void mqdtable_unlock(struct mqdtable *t)
{
	LeaveCriticalSection(&t->lock);
}

static struct mqd *get_mqd(mqd_t mqdesc)
{
	if(mqdtab != NULL) {
		if(mqdtab->desc[mqdesc].eflags & MQ_MQD_ALIVE)
			return &mqdtab->desc[mqdesc];
	}
	return NULL;
}

static int mqd_lock(struct mqd *d)
{
	DWORD ms = (d->flags & O_NONBLOCK) ? 1 : INFINITE;

	if(d->flags & O_PRIVATE && d->flags & O_NONBLOCK) {
		if(d->flags & O_NONBLOCK) {
			LPCRITICAL_SECTION cs = &d->lock.critical_section;
			int res = TryEnterCriticalSection(cs);
			return res == 1 ? 0 : -1;
		}
		EnterCriticalSection(&d->lock.critical_section);
		return 0;
	}

	switch (WaitForSingleObject(d->lock.mutex, ms)) {
	case WAIT_ABANDONED:
	case WAIT_OBJECT_0:
		return 0;
	case WAIT_TIMEOUT:
		return EBUSY;
	}
	return -1;
}

static void mqd_unlock(struct mqd *d)
{
	if(d->flags & O_PRIVATE)
		LeaveCriticalSection(&d->lock.critical_section);
	else
		ReleaseMutex(d->lock.mutex);
}

static void mqd_create_and_get_lock(struct mqd *d, int oflags, wchar_t *name)
{
	if(oflags & O_PRIVATE) {
		InitializeCriticalSection(&d->lock.critical_section);
		EnterCriticalSection(&d->lock.critical_section);
	} else if(oflags & O_CREAT) {
		d->lock.mutex = CreateMutexW(NULL, TRUE, name);
	} else {
		d->lock.mutex = OpenMutexW(SYNCHRONIZE, FALSE, name);
		WaitForSingleObject(d->lock.mutex, INFINITE);
	}
}

static void mqd_destroy_lock(struct mqd *d, int oflags)
{
	if(oflags & O_PRIVATE) {
		LeaveCriticalSection(&d->lock.critical_section);
		DeleteCriticalSection(&d->lock.critical_section);
	} else {
		ReleaseMutex(d->lock.mutex);
		CloseHandle(d->lock.mutex);
	}
}

#if 0
/* XXX: How to set gid underwindows? */
void create_secdesc(mode_t mode)
{
	static PSID oth;
	SID_IDENTIFIER_AUTHORIDY oauth = SECURITY_WORLD_SID_AUTHORITY;
	EXPLICIT_ACCESS_W acc[3];
	DWORD size;

	memset(acc, 0, sizeof(acc));

	size = SECURITY_MAX_SID_SIZE;

	if (oth == NULL)
		oth = LocalAlloc(LMEM_FIXED, size);

	/* XXX: what happens if NULL is passed instead of size? */
	CreateWellKnownSid(WinWorldSid, NULL, &oth, &size);

	/* check S_IRshits */
	if (!mode & S_IROTH)
		acc[0].grfAccessPermission |= READ_CONTROL;
	if (!mode & S_IWOTH)
		acc[0].grfAccessPermission |= WRITE_CONTROL;

	/* deny write access */
	acc[0].grfAccessPermission |= EXECUTE_CONTROL;
	acc[0].grfAccessMode = DENY_ACCESS;
	acc[0].grfInheritance = NO_INHERITANCE;
	acc[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	acc[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	acc[0].Trustee.ptrstrName = oth;
}
#endif

WCHAR *inflate(const char *src, DWORD maxsize)
{
	WCHAR *tmp;
	DWORD tmpsize;

	tmpsize = MultiByteToWideChar(CP_THREAD_ACP,
				      MB_ERR_INVALID_CHARS,
				      src,
				      -1,
				      NULL,
				      0);

	if (tmpsize > maxsize)
		return NULL;

	tmp = malloc(tmpsize);

	MultiByteToWideChar(CP_THREAD_ACP,
			    MB_ERR_INVALID_CHARS,
			    src,
			    -1,
			    tmp,
			    tmpsize);

	return tmp;
}

static struct message *mqueue_get_msg(volatile struct mqueue *mq, int index)
{
	if(index < 0)
		return NULL;
	return (struct message*)&((char*)(mq->buffer))[index * mq->msgsize];
}

static int valid_open_attr(struct mq_attr *a)
{
	return a->mq_maxmsg > 0 && a->mq_msgsize > 0 && a->mq_sleepdur > 0;
}

mqd_t mq_open(const char *name, int oflag, ...)
{
	va_list al;
	struct mqd *qd, d;	/* temporary */
	struct mqueue *mq;
	HANDLE *map;
	wchar_t *mqname, *lkname, *wname;
	wchar_t lkname_[MAX_PATH], mqname_[MAX_PATH];
	DWORD err, mapacc;
	int res;

	wname = inflate(name, MQ_NAME_MAX);
	if(wname == NULL) {
		errno = ENAMETOOLONG;
		return -1;
	}
	wcscpy(mqname_, MQ_PREFIX);
	wcscat(mqname_, wname);
	wcscpy(lkname_, wname);
	wcscat(lkname_, MQ_LOCK_SUFFIX);

	if(oflag & O_PRIVATE) {
		lkname = mqname = NULL;
	} else {
		lkname = lkname_;
		mqname = mqname_;
	}
	free(wname);

	memset(&d, 0, sizeof(d));
	mqd_create_and_get_lock(&d, oflag, lkname);

	mapacc = 0;
	switch (oflag & (O_RDWR | O_WRONLY)) {
	case O_RDWR:
		mapacc = FILE_MAP_READ | FILE_MAP_WRITE;
		break;
	case O_WRONLY:
		mapacc = FILE_MAP_WRITE;
		break;
	case O_RDONLY:
		mapacc = FILE_MAP_READ;
		break;
	default:
		errno = EINVAL;
		goto destroy_lock;
	}

	/* map the page file */
	if (oflag & O_CREAT) {
		struct mq_attr *attr;
		DWORD mapsize;
		int mode;
		int i;

		va_start(al, oflag);
		mode = va_arg(al, int);
		attr = va_arg(al, struct mq_attr *);

		/* secdesc = create_secdesc(mode); */

		/* Calculate the required size for the queue */
		if(attr == NULL) {
			d.attr.mq_maxmsg = MQ_MAX_MSG;
			d.attr.mq_msgsize = MQ_MSG_SIZE;
		} else if(valid_open_attr(attr)) {
			d.attr = *attr;
		} else {
			errno = EINVAL;
			goto destroy_lock;
		}

		d.attr.mq_msgsize = (sizeof(struct message)
					+ d.attr.mq_msgsize - 1);
		d.attr.mq_msgsize += d.attr.mq_msgsize % sizeof(int);
		mapsize = (sizeof(struct mqueue) - sizeof(struct message))
				+ (d.attr.mq_msgsize * d.attr.mq_maxmsg);
		mapsize += mapsize % sizeof(int);

		map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
					 PAGE_READWRITE, 0, mapsize, mqname);


		err = GetLastError();

		if (map == NULL) {
			/* TODO: find error values */
			goto destroy_lock;
		}

		if (err == ERROR_ALREADY_EXISTS) {
			if(oflag & O_EXCL) {
				errno = EEXIST;
				goto close_map;
			}
			goto copy_open;
		}

		mq = MapViewOfFile(map, mapacc, 0, 0, 0);

		if(mq == NULL) {
			/* TODO: find possible error values */
			goto close_map;
		}

		mq->maxmsg = d.attr.mq_maxmsg;
		mq->msgsize = d.attr.mq_curmsg;
		memcpy(mq->name, mqname, wcslen(mqname));
		mq->free_tail = d.attr.mq_maxmsg - 1;

		for(i = 1; i < d.attr.mq_maxmsg; ++i) {
			mqueue_get_msg(mq, i - 1)->next = i;
			mqueue_get_msg(mq, i)->prev = i - 1;
		}

		for(i = 0; i < MQ_PRIO_MAX; ++i)
			mq->prio_head[i] = mq->prio_tail[i] = -1;

		mqueue_get_msg(mq, d.attr.mq_maxmsg - 1)->next = -1;
	} else {
		map = OpenFileMappingW(mapacc, 0, mqname);

		if(map == NULL) {
			errno = ENOENT;
			goto destroy_lock;
		}
copy_open:
		mq = MapViewOfFile(map, mapacc, 0, 0, 0);
		if(mq == NULL) {
			/* XXX: what? */
			goto close_map;
		}
		d.attr.mq_curmsg = mq->curmsg;
		d.attr.mq_maxmsg = mq->maxmsg;
		d.attr.mq_msgsize = mq->msgsize;
	}
	d.map = map;
	d.mqd_u.queue = mq;
	d.flags = oflag;
	d.eflags = MQ_MQD_ALIVE;

	mqdtable_lock(mqdtab);

	/* remove from free list */
	qd = mqdtab->free_mqd.head;

	if (!qd) {
		errno = EMFILE;
		goto close_map;
	}

	if(qd->next) qd->next->prev = NULL;
	else mqdtab->free_mqd.tail = NULL;
	mqdtab->free_mqd.head = qd->next;

	/* move to live list */
	qd->prev = mqdtab->live_mqd.tail;
	if(qd->prev) qd->prev->next = qd;
	else mqdtab->live_mqd.tail = mqdtab->live_mqd.head = qd;
	qd->next = NULL;

	*qd = d;

	if(0) {
close_map:
		CloseHandle(map);
destroy_lock:
		mqd_destroy_lock(&d, oflag);
		res = -1;
	}

	mqdtable_unlock(mqdtab);

	return res;
}

#if 0
DWORD mqd_find_next_msg(struct mqd *d)
{
	int i;
	DWORD j;
	struct mqueue *q;
	struct message *m;
	long curmsg, maxmsg;

	/* queue is full */
	q = (void *)d->mqd_u.queue;
	curmsg = q->curmsg;
	maxmsg = q->maxmsg;

	if (curmsg >= maxmsg)
		return -1;

	/* an empty queue */
	if (!curmsg)
		return 0;

	/* assume free_head contains some message */
	j = q->free_head;
	m = mqueue_get_msg(q, j);

	/* free_head is a free msg. This will usually be the case except
	 * right after a message has been sent/inserted into the queue.
	 * This function is called to update mqueue->free_head.
	 */
	if (!(m->flags & MQ_MSG_ALIVE))
		return j;

	/* FIXME: only walk the free list */
	for (i = 1, ++j; i < maxmsg; ++i) {
		if (!(mqueue_get_msg(q, j)->flags & MQ_MSG_ALIVE))
			return j;
		j = (j + 1) % (maxmsg - 1);
	}
	/* on the off chance something goes wrong */
	return -1;
}
#endif

/**
 * XXX: What happens if a message in the live list is dead? Although it should
 * not happen under normal circumstances.
 */
int
mq_receive(mqd_t des, char *msg_ptr, size_t msg_size, unsigned *msg_prio)
{
	struct mqd *d;
	volatile struct mqueue *q;
	struct message *m, *next, *tail;
	int err, prio, startprio, minprio, nonblock;

	if (msg_ptr == NULL) {
		errno = EINVAL;
		return -1;
	}

	d = get_mqd(d);
	if(d == NULL) {
		errno = EBADF;
		return -1;
	}

	mqd_lock(d);

	if (!(d->flags & O_RDWR) && (d->flags & O_WRONLY)) {
		errno = EPERM;
		return -1;
	}

	q = d->mqd_u.queue;

	if (msg_prio != NULL) {
		minprio = startprio = *msg_prio;
		if (minprio >= MQ_PRIO_MAX && minprio < 0) {
			errno = EINVAL;
			goto bad;
		}
	} else {
		minprio = 0;
		startprio = MQ_PRIO_MAX - 1;
	}

	nonblock = d->attr.mq_flags & O_NONBLOCK;
	while (1) {
		for (prio = startprio; prio >= minprio; --prio) {
			if (q->prio_head[prio] != -1) {
				m = mqueue_get_msg(q, q->prio_head[prio]);
				goto received;
			}
		}

		if (nonblock) {
			errno = EAGAIN;
			goto bad;
		}

		mqd_unlock(d);
		Sleep(d->attr.mq_sleepdur);
		mqd_lock(d);
	}

received:
	if(m->size > msg_size) {
		errno = EMSGSIZE;
		goto bad;
	}

	memcpy(msg_ptr, m->buffer, m->size);

	tail = mqueue_get_msg(q, q->free_tail);
	next = mqueue_get_msg(q, m->next);
	m->flags &= ~MQ_MSG_ALIVE;

	/* add to the free list */
	if (tail) {
		tail->next = q->prio_head[prio];
		m->prev = q->free_tail;
		q->free_tail = q->prio_head[prio];
	} else {
		m->prev = -1;
		m->next = -1;
		q->free_tail = q->prio_head[prio];
		q->free_head = q->prio_head[prio];
	}

	/* remove from the live list */
	if (next) {
		next->prev = -1;
		q->prio_head[prio] = m->next;
	} else {
		q->prio_head[prio] = -1;
		q->prio_tail[prio] = -1;
	}

	err = 0;

	if (0) {
bad:
		err = -1;
	}

	mqd_unlock(d);
	return err;
}

int mq_send(mqd_t des, const char *msg_ptr, size_t msg_size, unsigned msg_prio)
{
	struct mqd *d;
	volatile struct mqueue *q;
	struct message *prev;
	struct message *m;
	int res = 0;
	long curmsg;

	d = get_mqd(des);

	if (d == NULL) {
		errno = EBADF;
		return -1;
	}

	/* mq_send MAYBE allowed to block here. */
	switch (mqd_lock(d)) {
	case EBUSY:
		/* EWOULDBLOCK? */
		goto bad;
	case -1:
		/* TODO: find out possible errors */
		goto bad;
	}

	q = d->mqd_u.queue;

	/* msg_size <= to mq_msgsize */
	if (msg_size > d->attr.mq_msgsize) {
		errno = EMSGSIZE;
		goto bad;
	}

	/* 0 <= msg_prio < MQ_PRIO_MAX */
	if (msg_prio >= MQ_PRIO_MAX || msg_prio < 0) {
		errno = EINVAL;
		goto bad;
	}

	/* fail if cannot be written to */
	if (!(d->flags & (O_RDWR | O_WRONLY))) {
		errno = EPERM;
		goto bad;
	}

	curmsg = q->curmsg;
#if MQ_PARANOID
	/* If q->curmsg > MQ_MAX_MSG, then the queue is invalid */
	if (curmsg > d->attr.mq_maxmsg) {
		errno = EBADMSG;
		goto bad;
	}
#endif

	if (curmsg == d->attr.mq_maxmsg) {
		if (d->flags & O_NONBLOCK) {
			errno = EAGAIN;
			goto bad;
		} else do {
				mqd_unlock(d);
				Sleep(d->attr.mq_sleepdur);
				mqd_lock(d);
		} while (q->curmsg == d->attr.mq_maxmsg);
	}

#if MQ_PARANOID
	if (q->curmsg > d->attr.mq_maxmsg) {
		errno = EBADMSG;
		goto bad;
	}
#endif

	/* create the message */
	m = mqueue_get_msg(q, q->free_head);
	m->size = msg_size;
	m->flags = MQ_MSG_ALIVE;
	memcpy(m->buffer, msg_ptr, msg_size);

	/* put the new message in the queue */
	m->prev = q->prio_tail[msg_prio];
	prev = mqueue_get_msg(q, q->prio_tail[msg_prio]);
	q->prio_tail[msg_prio] = prev->next = q->free_head;
	q->free_head = m->next;
	/* TODO: make next to the next highest priority message */
	m->next = -1;
	d->attr.mq_curmsg = ++q->curmsg;
	if(0) {
bad:
		res = -1;
	}
	mqd_unlock(d);
	return res;
}
