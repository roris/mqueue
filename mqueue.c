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

/**
 * XXX: mq_send/receive: What happens if a message in the live list is dead,
 * Although it should not happen under normal circumstances?
 *
 * XXX: If a process has two threads, and one thread calls mq_close and another
 * 	calls mq_receive, with the first thread successfully closing the queue
 * 	after the second thread has retrieved the pointer to the queue,
 * 	mq_receive would fail on trying to lock the queue, as the lock would be
 * 	non existent. Same for any functions other than mq_open/close.
 *
 * 	Solution: lock the table before getting a mqd, lock the mqd, then
 * 		  unlock the table, if the table does not get altered.
 *
 * XXX: If a thread is full in mq_send (or empty in mq_receive), and O_NONBLOCK
 * 	was no set, then the functions, may own a descriptor that can get
 * 	corrupted by a successful call to mq_close from another thread.
 *
 */


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
	CRITICAL_SECTION	private_lock;
	HANDLE			mutex;
	HANDLE		 	map;	/* handle to the shared memory */
	volatile struct mqueue *queue;
	struct mqd	       *next;	/* next queue descriptor */
	struct mqd	       *prev;	/* previous queue descriptor */
	struct mq_attr		attr;	/* flags for the current queue */
	int			flags;	/* private flags */
	int			eflags;	/* extended flags */
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

static int mqdtable_init(void)
{
	if (mqdtab == NULL)
		mqdtab = calloc(1, sizeof(struct mqdtable));

	if (mqdtab != NULL) {
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

static void mqdtable_lock(void)
{
	EnterCriticalSection(&mqdtab->lock);
}

static void mqdtable_unlock(void)
{
	LeaveCriticalSection(&mqdtab->lock);
}

static struct mqd *mqdtable_get_mqd(mqd_t mqdes)
{
	if(mqdes < 0 || mqdes >= MQ_OPEN_MAX)
		return NULL;

	if (mqdtab->desc[mqdes].eflags & MQ_MQD_ALIVE)
		return &mqdtab->desc[mqdes];

	return NULL;
}

static int mqd_lock_mutex(struct mqd *d)
{
	switch (WaitForSingleObjext(d->mutex)) {
	case WAIT_ABANDONED:
		return EBADMSG;
	case WAIT_OBJECT_0:
		return 0;
	case WAIT_FAILED:
	default:
		return EOTHER;
	}
}

static int mqd_lock(volatile struct mqd *d)
{
	mqd_public_lock();
	mqd_lock_mutex(d);
}

static void mqd_private_lock(struct mqd *d)
{
	EnterCriticalSection(&d->private_lock);
}

static struct mqd *mqdtable_get_and_lock_mqd(mqd_t mqdes)
{
	/* assume that mqdtab is never NULL */
	struct mqd *res;

	mqdtable_lock(mqdtab);

	res = mqdtable_get_mqd(mqdes);

	if(res != NULL)
		mqd_lock(res);

	mqdtable_unlock(mqdtab);

	return res;
}

static void mqd_unlock(volatile struct mqd *d)
{
	mqd_private_unlock(d);
	mqd_public_unlock(d);
}

static void mqd_create_private_lock(struct mqd *d)
{
	InitializeCriticalSection(&d->private_lock);
}


static int mqd_create_and_lock_mutex(struct mqd *d, int oflag, wchar_t *name)
{
	int err;
	if (!(oflag & O_PRIVATE)) {
		if (oflag & O_CREAT) {
			d->mutex = CreateMutexW(NULL, TRUE, name);
			err = GetLastError();

			if (err == ERROR_ALREADY_EXISTS) {
				err = mqd_lock_mutex(d);

				if (err == 0)
					return EEXIST;

				return err;
			}

			if (d->mutex != NULL)
				return 0;

			if (err == ERROR_ACCESS_DENIED)
				return EACCES;
		} else {
			d->mutex = OpenMutexW(SYNCHRONIZE, FALSE, name);

			if (d->mutex != NULL) {
				return mqd_lock_mutex(d);
			}

			err = GetLastError();

			if (err == ERROR_NOT_FOUND)
				return ENOENT;
		}
	} else {
		return 0;
	}
eoth:
	SetLastError(err);
	err = EOTHER;
	return err;
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
	if (index < 0 || index >= mq->maxmsg)
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
	struct mqd d;	/* temporary */
	volatile struct mqd *qd;
	struct mqueue *mq;
	HANDLE *map;
	wchar_t *mqname, *lkname, *wname;
	wchar_t lkname_[MAX_PATH], mqname_[MAX_PATH];
	DWORD err, mapacc;
	int res, private;

	private = oflag & O_PRIVATE;

	/* convert the name to unicode */
	wname = inflate(name, MQ_NAME_MAX);
	if (wname == NULL) {
		errno = ENAMETOOLONG;
		return -1;
	}
	wcscpy(mqname_, MQ_PREFIX);
	wcscat(mqname_, wname);

	if (!private) {
		wcscpy(lkname_, wname);
		wcscat(lkname_, MQ_LOCK_SUFFIX);
	}

	if (private) {
		lkname = mqname = NULL;
	} else {
		lkname = lkname_;
		mqname = mqname_;
	}
	free(wname);

	memset(&d, 0, sizeof(d));

	/* Try to own the queue first, before creating it. */
	if (!private) {
		err = mqd_create_and_lock_mutex(&d, oflag, lkname);
		/* when O_CREAT is set - continue with O_EXCL? */
		if (err == EEXIST)
			oflag &= ~O_EXCL;

		/* attempt to create it again? */
		if (err == EACCES) {
			oflag &= ~O_CREAT;
			/* check for possible error values */
			err = mqd_create_and_lock_mutex(&d, oflag, lkname);
		}

		if (err == ENOENT) {
			errno = ENOENT;
			return -1;
		}

		if (err == EOTHER) {
			errno = EOTHER;
			return -1;
		}

		if (err == EBADMSG) {
			/* destroy the queue? */
			/* A valid handle is present, destroy it. */
			CloseHandle(d.mutex);
			errno = EBADMSG;
			return -1;
		}
	}

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
		if (attr == NULL) {
			d.attr.mq_maxmsg = MQ_MAX_MSG;
			d.attr.mq_msgsize = MQ_MSG_SIZE;
		} else if (valid_open_attr(attr)) {
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
			if (oflag & O_EXCL) {
				errno = EEXIST;
				goto close_map;
			}
			goto copy_open;
		}

		mq = MapViewOfFile(map, mapacc, 0, 0, 0);

		if (mq == NULL) {
			/* TODO: find possible error values */
			goto close_map;
		}

		mq->maxmsg = d.attr.mq_maxmsg;
		mq->msgsize = d.attr.mq_curmsg;
		memcpy(mq->name, mqname, wcslen(mqname));
		mq->free_tail = d.attr.mq_maxmsg - 1;

		for (i = 1; i < d.attr.mq_maxmsg; ++i) {
			mqueue_get_msg(mq, i - 1)->next = i;
			mqueue_get_msg(mq, i)->prev = i - 1;
		}

		for (i = 0; i < MQ_PRIO_MAX; ++i)
			mq->prio_head[i] = mq->prio_tail[i] = -1;

		mqueue_get_msg(mq, d.attr.mq_maxmsg - 1)->next = -1;
	} else {
		map = OpenFileMappingW(mapacc, 0, mqname);

		if (map == NULL) {
			errno = ENOENT;
			goto destroy_lock;
		}
copy_open:
		mq = MapViewOfFile(map, mapacc, 0, 0, 0);
		if (mq == NULL) {
			/* XXX: what? */
			goto close_map;
		}
		d.attr.mq_curmsg = mq->curmsg;
		d.attr.mq_maxmsg = mq->maxmsg;
		d.attr.mq_msgsize = mq->msgsize;
	}
	d.map = map;
	d.queue = mq;
	d.flags = oflag;
	d.eflags = MQ_MQD_ALIVE;

	mqdtable_lock(mqdtab);
	qd = mqdtab->free_mqd.head;

	if (!qd) {
		errno = EMFILE;
		goto close_map;
	}

	/* remove from free list */
	if (qd->next) qd->next->prev = NULL;
	else mqdtab->free_mqd.tail = NULL;
	mqdtab->free_mqd.head = qd->next;

	/* move to live list */
	qd->prev = mqdtab->live_mqd.tail;
	if (qd->prev) qd->prev->next = qd;
	else mqdtab->live_mqd.tail = mqdtab->live_mqd.head = qd;
	qd->next = NULL;
	mqd_create_private_lock(&d);
	*qd = d;

	/* release the lock */
	if (!private)
		mqd_unlock_mutex(qd);

	if (0) {
close_map:
		CloseHandle(map);
destroy_lock:
		mqd_destroy_mutex(&d, oflag);
		res = -1;
	}

	mqdtable_unlock(mqdtab);

	return res;
}

int mq_close(mqd_t mqdes)
{
	volatile struct mqd *d;
	int err;

	/* lock table first */
	mqdtable_lock();
	d = mqdtable_get_mqd(mqdes);

	if (d == NULL) {
		errno = EBADF;
		err = -1;
		goto out;
	}

	/*
	 * Wait for other threads to finish up on the queue. No need to own the
	 * public lock as the queue itself is not altered. No need to unlock
	 * the private lock.
	 */
	EnterCriticalSection(&d->private_lock);

	/* free resources */
	UnmapViewOfFile((LPVOID)d->queue);
	CloseHandle(d->map);
	if(!(d->flags & O_PRIVATE))
		CloseHandle(d->mutex);

	/*
	 * This is required because there is no guarentee that these mqds
	 * aren't currently being used by other threads.
	 */
	if (d->next)
		EnterCriticalSection(&d->next->private_lock);

	if (d->prev)
		EnterCriticalSection(&d->prev->private_lock);

	if (d->next) {
		d->next->prev = d->prev;
		LeaveCriticalSection(&d->next->private_lock);
	}

	if (d->prev) {
		d->prev->next = d->next;
		LeaveCriticalSection(&d->prev->private_lock);
	}

	/*
	 * Not owning a lock is safe here, as the free list is only accessed
	 * after the table's lock is owned.
	 */
	if (mqdtab->free_mqd.tail) {
		mqdtab->free_mqd.tail->next = d;
		d->prev = mqdtab->free_mqd.tail;
		mqdtab->free_mqd.tail = d;
		d->next = NULL;
	} else {
		mqdtab->free_mqd.tail = mqdtab->free_mqd.head = d;
		d->next = d->prev = NULL;
	}

	/* finally destroy the queue's lock and release the table's lock */
	DeleteCriticalSection(&d->private_lock);
out:
	LeaveCriticalSection(&mqdtab->lock);
	return 0;
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

	d = mqdtable_get_and_lock_mqd(des);

	if (d == NULL) {
		errno = EBADF;
		return -1;
	}

	if (!(d->flags & O_RDWR) && d->flags & O_WRONLY) {
		errno = EPERM;
		return -1;
	}

	q = d->queue;

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
	if (m->size > msg_size) {
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

	d = mqdtable_get_and_lock_mqd(des);

	if (d == NULL) {
		errno = EBADF;
		return -1;
	}

	q = d->queue;

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

	/* XXX: make next point to the next highest priority message? */
	m->next = -1;
	d->attr.mq_curmsg = ++q->curmsg;
	if (0) {
bad:
		res = -1;
	}
	mqd_unlock(d);
	return res;
}

int mq_unlink(const char *name)
{
	errno = ENOSYS;
	return -1;
}
