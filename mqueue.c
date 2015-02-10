#include <windows.h>
#include <malloc.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include "mqueue.h"

#endif

#define MQ_MSG_ALIVE    0x1
#define MQ_MQD_COPIED   0x2

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
	wchar_t		name[MQ_NAME_MAX];
	struct message	buffer[1];
};

struct mqd {
	HANDLE		 lock;	/* lock on the queue */
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
	struct mqd	*free_mqd;
	int		 curqueues;
	struct mqd	 desc[MQ_OPEN_MAX];
};

static struct mqdtable *mqdtab;

BOOL mq_dll_main(HINSTANCE, DWORD, LPVOID);
struct mqd *get_mqd(mqd_t);
struct mqueue *mqd_get_mq(struct mqd *);

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
		mqdtab->free_mqd = mqdtab->desc;
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
			return mqdtab->desc[mqdesc];
	}
	return NULL;
}

static int mqd_lock(struct mqd *d)
{
	DWORD ms = (d->flags & O_NONBLOCK) ? 1 : INFINITE;

	switch (WaitForSingleObject(d->lock, ms)) {
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
	ReleaseMutex(d->lock);
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
	DWORD tmpsize, destlen;

	tmpsize = MultiByteToWideChar(CP_THREAD_ACP,
				      MB_ERR_INVALID_CHARS,
				      src,
				      -1,
				      NULL,
				      0);

	if (tmpsize > maxsize * sizeof(WCHAR))
		return NULL;

	tmp = malloc(tmpsize);

	MultiByteToWideChar(CP_THREAD_ACP,
			    MB_ERR_INVALID_CHARS,
			    src,
			    -1,
			    tmp,
			    tmpsize);

	if (bytes_written)
		*bytes_written = tmpsize;
	return tmp;
}

mqd_t mq_open(const char *name, int oflag, ...)
{
	struct mqd *qd;
	struct mqueue *mq;
	struct mqd_lock *lock;
	void *view;
	HANDLE *map;
	wchar_t *wname;
	DWORD namelen, err, mapacc;
	wchar_t lockname[MAX_PATH];
	wchar_t mqname[MAX_PATH];
	BOOL inherit;
	va_list al;
	int res;
	DWORD sleepdur;

	wname = inflate(name,
			MAX_PATH - (wcslen(L"/mq/") + wcslen(L".lock")));

	if(wname == NULL) {
		/* ENAMETOOLONG */
		return -1;
	}

	wcscpy(mqname, L"/mq/");
	wcscat(mqname, wname);
	wcscpy(lockname, msgname);
	wcscat(lockname, L".lock");
	free(wname);

	/* get the mqdtable for the current thread */
	mqdtable_lock(mqdtab);

	/* get a free mqd in the current thread's table. */
	qd = mqdtab->free_mqd;
	if (!qd) {
		/* EMFILE */
		goto unlock_table;
	}

	mqd_create_lock(&d, oflag, lockname);
	mqd_lock(&d);

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
	default:
		/* do what? */
		break;
	}

	/* map the page file */
	if (oflag & O_CREAT) {
		struct mq_attr *attr;
		long msgsize;
		long maxmsg;
		size_t somsg;
		mode_t mode;
		DWORD mem;
		DWORD mapsize;

		va_start(al, n);
		mode = va_arg(al, mode_t);
		attr = va_arg(al, struct mq_attr *);

		/* secdesc = create_secdesc(mode); */

		/* Calculate the required size for the queue */
		if(attr != NULL) {
			if(attr->mq_maxmsg <= 0 || attr->mq_msgsize <= 0
				|| attr->mq_sleepdur <= 0) {
				/* EINVAL */
				res = -1;
				goto unlock_table;
			}
			maxmsg = attr->mq_maxmsg;
			msgsize = attr->mq_msgsize;
			sleepdur = attr->mq_sleepdur;
		} else {
			msgsize = MQ_MSG_SIZE;
			maxmsg = MQ_MAX_MSG;
		}

		somsg = (sizeof(struct message) + msgsize - 1);
		somsg += somsg % sizeof(int);
		mapsize = sizeof(struct mqueue) - sizeof(struct message) + (somsg * maxmsg);
		mapsize += mapsize % sizeof(int);
		mem = oflag & O_NORESERVE ? SEC_COMMIT : SEC_RESERVE;
		map = CreateFileMappingW(INVALID_HANDLE_VALUE,
					 NULL,
					 PAGE_READWRITE | mem,
					 0,
					 mapsize,
					 tmp);
		error = GetLastError();

		if (map == NULL) {
			/* TODO: find error values */
			switch(error) {

			}
			goto cleanup;
		}

		if (error == ERROR_ALREADY_EXISTS) {
			if(oflag & O_EXCL)
				goto closemap;
			goto copy_on_open;
		}

	} else {
		BOOL inherit = !(oflag & O_NOINHERIT);
		map = OpenFileMappingW(mapacc, inherit, tmp);

		if(map == NULL) {
			/* ENOENT */
			goto cleanup;
		}
	}

	mq = view = MapViewOfFile(qd->map,
			     mapacc, 0, 0, sizeof(struct mq) + wnamelen);
	mq->curmsg = 0;
	mq->maxmsg = maxmsg;
	mq->maxsize = maxsize;
	memcpy(mq->name, qname, sizeof(qname));

	qd->flags = oflag & ~(O_NORESERVE | O_CREAT | O_EXCL);
	qd->lock = lock;
	mqdt_to_next_free_mqd(mqdt);

	if(0) {
cleanup:
		CloseFileMapping(map);
		mqd_destroy_lock(lock);
		res = -1;
	}
unlock_table:
	mqdtable_unlock(mqdtab);
out:
	return res;
}

static struct message *mqueue_get_msg(struct mqueue *mq, int index)
{
	void *bytes = &((char*)(mq->buffer))[index * mq->sizeofmsg];
	return bytes;
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

#ifdef MQ_RECV_
int
mq_receive(mqd_t des, const char *msg_ptr, size_t msg_size, unsigned *msg_prio)
{
	struct mqd *d;
	struct mqueue *q;
	struct message *m;
	int nonblock;
	int err;

	/* SHOULD probably lock here */
	d = get_mqd(des);

	mqd_lock(d);
	q = mqd_get_mq(d);
	nonblock = d->mq_attr.mq_flags & O_NONBLOCK;
	if (msg_prio != NULL) {

mq_recv_prio:
		m = mq_recv_prio(q, *msg_prio);

		if (m == NULL && nonblock) {
			Sleep(q->mq_attr.mq_sleepdur);
			goto mq_recv_prio;
		}

	} else {
mq_recv:
		m = mq_recv(q);
		if (m == NULL && nonblock) {
			Sleep(q->mq_attr.mq_sleepdur);
			goto mq_recv;
		}
	}

	mqd_unlock(d);
	return err;
}
#endif

int mq_send(mqd_t des, const char *msg_ptr, size_t msg_size, unsigned msg_prio)
{
	struct mqd *d;
	volatile struct mqueue *q;
	struct message *prev;
	struct message *m;
	int res = 0;
	long curmsg, msgsize, maxmsg;

	d = get_mqd(des);

	if (d == NULL) {
		/* EBADF */
		return -1;
	}

	q = d->mqd_u.queue;
	curmsg = q->curmsg;

	/* msg_size <= to mq_msgsize */
	if (msg_size > d->attr.mq_msgsize) {
		/* EMSGSIZE */
		return -1;
	}

	/* 0 <= msg_prio < MQ_PRIO_MAX */
	if (msg_prio >= MQ_PRIO_MAX || msg_prio < 0) {
		/* EINVAL */
		return -1;
	}

	/* fail if cannot be written to */
	if (!(d->flags & (O_RDWR | O_WRONLY))) {
		/* EPERM */
		return -1;
	}

	/* mq_send MAYBE allowed to block here. */
	switch (mqd_lock(d)) {
	case EBUSY:
		return -1;
	case -1:
		/* TODO: find out possible errors */
		return -1;
	}

	/* If q->curmsg > MQ_MAX_MSG, then the queue is invalid */
	curmsg = q->curmsg;
	if (curmsg > d->attr.mq_maxmsg) {
		/* possibly EBADF */
		goto bad;
	}

	if (curmsg == d->attr.mq_maxmsg) {
		if (d->flags & O_NONBLOCK) {
			/* EAGAIN */
			goto unlock;
		} else do {
				mqd_unlock(d);
				Sleep(d->attr.mq_sleepdur);
				mqd_lock(d);
		} while (q->curmsg == d->attr.mq_maxmsg);
	}

	if (q->curmsg > d->attr.mq_maxmsg) {
		/* EBADF */
		goto bad;
	}

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
	goto unlock;
out:
	res = -1;
unlock:
	mqd_unlock(d);
	return res;
}
