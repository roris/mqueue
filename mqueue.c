#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <errno.h>
#include <windows.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include "mqdefs.h"

#define SIZE_TO_WLEN(s)	((s) / sizeof(wchar_t) - 1)
#define MQ_MSG_ALIVE	0x1
#define MQ_MQD_ALIVE	0x1
#define MQ_PREFIX	L"/mq/"
#define MQ_LOCK_SUFFIX	L".lock"
#define MQ_LOCK_LEN	(SIZE_TO_WLEN(sizeof(MQ_LOCK_SUFFIX)))
#define MQ_PREFIX_LEN	(SIZE_TO_WLEN(sizeof(MQ_PREFIX)))
#define MQ_NAME_MAX	((MAX_PATH - MQ_LOCK_LEN) - MQ_PREFIX_LEN)

static struct mqdtable *mqdtab;

static void mqd_destroy_lock(struct mqd *d)
{
	CloseHandle(d->mutex);
	d->mutex = NULL;
}

static void mqdtable_lock(void)
{
	EnterCriticalSection(&mqdtab->lock);
}

static void mqdtable_unlock(void)
{
	LeaveCriticalSection(&mqdtab->lock);
}

static volatile struct mqd *get_mqd(mqd_t mqdes)
{
	if (mqdes < 0 || mqdes >= MQ_OPEN_MAX)
		goto bad;

	if (mqdtab->desc[mqdes].eflags & MQ_MQD_ALIVE)
		return &mqdtab->desc[mqdes];

bad:
	errno = EBADF;
	return NULL;
}

static int mq_wait_handle(HANDLE h)
{
	switch (WaitForSingleObject(h, INFINITE)) {
	case WAIT_ABANDONED:
		errno = EBADMSG;
		return -1;
	case WAIT_OBJECT_0:
		return 0;
	}
	errno = EOTHER;
	return -1;
}

static int mqd_get_lock(volatile struct mqd *d)
{
	return mq_wait_handle(d->mutex);
}

static struct mqd *get_and_lock_mqd(mqd_t mqdes)
{
	struct mqd *res;

	mqdtable_lock();

	res = (void*)get_mqd(mqdes);

	if(res != NULL)
		mqd_get_lock(res);

	mqdtable_unlock();

	return res;
}

static void mqd_release_lock(struct mqd *d)
{
	ReleaseMutex(d->mutex);
}

static int mqd_create_and_get_lock(struct mqd *d, wchar_t *name, int namelen)
{
	int err;
	int flags = d->flags;

	if (name) {
		name[namelen] = 0;
		wcscat(name, L".lock");
	}

	if (flags & O_CREAT) {
		d->mutex = CreateMutexW(NULL, TRUE, name);
		err = GetLastError();
		if (d->mutex != NULL) {
			if (err == ERROR_ALREADY_EXISTS) {
				errno = EEXIST;
				/* FAIL only if O_EXCL is set */
				if (d->flags & O_EXCL)
					return -1;
				d->flags &= ~O_CREAT;
				goto open_wait;
			}
			return 0;
		}
		/* mutex probably exists, so try to get a handle */
		if (err == ERROR_ACCESS_DENIED)
			goto open_mutex;
	} else {
open_mutex:
		d->mutex = OpenMutexW(SYNCHRONIZE, FALSE, name);

		/*
		 * If a handle was obtained, then return the value.
		 */
		if (d->mutex != NULL) {
open_wait:
			if (mq_wait_handle(d->mutex)) {
				mqd_destroy_lock(d);
				return -1;
			}
			return 0;
		}
		/* mutex is null, check last and set ENOENT, if the
		 * mutex does not exist.
		 */
		err = GetLastError();
		if (err == ERROR_NOT_FOUND) {
			errno = ENOENT;
			return -1;
		}
	}
	/* No idea what error codes lead to this */
	SetLastError(err);
	errno = EOTHER;
	return -1;
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

static int
inflate_conv(
	wchar_t *out,
	const char *src,
	int *length,
	DWORD maxsize)
{
	WCHAR *tmp;
	DWORD tmpsize;

	tmpsize = MultiByteToWideChar(CP_THREAD_ACP,
				      MB_ERR_INVALID_CHARS,
				      src,
				      -1,
				      NULL,
				      0);

	if (tmpsize > maxsize || tmpsize == 0)
		return -1;

	if (length)
		*length = tmpsize / sizeof(wchar_t);

	tmp = malloc(tmpsize);

	if (tmp == NULL)
		return -1;

	MultiByteToWideChar(CP_THREAD_ACP,
			    MB_ERR_INVALID_CHARS,
			    src,
			    -1,
			    tmp,
			    tmpsize);

	wcscpy(out, MQ_PREFIX);
	wcscat(out, tmp);

	free(tmp);
	return 0;
}

static struct message *mqueue_get_msg(volatile struct mqueue *mq, int index)
{
	if (index < 0 || index >= mq->maxmsg)
		return NULL;

	return (struct message*)&((char*)(mq->buffer))[index * mq->msgsize];
}

static int valid_open_attr(struct mq_attr *a)
{
	return a->mq_maxmsg > 0 && a->mq_msgsize > 0 &&
		a->mq_sleepdur > 0;
}

static HANDLE do_mqd_create_cond(struct mqd *d, wchar_t *name,
	BOOL signaled)
{
	HANDLE res;

	if (d->flags & O_CREAT) {
		res = CreateEventW(NULL, TRUE, signaled, name);

		if (res != NULL) {
			DWORD err;
			err = GetLastError();
			if (err == ERROR_ALREADY_EXISTS) {
				if (d->flags & O_EXCL) {
					CloseHandle(res);
					res = NULL;
				}
				errno = EEXIST;
				d->flags &= ~O_CREAT;
			}
		} else {
			errno = EOTHER;
		}
	} else {
		res = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
		if (res == NULL) {
			errno = EOTHER;
		}
	}

	return res;
}

static int mqd_create_cond(struct mqd *d, wchar_t *name, int namelen)
{
	int i;

	if (name != NULL) {
		name[namelen] = 0;
		wcscat(name, L".evnf");
	}
	d->not_full = do_mqd_create_cond(d, name, TRUE);
	if (d->not_full == NULL)
		return -1;
	if (name != NULL) {
		name[namelen] = 0;
		wcscat(name, L".eve?");
	}
	d->not_empty = do_mqd_create_cond(d, name, FALSE);
	if (d->not_empty == NULL)
		goto close_not_full;

	for (i = 0; i < MQ_PRIO_MAX; i++) {
		if (name != NULL) {
			name[namelen + 4] = L'0' + (i % 10);
			name[namelen + 3] = L'0' + (i / 10);
		}
		d->not_empty_prio[i] = do_mqd_create_cond(d, name, FALSE);
		if (d->not_empty_prio[i] == NULL) {
			int j = i - 1;
			for (; j >= 0; --j)
				CloseHandle(d->not_empty_prio[j]);
			CloseHandle(d->not_empty);
		close_not_full:
			CloseHandle(d->not_full);
			d->not_full = NULL;
			return -1;
		}
	}
	return 0;
}

static int mq_cond_set(HANDLE cond)
{
	if(!SetEvent(cond)) {
		errno = EOTHER;
		return -1;
	}
	return 0;
}

static void mqd_destroy_cond(struct mqd *d)
{
	int i;
	/* ignore failure at this point, for now. */
	mq_cond_set(d->not_full);
	CloseHandle(d->not_full);
	mq_cond_set(d->not_empty);
	CloseHandle(d->not_empty);

	for (i = 0; i < MQ_PRIO_MAX; ++i) {
		mq_cond_set(d->not_empty_prio[i]);
		CloseHandle(d->not_empty_prio[i]);
	}
}

mqd_t mq_open(const char *name, int oflag, ...)
{
	va_list al;
	struct mqd d;
	volatile struct mqd *qd;
	struct mqueue *mq;
	HANDLE *map;
	wchar_t wname[MAX_PATH];
	wchar_t *nameptr;
	DWORD err, mapacc;
	int res, private;
	int namelen;

	res = -1;
	private = oflag & O_PRIVATE;

	mqdtable_lock();

	if (mqdtab->curopen == MQ_OPEN_MAX) {
		errno = EMFILE;
		goto unlock_table;
	}

	/* convert the name to unicode */
	if (name != NULL && inflate_conv(wname, name, &namelen, MQ_NAME_MAX)) {
		errno = ENAMETOOLONG;
		goto unlock_table;
	}

	memset(&d, 0, sizeof(d));
	d.flags = oflag;


	/* create the muteces */
	nameptr = name != NULL ? wname : NULL;
	if(mqd_create_and_get_lock(&d, nameptr, namelen)) {
		if (d.mutex == NULL)
			goto unlock_table;
	}

	/* create condition variables. */
	if (mqd_create_cond(&d, nameptr, namelen)) {
		if (d.not_full == NULL)
			goto unlock_table;
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
		goto destroy_cond;
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

		if (attr == NULL) {
			d.attr.mq_maxmsg = MQ_MAX_MSG;
			d.attr.mq_msgsize = MQ_MSG_SIZE;
		} else if (valid_open_attr(attr)) {
			d.attr = *attr;
		} else {
			errno = EINVAL;
			goto destroy_lock;
		}

		/* Calculate the required size for the queue */
		d.attr.mq_msgsize = (sizeof(struct message)
					+ d.attr.mq_msgsize - 1);
		d.attr.mq_msgsize += d.attr.mq_msgsize % sizeof(int);
		mapsize = (sizeof(struct mqueue) - sizeof(struct message))
				+ (d.attr.mq_msgsize * d.attr.mq_maxmsg);
		mapsize += mapsize % sizeof(int);

		map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
					 PAGE_READWRITE, 0, mapsize, nameptr);

		if (map == NULL) {
			/* let the application handle failure :) */
			errno = EOTHER;
			goto destroy_lock;
		}

		err = GetLastError();
		if (err == ERROR_ALREADY_EXISTS) {
			if (oflag & O_EXCL) {
				errno = EEXIST;
				goto close_map;
			}
			goto copy_open;
		}

		mq = MapViewOfFile(map, mapacc, 0, 0, 0);
		if (mq == NULL) {
			errno = EOTHER;
			goto close_map;
		}

		mq->maxmsg = d.attr.mq_maxmsg;
		mq->msgsize = d.attr.mq_curmsg;

		if (name != NULL) {
			memcpy(mq->name, wname, namelen);
		}
		mq->free_tail = d.attr.mq_maxmsg - 1;
		for (i = 1; i < d.attr.mq_maxmsg; ++i) {
			struct message *c, *p;
			p = mqueue_get_msg(mq, i - 1);
			c = mqueue_get_msg(mq, i);
			if (p != NULL && c != NULL) {
				p->next = i;
				c->prev = i - 1;
			}
			else break;
		}

		for (i = 0; i < MQ_PRIO_MAX; ++i)
			mq->prio_head[i] = mq->prio_tail[i] = -1;
		{
			struct message *m;
			m = mqueue_get_msg(mq, d.attr.mq_maxmsg - 1);
			if (m != NULL) {
				m->prev = d.attr.mq_maxmsg - 2;
			}
		}

	} else {
		map = OpenFileMappingW(mapacc, 0, wname);

		if (map == NULL) {
			errno = ENOENT;
			goto destroy_lock;
		}
copy_open:
		mq = MapViewOfFile(map, mapacc, 0, 0, 0);
		if (mq == NULL) {
			errno = EOTHER;
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

	/* Since the table is locked here, it is not necessary to lock the
	 * other queue descriptors
	 */
	qd = mqdtab->free_mqd.head;

	if (qd->next) qd->next->prev = NULL;
	else mqdtab->free_mqd.tail = NULL;
	mqdtab->free_mqd.head = qd->next;

	qd->prev = mqdtab->live_mqd.tail;
	if (qd->prev) qd->prev->next = (void*)qd;
	else mqdtab->live_mqd.tail = mqdtab->live_mqd.head = (void*)qd;

	qd->next = NULL;
	*qd = d;
	mqdtab->curopen++;

	mqd_release_lock(&d);
	res = 0;

	if (0) {
close_map:
		CloseHandle(map);
destroy_cond:
		mqd_destroy_cond(&d);
destroy_lock:
		mqd_destroy_lock(&d);
		res = -1;
	}
unlock_table:
	mqdtable_unlock();

	return res;
}

int mq_close(mqd_t mqdes)
{
	struct mqd *d;
	int err;

	/* lock table first */
	mqdtable_lock();
	d = (void*)get_mqd(mqdes);

	if (d == NULL) {
		errno = EBADF;
		err = -1;
		goto out;
	}

	/* get the lock */
	mqd_get_lock(d);
	d->flags &= ~MQ_MQD_ALIVE;

	/* free resources */
	UnmapViewOfFile((LPVOID)d->queue);
	CloseHandle(d->map);
	if(!(d->flags & O_PRIVATE))
		CloseHandle(d->mutex);

	if (d->next)
		d->next->prev = d->prev;

	if (d->prev)
		d->prev->next = d->next;

	/*
	 * Not owning a lock is safe here, as the free list is only accessed
	 * after the table's lock is owned.
	 */
	if (mqdtab->free_mqd.tail) {
		mqdtab->free_mqd.tail->next = (void*)d;
		d->prev = mqdtab->free_mqd.tail;
		mqdtab->free_mqd.tail = (void*)d;
		d->next = NULL;
	} else {
		mqdtab->free_mqd.tail = mqdtab->free_mqd.head = (void*)d;
		d->next = d->prev = NULL;
	}

	/* finally destroy the queue's lock and release the table's lock */
	--mqdtab->curopen;
	mqd_destroy_lock(d);
	err = 0;
out:
	mqdtable_unlock();
	return err;
}

int mq_cond_unset(HANDLE cond)
{
	if (!ResetEvent(cond)) {
		errno = EOTHER;
		return -1;
	}
	return 0;
}

int
mq_receive(mqd_t des, char *msg_ptr, size_t msg_size, unsigned *msg_prio)
{
	struct mqd *d;
	struct mqueue *q;
	struct message *m, *next, *tail;
	int err, prio, startprio, minprio;

	if (msg_ptr == NULL) {
		errno = EINVAL;
		return -1;
	}

	d = get_and_lock_mqd(des);
	if (d == NULL) {
		errno = EBADF;
		return -1;
	}

	if (!(d->flags & O_RDWR) && d->flags & O_WRONLY) {
		errno = EPERM;
		return -1;
	}

	q = (void*)d->queue;

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

	for (prio = startprio; prio >= minprio; --prio) {
		if (q->prio_head[prio] != -1) {
			m = mqueue_get_msg(q, q->prio_head[prio]);
			if (m != NULL) {
				goto received;
			}
		}
	}

	/* no message was recieved. */
	if (d->attr.mq_flags & O_NONBLOCK) {
		errno = EAGAIN;
		goto bad;
	} else do {
		mqd_release_lock(d);

		/* prio should be valid at this point. */
		if (msg_prio) {
			/* XXX: Should a priority slot be signaled when a
			 * messsage gets queued onto a lesser priority slot?
			 */
			mq_wait_handle(d->not_empty_prio[prio]);
		} else {
			mq_wait_handle(d->not_empty);
		}

		/* Check if the descriptor is still valid. */
		d = get_and_lock_mqd(des);
		if(d == NULL)
			return -1;

		/* It shouldn't fail at this point. */
		for (prio = startprio; prio >= minprio; --prio) {
			m = mqueue_get_msg(d->queue, d->queue->prio_head[prio]);
			if (m != NULL) {
				q = (void*)d->queue;
				goto received;
			}
		}
		/* loop if failed, and O_NONBLOCK wasn't  set for the
		 * descriptor by another thread.
		 */
	} while (!(d->attr.mq_flags & O_NONBLOCK));

	/* O_NONBLOCK was set, and no message was recieved. */
	errno = EAGAIN;
	return -1;

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
		m->prev = q->free_tail;
		tail->next = q->free_tail = q->prio_head[prio];
	} else {
		/* last message in queue */
		m->prev = -1;
		m->next = -1;
		q->free_tail = q->prio_head[prio];
		q->free_head = q->prio_head[prio];
	}

	/* remove from the live list */
	--q->curmsg;
	if (next) {
		next->prev = -1;
		q->prio_head[prio] = m->next;
		if (q->curmsg == q->maxmsg - 1)
			mq_cond_set(d->not_full);
	} else {
		mq_cond_unset(d->not_empty_prio[prio]);
		q->prio_head[prio] = -1;
		q->prio_tail[prio] = -1;
		if (q->curmsg == 0)
			mq_cond_unset(d->not_empty);
	}

	err = 0;

	if (0) {
bad:
		err = -1;
	}

	mqd_release_lock(d);
	return err;
}

int mq_send(mqd_t des, const char *msg_ptr, size_t msg_size, unsigned msg_prio)
{
	struct mqd *d = NULL;
	struct mqueue *q;
	struct message *prev;
	struct message *m;
	int res = 0;

	if (msg_prio >= MQ_PRIO_MAX) {
		errno = EINVAL;
		return -1;
	}

	d = get_and_lock_mqd(des);
	if (d == NULL) {
		errno = EBADF;
		return -1;
	}

	/* discard volatile qualifier, as the queue will not be modified by
	 * other threads
	 */
	q = (void*)d->queue;

	if (msg_size > d->attr.mq_msgsize) {
		errno = EMSGSIZE;
		goto bad;
	}

	/* Check the queue's permisions */
	if (!(d->flags & (O_RDWR | O_WRONLY))) {
		errno = EPERM;
		goto bad;
	}

	if (q->free_head == -1) {
		if (!(d->flags & O_NONBLOCK)) do {
			mqd_release_lock(d);
			mq_wait_handle(&d->not_full);
			d = get_and_lock_mqd(des);
			if (d == NULL) {
				errno = EBADF;
				return -1;
			}
			if (d->queue->free_head != -1) {
				q = (void*)d->queue;
				goto send;
			}
		} while (!(d->flags & O_NONBLOCK));
		errno = EAGAIN;
		goto bad;
	}

	if (q->curmsg > d->attr.mq_maxmsg) {
		errno = EBADMSG;
		goto bad;
	}

send:
	/* create the message */
	m = mqueue_get_msg(q, q->free_head);
	if (m == NULL) {
		errno = EBADMSG;
		goto bad;
	}

	m->size = msg_size;
	m->flags = MQ_MSG_ALIVE;
	memcpy(m->buffer, msg_ptr, msg_size);
	m->prev = q->prio_tail[msg_prio];
	prev = mqueue_get_msg(q, q->prio_tail[msg_prio]);

	if (prev != NULL) {
	/* Put the new message in the queue. Ignore value of m->prev */
		q->prio_tail[msg_prio] = prev->next = q->free_head;
	}

	/* check if the queue can hold more messages */
	if (m->next == -1) {
		q->free_head = q->free_tail = -1;
		mq_cond_unset(&d->not_full);
	} else {
		q->free_head = m->next;
	}

	m->next = -1;
	d->attr.mq_curmsg = ++q->curmsg;

	/* signal that the queue is not empty */
	if (q->curmsg == 1) {
		mq_cond_set(&d->not_empty);
		mq_cond_set(&d->not_empty_prio[msg_prio]);
	}

	if (0) {
bad:
		res = -1;
	}
	mqd_release_lock(d);
	return res;
}

int mq_unlink(const char *name)
{
	errno = ENOSYS;
	return -1;
}

static int mqdtable_init(void)
{
	if (mqdtab == NULL)
		mqdtab = calloc(1, sizeof(struct mqdtable));

	if (mqdtab != NULL) {
		/* create a lock */
		int i = 1;
		InitializeCriticalSection(&mqdtab->lock);
		EnterCriticalSection(&mqdtab->lock);
		for (; i < MQ_OPEN_MAX; ++i) {
			mqdtab->desc[i - 1].next = &mqdtab->desc[i];
			mqdtab->desc[i].prev = &mqdtab->desc[i - 1];
		}
		mqdtab->free_mqd.head = mqdtab->desc;
		LeaveCriticalSection(&mqdtab->lock);
		return 0;
	}
	return -1;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD fdwReason, LPVOID reserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		if (mqdtable_init())
			return FALSE;
		break;
	}
	return TRUE;
}
