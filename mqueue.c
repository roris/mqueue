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

static int release_and_wait(HANDLE rel, HANDLE wait)
{
	switch (SignalObjectAndWait(rel, wait, INFINITE, FALSE)) {
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

#define QUEUE_INDEX_IN_RANGE(q, i)	(i >= -1 && i < q->maxmsg)
#define VALID_QUEUE_INDEX(q, i)		(QUEUE_INDEX_IN_RANGE(q, i) && i != -1)

static int queue_sanity_check(struct mqueue *q)
{
	int elements_are_sane = 1;
	int i = 0;

	if (!(q->curmsg <= q->maxmsg && q->curmsg >= 0 && q->maxmsg != 0))
		return 0;

	if (q->curmsg == q->maxmsg) {
		if (q->free_head != -1 || q->free_tail != -1)
			return 0;
	} else {
		if (q->free_head == -1 || q->free_tail == -1)
			return 0;
		if (q->free_tail == q->free_head && q->maxmsg - 1 != q->curmsg)
			return 0;
	}

	for (; i < MQ_PRIO_MAX; ++i) {
		elements_are_sane &= QUEUE_INDEX_IN_RANGE(q, q->prio_head[i]);
		elements_are_sane &= QUEUE_INDEX_IN_RANGE(q, q->prio_tail[i]);
	}

	return elements_are_sane && QUEUE_INDEX_IN_RANGE(q, q->free_tail) &&
	    QUEUE_INDEX_IN_RANGE(q, q->free_head);
}

static int message_sanity_check(struct message *m, struct mqueue *q)
{
	return QUEUE_INDEX_IN_RANGE(q, m->next) &&
	    QUEUE_INDEX_IN_RANGE(q, m->prev) && m->size <= q->msgsize;
}

static struct mqd *get_and_lock_mqd(mqd_t mqdes)
{
	struct mqd *res;

	mqdtable_lock();

	res = (void *)get_mqd(mqdes);

	if (res)
		mqd_get_lock(res);

	mqdtable_unlock();

	return res;
}

static void mqd_release_lock(struct mqd *d)
{
	ReleaseMutex(d->mutex);
}

static int mqd_create_and_get_lock(struct mqd *d, wchar_t * name, int namelen)
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
		if (d->mutex) {
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
		if (d->mutex) {
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

	if (!oth)
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
inflate_conv(wchar_t * out, const char *src, int *length, DWORD maxsize)
{
	WCHAR *tmp;
	DWORD tmpsize;

	tmpsize = MultiByteToWideChar(CP_THREAD_ACP,
				      MB_ERR_INVALID_CHARS, src, -1, NULL, 0);

	if (tmpsize > maxsize || tmpsize == 0)
		return -1;

	if (length)
		*length = tmpsize / sizeof(wchar_t);

	/* should this be changed to something else? */
	tmp = malloc(tmpsize);

	if (!tmp)
		return -1;

	MultiByteToWideChar(CP_THREAD_ACP,
			    MB_ERR_INVALID_CHARS, src, -1, tmp, tmpsize);

	wcscpy(out, MQ_PREFIX);
	wcscat(out, tmp);

	free(tmp);
	return 0;
}

static struct message *get_message(struct mqueue *mq, int index)
{
	return (struct message *)&((char *)(mq->buffer))[index * mq->msgsize];
}

static struct message *get_live_message(struct mqueue *q, int n)
{
	struct message *m = get_message(q, n);
	return (m->flags & MQ_MSG_ALIVE) ? m : NULL;
}

static int valid_open_attr(struct mq_attr *a)
{
	return a->mq_maxmsg > 0 && a->mq_msgsize > 0 && a->mq_sleepdur > 0;
}

static HANDLE do_mqd_create_cond(struct mqd *d, wchar_t * name, BOOL signaled)
{
	HANDLE res;

	if (d->flags & O_CREAT) {
		res = CreateEventW(NULL, TRUE, signaled, name);

		if (res) {
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
		if (!res) {
			errno = EOTHER;
		}
	}

	return res;
}

static int mqd_create_cond(struct mqd *d, wchar_t * name, int namelen)
{
	int i;

	if (name) {
		name[namelen] = 0;
		wcscat(name, L".evnf");
	}
	d->not_full = do_mqd_create_cond(d, name, TRUE);
	if (!d->not_full)
		return -1;
	if (name) {
		name[namelen] = 0;
		wcscat(name, L".eve?");
	}
	d->not_empty = do_mqd_create_cond(d, name, FALSE);
	if (!d->not_empty)
		goto close_not_full;

	d->empty = do_mqd_create_cond(d, name, TRUE);
	if (!d->empty)
		goto close_not_empty;

	for (i = 0; i < MQ_PRIO_MAX; i++) {
		if (name) {
			name[namelen + 4] = L'0' + (i % 10);
			name[namelen + 3] = L'0' + (i / 10);
		}
		d->not_empty_prio[i] = do_mqd_create_cond(d, name, FALSE);
		if (!d->not_empty_prio[i]) {
			int j = i - 1;
			for (; j >= 0; --j)
				CloseHandle(d->not_empty_prio[j]);
close_not_empty:
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
	if (!SetEvent(cond)) {
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
	mq_cond_set(d->empty);
	CloseHandle(d->empty);

	for (i = 0; i < MQ_PRIO_MAX; ++i) {
		mq_cond_set(d->not_empty_prio[i]);
		CloseHandle(d->not_empty_prio[i]);
	}
}

static void move_to_list(struct mqd *dp, struct mqd_list *dest,
			 struct mqd_list *src)
{
	/* Unlink from src first */
	if (dp->prev) {
		dp->prev->next = dp->next;
	} else {
		/* This is the head, so set the next node as the head. */
		src->head = dp->next;
	}

	/* Unlink the next node and this node. */
	if (dp->next) {
		dp->next->prev = dp->prev;
	} else {
		/* This is the tail. Make src->tail = prev. */
		src->tail = dp->prev;
	}

	/* Link this with dest. */
	dp->prev = dest->tail;
	dp->next = NULL;

	/* Link dest with this. */
	if (dest->tail) {
		dest->tail = dest->tail->next = dp;
	} else {
		dest->tail = dest->tail = dp;
	}
}

mqd_t mq_open(const char *name, int oflag, ...)
{
	struct mqd d;
	volatile struct mqd *qd;
	struct mqueue *mq;
	HANDLE *map;
	wchar_t *nameptr;
	wchar_t wname[MAX_PATH];
	long msgsize;
	DWORD err;
	DWORD mapacc;
	long maxmsg;
	int res;
	int namelen;
	va_list al;

	res = -1;
	mqdtable_lock();

	/*
	 * An application can open a max of MQ_OPEN_MAX queues. Check if the
	 * requesting application can open any more queues.
	 */
	if (mqdtab->curopen >= MQ_OPEN_MAX) {
		errno = EMFILE;
		goto unlock_table;
	}

	/* Convert the name to unicode. */
	namelen = 0;
	if (name && inflate_conv(wname, name, &namelen, MQ_NAME_MAX)) {
		errno = ENAMETOOLONG;
		goto unlock_table;
	}

	memset(&d, 0, sizeof(d));
	d.flags = oflag;

	/* Create the muteces first to prevent the queue from being created
	 * twice?
	 */
	nameptr = (name) ? wname : NULL;
	if (mqd_create_and_get_lock(&d, nameptr, namelen)) {
		if (!d.mutex)
			goto unlock_table;
	}

	/* create condition variables. */
	if (mqd_create_cond(&d, nameptr, namelen)) {
		if (!d.not_full)
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

	/* The application is requesting a new queue to be created. */
	if (oflag & O_CREAT) {
		struct mq_attr *attr;
		DWORD mapsize;
		int mode;
		int i;

		va_start(al, oflag);
		mode = va_arg(al, int);
		attr = va_arg(al, struct mq_attr *);
		(void)mode;

		/*
		 * FIXME: create a good security descritor.
		 * secdesc = create_secdesc(mode);
		 */

		/*
		 * Check if the user has provided any attributes for the queue,
		 * then set the attributes accordingly.
		 */
		if (!attr) {
			maxmsg = MQ_MAX_MSG;
			msgsize = MQ_MSG_SIZE;
		} else if (valid_open_attr(attr)) {
			maxmsg = attr->mq_maxmsg;
			msgsize = attr->mq_msgsize;
		} else {
			errno = EINVAL;
			goto destroy_lock;
		}

		/* Calculate the required size for the queue. */
		msgsize = (sizeof(struct message) + msgsize - 1);
		msgsize += msgsize % sizeof(int);
		mapsize = (sizeof(struct mqueue) - 1) + (msgsize * maxmsg);
		mapsize += mapsize % sizeof(int);

		map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
					 PAGE_READWRITE, 0, mapsize, nameptr);
		if (!map) {
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
		if (!mq) {
			errno = EOTHER;
			goto close_map;
		}

		mq->maxmsg = maxmsg;
		mq->msgsize = msgsize - (sizeof(struct message) + 1);

		if (name) {
			memcpy(mq->name, wname, namelen);
			mq->namelen = namelen;
		}
		mq->free_tail = maxmsg - 1;
		for (i = 1; i < maxmsg; ++i) {
			get_message(mq, i - 1)->next = i;
			get_message(mq, i)->prev = i - 1;
		}
		get_message(mq, maxmsg - 1)->next = -1;

		for (i = 0; i < MQ_PRIO_MAX; ++i) {
			mq->prio_head[i] = mq->prio_tail[i] = -1;
		}

	} else {
		map = OpenFileMappingW(mapacc, 0, wname);

		if (!map) {
			errno = ENOENT;
			goto destroy_lock;
		}
copy_open:
		mq = MapViewOfFile(map, mapacc, 0, 0, 0);
		if (!mq) {
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

	/*
	 * Since the table is locked here, it is not necessary to lock the
	 * other queue descriptors. It is impossible for the process to have
	 * MQ_OPEN_MAX queues open so mqd.free_mqd.head will not have been
	 * reached.
	 *
	 * TODO: merge mqd.free_mqd.head and mqd.curopen.
	 *
	 */

	*mqdtab->free_mqd.head = d;
	move_to_list(mqdtab->free_mqd.head, &mqdtab->open_mqd,
		     &mqdtab->free_mqd);
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

/**
 * WARNING: call only after locking mqdtab.
 */
static void mqd_close(struct mqd *d)
{
	/* Get the lock. Another thread might be owning the queue's lock. */
	mqd_get_lock(d);

	/* Turn off the live flag to prevent the queue from being accessed. */
	d->flags &= ~MQ_MQD_ALIVE;

	if (d->queue->pid == GetCurrentProcessId()) {
		d->queue->pid = 0;
		pthread_cancel(d->thread);
	}
	mqd_destroy_cond(d);
	/* Free resources. */
	if (d->thread)
		UnmapViewOfFile((LPVOID) d->queue);
	CloseHandle(d->map);
	if (!(d->flags & O_PRIVATE))
		CloseHandle(d->mutex);

	--mqdtab->curopen;
	/* finally destroy the queue's lock. */
	mqd_destroy_lock(d);
}

int mq_close(mqd_t mqdes)
{
	volatile struct mqd *d;
	int err;

	/* lock table first */
	mqdtable_lock();
	d = (void *)get_mqd(mqdes);

	/* Check The queue was already closed by another thread. */
	if (d) {
		mqd_close(d);
		err = 0;
	} else {
		errno = EBADF;
		err = -1;
		goto out;
	}

	/*
	 * Not owning a lock is safe here, as the free list is only accessed
	 * after the table's lock is owned. The current queue descriptor is
	 * appended to the mqtable's free list. If the free list does not have
	 * a tail, it set as the list's head and tail.
	 */
	move_to_list(d, &mqdtab->free_mqd, &mqdtab->open_mqd);
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

int mq_receive(mqd_t des, char *msg_ptr, size_t msg_size, unsigned *msg_prio)
{
	struct mqd *d;
	struct mqueue *q;
	struct message *m = NULL;
	int maxprio = (msg_prio) ? *msg_prio : MQ_PRIO_MAX - 1;
	int minprio = (msg_prio) ? *msg_prio : 0;
	int prio;
	int err;

	prio = maxprio;
	if (!msg_ptr || minprio < 0 || maxprio >= MQ_PRIO_MAX) {
		errno = EINVAL;
		return -1;
	}

	d = get_and_lock_mqd(des);
	if (!d) {
		errno = EBADF;
		return -1;
	}

	if (!(d->flags & O_RDWR) && d->flags & O_WRONLY) {
		errno = EPERM;
		goto bad;
	}
	goto check_queue;

	while (!m) {
again:
		if (d->flags & O_NONBLOCK) {
			errno = EAGAIN;
			goto bad;
		}
		mqd_release_lock(d);
		if (msg_prio) {
			mq_wait_handle(d->not_empty_prio[prio]);
		} else {
			mq_wait_handle(d->not_empty);
		}
		d = get_and_lock_mqd(des);
		if (!d)
			return -1;
		/* another waiting thread may have received the message. */
check_queue:
		q = (void *)d->queue;
		if (q->curmsg == 0)
			goto again;
		if (!queue_sanity_check(q)) {
			goto bad_message;
		}
		for (; prio >= minprio && !m; --prio) {
			int n = q->prio_head[prio];
			if (n != -1) {
				if (!QUEUE_INDEX_IN_RANGE(q, n)) {
					goto bad_message;
				}
				m = get_live_message(q, n);
				if (!m || message_sanity_check(m, q)) {
bad_message:
					errno = EBADMSG;
					goto bad;
				}
			}
		}
		prio = maxprio;
	}

	if (m->size > msg_size) {
		errno = EMSGSIZE;
		goto bad;
	}

	if (q->free_tail >= 0) {
		m->prev = q->free_tail;
		get_message(q, q->free_tail)->next = q->prio_head[prio];
		q->free_tail = q->prio_head[prio];
	} else {
		/* queue was full until this message was reached */
		m->prev = -1;
		m->next = -1;
		q->free_tail = q->prio_head[prio];
		q->free_head = q->prio_head[prio];
		mq_cond_set(d->not_full);
	}

	if (m->next >= 0) {
		get_message(q, m->next)->prev = -1;
		q->prio_head[prio] = m->next;
	} else {
		q->prio_head[prio] = -1;
		q->prio_tail[prio] = -1;
		if (q->curmsg == 0)
			mq_cond_unset(d->not_empty);
		mq_cond_unset(d->not_empty_prio[prio]);
	}
	m->flags &= ~MQ_MSG_ALIVE;
	--q->curmsg;
	memcpy(msg_ptr, m->buffer, m->size);
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
	struct mqd *d;
	struct mqueue *q;
	struct message *prev;
	struct message *m = NULL;
	int res = 0;
	int prio = msg_prio;

	if (prio >= MQ_PRIO_MAX || prio < 0 || !msg_ptr) {
		errno = EINVAL;
		return -1;
	}

	d = get_and_lock_mqd(des);
	if (!d) {
		errno = EBADF;
		return -1;
	}

	/* Check the queue's permisions, ones passed to mq_open. */
	if (!(d->flags & (O_RDWR | O_WRONLY))) {
		errno = EPERM;
		goto bad;
	}
	goto check_queue;

again:
	if (d->flags & O_NONBLOCK) {
		errno = EAGAIN;
		goto bad;
	}
	mqd_release_lock(d);

	/* perhaps it is best to duplicate this handle */

	mq_wait_handle(d->not_full);
	d = get_and_lock_mqd(des);
	if (!d) {
		errno = EBADF;
		return -1;
	}

check_queue:
	q = (void *)d->queue;
	if (msg_size > q->msgsize) {
		errno = EMSGSIZE;
		goto bad;
	}
	if (!queue_sanity_check(q))
		goto bad_message;
	if (q->curmsg == q->maxmsg)
		goto again;
	if (q->free_head == -1) {
bad_message:
		errno = EBADMSG;
		goto bad;
	}
	m = get_message(q, q->free_head);
	m->size = msg_size;
	m->prev = q->prio_tail[msg_prio];

	if (VALID_QUEUE_INDEX(q, q->prio_tail[msg_prio])
	    && q->prio_tail[msg_prio]) {
		/* Put the new message in the queue. Ignore value of m->prev */
		get_message(q, q->prio_tail[msg_prio])->next = q->free_head;
		q->prio_tail[msg_prio] = q->free_head;
	}

	/* no remaining free message slots */
	if (q->curmsg == q->maxmsg - 1) {
		q->free_head = q->free_tail = -1;
		mq_cond_unset(&d->not_full);
	} else {
		q->free_head = m->next;
	}
	m->next = -1;
	/* signal that the queue is not empty */
	if (q->curmsg == 0) {
		mq_cond_set(&d->not_empty);
		mq_cond_set(&d->not_empty_prio[msg_prio]);
	}

	m->flags = MQ_MSG_ALIVE;
	++q->curmsg;
	memcpy(m->buffer, msg_ptr, msg_size);
	if (0) {
bad:
		res = -1;
	}
	mqd_release_lock(d);
	return res;
}

void __cdecl *notify_proc(void *arg)
{
	mqd_t des = (mqd_t) arg;
	DWORD pid = GetCurrentProcessId();
	HANDLE proc = GetCurrentProcess();
	pthread_t thread;
	struct mqd *dp = get_and_lock_mqd(des);
	void *res = (void *)EXIT_FAILURE;
	BOOL err;

	if (!dp)
		goto out;

	if (dp->queue->curmsg) {
		/* if the queue already has messages, wait for it to become empty. */
		if (release_and_wait(dp, dp->empty))
			goto out;

		/* The state of the queue is unknown at this point */
		dp = get_and_lock_mqd(des);
		if (!dp)
			goto out;
		if (dp->thread_should_terminate) {
			return (void *)PTHREAD_CANCELLED;
		}
	}

	/* Assume that another thread may have gotten the message first. Loop until all messages are cleared. */
	do {
		/* if the queue does not have any messages, wait for one. */
		if (release_and_wait(dp, dp->not_empty))
			goto out;

		/* The state of the queue is unknown at this point */
		dp = get_and_lock_mqd(des);
		if (!dp)
			goto out;
		if (dp->thread_should_terminate) {
			return (void*)PTHREAD_CANCELLED;
		}
	} while (!dp->queue->curmsg);

	/* finally handle the sigevent */
	if (dp->notification.sigev_notify == SIGEV_THREAD) {
		pthread_create(&thread,
			       dp->notification.sigev_notify_attributes,
			       dp->notification.sigev_notify_function,
			       dp->notification.sigev_value.sival_ptr);
		dp->queue->pid = 0;
		mqd_release_lock(dp);
		pthread_join(thread, &res);
	} else {
		res = (void *)EXIT_SUCCESS;
	}

out:
	return res;
}

int mq_notify(mqd_t mqdes, const struct sigevent *notification)
{
	struct mqd *d = get_and_lock_mqd(mqdes);
	DWORD pid = GetCurrentProcessId();

	if (!d) {
		errno = EBADF;
		return -1;
	}

	if (!notification) {
		/* cleanup */
		if (d->queue->pid == pid) {
			d->thread_should_terminate = 1;
			pthread_cancel(d->thread);
			d->queue->pid = 0;
			return 0;
		}

		errno = EINVAL;
		return -1;
	}

	if (d->queue->pid) {
		errno = EBUSY;
		return -1;
	}

	if (notification->sigev_notify == SIGEV_SIGNAL) {
		errno = ENOSYS;
		return -1;
	}

	if (notification->sigev_notify != SIGEV_NONE
	    || notification->sigev_notify != SIGEV_THREAD) {
		errno = EINVAL;
		return -1;
	}

	d->queue->pid = pid;
	d->notification = *notification;
	d->thread_should_terminate = 0;
	if (pthread_create
	    (&d->thread, notification->sigev_notify_attributes, notify_proc,
	     (void *)mqdes)) {
		return -1;
	}

	return 0;
}

int mq_unlink(const char *name)
{
	errno = ENOSYS;
	return -1;
}

static int mqdtable_init(void)
{
	if (mqdtab)
		return;

	mqdtab = calloc(1, sizeof(struct mqdtable));

	if (mqdtab) {
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

static int mqdtable_fini(void)
{
	if (mqdtab) {
		struct mqd *desc = mqdtab->open_mqd.head, *p;

		while (desc) {
			p = desc->next;
			mqd_close(desc);
			desc = p;
		}

		DestroyCriticalSection(&mqdtab->lock);
		free(mqdtab);
		mqdtab = NULL;
	}
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		if (mqdtable_init())
			return FALSE;
		break;
	case DLL_PROCESS_DETACH:
		if (!reserved)
			mqdtable_fini();
	}
	return TRUE;
}
