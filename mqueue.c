#include <windows.h>
#include <malloc.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mqueue.h"

#define MQ_MSG_ALIVE    0x1
#define MQ_MQD_COPIED   0x2

struct mqd {
	struct mqd	*next;	/* next queue descriptor */
	struct mqd	*prev;	/* previous queue descriptor */
	union {
		volatile struct mqueue *queue;
		void	*view;
	} mqd_u;
	HANDLE		 lock;	/* lock on the queue */
	HANDLE		 map;	/* handle to the shared memory */
	int		 flags;	/* private flags */
	int		 alive;	/* non zero if alive */
	int		 id;	/* our index */
	struct mq_attr	 attr;	/* flags for the current queue */
};

struct message {
	DWORD	next;		/* index of the next message */
	DWORD	prev;		/* index of the previous message */
	WORD	size;		/* size of the message */
	char	buf[MQ_MSG_SIZE];
	BYTE	flags;		/* flags */
};

struct mqueue {
	long		curmsg;
	DWORD		next_msg;		/* Next free element or -1 */
	DWORD		prio_tail[MQ_PRIO_MAX];
	DWORD		prio_head[MQ_PRIO_MAX];
	struct message	msg[MQ_MAX_MSG];
	DWORD		namelen;
	wchar_t		name[1];
};

struct mqdtable {
	struct mqdtable	*parent;
	struct mqd	*free_mqs;		/* free mqs */
	struct mqd	 mqdes[MQ_OPEN_MAX];	/* queue descriptor buffer */
	CRITICAL_SECTION lock;
	WORD		 curqueue;		/* number of open queues */
};

static DWORD tls_index;
static struct mqdtable *global;

BOOL mq_dll_main(HINSTANCE, DWORD, LPVOID);
struct mqdtable *get_mqdt(void);
struct mqd *get_mqd(mqd_t);
struct mqueue *mqd_get_mq(struct mqd *);

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

struct mqdtable *get_mqdt(void)
{
	return TlsGetValue(tls_index);

}

static void mqdtable_lock(struct mqdtable *t)
{
	EnterCriticalSection(&t->lock);
}

static void mqdtable_unlock(struct mqdtable *t)
{
	LeaveCriticalSection(&t->lock);
}

static struct mqd *mqdtable_get_next_mqd(struct mqdtable *t)
{
	struct mqd *qd;
	const struct mqd *const end = t->mqdes[MQ_OPEN_MAX];

	/* walk the list */
	if (t->curqueue == MQ_OPEN_MAX)
		return NULL;

	/* find a dead qd */
	for (qd = t->mqdes; qd < &t->mqdes[MQ_OPEN_MAX]; ++qd)
		if (!qd->alive)
			return qd;

	return NULL;
}

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

void inflatecat(WCHAR * dest, const char *src, DWORD dest_size,
		DWORD * bytes_written)
{
	WCHAR *tmp;
	DWORD tmpsize, destlen;

	tmpsize = MultiByteToWideChar(CP_THREAD_ACP,
				      MB_ERR_INVALID_CHARS,
				      src,
				      -1,
				      NULL,
				      0);

	tmp = malloc(tmpsize);

	MultiByteToWideChar(CP_THREAD_ACP,
			    MB_ERR_INVALID_CHARS,
			    src,
			    -1,
			    tmp,
			    tmpsize);

	destlen = wcslen(dest);

	if (tmpsize + destlen > dest_size)
		goto skip_wcscat;
	wcscat(dest, tmp, tmpsize);

skip_wcscat:
	if (bytes_written)
		*bytes_written = tmpsize + destlen;
	free(tmp);
}

mqd_t mq_open(const char *name, int oflag, ...)
{
	void *view;
	struct mqd *qd;
	struct mqd_lock *lock;
	struct mqdtable *mqdt;
	HANDLE *map;
	DWORD namesize, err, mapacc;
	int res;
	WCHAR tmpn[MAX_PATH];
	BOOL inherit;

	/* change the name to a unicode name */
	wcscpy(tmp, L"/dev/mq/");
	inflatecat(tmp, name, MAX_PATH, &namesize);

	if (namesize > MAX_PATH) {
		/* ENAME2LONG */
		return -1;
	}

	/* get the mqdtable for the current thread */
	mqdt = get_mqdt();
	mqdtable_lock(mqdt);

	/* get a free mqd in the current thread's table. */
	qd = mqdt->free_mqs;
	if (!qd) goto cleanup;

	mqd_create_lock(&d, oflag, name);
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
	if (oflags & O_CREAT) {
		DWORD mem = oflag & O_NORESERVE ? SEC_COMMIT : SEC_RESERVE;
		map = CreateFileMappingW(INVALID_HANDLE_VALUE,
					 NULL,
					 PAGE_READWRITE | mem,
					 0,
					 sizeof(struct mqueue) + namelen,
					 tmp);
		error = GetLastError();

		if (d.map == NULL)
			goto cleanup;

		if (error == ERROR_ALREADY_EXISTS && oflags & O_EXCL)
			goto closemap;

	} else {
		BOOL inherit = !(oflag & O_NOINHERIT);
		map = OpenFileMappingW(mapacc, inherit, tmp);
	}

	view = MapViewOfFile(qd->map,
			     mapacc, 0, 0, sizeof(struct mq) + wnamelen);

	qd->flags = oflag & ~(O_NORESERVE | O_CREAT | O_EXCL);
	qd->lock = lock;
	mqdt_to_next_free_mqd(mqdt);
	mqdt_unlock(mqdt);
out:
	return res;

closemap:
	CloseFileMapping(map);
cleanup:
	destroy_lock(lock);
	res = -1;
	goto out;
}

DWORD mqd_get_next_msg(struct mqd *d)
{
	int i;
	DWORD j;
	struct mqueue *q;
	struct message *m;

	/* queue is full */
	q = (void *)d->mqd_u.queue;
	if (d->attr.mq_curmsg >= MQ_MAX_MSG)
		return -1;

	/* an empty queue */
	if (!d->attr.mq_curmsg)
		return 0;

	j = q->next_msg;
	m = q->msg;

	/* next_msg is a free msg */
	if (!(m->flags & MQ_MSG_ALIVE))
		return j;

	/* walk the array */
	for (i = 1, ++j; i < MQ_MAX_MSG; ++i) {
		if (!(q->msg[j].flags & MQ_MSG_ALIVE))
			return j;
		j = (j + 1) & (MQ_MAX_MSG - 1);
	}
	/* on the off chance something goes wrong */
	return -1;
}

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
	long curmsg;
	DWORD next;

	/* msg_size <= to mq_msgsize */
	if (msg_size > MQ_MSG_SIZE) {
		/* EMSGSIZE */
		return -1;
	}

	/* 0 <= msg_prio < MQ_PRIO_MAX */
	if (msg_prio >= MQ_PRIO_MAX || msg_prio < 0) {
		/* EINVAL */
		return -1;
	}

	d = get_mqd(des);

	if (d == NULL) {
		/* EBADF */
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

	q = d->mqd_u.queue;

	/* If q->curmsg > MQ_MAX_MSG, then the queue is invalid */
	curmsg = q->curmsg;
	if (curmsg > MQ_MAX_MSG) {
		/* possibly EBADF */
		goto bad;
	}

	if (curmsg == MQ_MAX_MSG) {
		if (d->flags & O_NONBLOCK) {
			/* EAGAIN */
			goto unlock;
		} else do {
				mqd_unlock(d);
				Sleep(d->mq_attr.mq_sleepdur);
				/* this should be handled */
				mqd_lock(d);
			} while (q->curmsg == MQ_MAX_MSG);
	}

	if (q->curmsg > MQ_MAX_MSG) {
		/* EBADF */
		goto bad;
	}

	/* create the message */
	next = q->next_msg;
	m = (void *)&q->msg[next];
	m->size = msg_size;
	m->flags = MQ_MSG_ALIVE;
	memcpy(m->buf, msg_ptr, msg_size);

	/* put the new message in the queue */
	prev = (void *)&q->msg[q->prio_tail[msg_prio]];
	prev->next = next;
	m->prev = q->prio_tail[msg_prio];
	m->next = -1;

	/* update the queue */
	q->prio_tail[msg_prio] = next;
	d->mq_attr.mq_curmsg = ++q->curmsg;
	q->next_msg = mqd_get_next_msg(d);
	goto unlock;
out:
	res = -1;
unlock:
	mqd_unlock(d);
	return res;
}
