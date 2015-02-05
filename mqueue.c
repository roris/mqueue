#include <windows.h>
#include <malloc.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mqueue.h"

#define MQ_MSG_ALIVE    0x1

struct mqd {
    struct mqd         *next;       /* next queue descriptor */
    struct mqd         *prev;       /* previous queue descriptor */
    union {
        volatile struct mqueue  *queue;
        HANDLE          map;        /* handle to shared memory */
    } mqd_u;
    HANDLE              lock;       /* lock on the queue */
    int                 flags;      /* flags */
    int                 alive;      /* non zero if alive */
    int                 id;         /* our index */
    struct mq_attr      mq_attr;    /* flags for the current queue */
};

struct message {
    DWORD   next;               /* index of the next message */
    DWORD   prev;               /* index of the previous message */
    WORD    size;               /* size of the message */
    char    buf[MQ_MSG_SIZE];
    BYTE    flags;              /* flags */
};

struct mqueue {
    long            curmsg;                 /* current msgs in the queue should be updated. */
    DWORD           atom;                   /* atom for the file name */
    DWORD           next_msg;               /* Next free element, -1 if queue is full. */
    DWORD           prio_tail[MQ_PRIO_MAX]; /* last element in each priority sub queue */
    DWORD           prio_head[MQ_PRIO_MAX]; /* head of each priority sub queue */
    struct message  msg[MQ_MAX_MSG];        /* all messages owned by this mqueue */
    DWORD           namelen;                /* length of the name */
    wchar_t         name[1];                /* name */
};

struct mqdtable {
    struct mqdtable    *parent;             /* parent table */
    struct mqd         *free_mqs;           /* free mqs */
    struct mqd          mqdes[MQ_OPEN_MAX]; /* queue descriptor buffer */
    CRITICAL_SECTION    lock;               /* tables are process specific */
    WORD                curqueue;           /* number of queues currently open (in the table) */
};

static DWORD tls_index;
static struct mqdtable *global;


BOOL mq_dll_main(HINSTANCE, DWORD, LPVOID);
struct mqdtable *get_mqdt(void);
struct mqd *get_mqd(mqd_t);
struct mqueue *mqd_get_mq(struct mqd *);

static int mqd_lock(struct mqd *d)
{
    DWORD ms = (d->flags & O_NONBLOCK)? 1 : INFINITE;

    switch(WaitForSingleObject(d->lock, ms)) {
    case WAIT_ABANDONED:
        /* EDEADLOCK? */
    case WAIT_OBJECT_0:
        return 0;
    }
    return -1;
}

static void mqd_unlock(struct mqd *d)
{
    ReleaseMutex(d->lock);
}

#if 0
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
    if(t->curqueue == MQ_OPEN_MAX)
        return NULL;

    /* find a dead qd */
    for(qd = t->mqdes; qd < &t->mqdes[MQ_OPEN_MAX]; ++qd)
        if(!qd->alive)
            return qd;

    return NULL;
}

static wchar_t *widen(const char *src, DWORD *out_size)
{
    wchar_t *result;
    DWORD tmpsize;

    tmpsize = MultiByteToWideChar(
        CP_THREAD_ACP,
        MB_ERR_INVALID_CHARS,
        src,
        -1,
        NULL,
        0
    );

    result = malloc(tmpsize);

    MultiByteToWideChar(
        CP_THREAD_ACP,
        MB_ERR_INVALID_CHARS,
        src,
        -1,
        result,
        tmpsize
    );

    if(out_size)
        *out_size = tmpsize;

    return result;
}

mqd_t mq_open(const char *name, int oflag, ...)
{
    DWORD wsize;
    BOOL inherit;
    int namelen = strlen(name);
    void *tmp;
    struct mqdtable *mqdt;
    int res = 0;
    struct mqd *qd;
    struct mqd *old;

    if(namelen >= MAX_PATH)
        return -1;

    /* change the name to a unicode name */
    tmp = widen(name, &wsize);

    /* get the mqdtable for the current thread */
    mqdt = get_mqdt();
    mqdtable_lock(mqdt);

    /* get a free mqd, in the current thread's table. */
    qd = mqdtable_get_next_mqd(mqdt);
    if(!qd) {
        res = -1;
        goto mqdt_unlock;
    }

    /* check if mqd exists (in the process)*/
    if((old = mq_opened(tmp)) != NULL) {
        *qd = *old;
        /* this MIGHT need special handling */
        if(qd->flags & O_NONINHERIT) {

        }
    } else {
        qd->map = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE | ((oflag & O_NORESERVE)? SEC_COMMIT : SEC_RESERVE),
            0,
            sizeof(struct mq) + wnamelen,
            tmp);

        last_error = GetLastError();
    }

    qd->flags = oflag;

    switch(last_error) {
    case ERROR_INVALID_HANDLE:
        goto on_error;
    case ERROR_ALREADY_EXISTS:
        if(oflag & O_EXCL)
            goto on_error
        exists = 1;
    }

    MapViewOfFile(
        mqd_get_map(mqd),
        (oflag & O_RDWR || oflag & O_WRONLY) ? FILE_MAP_WRITE : FILE_MAP_READ,
        0,
        0,
        sizeof(struct mq) + wnamelen);

    mq = mqd_get_mq(mqd);

    if(exists) {

    } else {

    }

    mqdt_to_next_free_mqd(mqdt);
    mqdt_unlock(mqdt);

    free(tmp);
    return res;
}

#endif

DWORD mqd_get_next_msg(struct mqd *d)
{
    int i;
    DWORD j;
    struct mqueue *q;
    struct message *m;

    /* queue is full */
    q = (void*)d->mqd_u.queue;
    if(d->mq_attr.mq_curmsg >= MQ_MAX_MSG)
        return -1;

    /* an empty queue */
    if(!d->mq_attr.mq_curmsg)
        return 0;

    j = q->next_msg;
    m = q->msg;

    /* next_msg is a free msg */
    if(!(m->flags & MQ_MSG_ALIVE))
        return j;

    /* walk the array */
    for(i = 1, ++j; i < MQ_MAX_MSG; ++i) {
        if(!(q->msg[j].flags & MQ_MSG_ALIVE))
            return j;
        ++j;
        j &= (MQ_MAX_MSG - 1);
    }
    /* on the off chance something goes wrong */
    return -1;
}

#if 0
int mq_receive(mqd_t des, const char *msg_ptr, size_t msg_size, unsigned *msg_prio)
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
    if(msg_prio != NULL) {

mq_recv_prio:
        m = mq_recv_prio(q, *msg_prio);

        if(m == NULL && nonblock) {
            Sleep(q->mq_attr.mq_sleepdur);
            goto mq_recv_prio;
        }

    } else {
mq_recv:
        m = mq_recv(q);
        if(m == NULL && nonblock) {
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
    DWORD next;
    DWORD sleep_dur;

    /* msg_size <= to mq_msgsize */
    if(msg_size > MQ_MSG_SIZE) {
        /* xxx: set errno */
        return -1;
    }

    /* 0 <= msg_prio < MQ_PRIO_MAX */
    if(msg_prio >= MQ_PRIO_MAX || msg_prio < 0) {
        /* xxx: set errno */
        return -1;
    }

    d = get_mqd(des);

    /* fail if cannot be written to */
    if(!(d->flags & (O_RDWR | O_WRONLY))) {
        /* XXX: should probably set errno to EPERM */
        return -1;
    }

    if(mqd_lock(d))
        return -1;

    q = (void*)d->mqd_u.queue;
    if(q->curmsg > MQ_MAX_MSG) {
        if(d->flags & O_NONBLOCK) {
            res = -1;
            goto mqd_unlock;
        }
        do {
            mqd_unlock(d);
            Sleep(d->mq_attr.mq_sleepdur);
            mqd_lock(d);
        } while(q->curmsg > MQ_MAX_MSG);
    }

    /* NOTE: queue is guarenteed to be not full, here */
    /* create the message */
    next = q->next_msg;
    m = (void*)&q->msg[next];
    m->size = msg_size;
    m->flags = MQ_MSG_ALIVE;
    memcpy(m->buf, msg_ptr, msg_size);

    /* put the new message in the queue */
    prev = (void*)&q->msg[q->prio_tail[msg_prio]];
    prev->next = next;
    m->prev = q->prio_tail[msg_prio];
    m->next = -1;

    /* update the queue */
    q->prio_tail[msg_prio] = next;
    d->mq_attr.mq_curmsg = ++q->curmsg;
    q->next_msg = mqd_get_next_msg(d);

mqd_unlock:
    mqd_unlock(d);
    return res;
}
