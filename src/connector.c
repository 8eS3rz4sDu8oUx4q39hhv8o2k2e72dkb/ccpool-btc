/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICshack LLC https://asicshack.com
 * Copyright 2014-2017 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "asicseer-pool.h"
#include "libasicseerpool.h"
#include "uthash.h"
#include "utlist.h"
#include "stratifier.h"
#include "generator.h"

#define MAX_MSGSIZE 1024
/* Finite ceiling for trusted remote / node peers to prevent unbounded recv growth */
#define MAX_REMOTE_MSGSIZE (16 * 1024 * 1024)

/* Reap silent TCP sockets that never deliver a complete Stratum JSON message */
#define IDLE_ACCEPT_TIMEOUT 60
#define IDLE_REAP_BATCH 128

/* Per-client queued outbound byte ceilings to prevent OOM from stalled peers */
#define DEFAULT_SENDQUEUE_LIMIT (1024 * 1024)
#define REMOTE_SENDQUEUE_LIMIT (64 * 1024 * 1024)

typedef struct client_instance client_instance_t;
typedef struct sender_send sender_send_t;
typedef struct share share_t;
typedef struct redirect redirect_t;
typedef struct csender csender_t;

struct client_instance {
    /* For clients hashtable */
    UT_hash_handle hh;
    int64_t id;

    /* fd is only closed once ref drops to 0 to prevent kernel fd reuse races */
    int fd;

    /* Reference count for when this instance is used outside of the
     * connector_data lock */
    int ref;

    /* Have we disabled this client to be removed when there are no refs? */
    bool invalid;

    /* For dead_clients list */
    client_instance_t *dead_next;
    client_instance_t *dead_prev;

    client_instance_t *recycled_next;
    client_instance_t *recycled_prev;

    struct sockaddr_storage address_storage;
    struct sockaddr *address;
    char address_name[INET6_ADDRSTRLEN];

    /* Which serverurl is this instance connected to */
    int server;

    char *buf;
    unsigned long bufofs;

    /* Are we currently sending a blocked message from this client */
    sender_send_t *sending;

    /* Is this a trusted remote server */
    bool remote;

    /* Is this the parent passthrough client */
    bool passthrough;

    /* Linked list of shares in redirector mode */
    share_t *shares;

    /* Has this client already been told to redirect */
    bool redirected;
    /* Has this client been authorized in redirector mode */
    bool authorized;

    /* Time this client started blocking, 0 when not blocked */
    time_t blocked_time;

    /* Pre-session DoS protection: protected by cdata->lock */
    time_t accept_time;
    bool got_msg;

    /* The size of the socket send buffer (SO_SNDBUF) */
    int sendbufsize;

    /* Bytes currently queued but not yet written; protected by owning csender->lock */
    int64_t queued_bytes;
};

struct sender_send {
    struct sender_send *next;
    struct sender_send *prev;

    client_instance_t *client;
    char *buf;
    int len;
    int ofs;
    int qlen; /* Original byte length accounted against client->queued_bytes */
};

struct share {
    share_t *next;
    share_t *prev;

    time_t submitted;
    int64_t id;
};

struct redirect {
    UT_hash_handle hh;
    char address_name[INET6_ADDRSTRLEN];
    int id;
    int redirect_no;
};

/* Private data for the connector */
struct connector_data {
    pool_t *ckp;
    cklock_t lock;
    proc_instance_t *pi;

    time_t start_time;

    /* Array of server fds */
    int *serverfd;
    /* All time count of clients connected */
    int nfds;
    /* The epoll or kqueue fd */
    int epfd;

    bool accept;
    pthread_t pth_receiver;

    /* For the hashtable of all clients */
    client_instance_t *clients;
    /* Linked list of dead clients no longer in use but may still have references */
    client_instance_t *dead_clients;
    /* Linked list of client structures we can reuse */
    client_instance_t *recycled_clients;

    int64_t clients_generated;
    int64_t dead_generated;

    int64_t client_ids;

    /* client message process queue */
    ckmsgq_t *cmpq;

    /* client message event process queue */
    ckmsgq_t *cevents;

    /* Sharded sender threads: each client maps to id % nsenders (single-writer FIFO) */
    int nsenders;
    csender_t *csenders;

    /* Hash list of all redirected IP address in redirector mode */
    redirect_t *redirects;
    /* What redirect we're currently up to */
    int redirect;

    /* Pending sends to the upstream server */
    ckmsgq_t *upstream_sends;
    connsock_t upstream_cs;
};

typedef struct connector_data cdata_t;

struct csender {
    cdata_t *cdata;
    int id;

    sender_send_t *sends;

    int64_t sends_generated;
    int64_t sends_delayed;
    int64_t sends_queued;
    int64_t sends_size;

    mutex_t lock;
    pthread_cond_t cond;
    pthread_t pth;
};

static int drop_client__(cdata_t *cdata, client_instance_t *client);
static void reap_dead_clients(cdata_t *cdata);
static void send_client(pool_t *ckp, cdata_t *cdata, const int64_t id, char *buf);

void connector_upstream_msg(pool_t *ckp, char *msg)
{
    cdata_t *cdata = ckp->cdata;

    LOGDEBUG("Upstreaming %s", msg);
    ckmsgq_add(cdata->upstream_sends, msg);
}

/* Increase the reference count of instance */
static void inc_instance_ref__(client_instance_t *client)
{
    client->ref++;
}

static void inc_instance_ref(cdata_t *cdata, client_instance_t *client)
{
    ck_wlock(&cdata->lock);
    inc_instance_ref__(client);
    ck_wunlock(&cdata->lock);
}

/* Decrease the reference count of instance */
static void dec_instance_ref__(client_instance_t *client)
{
    client->ref--;
}

static void dec_instance_ref(cdata_t *cdata, client_instance_t *client)
{
    bool need_reap = false;

    ck_wlock(&cdata->lock);
    dec_instance_ref__(client);
    if (unlikely(client->invalid && !client->ref))
        need_reap = true;
    ck_wunlock(&cdata->lock);

    if (unlikely(need_reap))
        reap_dead_clients(cdata);
}

/* Recruit a client structure from a recycled one if available, creating a
 * new structure only if we have none to reuse. */
static client_instance_t *recruit_client(cdata_t *cdata)
{
    client_instance_t *client = NULL;

    ck_wlock(&cdata->lock);
    if (cdata->recycled_clients) {
        client = cdata->recycled_clients;
        DL_DELETE2(cdata->recycled_clients, client, recycled_prev, recycled_next);
    } else
        cdata->clients_generated++;
    ck_wunlock(&cdata->lock);

    if (!client) {
        LOGDEBUG("Connector created new client instance");
        client = ckzalloc(sizeof(client_instance_t));
    } else
        LOGDEBUG("Connector recycled client instance");

    client->id = -1;
    client->fd = -1;
    client->buf = ckzalloc(PAGESIZE);

    return client;
}

static void recycle_client__(cdata_t *cdata, client_instance_t *client)
{
    share_t *share, *tmp;

    dealloc(client->buf);
    DL_FOREACH_SAFE(client->shares, share, tmp) {
        DL_DELETE(client->shares, share);
        dealloc(share);
    }
    memset(client, 0, sizeof(client_instance_t));
    client->id = -1;
    client->fd = -1;
    DL_APPEND2(cdata->recycled_clients, client, recycled_prev, recycled_next);
}

static void recycle_client(cdata_t *cdata, client_instance_t *client)
{
    ck_wlock(&cdata->lock);
    recycle_client__(cdata, client);
    ck_wunlock(&cdata->lock);
}

/* Allows the stratifier to get a unique local virtualid for subclients */
int64_t connector_newclientid(pool_t *ckp)
{
    int64_t ret;

    cdata_t *cdata = ckp->cdata;

    ck_wlock(&cdata->lock);
    ret = cdata->client_ids++;
    ck_wunlock(&cdata->lock);

    return ret;
}

/* Accepts incoming connections on the server socket and generates client
 * instances */
static int accept_client(cdata_t *cdata, const int epfd, const uint64_t server)
{
    int fd, port, no_clients, sockd;
    pool_t *ckp = cdata->ckp;
    client_instance_t *client;
    socklen_t address_len;
    socklen_t optlen;
    const int on = 1;

    ck_rlock(&cdata->lock);
    no_clients = HASH_COUNT(cdata->clients);
    ck_runlock(&cdata->lock);

    sockd = cdata->serverfd[server];

    if (unlikely(ckp->maxclients && no_clients >= ckp->maxclients)) {
        static time_t last_full_warn = 0;
        static int full_suppressed = 0;
        time_t now_t = time(NULL);

        /* Drain level-triggered listen socket to avoid 100% CPU spin */
        fd = accept(sockd, NULL, NULL);
        if (likely(fd >= 0))
            Close(fd);
        if (now_t - last_full_warn >= 60) {
            if (full_suppressed) {
                LOGWARNING("Server full with %d clients (%d further connections dropped)",
                           no_clients, full_suppressed);
            } else {
                LOGWARNING("Server full with %d clients", no_clients);
            }
            last_full_warn = now_t;
            full_suppressed = 0;
        } else {
            full_suppressed++;
        }
        return 0;
    }

    client = recruit_client(cdata);
    client->server = server;
    client->address = (struct sockaddr *)&client->address_storage;
    address_len = sizeof(client->address_storage);
    fd = accept(sockd, client->address, &address_len);
    if (unlikely(fd < 0)) {
        static time_t last_res_warn = 0;
        int err = errno;

        recycle_client(cdata, client);
        switch (err) {
            case EBADF:
            case EFAULT:
            case EINVAL:
            case ENOTSOCK:
            case EOPNOTSUPP:
                LOGERR("Failed to accept on socket %d in acceptor: %s", sockd, strerror(err));
                return -1;
            case EMFILE:
            case ENFILE:
            case ENOBUFS:
            case ENOMEM:
                if (time(NULL) - last_res_warn >= 60) {
                    LOGWARNING("Unable to accept on socket %d: %s", sockd, strerror(err));
                    last_res_warn = time(NULL);
                }
                cksleep_ms(100);
                return 0;
            default:
                LOGNOTICE("Recoverable error on accept in accept_client: %s", strerror(err));
                return 0;
        }
    }

    switch (client->address->sa_family) {
        const struct sockaddr_in *inet4_in;
        const struct sockaddr_in6 *inet6_in;

        case AF_INET:
            inet4_in = (struct sockaddr_in *)client->address;
            inet_ntop(AF_INET, &inet4_in->sin_addr, client->address_name, INET6_ADDRSTRLEN);
            port = ntohs(inet4_in->sin_port);
            break;
        case AF_INET6:
            inet6_in = (struct sockaddr_in6 *)client->address;
            inet_ntop(AF_INET6, &inet6_in->sin6_addr, client->address_name, INET6_ADDRSTRLEN);
            port = ntohs(inet6_in->sin6_port);
            break;
        default:
            LOGWARNING("Unknown INET type for client %d on socket %d",
                   cdata->nfds, fd);
            Close(fd);
            recycle_client(cdata, client);
            return 0;
    }

    /* Configure low-latency non-blocking TCP socket before publishing */
    keep_sockalive(fd);
    noblock_socket(fd);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    /* Populate all immutable/initial fields BEFORE publishing into cdata->clients */
    client->fd = fd;
    client->accept_time = time(NULL);
    client->got_msg = false;
    optlen = sizeof(client->sendbufsize);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &client->sendbufsize, &optlen);
    LOGDEBUG("Client sendbufsize detected as %d", client->sendbufsize);

    LOGINFO("Connected new client %d on socket %d to %d active clients from %s:%d",
        cdata->nfds, fd, no_clients, client->address_name, port);

    /* Atomically assign id, take epoll refcount=1, and publish under write lock */
    ck_wlock(&cdata->lock);
    client->id = cdata->client_ids++;
    inc_instance_ref__(client);
    HASH_ADD_I64(cdata->clients, id, client);
    cdata->nfds++;
    ck_wunlock(&cdata->lock);

    if (unlikely(epfd_add(epfd, fd, client->id, true, true, false)) < 0) {
        LOGERR("Failed to epfd_add in accept_client");
        ck_wlock(&cdata->lock);
        drop_client__(cdata, client);
        ck_wunlock(&cdata->lock);
        reap_dead_clients(cdata);
        return 0;
    }

    return 1;
}

/* Mark client invalid, unhash it, and shut down the socket without closing the
 * fd yet. Keeping the fd reserved until ref == 0 eliminates any possibility of
 * accept() reusing the fd number while a sender thread is still writing to it. */
static int drop_client__(cdata_t *cdata, client_instance_t *client)
{
    int ret = -1;

    if (client->invalid)
        goto out;
    client->invalid = true;
    ret = client->fd;
    if (likely(client->fd >= 0))
        shutdown(client->fd, SHUT_RDWR);
    HASH_DEL(cdata->clients, client);
    DL_APPEND2(cdata->dead_clients, client, dead_prev, dead_next);
    /* Drop the reference representing this client's presence in epoll */
    dec_instance_ref__(client);
    cdata->dead_generated++;
out:
    return ret;
}

/* Close and recycle all dead clients whose reference counts have reached zero */
static void reap_dead_clients(cdata_t *cdata)
{
    client_instance_t *dead, *tmp;

    ck_wlock(&cdata->lock);
    DL_FOREACH_SAFE2(cdata->dead_clients, dead, tmp, dead_next) {
        if (!dead->ref) {
            DL_DELETE2(cdata->dead_clients, dead, dead_prev, dead_next);
            LOGINFO("Connector recycling client %"PRId64, dead->id);
            if (likely(dead->fd >= 0)) {
                nolinger_socket(dead->fd);
                Close(dead->fd);
            }
            recycle_client__(cdata, dead);
        }
    }
    ck_wunlock(&cdata->lock);
}

static void stratifier_drop_id(pool_t *ckp, const int64_t id)
{
    char buf[256];

    sprintf(buf, "dropclient=%"PRId64, id);
    send_proc(ckp->stratifier, buf);
}

/* Complete side effects after drop_client__ has atomically invalidated client */
static int finish_drop_client(pool_t *ckp, client_instance_t *client, int fd)
{
    bool passthrough = client->passthrough, remote = client->remote;
    char address_name[INET6_ADDRSTRLEN];
    int64_t client_id = client->id;

    strcpy(address_name, client->address_name);
    if (fd > -1) {
        if (passthrough) {
            LOGNOTICE("Connector dropped passthrough %"PRId64" %s",
                  client_id, address_name);
        } else if (remote) {
            LOGWARNING("Remote trusted server client %"PRId64" %s disconnected",
                   client_id, address_name);
        }
        LOGDEBUG("Connector dropped fd %d", fd);
        stratifier_drop_id(ckp, client_id);
    }

    return fd;
}

/* For sending the drop command to the upstream pool in passthrough mode */
static void generator_drop_client(pool_t *ckp, const client_instance_t *client)
{
    json_t *val;

    JSON_CPACK(val, "{si,sI:ss:si:ss:s[]}", "id", 42, "client_id", client->id, "address",
           client->address_name, "server", client->server, "method", "mining.term",
           "params");
    generator_add_send(ckp, val);
}

static void stratifier_drop_client(pool_t *ckp, const client_instance_t *client)
{
    stratifier_drop_id(ckp, client->id);
}

/* Complete invalidation side effects and reap unreferenced dead clients */
static int finish_invalidate_client(pool_t *ckp, cdata_t *cdata, client_instance_t *client, int ret)
{
    ret = finish_drop_client(ckp, client, ret);
    if ((!ckp->passthrough || ckp->node) && !client->passthrough)
        stratifier_drop_client(ckp, client);
    if (ckp->passthrough)
        generator_drop_client(ckp, client);

    reap_dead_clients(cdata);
    return ret;
}

/* Invalidate this instance. Client must hold a reference count. */
static int invalidate_client(pool_t *ckp, cdata_t *cdata, client_instance_t *client)
{
    int ret;

    ck_wlock(&cdata->lock);
    ret = drop_client__(cdata, client);
    ck_wunlock(&cdata->lock);
    return finish_invalidate_client(ckp, cdata, client, ret);
}

static void drop_all_clients(cdata_t *cdata)
{
    client_instance_t *client, *tmp;
    int64_t *ids = NULL;
    int n = 0, i;

    ck_wlock(&cdata->lock);
    HASH_ITER(hh, cdata->clients, client, tmp) {
        int64_t id = client->id;
        if (drop_client__(cdata, client) > -1) {
            ids = ckrealloc(ids, (size_t)(n + 1) * sizeof(*ids));
            ids[n++] = id;
        }
    }
    ck_wunlock(&cdata->lock);

    for (i = 0; i < n; i++)
        stratifier_drop_id(cdata->ckp, ids[i]);
    dealloc(ids);
    reap_dead_clients(cdata);
}

/* Look for shares being submitted via a redirector and add them to a linked
 * list for looking up the responses. */
static void parse_redirector_share(cdata_t *cdata, client_instance_t *client, const json_t *val)
{
    share_t *share, *tmp;
    time_t now;
    int64_t id;

    if (!json_get_int64(&id, val, "id")) {
        LOGNOTICE("Failed to find redirector share id");
        return;
    }
    share = ckzalloc(sizeof(share_t));
    now = time(NULL);
    share->submitted = now;
    share->id = id;

    LOGINFO("Redirector adding client %"PRId64" share id: %"PRId64, client->id, id);

    ck_wlock(&cdata->lock);
    DL_APPEND(client->shares, share);

    /* Age old shares */
    DL_FOREACH_SAFE(client->shares, share, tmp) {
        if (now > share->submitted + 120) {
            DL_DELETE(client->shares, share);
            dealloc(share);
        }
    }
    ck_wunlock(&cdata->lock);
}

/* Client is holding a reference count from being on the epoll list. Returns
 * true if we will still be receiving messages from this client. */
static bool parse_client_msg(pool_t *ckp, cdata_t *cdata, client_instance_t *client)
{
    int buflen, ret;
    json_t *val;
    char *eol;

retry:
    if (unlikely(client->bufofs > MAX_MSGSIZE)) {
        if (unlikely(!client->remote || client->bufofs > MAX_REMOTE_MSGSIZE)) {
            LOGNOTICE("Client id %"PRId64" fd %d overloaded buffer without EOL, disconnecting",
                client->id, client->fd);
            return false;
        }
        char *newbuf = realloc(client->buf, round_up_page(client->bufofs + MAX_MSGSIZE + 1));
        if (unlikely(!newbuf)) {
            LOGERR("Client id %"PRId64" failed to grow remote recv buffer", client->id);
            return false;
        }
        client->buf = newbuf;
    }
    /* This read call is non-blocking since the socket is set to O_NONBLOCK */
    ret = read(client->fd, client->buf + client->bufofs, MAX_MSGSIZE);
    if (ret == 0) {
        /* Clean TCP EOF from peer */
        LOGINFO("Client id %"PRId64" fd %d closed connection (EOF)", client->id, client->fd);
        return false;
    }
    if (ret < 0) {
        if (likely(errno == EAGAIN || errno == EWOULDBLOCK))
            return true;
        LOGINFO("Client id %"PRId64" fd %d disconnected - recv fail with bufofs %lu ret %d errno %d %s",
            client->id, client->fd, client->bufofs, ret, errno, strerror(errno));
        return false;
    }
    client->bufofs += ret;
    client->buf[client->bufofs] = '\0';
reparse:
    eol = memchr(client->buf, '\n', client->bufofs);
    if (!eol)
        goto retry;

    /* Do something useful with this message now */
    buflen = eol - client->buf + 1;
    if (unlikely(buflen > MAX_MSGSIZE && (!client->remote || buflen > MAX_REMOTE_MSGSIZE))) {
        LOGNOTICE("Client id %"PRId64" fd %d message oversize, disconnecting", client->id, client->fd);
        return false;
    }

    if (unlikely(client->buf[0] != '{' ||
        !(val = json_loads(client->buf, JSON_DISABLE_EOF_CHECK, NULL)))) {
        char *buf = strdup("Invalid JSON, disconnecting\n");

        LOGINFO("Client id %"PRId64" sent invalid json message %s", client->id, client->buf);
        send_client(ckp, cdata, client->id, buf);
        return false;
    } else {
        if (client->passthrough) {
            int64_t passthrough_id = 0;

            json_getdel_int64(&passthrough_id, val, "client_id");
            /* Restrict remotely supplied subclient id to lower 32 bits */
            passthrough_id = (client->id << 32) | (passthrough_id & 0xffffffffLL);
            json_object_set_new_nocheck(val, "client_id", json_integer(passthrough_id));
        } else {
            if (ckp->redirector && !client->redirected && strstr(client->buf, "mining.submit"))
                parse_redirector_share(cdata, client, val);
            json_object_set_new_nocheck(val, "client_id", json_integer(client->id));
            json_object_set_new_nocheck(val, "address", json_string(client->address_name));
        }
        json_object_set_new_nocheck(val, "server", json_integer(client->server));

        /* Mark client as actively speaking Stratum protocol */
        if (unlikely(!client->got_msg)) {
            ck_wlock(&cdata->lock);
            client->got_msg = true;
            ck_wunlock(&cdata->lock);
        }

        /* Do not send messages of clients we've already dropped. We
         * do this unlocked as the occasional false negative can be
         * filtered by the stratifier. */
        if (likely(!client->invalid)) {
            if (!ckp->passthrough)
                stratifier_add_recv(ckp, val);
            if (ckp->node)
                stratifier_add_recv(ckp, json_deep_copy(val));
            if (ckp->passthrough)
                generator_add_send(ckp, val);
        } else
            json_decref(val);
    }
    client->bufofs -= buflen;
    if (client->bufofs)
        memmove(client->buf, client->buf + buflen, client->bufofs);
    client->buf[client->bufofs] = '\0';

    if (client->bufofs)
        goto reparse;
    goto retry;
}

static client_instance_t *ref_client_by_id(cdata_t *cdata, int64_t id)
{
    client_instance_t *client;

    ck_wlock(&cdata->lock);
    HASH_FIND_I64(cdata->clients, &id, client);
    if (client) {
        if (!client->invalid)
            inc_instance_ref__(client);
        else
            client = NULL;
    }
    ck_wunlock(&cdata->lock);

    return client;
}

/* Safely drop a client by id when caller does not hold a reference */
static void drop_client_by_id(pool_t *ckp, cdata_t *cdata, const int64_t id)
{
    client_instance_t *client = ref_client_by_id(cdata, id);

    if (unlikely(!client))
        return;
    invalidate_client(ckp, cdata, client);
    dec_instance_ref(cdata, client);
}

static bool redirect_matches(cdata_t *cdata, client_instance_t *client)
{
    redirect_t *redirect;

    ck_rlock(&cdata->lock);
    HASH_FIND_STR(cdata->redirects, client->address_name, redirect);
    ck_runlock(&cdata->lock);

    return redirect;
}

static void client_event_processor(pool_t *ckp, aevt_t *event)
{
    const uint64_t id = event->userdata;
    cdata_t *cdata = ckp->cdata;
    client_instance_t *client;

    client = ref_client_by_id(cdata, id);
    if (unlikely(!client)) {
        LOGNOTICE("Failed to find client by id %"PRId64" in receiver!", id);
        goto outnoclient;
    }
    /* We can have both messages and read hang ups so process the
     * message first. */
    if (likely(event->in)) {
        /* Rearm the client for epoll events if we have successfully
         * parsed a message from it */
        if (unlikely(!parse_client_msg(ckp, cdata, client))) {
            invalidate_client(ckp, cdata, client);
            goto out;
        }
    }
    if (unlikely(event->err)) {
        socklen_t errlen = sizeof(int);
        int error = 0;

        getsockopt(client->fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
        if (error != ECONNRESET) {
            LOGNOTICE("Client id %"PRId64" fd %d epollerr HUP in epoll with errno %d: %s",
                    client->id, client->fd, error, strerror(error));
        } else {
            LOGINFO("Client id %"PRId64" fd %d epollerr HUP in epoll with errno %d: %s",
                client->id, client->fd, error, strerror(error));
        }
        invalidate_client(cdata->pi->ckp, cdata, client);
    } else if (unlikely(event->hup)) {
        LOGINFO("Client id %"PRId64" fd %d HUP in epoll", client->id, client->fd);
        invalidate_client(cdata->pi->ckp, cdata, client);
    } else if (unlikely(event->rdhup)) {
        LOGINFO("Client id %"PRId64" fd %d RDHUP in epoll", client->id, client->fd);
        invalidate_client(cdata->pi->ckp, cdata, client);
    }
out:
    if (likely(!client->invalid)) {
        /* Rearm the fd in the epoll list if it's still active */
        epfd_mod(cdata->epfd, client->fd, id, true, true, false);
    }
    dec_instance_ref(cdata, client);
outnoclient:
    free(event);
}

/* Reap silent TCP connections that connected but never sent a single Stratum
 * JSON line within IDLE_ACCEPT_TIMEOUT seconds (anti-Slowloris / fd exhaustion). */
static void reap_idle_clients(pool_t *ckp, cdata_t *cdata)
{
    int64_t ids[IDLE_REAP_BATCH];
    client_instance_t *client, *tmp;
    time_t now_t = time(NULL);
    int nids = 0, i;

    ck_rlock(&cdata->lock);
    HASH_ITER(hh, cdata->clients, client, tmp) {
        if (client->invalid || client->got_msg)
            continue;
        if (now_t - client->accept_time > IDLE_ACCEPT_TIMEOUT) {
            ids[nids++] = client->id;
            if (unlikely(nids >= IDLE_REAP_BATCH))
                break;
        }
    }
    ck_runlock(&cdata->lock);

    for (i = 0; i < nids; i++) {
        int fd = -1;

        client = ref_client_by_id(cdata, ids[i]);
        if (unlikely(!client))
            continue;

        ck_wlock(&cdata->lock);
        if (!client->invalid && !client->got_msg &&
            now_t - client->accept_time > IDLE_ACCEPT_TIMEOUT)
            fd = drop_client__(cdata, client);
        ck_wunlock(&cdata->lock);

        if (fd >= 0) {
            LOGNOTICE("Reaping client id %"PRId64" %s idle without a message for %d seconds",
                      client->id, client->address_name, IDLE_ACCEPT_TIMEOUT);
            finish_invalidate_client(ckp, cdata, client, fd);
        }
        dec_instance_ref(cdata, client);
    }
}

/* Waits on fds ready to read on from the list stored in conn_instance and
 * handles the incoming messages */
static void *receiver(void *arg)
{
    time_t last_reap = time(NULL);
    cdata_t *cdata = (cdata_t *)arg;
    aevt_t *event = ckzalloc(sizeof(aevt_t));
    pool_t *ckp = cdata->ckp;
    uint64_t serverfds, i;
    int ret, epfd;

    rename_proc("creceiver");

    epfd = cdata->epfd = epfd_create();
    if (epfd < 0) {
        LOGEMERG("FATAL: Failed to create epfd in receiver");
        goto out;
    }
    serverfds = ckp->serverurls;
    /* Add all the serverfds to the epfd */
    for (i = 0; i < serverfds; i++) {
        ret = epfd_add(epfd, cdata->serverfd[i], i, true, false, false);
        if (ret < 0) {
            LOGEMERG("FATAL: Failed to add epfd_add fd %d to epfd %d", cdata->serverfd[i], epfd);
            goto out;
        }
    }

    /* Wait for the stratifier to be ready for us */
    while (!ckp->stratifier_ready)
        cksleep_ms(10);

    while (42) {
        uint64_t edu64;
        time_t now_t;

        while (unlikely(!cdata->accept))
            cksleep_ms(10);
        ret = epfd_wait(epfd, event, 1000);

        /* Periodic 1s housekeeping: reap silent sockets and close unreferenced dead fds */
        now_t = time(NULL);
        if (now_t != last_reap) {
            last_reap = now_t;
            reap_idle_clients(ckp, cdata);
            reap_dead_clients(cdata);
        }

        if (unlikely(ret < 1)) {
            if (unlikely(ret == -1)) {
                if (errno == EINTR)
                    continue;
                LOGEMERG("FATAL: Failed to epfd_wait in receiver");
                break;
            }
            continue;
        }
        edu64 = event->userdata;
        if (edu64 < serverfds) {
            ret = accept_client(cdata, epfd, edu64);
            if (unlikely(ret < 0)) {
                LOGEMERG("FATAL: Failed to accept_client in receiver");
                break;
            }
            continue;
        }
        /* Event structure is handed off to client_event_processor
         * here to be freed so we need to allocate a new one */
        ckmsgq_add(cdata->cevents, event);
        event = ckzalloc(sizeof(aevt_t));
    }
out:
    if (event) dealloc(event);
    return NULL;
}

/* Send a sender_send message and return true if we've finished sending it or
 * are unable to send any more. */
static bool send_sender_send(pool_t *ckp, cdata_t *cdata, sender_send_t *sender_send)
{
    client_instance_t *client = sender_send->client;
    time_t now_t;

    if (unlikely(client->invalid))
        goto out_true;

    /* Make sure we only send one message at a time to each client */
    if (unlikely(client->sending && client->sending != sender_send))
        return false;

    client->sending = sender_send;
    now_t = time(NULL);

    /* Increase sendbufsize to match large messages sent to clients - this
     * usually only applies to clients as mining nodes. */
    if (unlikely(!ckp->wmem_warn && sender_send->len > client->sendbufsize))
        client->sendbufsize = set_sendbufsize(ckp, client->fd, sender_send->len);

    while (sender_send->len) {
        ssize_t ret = send(client->fd, sender_send->buf + sender_send->ofs,
                           sender_send->len, MSG_NOSIGNAL);

        if (ret < 1) {
            if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!client->blocked_time) {
                    client->blocked_time = now_t;
                } else {
                    const time_t blocking_timeout = ckp->blocking_timeout > 0 ? ckp->blocking_timeout : 60;
                    if (unlikely(now_t - client->blocked_time >= blocking_timeout)) {
                        LOGNOTICE("Client id %"PRId64" fd %d blocked for >%"PRId64" seconds, disconnecting",
                                  client->id, client->fd, (int64_t)blocking_timeout);
                        invalidate_client(ckp, cdata, client);
                        goto out_true;
                    }
                }
                return false;
            }
            LOGINFO("Client id %"PRId64" fd %d disconnected with send errno %d:%s",
                client->id, client->fd, errno, strerror(errno));
            invalidate_client(ckp, cdata, client);
            goto out_true;
        }
        sender_send->ofs += (int)ret;
        sender_send->len -= (int)ret;
        client->blocked_time = 0;
    }
out_true:
    client->sending = NULL;
    return true;
}

static void clear_sender_send(sender_send_t *sender_send, cdata_t *cdata)
{
    client_instance_t *client = sender_send->client;
    csender_t *cs = &cdata->csenders[(uint64_t)client->id % (uint64_t)cdata->nsenders];

    mutex_lock(&cs->lock);
    client->queued_bytes -= sender_send->qlen;
    if (unlikely(client->queued_bytes < 0))
        client->queued_bytes = 0;
    mutex_unlock(&cs->lock);

    dec_instance_ref(cdata, client);
    free(sender_send->buf);
    free(sender_send);
}

/* Sharded sender thread: sleeps completely idle via pthread_cond_wait when no
 * writes are EAGAIN-delayed (zero wasted 10ms wakeups), switching to a 10ms
 * retry poll only while blocked sends remain in the local queue. */
static void *sender(void *arg)
{
    csender_t *cs = (csender_t *)arg;
    cdata_t *cdata = cs->cdata;
    sender_send_t *sends = NULL;
    pool_t *ckp = cdata->ckp;
    char procname[16];

    snprintf(procname, sizeof(procname), "csender%d", cs->id);
    rename_proc(procname);

    while (42) {
        int64_t sends_queued = 0, sends_size = 0;
        sender_send_t *sending, *tmp;

        /* Check all sends to see if they can be written out */
        DL_FOREACH_SAFE(sends, sending, tmp) {
            if (send_sender_send(ckp, cdata, sending)) {
                DL_DELETE(sends, sending);
                clear_sender_send(sending, cdata);
            } else {
                sends_queued++;
                sends_size += sizeof(sender_send_t) + sending->len + 1;
            }
        }

        mutex_lock(&cs->lock);
        cs->sends_delayed += sends_queued;
        cs->sends_queued = sends_queued;
        cs->sends_size = sends_size;
        if (!cs->sends) {
            if (likely(!sends)) {
                /* True event-driven sleep: pass underlying pthread_mutex_t */
                cond_wait(&cs->cond, &cs->lock);
            } else {
                /* Retry EAGAIN-blocked sockets after 10ms */
                const ts_t polltime = {0, 10000000};
                ts_t timeout_ts;

                ts_realtime(&timeout_ts);
                timeraddspec(&timeout_ts, &polltime);
                cond_timedwait(&cs->cond, &cs->lock, &timeout_ts);
            }
        }
        if (cs->sends) {
            DL_CONCAT(sends, cs->sends);
            cs->sends = NULL;
        }
        mutex_unlock(&cs->lock);
    }
    return NULL;
}

static int64_t client_sendqueue_limit(const client_instance_t *client)
{
    int64_t limit;

    if (client->remote || client->passthrough)
        return REMOTE_SENDQUEUE_LIMIT;
    limit = (int64_t)client->sendbufsize * 4;
    if (limit < DEFAULT_SENDQUEUE_LIMIT)
        limit = DEFAULT_SENDQUEUE_LIMIT;
    return limit;
}

/* Append a pending send to the shard owning client->id and wake that shard.
 * Never holds cs->lock while calling drop_client_by_id (strict lock hierarchy). */
static void queue_sender_send(pool_t *ckp, cdata_t *cdata, client_instance_t *client,
                              sender_send_t *sender_send)
{
    csender_t *cs = &cdata->csenders[(uint64_t)client->id % (uint64_t)cdata->nsenders];
    int64_t queued;

    sender_send->qlen = sender_send->len;

    mutex_lock(&cs->lock);
    cs->sends_generated++;
    client->queued_bytes += sender_send->qlen;
    queued = client->queued_bytes;
    DL_APPEND(cs->sends, sender_send);
    pthread_cond_signal(&cs->cond);
    mutex_unlock(&cs->lock);

    if (unlikely(queued > client_sendqueue_limit(client) && !client->invalid)) {
        LOGNOTICE("Client id %"PRId64" fd %d %s exceeded send queue limit with %"PRId64
                  " bytes queued, disconnecting", client->id, client->fd,
                  client->address_name, queued);
        drop_client_by_id(ckp, cdata, client->id);
    }
}

static int add_redirect(pool_t *ckp, cdata_t *cdata, client_instance_t *client)
{
    redirect_t *redirect;
    bool found;

    ck_wlock(&cdata->lock);
    HASH_FIND_STR(cdata->redirects, client->address_name, redirect);
    if (!redirect) {
        redirect = ckzalloc(sizeof(redirect_t));
        strcpy(redirect->address_name, client->address_name);
        redirect->redirect_no = cdata->redirect++;
        if (cdata->redirect >= ckp->redirecturls)
            cdata->redirect = 0;
        HASH_ADD_STR(cdata->redirects, address_name, redirect);
        found = false;
    } else
        found = true;
    ck_wunlock(&cdata->lock);

    LOGNOTICE("Redirecting client %"PRId64" from %s IP %s to redirecturl %d",
          client->id, found ? "matching" : "new", client->address_name, redirect->redirect_no);
    return redirect->redirect_no;
}

static void redirect_client(pool_t *ckp, client_instance_t *client)
{
    sender_send_t *sender_send;
    cdata_t *cdata = ckp->cdata;
    json_t *val;
    char *buf;
    int num;

    /* Set the redirected bool to only try redirecting them once */
    client->redirected = true;

    num = add_redirect(ckp, cdata, client);
    JSON_CPACK(val, "{sosss[ssi]}", "id", json_null(), "method", "client.reconnect",
           "params", ckp->redirecturl[num], ckp->redirectport[num], 0);
    buf = json_dumps(val, JSON_EOL | JSON_COMPACT);
    json_decref(val);

    sender_send = ckzalloc(sizeof(sender_send_t));
    sender_send->client = client;
    sender_send->buf = buf;
    sender_send->len = strlen(buf);
    inc_instance_ref(cdata, client);

    queue_sender_send(ckp, cdata, client, sender_send);
}

/* Look for accepted shares in redirector mode to know we can redirect this
 * client to a protected server. */
static bool test_redirector_shares(cdata_t *cdata, client_instance_t *client, const char *buf)
{
    json_t *val = json_loads(buf, 0, NULL);
    share_t *share, *found = NULL;
    bool ret = false;
    int64_t id;

    if (!val) {
        LOGINFO("Invalid json response to client %"PRId64 "%s", client->id, buf);
        return ret;
    }
    if (!json_get_int64(&id, val, "id")) {
        LOGINFO("Failed to find response id");
        goto out;
    }

    ck_rlock(&cdata->lock);
    DL_FOREACH(client->shares, share) {
        if (share->id == id) {
            LOGDEBUG("Found matching share %"PRId64" in trs for client %"PRId64,
                 id, client->id);
            found = share;
            break;
        }
    }
    ck_runlock(&cdata->lock);

    if (found) {
        bool result = false;

        if (!json_get_bool(&result, val, "result")) {
            LOGINFO("Failed to find result in trs share");
            goto out;
        }
        if (!json_is_null(json_object_get(val, "error"))) {
            LOGINFO("Got error for trs share");
            goto out;
        }
        if (!result) {
            LOGDEBUG("Rejected trs share");
            goto out;
        }
        LOGNOTICE("Found accepted share for client %"PRId64" - redirecting",
               client->id);
        ret = true;

        ck_wlock(&cdata->lock);
        DL_FOREACH_SAFE(client->shares, share, found) {
            DL_DELETE(client->shares, share);
            dealloc(share);
        }
        ck_wunlock(&cdata->lock);
    }
out:
    json_decref(val);
    return ret;
}

/* Send a client by id a heap allocated buffer, allowing this function to
 * free the ram. */
static void send_client(pool_t *ckp, cdata_t *cdata, const int64_t id, char *buf)
{
    sender_send_t *sender_send;
    client_instance_t *client;
    bool redirect = false;
    int64_t pass_id;
    int len;

    if (unlikely(!buf)) {
        LOGWARNING("Connector send_client sent a null buffer");
        return;
    }
    len = strlen(buf);
    if (unlikely(!len)) {
        LOGWARNING("Connector send_client sent a zero length buffer");
        free(buf);
        return;
    }

    if (unlikely(ckp->node && !id)) {
        LOGDEBUG("Message for node: %s", buf);
        send_proc(ckp->stratifier, buf);
        free(buf);
        return;
    }

    if ((pass_id = subclient(id))) {
        int64_t client_id = id & 0xffffffffll;

        client = ref_client_by_id(cdata, pass_id);
        if (unlikely(!client)) {
            LOGINFO("Connector failed to find passthrough id %"PRId64" of client id %"PRId64" to send to",
                pass_id, client_id);
            client = ref_client_by_id(cdata, client_id);
            if (client) {
                invalidate_client(ckp, cdata, client);
                dec_instance_ref(cdata, client);
            } else
                stratifier_drop_id(ckp, id);
            free(buf);
            return;
        }
    } else {
        client = ref_client_by_id(cdata, id);
        if (unlikely(!client)) {
            LOGINFO("Connector failed to find client id %"PRId64" to send to", id);
            stratifier_drop_id(ckp, id);
            free(buf);
            return;
        }
        if (ckp->redirector && !client->redirected && client->authorized) {
            if (redirect_matches(cdata, client))
                redirect = true;
            else
                redirect = test_redirector_shares(cdata, client, buf);
        }
    }

    sender_send = ckzalloc(sizeof(sender_send_t));
    sender_send->client = client;
    sender_send->buf = buf;
    sender_send->len = len;

    queue_sender_send(ckp, cdata, client, sender_send);

    /* Redirect after sending response to shares and authorize */
    if (unlikely(redirect))
        redirect_client(ckp, client);
}

static void send_client_json(pool_t *ckp, cdata_t *cdata, int64_t client_id, json_t *json_msg)
{
    client_instance_t *client;
    char *msg;

    if (ckp->node && (client = ref_client_by_id(cdata, client_id))) {
        json_t *val = json_deep_copy(json_msg);

        json_object_set_new_nocheck(val, "client_id", json_integer(client_id));
        json_object_set_new_nocheck(val, "address", json_string(client->address_name));
        json_object_set_new_nocheck(val, "server", json_integer(client->server));
        dec_instance_ref(cdata, client);
        stratifier_add_recv(ckp, val);
    }
    if (ckp->passthrough && client_id)
        json_object_del(json_msg, "node.method");

    msg = json_dumps(json_msg, JSON_EOL | JSON_COMPACT);
    send_client(ckp, cdata, client_id, msg);
    json_decref(json_msg);
}

/* When testing if a client exists, passthrough clients don't exist when their
 * parent no longer exists. */
static bool client_exists(cdata_t *cdata, int64_t id)
{
    int64_t parent_id = subclient(id);
    client_instance_t *client;

    if (parent_id)
        id = parent_id;

    ck_rlock(&cdata->lock);
    HASH_FIND_I64(cdata->clients, &id, client);
    ck_runlock(&cdata->lock);

    return !!client;
}

static void passthrough_client(pool_t *ckp, cdata_t *cdata, client_instance_t *client)
{
    json_t *val;

    LOGINFO("Connector adding passthrough client %"PRId64, client->id);
    client->passthrough = true;
    JSON_CPACK(val, "{sb}", "result", true);
    send_client_json(ckp, cdata, client->id, val);
    if (!ckp->rmem_warn)
        set_recvbufsize(ckp, client->fd, 1048576);
    if (!ckp->wmem_warn)
        client->sendbufsize = set_sendbufsize(ckp, client->fd, 1048576);
}

static void remote_server(pool_t *ckp, cdata_t *cdata, client_instance_t *client)
{
    json_t *val;

    LOGWARNING("Connector adding client %"PRId64" %s as remote trusted server",
           client->id, client->address_name);
    client->remote = true;
    JSON_CPACK(val, "{sbsb}", "result", true, "ckdb", false);
    send_client_json(ckp, cdata, client->id, val);
    if (!ckp->rmem_warn)
        set_recvbufsize(ckp, client->fd, 2097152);
    if (!ckp->wmem_warn)
        client->sendbufsize = set_sendbufsize(ckp, client->fd, 2097152);
}

static bool connect_upstream(pool_t *ckp, connsock_t *cs)
{
    json_t *req, *val = NULL, *res_val, *err_val;
    bool res, ret = false;
    float timeout = 10;

    cksem_wait(&cs->sem);
    cs->fd = connect_socket(cs->url, cs->port);
    if (cs->fd < 0) {
        LOGWARNING("Failed to connect to upstream server %s:%s", cs->url, cs->port);
        goto out;
    }
    keep_sockalive(cs->fd);

    if (!ckp->rmem_warn)
        set_recvbufsize(ckp, cs->fd, 2097152);
    if (!ckp->wmem_warn)
        cs->sendbufsiz = set_sendbufsize(ckp, cs->fd, 2097152);

    JSON_CPACK(req, "{ss,s[s]}",
            "method", "mining.remote",
            "params", PACKAGE"/"VERSION);
    res = send_json_msg(cs, req);
    json_decref(req);
    if (!res) {
        LOGWARNING("Failed to send message in connect_upstream");
        goto out;
    }
    if (read_socket_line(cs, &timeout) < 1) {
        LOGWARNING("Failed to receive line in connect_upstream");
        goto out;
    }
    val = json_msg_result(cs->buf, &res_val, &err_val);
    if (!val || !res_val) {
        LOGWARNING("Failed to get a json result in connect_upstream, got: %s",
             cs->buf);
        goto out;
    }
    ret = json_is_true(res_val);
    if (!ret) {
        LOGWARNING("Denied upstream trusted connection");
        goto out;
    }
    res_val = json_object_get(val, "ckdb");
    if (!res_val || json_is_true(res_val))
        ckp->upstream_ckdb = true;
    LOGWARNING("Connected to upstream %sckdb server %s:%s as trusted remote",
           ckp->upstream_ckdb ? "" : "non-", cs->url, cs->port);
    ret = true;
out:
    if (val)
        json_decref(val);
    cksem_post(&cs->sem);

    return ret;
}

static void usend_process(pool_t *ckp, char *buf)
{
    cdata_t *cdata = ckp->cdata;
    connsock_t *cs = &cdata->upstream_cs;
    int len, sent;

    if (unlikely(!buf || !strlen(buf))) {
        LOGERR("Send empty message to usend_process");
        goto out;
    }
    LOGDEBUG("Sending upstream msg: %s", buf);
    len = strlen(buf);
    while (42) {
        sent = write_socket(cs->fd, buf, len);
        if (sent == len)
            break;
        if (cs->fd > 0) {
            LOGWARNING("Upstream pool failed, attempting reconnect while caching messages");
            Close(cs->fd);
        }
        do
            sleep(5);
        while (!connect_upstream(ckp, cs));
    }
out:
    free(buf);
}

static void ping_upstream(cdata_t *cdata)
{
    char *buf;

    ASPRINTF(&buf, "{\"method\":\"ping\"}\n");
    ckmsgq_add(cdata->upstream_sends, buf);
}

static void *urecv_process(void *arg)
{
    pool_t *ckp = (pool_t *)arg;
    cdata_t *cdata = ckp->cdata;
    connsock_t *cs = &cdata->upstream_cs;
    bool alive = true;

    rename_proc("ureceiver");

    pthread_detach(pthread_self());

    while (42) {
        const char *method;
        float timeout = 5;
        json_t *val;
        int ret;

        cksem_wait(&cs->sem);
        ret = read_socket_line(cs, &timeout);
        if (ret < 1) {
            ping_upstream(cdata);
            if (likely(!ret)) {
                LOGDEBUG("No message from upstream pool");
            } else {
                LOGNOTICE("Failed to read from upstream pool");
                alive = false;
            }
            goto nomsg;
        }
        alive = true;
        val = json_loads(cs->buf, 0, NULL);
        if (unlikely(!val)) {
            LOGWARNING("Received non-json msg from upstream pool %s",
                   cs->buf);
            goto nomsg;
        }
        method = json_string_value(json_object_get(val, "method"));
        if (unlikely(!method)) {
            LOGWARNING("Failed to find method from upstream pool json %s",
                   cs->buf);
            /* Single decref at label decref (fixes double-free bug) */
            goto decref;
        }
        if (!safecmp(method, stratum_msgs[SM_TRANSACTIONS]))
            parse_upstream_txns(ckp, val);
        else if (!safecmp(method, stratum_msgs[SM_AUTHRESULT]))
            parse_upstream_auth(ckp, val);
        else if (!safecmp(method, stratum_msgs[SM_WORKINFO]))
            parse_upstream_workinfo(ckp, val);
        else if (!safecmp(method, stratum_msgs[SM_BLOCK]))
            parse_upstream_block(ckp, val);
        else if (!safecmp(method, stratum_msgs[SM_REQTXNS]))
            parse_upstream_reqtxns(ckp, val);
        else if (!safecmp(method, "pong"))
            LOGDEBUG("Received upstream pong");
        else
            LOGWARNING("Unrecognised upstream method %s", method);
decref:
        json_decref(val);
nomsg:
        cksem_post(&cs->sem);

        if (!alive)
            sleep(5);
    }
    return NULL;
}

static bool setup_upstream(pool_t *ckp, cdata_t *cdata)
{
    connsock_t *cs = &cdata->upstream_cs;
    bool ret = false;
    pthread_t pth;

    cs->ckp = ckp;
    if (!ckp->upstream) {
        LOGEMERG("No upstream server set in remote trusted server mode");
        goto out;
    }
    if (!extract_sockaddr(ckp->upstream, &cs->url, &cs->port)) {
        LOGEMERG("Failed to extract upstream address from %s", ckp->upstream);
        goto out;
    }

    cksem_init(&cs->sem);
    cksem_post(&cs->sem);

    while (!connect_upstream(ckp, cs))
        cksleep_ms(5000);

    create_pthread(&pth, urecv_process, ckp);
    cdata->upstream_sends = create_ckmsgq(ckp, "usender", &usend_process);
    ret = true;
out:
    return ret;
}

static void client_message_processor(pool_t *ckp, json_t *json_msg)
{
    cdata_t *cdata = ckp->cdata;
    client_instance_t *client;
    int64_t client_id;

    if (unlikely(!json_msg))
        return;

    /* Extract the client id from the json message and remove its entry */
    client_id = json_integer_value(json_object_get(json_msg, "client_id"));
    json_object_del(json_msg, "client_id");
    /* Put client_id back in for a passthrough subclient, passing its
     * upstream client_id instead of the passthrough's. */
    if (subclient(client_id))
        json_object_set_new_nocheck(json_msg, "client_id", json_integer(client_id & 0xffffffffll));

    /* Flag redirector clients once they've been authorized */
    if (ckp->redirector && (client = ref_client_by_id(cdata, client_id))) {
        if (!client->redirected && !client->authorized) {
            json_t *method_val = json_object_get(json_msg, "node.method");
            const char *method = json_string_value(method_val);

            if (!safecmp(method, stratum_msgs[SM_AUTHRESULT]))
                client->authorized = true;
        }
        dec_instance_ref(cdata, client);
    }
    send_client_json(ckp, cdata, client_id, json_msg);
}

void connector_add_message(pool_t *ckp, json_t *val)
{
    cdata_t *cdata = ckp->cdata;

    ckmsgq_add(cdata->cmpq, val);
}

/* Send the passthrough the terminate node.method */
static void drop_passthrough_client(pool_t *ckp, cdata_t *cdata, const int64_t id)
{
    int64_t client_id;
    char *msg;

    LOGINFO("Asked to drop passthrough client %"PRId64", forwarding to passthrough", id);
    client_id = id & 0xffffffffll;
    ASPRINTF(&msg, "dropclient=%"PRId64"\n", client_id);
    send_client(ckp, cdata, id, msg);
}

char *connector_stats(void *data, const int runtime)
{
    json_t *val = json_object(), *subval;
    client_instance_t *client;
    int objects;
    cdata_t *cdata = data;
    sender_send_t *send;
    int64_t memsize, generated;
    char *buf;

    if (runtime)
        json_set_int(val, "runtime", runtime);

    ck_rlock(&cdata->lock);
    objects = HASH_COUNT(cdata->clients);
    memsize = SAFE_HASH_OVERHEAD(cdata->clients) + sizeof(client_instance_t) * objects;
    generated = cdata->clients_generated;
    ck_runlock(&cdata->lock);

    JSON_CPACK(subval, "{si,sI,sI}", "count", objects, "memory", memsize, "generated", generated);
    json_steal_object(val, "clients", subval);

    ck_rlock(&cdata->lock);
    DL_COUNT2(cdata->dead_clients, client, objects, dead_next);
    generated = cdata->dead_generated;
    ck_runlock(&cdata->lock);

    memsize = objects * sizeof(client_instance_t);
    JSON_CPACK(subval, "{si,sI,sI}", "count", objects, "memory", memsize, "generated", generated);
    json_steal_object(val, "dead", subval);

    objects = 0;
    memsize = 0;

    {
        int64_t sends_generated = 0, sends_queued = 0, sends_size = 0, sends_delayed = 0;
        int i;

        for (i = 0; i < cdata->nsenders; i++) {
            csender_t *cs = &cdata->csenders[i];

            mutex_lock(&cs->lock);
            DL_FOREACH(cs->sends, send) {
                objects++;
                memsize += sizeof(sender_send_t) + send->len + 1;
            }
            sends_generated += cs->sends_generated;
            sends_queued += cs->sends_queued;
            sends_size += cs->sends_size;
            sends_delayed += cs->sends_delayed;
            mutex_unlock(&cs->lock);
        }
        JSON_CPACK(subval, "{si,sI,sI}", "count", objects, "memory", memsize, "generated", sends_generated);
        json_steal_object(val, "sends", subval);

        JSON_CPACK(subval, "{sI,sI,sI}", "count", sends_queued, "memory", sends_size, "generated", sends_delayed);
        json_steal_object(val, "delays", subval);
    }

    buf = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER);
    json_decref(val);
    if (runtime)
        LOGNOTICE("Passthrough:%s", buf);
    else
        LOGNOTICE("Connector stats: %s", buf);
    return buf;
}

void connector_send_fd(pool_t *ckp, const int fdno, const int sockd)
{
    cdata_t *cdata = ckp->cdata;

    if (fdno > -1 && fdno < ckp->serverurls)
        send_fd(cdata->serverfd[fdno], sockd);
    else
        LOGWARNING("Connector asked to send invalid fd %d", fdno);
}

static void connector_loop(proc_instance_t *pi, cdata_t *cdata)
{
    unix_msg_t *umsg = NULL;
    pool_t *ckp = pi->ckp;
    time_t last_stats;
    int64_t client_id;
    int ret = 0;
    char *buf;

    last_stats = cdata->start_time;

retry:
    if (ckp->passthrough) {
        time_t diff = time(NULL);

        if (diff - last_stats >= 60) {
            last_stats = diff;
            diff -= cdata->start_time;
            buf = connector_stats(cdata, diff);
            dealloc(buf);
        }
    }

    if (umsg) {
        Close(umsg->sockd);
        free(umsg->buf);
        dealloc(umsg);
    }

    do {
        umsg = get_unix_msg(pi);
    } while (!umsg);

    buf = umsg->buf;
    LOGDEBUG("Connector received message: %s", buf);
    if (likely(buf[0] == '{')) {
        json_t *val = json_loads(buf, JSON_DISABLE_EOF_CHECK, NULL);

        if (likely(val))
            ckmsgq_add(cdata->cmpq, val);
    } else if (cmdmatch(buf, "dropclient")) {
        client_instance_t *client;

        ret = sscanf(buf, "dropclient=%"PRId64, &client_id);
        if (ret < 0) {
            LOGDEBUG("Connector failed to parse dropclient command: %s", buf);
            goto retry;
        }
        if (subclient(client_id)) {
            drop_passthrough_client(ckp, cdata, client_id);
            goto retry;
        }
        client = ref_client_by_id(cdata, client_id);
        if (unlikely(!client)) {
            LOGINFO("Connector failed to find client id %"PRId64" to drop", client_id);
            goto retry;
        }
        ret = invalidate_client(ckp, cdata, client);
        dec_instance_ref(cdata, client);
        if (ret >= 0)
            LOGINFO("Connector dropped client id: %"PRId64, client_id);
    } else if (cmdmatch(buf, "testclient")) {
        ret = sscanf(buf, "testclient=%"PRId64, &client_id);
        if (unlikely(ret < 0)) {
            LOGDEBUG("Connector failed to parse testclient command: %s", buf);
            goto retry;
        }
        if (client_exists(cdata, client_id))
            goto retry;
        LOGINFO("Connector detected non-existent client id: %"PRId64, client_id);
        stratifier_drop_id(ckp, client_id);
    } else if (cmdmatch(buf, "ping")) {
        LOGDEBUG("Connector received ping request");
        send_unix_msg(umsg->sockd, "pong");
    } else if (cmdmatch(buf, "accept")) {
        LOGDEBUG("Connector received accept signal");
        cdata->accept = true;
    } else if (cmdmatch(buf, "reject")) {
        LOGDEBUG("Connector received reject signal");
        cdata->accept = false;
        if (ckp->passthrough)
            drop_all_clients(cdata);
    } else if (cmdmatch(buf, "stats")) {
        char *msg;

        LOGDEBUG("Connector received stats request");
        msg = connector_stats(cdata, 0);
        send_unix_msg(umsg->sockd, msg);
        dealloc(msg);
    } else if (cmdmatch(buf, "loglevel")) {
        sscanf(buf, "loglevel=%d", &ckp->loglevel);
    } else if (cmdmatch(buf, "passthrough")) {
        client_instance_t *client;

        ret = sscanf(buf, "passthrough=%"PRId64, &client_id);
        if (ret < 0) {
            LOGDEBUG("Connector failed to parse passthrough command: %s", buf);
            goto retry;
        }
        client = ref_client_by_id(cdata, client_id);
        if (unlikely(!client)) {
            LOGINFO("Connector failed to find client id %"PRId64" to pass through", client_id);
            goto retry;
        }
        passthrough_client(ckp, cdata, client);
        dec_instance_ref(cdata, client);
    } else if (cmdmatch(buf, "remote")) {
        client_instance_t *client;

        ret = sscanf(buf, "remote=%"PRId64, &client_id);
        if (ret < 0) {
            LOGDEBUG("Connector failed to parse remote command: %s", buf);
            goto retry;
        }
        client = ref_client_by_id(cdata, client_id);
        if (unlikely(!client)) {
            LOGINFO("Connector failed to find client id %"PRId64" to add as remote", client_id);
            goto retry;
        }
        remote_server(ckp, cdata, client);
        dec_instance_ref(cdata, client);
    } else if (cmdmatch(buf, "getxfd")) {
        int fdno = -1;

        sscanf(buf, "getxfd%d", &fdno);
        if (fdno > -1 && fdno < ckp->serverurls)
            send_fd(cdata->serverfd[fdno], umsg->sockd);
    } else
        LOGWARNING("Unhandled connector message: %s", buf);
    goto retry;
}

void *connector(void *arg)
{
    proc_instance_t *pi = (proc_instance_t *)arg;
    cdata_t *cdata = ckzalloc(sizeof(cdata_t));
    char newurl[INET6_ADDRSTRLEN], newport[8];
    int threads, sockd, i, tries = 0, ret;
    pool_t *ckp = pi->ckp;
    const int on = 1;

    rename_proc(pi->processname);
    LOGWARNING("%s connector starting", ckp->name);
    ckp->cdata = cdata;
    cdata->ckp = ckp;

    if (!ckp->serverurls) {
        struct sockaddr_in serv_addr;

        cdata->serverfd = ckalloc(sizeof(int *));

        sockd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockd < 0) {
            LOGERR("Connector failed to open socket");
            goto out;
        }
        setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(ckp->proxy ? 3334 : 3333);
        do {
            ret = bind(sockd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

            if (!ret)
                break;
            LOGWARNING("Connector failed to bind to socket, retrying in 5s");
            sleep(5);
        } while (++tries < 25);
        if (ret < 0) {
            LOGERR("Connector failed to bind to socket for 2 minutes");
            Close(sockd);
            goto out;
        }
        if (listen(sockd, 8192) < 0) {
            LOGERR("Connector failed to listen on socket");
            Close(sockd);
            goto out;
        }
        cdata->serverfd[0] = sockd;
        url_from_socket(sockd, newurl, newport);
        ASPRINTF(&ckp->serverurl[0], "%s:%s", newurl, newport);
        ckp->serverurls = 1;
    } else {
        cdata->serverfd = ckalloc(sizeof(int *) * ckp->serverurls);

        for (i = 0; i < ckp->serverurls; i++) {
            char oldurl[INET6_ADDRSTRLEN], oldport[8];
            char *serverurl = ckp->serverurl[i];

            if (!url_from_serverurl(serverurl, newurl, newport)) {
                LOGWARNING("Failed to extract resolved url from %s", serverurl);
                goto out;
            }
            sockd = ckp->oldconnfd[i];
            if (url_from_socket(sockd, oldurl, oldport)) {
                if (strcmp(newurl, oldurl) || strcmp(newport, oldport)) {
                    LOGWARNING("Handed over socket url %s:%s does not match config %s:%s, creating new socket",
                           oldurl, oldport, newurl, newport);
                    Close(sockd);
                }
            }

            do {
                if (sockd > 0)
                    break;
                sockd = bind_socket(newurl, newport);
                if (sockd > 0)
                    break;
                LOGWARNING("Connector failed to bind to socket, retrying in 5s");
                sleep(5);
            } while (++tries < 25);

            if (sockd < 0) {
                LOGERR("Connector failed to bind to socket for 2 minutes");
                goto out;
            }
            if (listen(sockd, 8192) < 0) {
                LOGERR("Connector failed to listen on socket");
                Close(sockd);
                goto out;
            }
            cdata->serverfd[i] = sockd;
        }
    }

    if (tries)
        LOGWARNING("Connector successfully bound after retries");

    cdata->cmpq = create_ckmsgq(ckp, "cmpq", &client_message_processor);

    if (ckp->remote && !setup_upstream(ckp, cdata))
        goto out;

    cklock_init(&cdata->lock);
    cdata->pi = pi;
    cdata->nfds = 0;
    /* Set the client id to the highest serverurl count to distinguish
     * them from the server fds in epoll/kqueue. */
    cdata->client_ids = ckp->serverurls;

    threads = sysconf(_SC_NPROCESSORS_ONLN) / 2;
    threads = threads > 0 ? threads : 1;

    /* Spawn sharded sender threads (csender0..csenderN) for parallel socket writes */
    cdata->nsenders = threads;
    cdata->csenders = ckzalloc(sizeof(csender_t) * cdata->nsenders);
    for (i = 0; i < cdata->nsenders; i++) {
        csender_t *cs = &cdata->csenders[i];

        cs->cdata = cdata;
        cs->id = i;
        mutex_init(&cs->lock);
        cond_init(&cs->cond);
        create_pthread(&cs->pth, sender, cs);
    }

    cdata->cevents = create_ckmsgqs(ckp, "cevent", &client_event_processor, threads);
    create_pthread(&cdata->pth_receiver, receiver, cdata);
    cdata->start_time = time(NULL);

    ckp->connector_ready = true;
    LOGWARNING("%s connector ready (%d sender shards)", ckp->name, cdata->nsenders);

    connector_loop(pi, cdata);
out:
    /* We should never get here unless there's a fatal error */
    LOGEMERG("Connector failure, shutting down");
    exit(1);
    return NULL;
}
