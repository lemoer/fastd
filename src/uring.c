// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

/**
   \file

   Asynchronous IO callback abstraction for io_uring support
*/

/*** Handling IO requests asynchonously
 * For io_uring to work efficiently, many requests should be queued into the submission queue (sqe)
 * to never let the kernel processing starve because of unavailable userspace-mapped memory.
 * The result of the request can be asynchronously read from the completion queue (cqe).
 * Therefore the replacement functions defined herein for IO system calls like read, write etc.
 * require the caller to specify a function pointer for a callback with the result of the function
 * equivalent and a caller-defined pointer which will then be called asynchronously on processing of
 * the result in the completion queue.
 ***/

#include <sys/eventfd.h>
#include <unistd.h>
#include <liburing.h>
#include "uring.h"
#include "async.h"
#include "peer.h"
#include "fastd.h"

#define MAX_URING_SIZE 256		/**/
#define FASTD_URING_TIMEOUT	((__u64) -1234)

#define URING_RECVMSG_NUM	32	/**/
#define URING_READ_NUM		32	/**/

bool mustsubmit;
int uring_read_flags;
int uring_recvmsg_flags;

/** Returns the time to the next task or -1 */
static inline int task_timeout(void) {
	fastd_timeout_t timeout = fastd_task_queue_timeout();
	if (timeout == FASTD_TIMEOUT_INV)
		return -1;

	int diff_msec = timeout - ctx.now;
	if (diff_msec < 0)
		return 0;
	else
		return diff_msec;
}

/** Allocate and initialize a uring_priv */
static inline struct fastd_uring_priv *uring_priv_new(fastd_poll_fd_t *fd,
		    fastd_uring_action_t action, void *data, void (*cb)(ssize_t, void *)) {
	struct fastd_uring_priv *priv = fastd_new0(struct fastd_uring_priv);

	priv->fd = fd;
	priv->action = action;
	priv->caller_priv = data;
	priv->caller_func = cb;

	return priv;
}

static int uring_submit(void) {
	int ret = io_uring_submit(&ctx.uring);

	if (ret < 0) {
		pr_debug("uring_submit() failed: %s\n", strerror(-ret));
		exit_bug("uring_submit");
	} else {
		pr_debug("submitted %i SQEs", ret);
	}
	
	if(ret == 0) {
		exit_bug("submit without CQEs");
	}

	return ret;
}

/** Free a uring_priv */
static inline void uring_priv_free(struct fastd_uring_priv *priv) {
	free(priv);
}

static inline void uring_submit_priv(struct io_uring_sqe *sqe, struct fastd_uring_priv *priv, int flags) {
	const char *inout;

	if (priv->action == URING_INPUT)
		inout = "URING_INPUT";
	else
		inout = "URING_OUTPUT";

	pr_debug("uring_submit_priv() called, fd=%i, action=%s", priv->fd->fd, inout);

	if (ctx.uring_sqe_must_link) {
		io_uring_sqe_set_flags(sqe, flags | IOSQE_IO_HARDLINK);
	} else {
		io_uring_sqe_set_flags(sqe, flags);
	}

	pr_debug("setting data pointer %p\n", priv);
	io_uring_sqe_set_data(sqe, priv);

	if(mustsubmit) {
		mustsubmit = false;
		uring_submit();
	}
}

static inline struct io_uring_sqe *uring_get_sqe() {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx.uring);

	if (!sqe)
		exit_bug("No SQE available");

	return sqe;
}


/* registers the TUN/TAP file descriptor for IOSQE_FIXED_FILE */
static void uring_fixed_file_register(fastd_poll_fd_t *fd) {
/*
'''
  To  successfully  use  this feature, the application must register a set of files to be
  used for IO through io_uring_register(2) using the IORING_REGISTER_FILES opcode.  Fail-
  ure to do so will result in submitted IO being errored with EBADF.
'''

NOTE: 	Needs to set io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
*/
	pr_debug("uring_fixed_file_register() called");
	int ret;

	fd->uring_idx = ctx.uring_fixed_file_fps_cnt;
	ctx.uring_fixed_file_fps[fd->uring_idx] = fd->fd;

	if (ctx.uring_fixed_file_fps_cnt < 1) {
		__s32 fds[64];

		fds[0] = fd->fd;
		for (size_t i = 1; i < 64; i++) {
			fds[i] = -1;
		}

		ret = io_uring_register_files(&ctx.uring, fds, 64);
	} else {
		ret = io_uring_register_files_update(&ctx.uring, fd->uring_idx, &fd->fd, 1);
	}

	ctx.uring_fixed_file_fps_cnt++;

	if(ret < 0)
		exit_bug("err_uring_fixed_file_register: BUG");
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_accept_unsupported(fastd_poll_fd_t *fd, struct sockaddr *addr, socklen_t *addrlen, void *data, void (*cb)(ssize_t, void *)) {
	cb(accept(fd->fd, addr, addrlen), data);
}

void fastd_uring_accept(fastd_poll_fd_t *fd, struct sockaddr *addr, socklen_t *addrlen, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	io_uring_prep_accept(sqe, fd->uring_idx, addr, addrlen, 0);
	mustsubmit = true;
	uring_submit_priv(sqe, priv, IOSQE_FIXED_FILE);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_recvmsg_unsupported(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	cb(recvmsg(fd->fd, msg, flags), data);
}

void fastd_uring_recvmsg(fastd_poll_fd_t *fd, struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	io_uring_prep_recvmsg(sqe, fd->uring_idx, msg, flags); // | 	uring_recvmsg_flags

	/*sqe->buf_group = fd->type; the buffer group of fixed buffers
	io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT); used for fixed buffers*/
	uring_submit_priv(sqe, priv, IOSQE_FIXED_FILE);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_sendmsg_unsupported(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	cb(sendmsg(fd->fd, msg, flags), data);
}

void fastd_uring_sendmsg(fastd_poll_fd_t *fd, const struct msghdr *msg, int flags, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_OUTPUT, data, cb);

	io_uring_prep_sendmsg(sqe, fd->uring_idx, msg, flags);
	//io_uring_sqe_set_flags(sqe, IOSQE_ASYNC); used for blocking devices
	mustsubmit = true;
	uring_submit_priv(sqe, priv, IOSQE_FIXED_FILE);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_read_unsupported(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	cb(read(fd->fd, buf, count), data);
}

void fastd_uring_read(fastd_poll_fd_t *fd, void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_INPUT, data, cb);

	io_uring_prep_read(sqe, fd->uring_idx, buf, count, 0);
	uring_submit_priv(sqe, priv, IOSQE_FIXED_FILE);
}

/** Used when the kernel doesn't support io_uring */
void fastd_uring_write_unsupported(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	cb(write(fd->fd, buf, count), data);
}

void fastd_uring_write(fastd_poll_fd_t *fd, const void *buf, size_t count, void *data, void (*cb)(ssize_t, void *)) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct fastd_uring_priv *priv = uring_priv_new(fd, URING_OUTPUT, data, cb);
	mustsubmit = true;
	io_uring_prep_write(sqe, fd->uring_idx, buf, count, 0);
	uring_submit_priv(sqe, priv, IOSQE_FIXED_FILE);
}

void uring_poll_add(fastd_poll_fd_t *fd, short poll_mask) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	mustsubmit = true;
	io_uring_prep_poll_add(sqe, fd->fd, poll_mask);
	uring_submit_priv(sqe, (struct fastd_uring_priv *)&fd, 0);
}

void uring_poll_remove(fastd_poll_fd_t *fd) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	mustsubmit = true;
	io_uring_prep_poll_remove(sqe, &fd);
	uring_submit_priv(sqe, (struct fastd_uring_priv *)&fd, 0);
}


static const char *op_strs[] = {
        "IORING_OP_NOP",
        "IORING_OP_READV",
        "IORING_OP_WRITEV",
        "IORING_OP_FSYNC",
        "IORING_OP_READ_FIXED",
        "IORING_OP_WRITE_FIXED",
        "IORING_OP_POLL_ADD",
        "IORING_OP_POLL_REMOVE",
        "IORING_OP_SYNC_FILE_RANGE",
        "IORING_OP_SENDMSG",
        "IORING_OP_RECVMSG",
        "IORING_OP_TIMEOUT",
        "IORING_OP_TIMEOUT_REMOVE",
        "IORING_OP_ACCEPT",
        "IORING_OP_ASYNC_CANCEL",
        "IORING_OP_LINK_TIMEOUT",
        "IORING_OP_CONNECT",
        "IORING_OP_FALLOCATE",
        "IORING_OP_OPENAT",
        "IORING_OP_CLOSE",
        "IORING_OP_FILES_UPDATE",
        "IORING_OP_STATX",
        "IORING_OP_READ",
        "IORING_OP_WRITE",
        "IORING_OP_FADVISE",
        "IORING_OP_MADVISE",
        "IORING_OP_SEND",
        "IORING_OP_RECV",
        "IORING_OP_OPENAT2",
        "IORING_OP_EPOLL_CTL",
        "IORING_OP_SPLICE",
        "IORING_OP_PROVIDE_BUFFERS",
        "IORING_OP_REMOVE_BUFFERS",
};

static inline int uring_is_supported() {
	struct io_uring_probe *probe = io_uring_get_probe();

	if (!probe)
		return 0;
	if (!io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
		pr_debug("IORING_OP_PROVIDE_BUFFERS not supported\n");
		exit(0);
	}

	pr_debug("Supported io_uring operations:");
	for (int i = 0; i < IORING_OP_LAST; i++)
		if(io_uring_opcode_supported(probe, i))
			pr_debug("%s", op_strs[i]);

	pr_debug("\n");

	free(probe);

	return 1;
}

#define uring_link_counter_decrease(cnt, num) \
	if(cnt > 1) { cnt--; } else { cnt = num; ctx.uring_sqe_must_link = true; } \
	for(int __link_counter = 1; cnt == num && __link_counter < num; __link_counter++)

/* creates a new URING_INPUT submission */
static inline void uring_sqe_input(fastd_poll_fd_t *fd) {
	pr_debug("sqe input for fd=%i type=%i", fd->fd, fd->type);
	switch(fd->type) {
	case POLL_TYPE_IFACE: {
			pr_debug("iface handle \n");
			fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);


			uring_link_counter_decrease(ctx.uring_read_num, URING_READ_NUM) {
				pr_debug("creating linked iface read %i", ctx.uring_read_num);
				fastd_iface_handle(iface);
			}
			
			if(ctx.uring_sqe_must_link) {
				mustsubmit = true;
				/* we need to close the SQE link chain */
				ctx.uring_sqe_must_link = false;
				fastd_iface_handle(iface);
				uring_read_flags = 0;
			}


			break;
		}
	case POLL_TYPE_SOCKET: {
			pr_debug("socket handle \n");
			fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);

			uring_link_counter_decrease(ctx.uring_recvmsg_num, URING_RECVMSG_NUM) {
				pr_debug("creating linked socket recvmsg %i", ctx.uring_recvmsg_num);
				fastd_receive(sock);
				
				/* When setting up multiple recvmsgs, we only want the first
				 * one to do polling. The following in the chain
				 * must not block the result, thus they must fail if no data
				 * is available. We achieve this by setting the MSG_DONTWAIT
				 * flag for all but the first recvmsgs in a chain */
				uring_recvmsg_flags = MSG_DONTWAIT;
			}

			if(ctx.uring_sqe_must_link) {
				mustsubmit = true;
				/* we need to close the SQE link chain */
				ctx.uring_sqe_must_link = false;
				fastd_receive(sock);
				uring_recvmsg_flags = 0;
			}


			break;
		}
	case POLL_TYPE_ASYNC:
		pr_debug("async handle \n");
		uring_poll_add(fd, POLLIN);

		break;
	case POLL_TYPE_STATUS:
		pr_debug("status handle \n");
		mustsubmit = true;
		fastd_status_handle();
		break;
	default:
		pr_debug("unknown FD type %i", fd->type);
	}
}

/* handles a completion queue event */
static inline void uring_cqe_handle(struct io_uring_cqe *cqe) {
	struct fastd_uring_priv *priv = (struct fastd_uring_priv *)io_uring_cqe_get_data(cqe);

	pr_debug("handle CQE with result %i\n", cqe->res);

	if (!priv) {
		pr_debug("err no priv\n");
		return;
	}

	pr_debug("priv %p\n", priv);
	pr_debug("fd type %i\n", priv->fd->type);
	
	if (priv->fd->type == POLL_TYPE_ASYNC) {
		fastd_async_handle();
		uring_sqe_input(priv->fd);
		return;
	}

	if (priv->action == URING_OUTPUT)  {
		pr_debug("output\n");
	}

	priv->caller_func(cqe->res, priv->caller_priv);
	pr_debug("uring callback called\n");
	
	if (priv->action == URING_OUTPUT)
		goto free;

	if (cqe->res < 0) {
		pr_debug("CQE failed %s\n", strerror(-cqe->res));
		exit_bug("CQE fail");
	}

	/* FIXME: we should not reset the connection more than once, but we need
	 * to go through every outstanding completion to free the privs.
	 * Therefore it needs be made sure that the reset only happens once by e.g.
	 * checking for a new fd number. This needs a FLUSH.
	 */
	if (cqe->res == -ECANCELED && POLL_TYPE_SOCKET == priv->fd->type) {
		fastd_socket_t *sock = container_of(priv->fd, fastd_socket_t, fd);

		/* the connection is broken */
		if (sock->peer)
			fastd_peer_reset_socket(sock->peer);
		else
			fastd_socket_error(sock);

		goto free;
	}

	uring_sqe_input(priv->fd);

free:
	uring_priv_free(priv);
}

fastd_poll_fd_t *async_fd;

/* Initializes the fds and generates input cqes */
void fastd_uring_fd_register(fastd_poll_fd_t *fd) {
	if (fd->fd < 0)
		exit_bug("fastd_uring_fd_register: invalid FD");

	pr_debug("uring_register fdtype=%i\n", fd->type);
	switch(fd->type) {
	case POLL_TYPE_IFACE:
			uring_fixed_file_register(fd);
			uring_sqe_input(fd);
			uring_sqe_input(async_fd);

			break;
	case POLL_TYPE_SOCKET: {
			uring_fixed_file_register(fd);
			//uring_sqe_input(fd);
			/* FIXME: It seems there is a bug where the first recvmsg will always return length 38
			 * Thus we only schedule a single recvmsg which will fail and afterwards everything works
			 * as expected #crazyworkaround
			 */
			fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);
			fastd_receive(sock);
			break;
		}
	case POLL_TYPE_ASYNC:
		async_fd = fd;
		//uring_sqe_input(fd);

		break;
	case POLL_TYPE_STATUS:
		//status_fd = fd;
		uring_sqe_input(fd);

		break;
	default:
		pr_debug("uring wrong fd type received %i", fd->type);
		break;
	}
}

bool fastd_uring_fd_close(fastd_poll_fd_t *fd) {
	/* TODO: Block new input, insert a flush and only close it afterwards Hint: Set fixed file index -1 */

	return (close(fd->fd) == 0);
}

static inline void uring_submit_timeout_add(int timeout) {
	struct io_uring_sqe *sqe = uring_get_sqe();
	struct __kernel_timespec ts = {
			.tv_sec = timeout / 1000,
			.tv_nsec = (timeout % 1000) * 1000000
		};

	io_uring_prep_timeout(sqe, &ts, 0, 0);
	sqe->user_data = FASTD_URING_TIMEOUT;

	uring_submit();
}

static inline void uring_submit_timeout_remove() {
	pr_debug("uring_submit_timeout_remove()");
	struct io_uring_sqe *sqe = uring_get_sqe();

	io_uring_prep_timeout_remove(sqe, FASTD_URING_TIMEOUT, 0);

	uring_submit();
}

void fastd_uring_eventfd() {
	ctx.uring_fd = FASTD_POLL_FD(POLL_TYPE_URING, eventfd(0, 0));
	if (ctx.uring_fd.fd < 0)
		exit_bug("eventfd");
}

void fastd_uring_eventfd_read() {
	eventfd_t v;
	int ret = eventfd_read(ctx.uring_fd.fd, &v);
	pr_debug("eventfd_read result=%i", ret);
	if (ret < 0) exit_bug("eventfd_read");
}

void fastd_uring_handle(void) {
	struct io_uring_cqe *cqe;
	struct io_uring_cqe *cqes[MAX_URING_SIZE / 2];
	int timeout = task_timeout();
	unsigned head, count = 0, count_total = 0;
	bool has_timeout = false;

	pr_debug("fastd_uring_handle() called");
	pr_debug("time remaining %i count %i", timeout, count);

	//fastd_uring_eventfd_read();
        uring_submit_timeout_add(timeout);
	while(1) {

		int ret = io_uring_wait_cqe(&ctx.uring, &cqe);

		if (ret != 0) {
		    pr_debug("io_uring_wait_cqe\n");
		    exit_bug("io_uring_wait_cqe");
		}

		count++;
		
		if (cqe->user_data == FASTD_URING_TIMEOUT) {
			pr_debug("timeout");
			has_timeout = true;
			io_uring_cqe_seen(&ctx.uring, cqe);
			break;
		}
		
		if(cqe->user_data) {
			uring_cqe_handle(cqe);
		}

		io_uring_cqe_seen(&ctx.uring, cqe);
		/* Do not advance the CQE queue after every CQE as it is expensive.
		 * To avoid dropping CQEs advance after at most MAX_URING_SIZE / 2 CQEs.
		 */
		/*if (count > MAX_URING_SIZE / 2) {
			io_uring_cq_advance(&ctx.uring, count);
			count_total += count;
			count = 0;
		}*/

	}
	
	fastd_update_time();
	//count_total += count;
	//io_uring_cq_advance(&ctx.uring, count);
	//count = 0;
	//fastd_uring_eventfd_read();

	pr_debug("HANDLED %i CQEs", count);

	if(!has_timeout) {
		uring_submit_timeout_remove();
	} else if(mustsubmit) {
		uring_submit();
	}

	pr_debug("URING END");
}

void fastd_uring_init(void) {
	if (!uring_is_supported()) {
		ctx.func_recvmsg = fastd_uring_recvmsg_unsupported;
		ctx.func_sendmsg = fastd_uring_sendmsg_unsupported;
		ctx.func_read = fastd_uring_read_unsupported;
		ctx.func_write = fastd_uring_write_unsupported;
		ctx.func_fd_register = fastd_poll_fd_register;
		ctx.func_fd_close = fastd_poll_fd_close;
		ctx.func_io_handle = fastd_poll_handle;
		ctx.func_io_free = fastd_poll_free;
		ctx.func_accept = fastd_uring_accept_unsupported;
		fastd_poll_init();

		return;
	}

	fastd_poll_init();
	uring_recvmsg_flags = 0;
	uring_read_flags = 0;
	ctx.func_recvmsg = fastd_uring_recvmsg;
	ctx.func_sendmsg = fastd_uring_sendmsg;
	ctx.func_read = fastd_uring_read;
	ctx.func_write = fastd_uring_write;
	ctx.func_fd_register = fastd_uring_fd_register;
	ctx.func_fd_close = fastd_uring_fd_close;
	ctx.func_io_handle = fastd_uring_handle;
	ctx.func_io_free = fastd_uring_free;
	ctx.func_accept = fastd_uring_accept;

	memset(&ctx.uring_params, 0, sizeof(ctx.uring_params));

	ctx.uring_recvmsg_num = 0;
	ctx.uring_read_num = 0;
	ctx.uring_sqe_must_link = false;
	/* TODO: Try SQPOLL mode - needs privileges
	 * NOTE: We found SQPOLL mode to be too resource intensive. Maybe this needs optimization.
	if (!geteuid()) {

		pr_debug("uring: Activating SQPOLL mode - Experimental! \n");
		ctx.uring_params.flags |= IORING_SETUP_SQPOLL;

		ctx.uring_params.sq_thread_idle = 8000;
	}*/

	if (io_uring_queue_init_params(MAX_URING_SIZE, &ctx.uring, &ctx.uring_params) < 0)
        	exit_bug("uring init failed");

	/* Without FASTPOLL non-blocking IO is computation intensive.
	 * It might be possible to LINK a poll to the beginning of a read to
	 * mitigate missing FASTPOLL support.
	 */
	if (!(ctx.uring_params.features & IORING_FEAT_FAST_POLL))
		pr_debug("uring fast poll not supported by the kernel.");

	/* NOTE: With NODROP we can make sure that CQEs won't be dropped
	 * if the ring is full by blocking new SQEs. Actually we want to
	 * define the ring big enough to never let this happen.
	 */
	if (!(ctx.uring_params.features & IORING_FEAT_NODROP)) {
		pr_debug("uring nodrop not supported by the kernel.");
		/*ctx.uring_params.flags |= IORING_SETUP_CQ_NODROP;*/
	}

	/*fastd_uring_eventfd();
	fastd_poll_fd_register(&ctx.uring_fd);
	io_uring_register_eventfd(&ctx.uring, ctx.uring_fd.fd);
	*/
}

void fastd_uring_free(void) {
	/* TODO: Find out if it triggers error cqes and if our privs get freed */
	/* TODO: If a file subscriptr was fixed, unregister*/
	/* TODO create a NOP with flag IOSQE_IO_DRAIN and cancel any new submissions */
	
	/* TODO Check on return value*/
	io_uring_unregister_files(&ctx.uring);
	io_uring_queue_exit(&ctx.uring);
}
