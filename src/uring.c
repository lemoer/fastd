// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Vincent Wiemann <vw@derowe.com>
  All rights reserved.
*/

/**
   \file

   Extends the polling with io_uring support
*/

#include <liburing.h>
#include "uring.h"

static inline struct uring_priv *fastd_uring_priv_acquire() {
	struct uring_priv *priv = ctx.uring_priv_avail;

	if (!priv)
		exit_bug("uring out of buffers");

	ctx.uring_priv_avail = priv->next;

	return priv;
}

static inline void fastd_uring_priv_release(struct uring_priv *priv) {
	memset(priv, 0, sizeof(*priv));
	priv->next = ctx.uring_priv_avail;
	ctx.uring_priv_avail = priv;
}

void fastd_uring_init(void) {
	int i;

	memset(&ctx.uring_privs, 0, sizeof(ctx.uring_privs));

	for (i = 0; i < (MAX_URING_SIZE - 1); i++)
		ctx.uring_privs[i].next = &uring_privs[i + 1];

	ctx.uring_priv_avail = &ctx.uring_privs[0];

	memset(&ctx.uring_params, 0, sizeof(ctx.uring_params));

	if (io_uring_queue_init_params(MAX_URING_SIZE, &ctx.uring, &ctx.uring_params) < 0)
        	exit_bug("uring init failed.");

	if (!(ctx.params.features & IORING_FEAT_FAST_POLL))
		exit_bug("uring fast poll not supported by the kernel.");
}

void fastd_uring_free(void) {
	io_uring_queue_exit(&ctx.uring);
}

void fastd_uring_iface_read(fastd_iface_t *iface) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(ctx.uring);
	struct uring_priv *priv = fastd_uring_priv_acquire();
	size_t max_len = fastd_max_payload(iface->mtu);

	io_uring_sqe_set_flags(sqe, 0);

	ctx.uring_priv_avail = priv->next;

	priv->buf = fastd_iface_buffer_alloc(iface, max_len);
	priv->iov[0].iov_base = priv->buf.data;
	priv->iov[0].iov_len = max_len;
	priv->action = EVENT_TYPE_IFACE_READ;

	io_uring_prep_readv(sqe, iface->fd.fd, &req->iov[0], 1, 0);
	io_uring_sqe_set_data(sqe, priv);
}

void fastd_uring_iface_write(int fd, void *data, size_t len) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(ctx.uring);
	struct uring_priv *priv = fastd_uring_priv_acquire();

	io_uring_sqe_set_flags(sqe, 0);

	ctx.uring_priv_avail = priv->next;

	priv->action = EVENT_TYPE_IFACE_WRITE;
	priv->buf = fastd_iface_buffer_alloc(iface, max_len);
	priv->iov[0].iov_base = data;
	priv->iov[0].iov_len = len;

	io_uring_prep_writev(sqe, fd, &priv->iov[0], 1, 0);
	io_uring_sqe_set_data(sqe, priv);
}

void fastd_uring_sock_recvmsg(fastd_socket_t *sock) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(ctx.uring);
	struct uring_priv *priv = fastd_uring_priv_acquire();
	size_t max_len = 1 + fastd_max_payload(ctx.max_mtu) + conf.max_overhead;
	fastd_buffer_t buffer;
	fastd_peer_address_t local_addr;
	fastd_peer_address_t recvaddr;

	io_uring_sqe_set_flags(sqe, 0);

	ctx.uring_priv_avail = priv->next;

	priv->action = EVENT_TYPE_SOCK_RECVMSG;
	priv->buf = fastd_buffer_alloc(max_len, conf.min_decrypt_head_space, conf.min_decrypt_tail_space);
	priv->iov[0].iov_base = priv->buf.data;
	priv->iov[0].iov_len = priv->buf.len;
	priv->msg.msg_name = &recvaddr;
	priv->msg.msg_namelen = sizeof(recvaddr),
	priv->msg.msg_iov = &priv->iov,
	priv->msg.msg_iovlen = 1,
	priv->msg.msg_control = priv->cbuf,
	priv->msg.msg_controllen = sizeof(priv->cbuf),

	io_uring_prep_recvmsg(sqe, sock->fd.fd, &priv->msg, 0);
	io_uring_sqe_set_data(sqe, priv);
	io_uring_sqe_set_flags(sqe, 0);

}

void fastd_uring_sock_sendmsg(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, uint8_t packet_type, fastd_buffer_t buffer, size_t stat_size) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(ctx.uring);
	struct uring_priv *priv = fastd_uring_priv_acquire();
	size_t max_len = fastd_max_payload(iface->mtu);
	fastd_peer_address_t remote_addr6;

	if (!sock)
		exit_bug("send: sock == NULL");

	priv->action = EVENT_TYPE_SOCK_SENDMSG;
	priv->buf = buffer;
	priv->cbuf = {};
	priv->msg = {};

	switch (remote_addr->sa.sa_family) {
	case AF_INET:
		priv->msg.msg_name = (void *)&remote_addr->in;
		priv->msg.msg_namelen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		priv->msg.msg_name = (void *)&remote_addr->in6;
		priv->msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;

	default:
		exit_bug("unsupported address family");
	}

	if (sock->bound_addr->sa.sa_family == AF_INET6) {
		remote_addr6 = *remote_addr;
		fastd_peer_address_widen(&remote_addr6);

		priv->msg.msg_name = (void *)&remote_addr6.in6;
		priv->msg.msg_namelen = sizeof(struct sockaddr_in6);
	}

	priv->iov[0].iov_base = priv->buf.data;
	priv->iov[0].iov_len = 1;

	priv->iov[1].iov_base = priv->buf.data;
	priv->iov[1].iov_len = max_len;

	priv->msg.msg_iov = &priv->iov;
	priv->msg.msg_iovlen = priv->buf.len ? 2 : 1;
	priv->msg.msg_control = cbuf;
	priv->msg.msg_controllen = 0;

	add_pktinfo(&priv->msg, local_addr);

	if (!priv->msg.msg_controllen)
		priv->msg.msg_control = NULL;


	io_uring_prep_sendmsg(sqe, sock->fd.fd, &msg, 0);
	io_uring_sqe_set_data(sqe, priv);
	io_uring_sqe_set_flags(sqe, 0);
}

void fastd_uring_fd_register(fastd_poll_fd_t *fd) {
	switch(fd->type) {
	case POLL_TYPE_URING_IFACE:
		fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);

		for(int i = 0; i < MAX_READ_JOBS; i++)
			fastd_uring_iface_read(iface);

		io_uring_submit(&ctx.uring);
		break;
	case POLL_TYPE_URING_SOCK:
		fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);

		break;
	default:
		if (fd->fd < 0)
			exit_bug("fastd_poll_fd_register: invalid FD");

		struct epoll_event event = {
			.events = EPOLLIN,
			.data.ptr = fd,
		};

		if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fd->fd, &event) < 0)
			exit_errno("epoll_ctl");

		break;

	}
}

bool fastd_uring_fd_close(fastd_poll_fd_t *fd) {
	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_DEL, fd->fd, NULL) < 0)
		exit_errno("epoll_ctl");

	return (close(fd->fd) == 0);
}


static inline void handle_cqe(struct io_uring_cqe *cqe) {
	priv = (struct uring_priv *)io_uring_cqe_get_data(cqe);

	switch(priv->action) {
	case EVENT_TYPE_ACCEPT: {
		int sock_conn_fd = cqe->res;
			io_uring_cqe_seen(&ring, cqe);

			// new connected client; read data from socket and re-add accept to monitor for new connections
			add_socket_read(&ring, sock_conn_fd, MAX_MESSAGE_LEN, 0);
			add_accept(&ring, sock_listen_fd, (struct sockaddr *)&client_addr, &client_len, 0);

			break;
		}
	case EVENT_TYPE_READ:
		if (cqe->res <= 0) {
			// no bytes available on socket, client must be disconnected

			shutdown(user_data->fd, SHUT_RDWR);
		} else	{
			// bytes have been read into bufs, now add write to socket sqe
			io_uring_cqe_seen(&ring, cqe);
			add_socket_write(&ring, user_data->fd, cqe->res, 0);
		}

		if (POLL_TYPE_URING_SOCK == priv->fd->type) {
			fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);
			int res = cqe->res;

			io_uring_cqe_seen(&ctx.ring, cqe);

			if (res <= 0) {
				fastd_buffer_free(priv->buf);
				memset(priv, 0, sizeof(priv));

				if (sock->peer)
					fastd_peer_reset_socket(sock->peer);
				else
					fastd_socket_error(sock);

				break;
			}

			fastd_receive_callback(sock, priv->msg, cqe->res, priv->buf);


		} else if (POLL_TYPE_URING_IFACE == priv->fd->type) {
			fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);
			fastd_iface_handle(iface);
		} else {
			exit_bug("unknown poll type");
		}

		break;
	case EVENT_TYPE_WRITE:
		if (POLL_TYPE_URING_SOCK == priv->fd->type) {
			send_callback(priv->msg, priv->peer, cqe->res, priv->buf);
		} else if (POLL_TYPE_URING_IFACE == priv->fd->type) {
			iface_callback();
		}

		io_uring_cqe_seen(&ctx.uring, cqe);
		break;

	default:
		exit_bug("unknown FD type");
		break;
	}

}

void fastd_uring_handle(void) {
	struct io_uring_cqe *cqe;
	struct io_uring_cqe *cqes[BACKLOG];
	struct uring_priv *priv;
	int timeout = task_timeout();
	int cqe_count, ret, i;
	struct __kernel_timespec ts = {
		.tv_sec = timeout / 1000,
		.tv_nsec = (timeout % 1000) * 1000,
	};

	ret = io_uring_wait_cqe_timeout(&ctx.uring, &cqe, ts);
	if (ret < 0)
	    exit_bug("uring_wait_cqe_timeout failed.");

	fastd_update_time();

	cqe_count = io_uring_peek_batch_cqe(&ring, cqes, sizeof(cqes) / sizeof(cqes[0]));

	for (i = 0; i < cqe_count; ++i)
		handle_cqe(cqes[i]);
}
