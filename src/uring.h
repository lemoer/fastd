
#pragma once

#include "poll.h"
#include "buffer.h"

#define MAX_URING_SIZE 256
#define MAX_READ_JOBS 64
#define MAX_PACKETS

typedef enum fastd_poll_uring_type {
	EVENT_TYPE_INPUT,
	EVENT_TYPE_OUTPUT
} fastd_poll_uring_t;

struct uring_priv {
	fastd_poll_uring_t action;
	fastd_buffer_t buf;
	struct msghdr msg;
	uint8_t cbuf[1024] __attribute__((aligned(8)));
	struct fastd_poll_fd *fd;
	int iovec_count;
	struct iovec iov[2];
	struct uring_priv *next;
};

extern struct uring_priv uring_privs[MAX_URING_SIZE];

void fastd_uring_init(void);
void fastd_poll_free(void);

void fastd_uring_iface_read(fastd_iface_t *iface);
void fastd_uring_iface_write(fastd_iface_t *iface, fastd_buffer_t buf);
void fastd_uring_sock_recvmsg(fastd_socket_t *sock);

void fastd_uring_sock_sendmsg(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, uint8_t packet_type, fastd_buffer_t buffer, size_t stat_size);

void fastd_uring_fd_register(fastd_poll_fd_t *fd);
bool fastd_uring_fd_close(fastd_poll_fd_t *fd);
void fastd_uring_handle(void);
