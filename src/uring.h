
#pragma once

void fastd_uring_init(void);
void fastd_poll_free(void);

void fastd_uring_iface_read(fastd_iface_t *iface);
void fastd_uring_iface_write(int fd, void *data, size_t len);
void fastd_uring_sock_recvmsg(fastd_socket_t *sock);

void fastd_uring_sock_sendmsg(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, uint8_t packet_type, fastd_buffer_t buffer, size_t stat_size);

void fastd_uring_fd_register(fastd_poll_fd_t *fd);
bool fastd_uring_fd_close(fastd_poll_fd_t *fd);
void fastd_uring_handle(void);
