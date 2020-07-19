// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Functions for receiving and handling packets
*/


#include "fastd.h"
#include "handshake.h"
#include "hash.h"
#include "peer.h"
#include "peer_hashtable.h"

#include <sys/uio.h>


/** Handles the ancillary control messages of received packets */
static inline void
handle_socket_control(struct msghdr *message, const fastd_socket_t *sock, fastd_peer_address_t *local_addr) {
	memset(local_addr, 0, sizeof(fastd_peer_address_t));

	const uint8_t *end = (const uint8_t *)message->msg_control + message->msg_controllen;

	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
		if ((const uint8_t *)cmsg + sizeof(*cmsg) > end)
			return;

#ifdef USE_PKTINFO
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo pktinfo;

			if ((const uint8_t *)CMSG_DATA(cmsg) + sizeof(pktinfo) > end)
				return;

			memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

			local_addr->in.sin_family = AF_INET;
			local_addr->in.sin_addr = pktinfo.ipi_addr;
			local_addr->in.sin_port = fastd_peer_address_get_port(sock->bound_addr);

			return;
		}
#endif

		if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo pktinfo;

			if ((uint8_t *)CMSG_DATA(cmsg) + sizeof(pktinfo) > end)
				return;

			memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

			local_addr->in6.sin6_family = AF_INET6;
			local_addr->in6.sin6_addr = pktinfo.ipi6_addr;
			local_addr->in6.sin6_port = fastd_peer_address_get_port(sock->bound_addr);

			if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr))
				local_addr->in6.sin6_scope_id = pktinfo.ipi6_ifindex;

			return;
		}
	}
}

/** Initializes the hashtables used to keep track of handshakes sent to unknown peers */
void fastd_receive_unknown_init(void) {
	size_t i, j;
	for (i = 0; i < UNKNOWN_TABLES; i++) {
		ctx.unknown_handshakes[i] = fastd_new0_array(UNKNOWN_ENTRIES, fastd_handshake_timeout_t);

		for (j = 0; j < UNKNOWN_ENTRIES; j++)
			ctx.unknown_handshakes[i][j].timeout = ctx.now;
	}

	fastd_random_bytes(&ctx.unknown_handshake_seed, sizeof(ctx.unknown_handshake_seed), false);
}

/** Frees the hashtables used to keep track of handshakes sent to unknown peers */
void fastd_receive_unknown_free(void) {
	size_t i;
	for (i = 0; i < UNKNOWN_TABLES; i++)
		free(ctx.unknown_handshakes[i]);
}

/** Returns the i'th hash bucket for a peer address */
fastd_handshake_timeout_t *unknown_hash_entry(int64_t base, size_t i, const fastd_peer_address_t *addr) {
	int64_t slice = base - i;
	uint32_t hash = ctx.unknown_handshake_seed;
	fastd_hash(&hash, &slice, sizeof(slice));
	fastd_peer_address_hash(&hash, addr);
	fastd_hash_final(&hash);

	return &ctx.unknown_handshakes[(size_t)slice % UNKNOWN_TABLES][hash % UNKNOWN_ENTRIES];
}


/**
   Checks if a handshake should be sent after an unexpected payload packet has been received

   backoff_unknown() tries to avoid flooding hosts with handshakes.
*/
static bool backoff_unknown(const fastd_peer_address_t *addr) {
	static const size_t table_interval = MIN_HANDSHAKE_INTERVAL / (UNKNOWN_TABLES - 1);

	int64_t base = ctx.now / table_interval;
	size_t first_empty = UNKNOWN_TABLES, i;

	for (i = 0; i < UNKNOWN_TABLES; i++) {
		const fastd_handshake_timeout_t *t = unknown_hash_entry(base, i, addr);

		if (fastd_timed_out(t->timeout)) {
			if (first_empty == UNKNOWN_TABLES)
				first_empty = i;

			continue;
		}

		if (!fastd_peer_address_equal(addr, &t->address))
			continue;

		pr_debug2("sent a handshake to unknown address %I a short time ago, not sending again", addr);
		return true;
	}

	/* We didn't find the address in any of the hashtables, now insert it */
	if (first_empty == UNKNOWN_TABLES)
		first_empty = fastd_rand(0, UNKNOWN_TABLES);

	fastd_handshake_timeout_t *t = unknown_hash_entry(base, first_empty, addr);

	t->address = *addr;
	t->timeout = ctx.now + MIN_HANDSHAKE_INTERVAL - first_empty * table_interval;

	return false;
}

/** Handles a packet received from a known peer address */
static inline void handle_socket_receive_known(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!fastd_peer_may_connect(peer)) {
		fastd_buffer_free(buffer);
		return;
	}

	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(&buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		if (!fastd_peer_is_established(peer) || !fastd_peer_address_equal(&peer->local_address, local_addr)) {
			fastd_buffer_free(buffer);

			if (!backoff_unknown(remote_addr)) {
				pr_debug("unexpectedly received payload data from %P[%I]", peer, remote_addr);
				conf.protocol->handshake_init(sock, local_addr, remote_addr, NULL);
			}
			return;
		}

		conf.protocol->handle_recv(peer, buffer);
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(sock, local_addr, remote_addr, peer, buffer);
	}
}

/** Determines if packets from known addresses are accepted */
static inline bool allow_unknown_peers(void) {
	return ctx.has_floating || fastd_allow_verify();
}

/** Handles a packet received from an unknown address */
static inline void handle_socket_receive_unknown(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_buffer_t buffer) {
	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(&buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		fastd_buffer_free(buffer);

		if (!backoff_unknown(remote_addr)) {
			pr_debug("unexpectedly received payload data from unknown address %I", remote_addr);
			conf.protocol->handshake_init(sock, local_addr, remote_addr, NULL);
		}
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(sock, local_addr, remote_addr, NULL, buffer);
	}
}

/** Handles a packet read from a socket */
static inline void handle_socket_receive(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_buffer_t buffer) {
	fastd_peer_t *peer = NULL;

	if (sock->peer) {
		if (!fastd_peer_address_equal(&sock->peer->address, remote_addr)) {
			fastd_buffer_free(buffer);
			return;
		}

		peer = sock->peer;
	} else {
		peer = fastd_peer_hashtable_lookup(remote_addr);
	}

	if (peer) {
		handle_socket_receive_known(sock, local_addr, remote_addr, peer, buffer);
	} else if (allow_unknown_peers()) {
		handle_socket_receive_unknown(sock, local_addr, remote_addr, buffer);
	} else {
		pr_debug("received packet from unknown peer %I", remote_addr);
		fastd_buffer_free(buffer);
	}
}

struct receive_priv {
	uint8_t cbuf[1024];
	fastd_socket_t *sock;
	size_t max_len;
	fastd_buffer_t buffer;
	fastd_peer_address_t local_addr;
	fastd_peer_address_t recvaddr;
	struct iovec buffer_vec;
	struct msghdr message;
};

#ifdef HAVE_LIBURING
/* forward declaration */
void fastd_receive_callback(ssize_t len, void *p);
#endif

/** Reads a packet from a socket */
void fastd_receive(fastd_socket_t *sock) {
#ifdef HAVE_LIBURING
	struct receive_priv *priv = fastd_new_aligned(struct receive_priv, 16);

	memset(priv, 0, sizeof(struct receive_priv));
#else
	uint8_t tmp_priv[sizeof(struct receive_priv)] __attribute__((aligned(8)));
	struct receive_priv *priv = &tmp_priv;
#endif

	priv->max_len = 1 + fastd_max_payload(ctx.max_mtu) + conf.max_overhead;
	priv->buffer = fastd_buffer_alloc(priv->max_len, conf.min_decrypt_head_space, conf.min_decrypt_tail_space);
	priv->buffer_vec.iov_base = priv->buffer.data;
	priv->buffer_vec.iov_len = priv->buffer.len;
	priv->sock = sock;

	priv->message.msg_name = &priv->recvaddr;
	priv->message.msg_namelen = sizeof(priv->recvaddr);
	priv->message.msg_iov = &priv->buffer_vec;
	priv->message.msg_iovlen = 1;
	/*
	priv->message.msg_control = priv->cbuf;
	priv->message.msg_controllen = sizeof(priv->cbuf);*/


#ifndef HAVE_LIBURING
	ssize_t len = recvmsg(sock->fd.fd, &message, 0);
#else
	ctx.func_recvmsg(&sock->fd, &priv->message, MSG_WAITALL, priv, fastd_receive_callback);
}

void fastd_receive_callback(ssize_t len, void *p) {
	struct receive_priv *priv = p;
#endif
	if (len <= 0) {
		if (len < 0)
			pr_warn_errno("recvmsg");
		pr_debug("fastd_receive_callback err fd=%i", priv->sock->fd.fd);

		/* Done in uring.c
		if (priv->sock->peer) {
			fastd_peer_reset_socket(priv->sock->peer);
		} else {
			fastd_socket_error(priv->sock);
		}*/
		pr_debug("fastd_receive_callback out");
		fastd_buffer_free(priv->buffer);
		goto out;
	}

	priv->buffer.len = len;

	handle_socket_control(&priv->message, priv->sock, &priv->local_addr);

#ifdef USE_PKTINFO
	if (!priv->local_addr.sa.sa_family) {
		pr_error("received packet without packet info");
		fastd_buffer_free(priv->buffer);
		goto out;
	}
#endif

	fastd_peer_address_simplify(&priv->local_addr);
	fastd_peer_address_simplify(&priv->recvaddr);

	pr_debug("fastd_receive_callback received %i bytes", priv->buffer.len);
	char test_str[10];
	memcpy(test_str, priv->buffer.data, 10);
	test_str[0] = 'h';
	test_str[10] = '\0';
	pr_debug("fastd first bytes %s", test_str);

	handle_socket_receive(priv->sock, &priv->local_addr, &priv->recvaddr, priv->buffer);

out:
#ifdef HAVE_LIBURING
	pr_debug("fastd_receive_callback free1");
	free(priv);
	pr_debug("fastd_receive_callback free2");
#endif
}

/** Handles a received and decrypted payload packet */
void fastd_handle_receive(fastd_peer_t *peer, fastd_buffer_t buffer, bool reordered) {
	if (conf.mode == MODE_TAP) {
		if (buffer.len < sizeof(fastd_eth_header_t)) {
			pr_debug("received truncated packet");
			fastd_buffer_free(buffer);
			return;
		}

		fastd_eth_addr_t src_addr = fastd_buffer_source_address(buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(peer, src_addr);
	}

	fastd_stats_add(peer, STAT_RX, buffer.len);

	if (reordered)
		fastd_stats_add(peer, STAT_RX_REORDERED, buffer.len);

	fastd_iface_write(peer->iface, buffer);

	if (conf.mode == MODE_TAP && conf.forward) {
		fastd_send_data(buffer, peer, NULL);
		return;
	}

	fastd_buffer_free(buffer);
}
