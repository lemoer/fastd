// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Portable polling API
*/


#pragma once


#include "types.h"
#include "uring.h"


/** A file descriptor to poll on */
struct fastd_poll_fd {
	fastd_poll_type_t type; /**< What the file descriptor is used for */
	int fd;                 /**< The file descriptor itself */
};

#ifdef USE_IO_URING
#define MAX_URING_SIZE 256
#define MAX_READ_JOBS 64
#define MAX_PACKETS

struct uring_priv {
	fastd_poll_uring_t action;
	fastd_buffer_t buf;
	struct msghdr msg;
	uint8_t cbuf[1024] __attribute__((aligned(8)));
	struct fastd_poll_fd *fd;
	int iovec_count;
	struct iovec iov[2];
}

struct uring_priv uring_privs[MAX_URING_SIZE];

#endif


/** Initializes the poll interface */
void fastd_poll_init(void);
/** Frees the poll interface */
void fastd_poll_free(void);

/** Returns a fastd_poll_fd_t structure */
#define FASTD_POLL_FD(type, fd) ((fastd_poll_fd_t){ type, fd })

/** Registers a new file descriptor to poll on */
void fastd_poll_fd_register(fastd_poll_fd_t *fd);
/** Unregisters and closes a file descriptor */
bool fastd_poll_fd_close(fastd_poll_fd_t *fd);

/** Waits for the next input event */
void fastd_poll_handle(void);
