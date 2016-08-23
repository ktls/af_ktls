/*
 * af_ktls: TLS/DTLS socket
 *
 * Copyright (C) 2016
 *
 * Original authors:
 *   Fridolin Pokorny <fpokorny@redhat.com>
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef AF_KTLS_H_
#define AF_KTLS_H_

#include <linux/types.h>

#define PF_KTLS				12
#define AF_KTLS				PF_KTLS

/* getsockopt() optnames */
#define KTLS_SET_IV_RECV		1
#define KTLS_SET_KEY_RECV		2
#define KTLS_SET_SALT_RECV		3
#define KTLS_SET_IV_SEND		4
#define KTLS_SET_KEY_SEND		5
#define KTLS_SET_SALT_SEND		6
#define KTLS_SET_MTU			7
#define KTLS_UNATTACH			8

/* setsockopt() optnames */
#define KTLS_GET_IV_RECV		11
#define KTLS_GET_KEY_RECV		12
#define KTLS_GET_SALT_RECV		13
#define KTLS_GET_IV_SEND		14
#define KTLS_GET_KEY_SEND		15
#define KTLS_GET_SALT_SEND		16
#define KTLS_GET_MTU			17

/* Supported ciphers */
#define KTLS_CIPHER_AES_GCM_128		51

#define KTLS_VERSION_LATEST		0
#define KTLS_VERSION_1_2		1

/* Constants */
#define KTLS_AES_GCM_128_IV_SIZE	((size_t)8)
#define KTLS_AES_GCM_128_KEY_SIZE	((size_t)16)
#define KTLS_AES_GCM_128_SALT_SIZE	((size_t)4)

/* Maximum data size carried in a TLS/DTLS record */
#define KTLS_MAX_PAYLOAD_SIZE		((size_t)1 << 14)

struct sockaddr_ktls {
	__u16   sa_cipher;
	__u16   sa_socket;
	__u16   sa_version;
};

#endif
