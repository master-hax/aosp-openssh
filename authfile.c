<<<<<<< HEAD   (22246b Merge "Pass control to adelva@")
/* $OpenBSD: authfile.c,v 1.111 2015/02/23 16:55:51 djm Exp $ */
/*
 * Copyright (c) 2000, 2013 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "cipher.h"
#include "key.h"
#include "ssh.h"
#include "log.h"
#include "authfile.h"
#include "rsa.h"
#include "misc.h"
#include "atomicio.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "krl.h"

#define MAX_KEY_FILE_SIZE	(1024 * 1024)

/* Save a key blob to a file */
static int
sshkey_save_private_blob(struct sshbuf *keybuf, const char *filename)
{
	int fd, oerrno;

	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
		return SSH_ERR_SYSTEM_ERROR;
	if (atomicio(vwrite, fd, (u_char *)sshbuf_ptr(keybuf),
	    sshbuf_len(keybuf)) != sshbuf_len(keybuf)) {
		oerrno = errno;
		close(fd);
		unlink(filename);
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	}
	close(fd);
	return 0;
}

int
sshkey_save_private(struct sshkey *key, const char *filename,
    const char *passphrase, const char *comment,
    int force_new_format, const char *new_format_cipher, int new_format_rounds)
{
	struct sshbuf *keyblob = NULL;
	int r;

	if ((keyblob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    force_new_format, new_format_cipher, new_format_rounds)) != 0)
		goto out;
	if ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	return r;
}

/* Load a key from a fd into a buffer */
int
sshkey_load_file(int fd, struct sshbuf *blob)
{
	u_char buf[1024];
	size_t len;
	struct stat st;
	int r;

	if (fstat(fd, &st) < 0)
		return SSH_ERR_SYSTEM_ERROR;
	if ((st.st_mode & (S_IFSOCK|S_IFCHR|S_IFIFO)) == 0 &&
	    st.st_size > MAX_KEY_FILE_SIZE)
		return SSH_ERR_INVALID_FORMAT;
	for (;;) {
		if ((len = atomicio(read, fd, buf, sizeof(buf))) == 0) {
			if (errno == EPIPE)
				break;
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		}
		if ((r = sshbuf_put(blob, buf, len)) != 0)
			goto out;
		if (sshbuf_len(blob) > MAX_KEY_FILE_SIZE) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	if ((st.st_mode & (S_IFSOCK|S_IFCHR|S_IFIFO)) == 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		goto out;
	}
	r = 0;

 out:
	explicit_bzero(buf, sizeof(buf));
	if (r != 0)
		sshbuf_reset(blob);
	return r;
}

#ifdef WITH_SSH1
/*
 * Loads the public part of the ssh v1 key file.  Returns NULL if an error was
 * encountered (the file does not exist or is not readable), and the key
 * otherwise.
 */
static int
sshkey_load_public_rsa1(int fd, struct sshkey **keyp, char **commentp)
{
	struct sshbuf *b = NULL;
	int r;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_load_file(fd, b)) != 0)
		goto out;
	if ((r = sshkey_parse_public_rsa1_fileblob(b, keyp, commentp)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}
#endif /* WITH_SSH1 */

/* XXX remove error() calls from here? */
int
sshkey_perm_ok(int fd, const char *filename)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	if (check_ntsec(filename))
#endif
	if ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is recommended that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		return SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	return 0;
}

/* XXX kill perm_ok now that we have SSH_ERR_KEY_BAD_PERMISSIONS? */
int
sshkey_load_private_type(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp, int *perm_ok)
{
	int fd, r;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		if (perm_ok != NULL)
			*perm_ok = 0;
		return SSH_ERR_SYSTEM_ERROR;
	}
	if (sshkey_perm_ok(fd, filename) != 0) {
		if (perm_ok != NULL)
			*perm_ok = 0;
		r = SSH_ERR_KEY_BAD_PERMISSIONS;
		goto out;
	}
	if (perm_ok != NULL)
		*perm_ok = 1;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
 out:
	close(fd);
	return r;
}

int
sshkey_load_private_type_fd(int fd, int type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	int r;

	if ((buffer = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_load_file(fd, buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	if (buffer != NULL)
		sshbuf_free(buffer);
	return r;
}

/* XXX this is almost identical to sshkey_load_private_type() */
int
sshkey_load_private(const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	int r, fd;

	*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return SSH_ERR_SYSTEM_ERROR;
	if (sshkey_perm_ok(fd, filename) != 0) {
		r = SSH_ERR_KEY_BAD_PERMISSIONS;
		goto out;
	}

	if ((buffer = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_load_file(fd, buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob(buffer, passphrase, filename,
	    keyp, commentp)) != 0)
		goto out;
	r = 0;
 out:
	close(fd);
	if (buffer != NULL)
		sshbuf_free(buffer);
	return r;
}

static int
sshkey_try_load_public(struct sshkey *k, const char *filename, char **commentp)
{
	FILE *f;
	char line[SSH_MAX_PUBKEY_BYTES];
	char *cp;
	u_long linenum = 0;
	int r;

	if (commentp != NULL)
		*commentp = NULL;
	if ((f = fopen(filename, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;
	while (read_keyfile_line(f, filename, line, sizeof(line),
		    &linenum) != -1) {
		cp = line;
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}
		/* Abort loading if this looks like a private key */
		if (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			break;
		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		if (*cp) {
			if ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				if (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					if (*commentp == NULL)
						r = SSH_ERR_ALLOC_FAIL;
				}
				fclose(f);
				return r;
			}
		}
	}
	fclose(f);
	return SSH_ERR_INVALID_FORMAT;
}

/* load public key from ssh v1 private or any pubkey file */
int
sshkey_load_public(const char *filename, struct sshkey **keyp, char **commentp)
{
	struct sshkey *pub = NULL;
	char file[PATH_MAX];
	int r, fd;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	/* XXX should load file once and attempt to parse each format */

	if ((fd = open(filename, O_RDONLY)) < 0)
		goto skip;
#ifdef WITH_SSH1
	/* try rsa1 private key */
	r = sshkey_load_public_rsa1(fd, keyp, commentp);
	close(fd);
	switch (r) {
	case SSH_ERR_INTERNAL_ERROR:
	case SSH_ERR_ALLOC_FAIL:
	case SSH_ERR_INVALID_ARGUMENT:
	case SSH_ERR_SYSTEM_ERROR:
	case 0:
		return r;
	}
#endif /* WITH_SSH1 */

	/* try ssh2 public key */
	if ((pub = sshkey_new(KEY_UNSPEC)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_try_load_public(pub, filename, commentp)) == 0) {
		if (keyp != NULL)
			*keyp = pub;
		return 0;
	}
	sshkey_free(pub);

#ifdef WITH_SSH1
	/* try rsa1 public key */
	if ((pub = sshkey_new(KEY_RSA1)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_try_load_public(pub, filename, commentp)) == 0) {
		if (keyp != NULL)
			*keyp = pub;
		return 0;
	}
	sshkey_free(pub);
#endif /* WITH_SSH1 */

 skip:
	/* try .pub suffix */
	if ((pub = sshkey_new(KEY_UNSPEC)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	r = SSH_ERR_ALLOC_FAIL;	/* in case strlcpy or strlcat fail */
	if ((strlcpy(file, filename, sizeof file) < sizeof(file)) &&
	    (strlcat(file, ".pub", sizeof file) < sizeof(file)) &&
	    (r = sshkey_try_load_public(pub, file, commentp)) == 0) {
		if (keyp != NULL)
			*keyp = pub;
		return 0;
	}
	sshkey_free(pub);

	return r;
}

/* Load the certificate associated with the named private key */
int
sshkey_load_cert(const char *filename, struct sshkey **keyp)
{
	struct sshkey *pub = NULL;
	char *file = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	*keyp = NULL;

	if (asprintf(&file, "%s-cert.pub", filename) == -1)
		return SSH_ERR_ALLOC_FAIL;

	if ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
		goto out;
	}
	if ((r = sshkey_try_load_public(pub, file, NULL)) != 0)
		goto out;

	*keyp = pub;
	pub = NULL;
	r = 0;

 out:
	if (file != NULL)
		free(file);
	if (pub != NULL)
		sshkey_free(pub);
	return r;
}

/* Load private key and certificate */
int
sshkey_load_private_cert(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp, int *perm_ok)
{
	struct sshkey *key = NULL, *cert = NULL;
	int r;

	*keyp = NULL;

	switch (type) {
#ifdef WITH_OPENSSL
	case KEY_RSA:
	case KEY_DSA:
	case KEY_ECDSA:
	case KEY_ED25519:
#endif /* WITH_OPENSSL */
	case KEY_UNSPEC:
		break;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	if ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, NULL, perm_ok)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		goto out;

	/* Make sure the private key matches the certificate */
	if (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}

	if ((r = sshkey_to_certified(key, sshkey_cert_is_legacy(cert))) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		goto out;
	r = 0;
	*keyp = key;
	key = NULL;
 out:
	if (key != NULL)
		sshkey_free(key);
	if (cert != NULL)
		sshkey_free(cert);
	return r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certficiate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
int
sshkey_in_file(struct sshkey *key, const char *filename, int strict_type,
    int check_ca)
{
	FILE *f;
	char line[SSH_MAX_PUBKEY_BYTES];
	char *cp;
	u_long linenum = 0;
	int r = 0;
	struct sshkey *pub = NULL;
	int (*sshkey_compare)(const struct sshkey *, const struct sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	if ((f = fopen(filename, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;

	while (read_keyfile_line(f, filename, line, sizeof(line),
	    &linenum) != -1) {
		cp = line;

		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}

		if ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((r = sshkey_read(pub, &cp)) != 0)
			goto out;
		if (sshkey_compare(key, pub) ||
		    (check_ca && sshkey_is_cert(key) &&
		    sshkey_compare(key->cert->signature_key, pub))) {
			r = 0;
			goto out;
		}
		sshkey_free(pub);
		pub = NULL;
	}
	r = SSH_ERR_KEY_NOT_FOUND;
 out:
	if (pub != NULL)
		sshkey_free(pub);
	fclose(f);
	return r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
int
sshkey_check_revoked(struct sshkey *key, const char *revoked_keys_file)
{
	int r;

	r = ssh_krl_file_contains_key(revoked_keys_file, key);
	/* If this was not a KRL to begin with then continue below */
	if (r != SSH_ERR_KRL_BAD_MAGIC)
		return r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	switch ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	case 0:
		/* Key found => revoked */
		return SSH_ERR_KEY_REVOKED;
	case SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		return 0;
	default:
		/* Some other error occurred */
		return r;
	}
}

=======
/* $OpenBSD: authfile.c,v 1.140 2020/04/17 07:15:11 djm Exp $ */
/*
 * Copyright (c) 2000, 2013 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "cipher.h"
#include "ssh.h"
#include "log.h"
#include "authfile.h"
#include "misc.h"
#include "atomicio.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "krl.h"

#define MAX_KEY_FILE_SIZE	(1024 * 1024)

/* Save a key blob to a file */
static int
sshkey_save_private_blob(struct sshbuf *keybuf, const char *filename)
{
	int r;
	mode_t omask;

	omask = umask(077);
	r = sshbuf_write_file(filename, keybuf);
	umask(omask);
	return r;
}

int
sshkey_save_private(struct sshkey *key, const char *filename,
    const char *passphrase, const char *comment,
    int format, const char *openssh_format_cipher, int openssh_format_rounds)
{
	struct sshbuf *keyblob = NULL;
	int r;

	if ((keyblob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_private_to_fileblob(key, keyblob, passphrase, comment,
	    format, openssh_format_cipher, openssh_format_rounds)) != 0)
		goto out;
	if ((r = sshkey_save_private_blob(keyblob, filename)) != 0)
		goto out;
	r = 0;
 out:
	sshbuf_free(keyblob);
	return r;
}

/* XXX remove error() calls from here? */
int
sshkey_perm_ok(int fd, const char *filename)
{
	struct stat st;

	if (fstat(fd, &st) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	if (check_ntsec(filename))
#endif
	if ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is required that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		return SSH_ERR_KEY_BAD_PERMISSIONS;
	}
	return 0;
}

int
sshkey_load_private_type(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	int fd, r;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return SSH_ERR_SYSTEM_ERROR;

	r = sshkey_perm_ok(fd, filename);
	if (r != 0)
		goto out;

	r = sshkey_load_private_type_fd(fd, type, passphrase, keyp, commentp);
	if (r == 0 && keyp && *keyp)
		r = sshkey_set_filename(*keyp, filename);
 out:
	close(fd);
	return r;
}

int
sshkey_load_private(const char *filename, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	return sshkey_load_private_type(KEY_UNSPEC, filename, passphrase,
	    keyp, commentp);
}

int
sshkey_load_private_type_fd(int fd, int type, const char *passphrase,
    struct sshkey **keyp, char **commentp)
{
	struct sshbuf *buffer = NULL;
	int r;

	if (keyp != NULL)
		*keyp = NULL;
	if ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_private_fileblob_type(buffer, type,
	    passphrase, keyp, commentp)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	sshbuf_free(buffer);
	return r;
}

/* Load a pubkey from the unencrypted envelope of a new-format private key */
static int
sshkey_load_pubkey_from_private(const char *filename, struct sshkey **pubkeyp)
{
	struct sshbuf *buffer = NULL;
	struct sshkey *pubkey = NULL;
	int r, fd;

	if (pubkeyp != NULL)
		*pubkeyp = NULL;

	if ((fd = open(filename, O_RDONLY)) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	if ((r = sshbuf_load_fd(fd, &buffer)) != 0 ||
	    (r = sshkey_parse_pubkey_from_private_fileblob_type(buffer,
	    KEY_UNSPEC, &pubkey)) != 0)
		goto out;
	if ((r = sshkey_set_filename(pubkey, filename)) != 0)
		goto out;
	/* success */
	if (pubkeyp != NULL) {
		*pubkeyp = pubkey;
		pubkey = NULL;
	}
	r = 0;
 out:
	close(fd);
	sshbuf_free(buffer);
	sshkey_free(pubkey);
	return r;
}

static int
sshkey_try_load_public(struct sshkey **kp, const char *filename,
    char **commentp)
{
	FILE *f;
	char *line = NULL, *cp;
	size_t linesize = 0;
	int r;
	struct sshkey *k = NULL;

	*kp = NULL;
	if (commentp != NULL)
		*commentp = NULL;
	if ((f = fopen(filename, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;
	if ((k = sshkey_new(KEY_UNSPEC)) == NULL) {
		fclose(f);
		return SSH_ERR_ALLOC_FAIL;
	}
	while (getline(&line, &linesize, f) != -1) {
		cp = line;
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}
		/* Abort loading if this looks like a private key */
		if (strncmp(cp, "-----BEGIN", 10) == 0 ||
		    strcmp(cp, "SSH PRIVATE KEY FILE") == 0)
			break;
		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;
		if (*cp) {
			if ((r = sshkey_read(k, &cp)) == 0) {
				cp[strcspn(cp, "\r\n")] = '\0';
				if (commentp) {
					*commentp = strdup(*cp ?
					    cp : filename);
					if (*commentp == NULL)
						r = SSH_ERR_ALLOC_FAIL;
				}
				/* success */
				*kp = k;
				free(line);
				fclose(f);
				return r;
			}
		}
	}
	free(k);
	free(line);
	fclose(f);
	return SSH_ERR_INVALID_FORMAT;
}

/* load public key from any pubkey file */
int
sshkey_load_public(const char *filename, struct sshkey **keyp, char **commentp)
{
	char *pubfile = NULL;
	int r;

	if (keyp != NULL)
		*keyp = NULL;
	if (commentp != NULL)
		*commentp = NULL;

	if ((r = sshkey_try_load_public(keyp, filename, commentp)) == 0)
		goto out;

	/* try .pub suffix */
	if (asprintf(&pubfile, "%s.pub", filename) == -1)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshkey_try_load_public(keyp, pubfile, commentp)) == 0)
		goto out;

	/* finally, try to extract public key from private key file */
	if ((r = sshkey_load_pubkey_from_private(filename, keyp)) == 0)
		goto out;

 out:
	free(pubfile);
	return r;
}

/* Load the certificate associated with the named private key */
int
sshkey_load_cert(const char *filename, struct sshkey **keyp)
{
	struct sshkey *pub = NULL;
	char *file = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if (keyp != NULL)
		*keyp = NULL;

	if (asprintf(&file, "%s-cert.pub", filename) == -1)
		return SSH_ERR_ALLOC_FAIL;

	r = sshkey_try_load_public(keyp, file, NULL);
	free(file);
	sshkey_free(pub);
	return r;
}

/* Load private key and certificate */
int
sshkey_load_private_cert(int type, const char *filename, const char *passphrase,
    struct sshkey **keyp)
{
	struct sshkey *key = NULL, *cert = NULL;
	int r;

	if (keyp != NULL)
		*keyp = NULL;

	switch (type) {
#ifdef WITH_OPENSSL
	case KEY_RSA:
	case KEY_DSA:
	case KEY_ECDSA:
#endif /* WITH_OPENSSL */
	case KEY_ED25519:
	case KEY_XMSS:
	case KEY_UNSPEC:
		break;
	default:
		return SSH_ERR_KEY_TYPE_UNKNOWN;
	}

	if ((r = sshkey_load_private_type(type, filename,
	    passphrase, &key, NULL)) != 0 ||
	    (r = sshkey_load_cert(filename, &cert)) != 0)
		goto out;

	/* Make sure the private key matches the certificate */
	if (sshkey_equal_public(key, cert) == 0) {
		r = SSH_ERR_KEY_CERT_MISMATCH;
		goto out;
	}

	if ((r = sshkey_to_certified(key)) != 0 ||
	    (r = sshkey_cert_copy(cert, key)) != 0)
		goto out;
	r = 0;
	if (keyp != NULL) {
		*keyp = key;
		key = NULL;
	}
 out:
	sshkey_free(key);
	sshkey_free(cert);
	return r;
}

/*
 * Returns success if the specified "key" is listed in the file "filename",
 * SSH_ERR_KEY_NOT_FOUND: if the key is not listed or another error.
 * If "strict_type" is set then the key type must match exactly,
 * otherwise a comparison that ignores certficiate data is performed.
 * If "check_ca" is set and "key" is a certificate, then its CA key is
 * also checked and sshkey_in_file() will return success if either is found.
 */
int
sshkey_in_file(struct sshkey *key, const char *filename, int strict_type,
    int check_ca)
{
	FILE *f;
	char *line = NULL, *cp;
	size_t linesize = 0;
	int r = 0;
	struct sshkey *pub = NULL;

	int (*sshkey_compare)(const struct sshkey *, const struct sshkey *) =
	    strict_type ?  sshkey_equal : sshkey_equal_public;

	if ((f = fopen(filename, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;

	while (getline(&line, &linesize, f) != -1) {
		sshkey_free(pub);
		pub = NULL;
		cp = line;

		/* Skip leading whitespace. */
		for (; *cp && (*cp == ' ' || *cp == '\t'); cp++)
			;

		/* Skip comments and empty lines */
		switch (*cp) {
		case '#':
		case '\n':
		case '\0':
			continue;
		}

		if ((pub = sshkey_new(KEY_UNSPEC)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		switch (r = sshkey_read(pub, &cp)) {
		case 0:
			break;
		case SSH_ERR_KEY_LENGTH:
			continue;
		default:
			goto out;
		}
		if (sshkey_compare(key, pub) ||
		    (check_ca && sshkey_is_cert(key) &&
		    sshkey_compare(key->cert->signature_key, pub))) {
			r = 0;
			goto out;
		}
	}
	r = SSH_ERR_KEY_NOT_FOUND;
 out:
	free(line);
	sshkey_free(pub);
	fclose(f);
	return r;
}

/*
 * Checks whether the specified key is revoked, returning 0 if not,
 * SSH_ERR_KEY_REVOKED if it is or another error code if something
 * unexpected happened.
 * This will check both the key and, if it is a certificate, its CA key too.
 * "revoked_keys_file" may be a KRL or a one-per-line list of public keys.
 */
int
sshkey_check_revoked(struct sshkey *key, const char *revoked_keys_file)
{
	int r;

	r = ssh_krl_file_contains_key(revoked_keys_file, key);
	/* If this was not a KRL to begin with then continue below */
	if (r != SSH_ERR_KRL_BAD_MAGIC)
		return r;

	/*
	 * If the file is not a KRL or we can't handle KRLs then attempt to
	 * parse the file as a flat list of keys.
	 */
	switch ((r = sshkey_in_file(key, revoked_keys_file, 0, 1))) {
	case 0:
		/* Key found => revoked */
		return SSH_ERR_KEY_REVOKED;
	case SSH_ERR_KEY_NOT_FOUND:
		/* Key not found => not revoked */
		return 0;
	default:
		/* Some other error occurred */
		return r;
	}
}

/*
 * Advanced *cpp past the end of key options, defined as the first unquoted
 * whitespace character. Returns 0 on success or -1 on failure (e.g.
 * unterminated quotes).
 */
int
sshkey_advance_past_options(char **cpp)
{
	char *cp = *cpp;
	int quoted = 0;

	for (; *cp && (quoted || (*cp != ' ' && *cp != '\t')); cp++) {
		if (*cp == '\\' && cp[1] == '"')
			cp++;	/* Skip both */
		else if (*cp == '"')
			quoted = !quoted;
	}
	*cpp = cp;
	/* return failure for unterminated quotes */
	return (*cp == '\0' && quoted) ? -1 : 0;
}

/* Save a public key */
int
sshkey_save_public(const struct sshkey *key, const char *path,
    const char *comment)
{
	int fd, oerrno;
	FILE *f = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	if ((f = fdopen(fd, "w")) == NULL) {
		r = SSH_ERR_SYSTEM_ERROR;
		goto fail;
	}
	if ((r = sshkey_write(key, f)) != 0)
		goto fail;
	fprintf(f, " %s\n", comment);
	if (ferror(f) || fclose(f) != 0) {
		r = SSH_ERR_SYSTEM_ERROR;
 fail:
		oerrno = errno;
		if (f != NULL)
			fclose(f);
		else
			close(fd);
		errno = oerrno;
		return r;
	}
	return 0;
}
>>>>>>> BRANCH (ecb2c0 upstream: fix compilation with DEBUG_KEXDH; bz#3160 ok dtuck)
