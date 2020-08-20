/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

<<<<<<< HEAD   (22246b Merge "Pass control to adelva@")
/* $Id: md5crypt.h,v 1.4 2003/05/18 14:46:46 djm Exp $ */

=======
>>>>>>> BRANCH (ecb2c0 upstream: fix compilation with DEBUG_KEXDH; bz#3160 ok dtuck)
#ifndef _MD5CRYPT_H
#define _MD5CRYPT_H

#include "config.h"

#if defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT)

int is_md5_salt(const char *);
char *md5_crypt(const char *, const char *);

#endif /* defined(HAVE_MD5_PASSWORDS) && !defined(HAVE_MD5_CRYPT) */

#endif /* MD5CRYPT_H */
