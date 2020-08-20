<<<<<<< HEAD   (22246b Merge "Pass control to adelva@")
/* In OpenSSH, umac.c is compiled twice, with different #defines set on the
 * command line. Since we don't want to stretch the Android build system, in
 * Android this file is duplicated as umac.c and umac128.c. The latter contains
 * the #defines (that were set in OpenSSH's Makefile) at the top of the
 * file and then #includes umac.c. */

#define UMAC_OUTPUT_LEN 16
#define umac_new umac128_new
#define umac_update umac128_update
#define umac_final umac128_final
#define umac_delete umac128_delete
=======
/* $OpenBSD: umac128.c,v 1.2 2018/02/08 04:12:32 dtucker Exp $ */

#define UMAC_OUTPUT_LEN	16
#define umac_new	umac128_new
#define umac_update	umac128_update
#define umac_final	umac128_final
#define umac_delete	umac128_delete
#define umac_ctx	umac128_ctx
>>>>>>> BRANCH (ecb2c0 upstream: fix compilation with DEBUG_KEXDH; bz#3160 ok dtuck)

#include "umac.c"
