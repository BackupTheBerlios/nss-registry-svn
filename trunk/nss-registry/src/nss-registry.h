/* Svn stuff
$Id$
$LastChangedBy$
*/


#ifndef _HAVE_NSS_REGISTRY_H
#define _HAVE_NSS_REGISTRY_H
#include <registry.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

/* Taken from nss-mysql */
#ifdef HAVE_NSSWITCH_H
#include <nss_common.h>

typedef nss_status_t NSS_STATUS;

#define NSS_STATUS_SUCCESS      NSS_SUCCESS
#define NSS_STATUS_NOTFOUND     NSS_NOTFOUND
#define NSS_STATUS_UNAVAIL      NSS_UNAVAIL
#define NSS_STATUS_TRYAGAIN     NSS_TRYAGAIN

#else
#include <nss.h>

typedef enum nss_status NSS_STATUS;

#endif


#endif /* _HAVE_NSS_REGISTRY_H */
