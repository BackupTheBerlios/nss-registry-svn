
/* Svn stuff 
$Id$
$LastChangedBy$
*/

#ifndef _HAVE_NSS_ELEKTRA_LIB_H
#define _HAVE_NSS_ELEKTRA_LIB_H

#include <pwd.h>
#include "nss-elektra.h"

#define ELEKTRAUSER 0
#define ELEKTRAGROUP 1

#ifdef DEBUG
#define _D _nss_elektra_log
#else
#define _D
#endif

extern char *_nss_elektra_get_string (int type, char *username,
				       char *keyname, int *errnop);
extern NSS_STATUS _nss_elektra_finduserbyname (const char *name);
extern NSS_STATUS _nss_elektra_finduserbyuid (uid_t uid, char **name);
extern NSS_STATUS _nss_elektra_findgroupbyname (const char *name);
extern NSS_STATUS _nss_elektra_findgroupbygid (gid_t gid, char **name);

extern void _nss_elektra_log (int err, const char *format, ...);
extern char *_nss_elektra_copy_to_buffer (char **buffer, size_t * buflen,
					   const char *string);
extern long _nss_elektra_strtol (char *str, long fallback, int *error);
extern int _nss_elektra_isempty (char *str);
#endif /* _HAVE_NSS_ELEKTRA_LIB_H */
