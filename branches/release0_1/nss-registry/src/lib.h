#ifndef _HAVE_NSS_REGISTRY_LIB_H
#define _HAVE_NSS_REGISTRY_LIB_H

#include <pwd.h>
#include "nss-registry.h"

#define REGISTRYUSER 0
#define REGISTRYGROUP 1

#ifdef DEBUG
#define _D(x) _nss_registry_log(LOG_ERR, x);
#else
#define _D(x)
#endif

extern char *_nss_registry_get_string(int type, char *username, char *keyname);
extern NSS_STATUS _nss_registry_finduserbyname(const char *name);
extern NSS_STATUS _nss_registry_finduserbyuid(uid_t uid,char **name);
extern NSS_STATUS _nss_registry_findgroupbyname(const char *name);
extern NSS_STATUS _nss_registry_findgroupbygid(gid_t gid,char **name);

extern void _nss_registry_log(int err,const char *format, ...);
extern char * _nss_registry_copy_to_buffer(char ** buffer,size_t * buflen, const
                char * string);
extern long _nss_registry_strtol(char * str, long fallback, int * error);
extern int _nss_registry_isempty(char * str);
#endif /* _HAVE_NSS_REGISTRY_LIB_H */
