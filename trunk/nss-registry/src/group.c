/* Nss-registry
*  Copyright (C) 2004 Jens Andersen <rayman@skumler.net>
*
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*  
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*  
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

/*
 * $Id: group.c,v 1.2 2004/04/22 11:22:52 rayman Exp $ 
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <grp.h>
#include <stdio.h>

#include "nss-registry.h"

#include "group.h"
#include "lib.h"
#ifdef DMALLOC
	#include <dmalloc.h>
#endif

/* Taken from nss-mysql */
#define FALLBACK -1 /* if the last change coloum can't be read,
                              fall back to -1.(This is what the nss-files does so)*/

/* Global keyset & key for setspent, getspent and endspent */
KeySet *groupks = NULL;
Key *groupkey = NULL;

NSS_STATUS _nss_registry_initgroups (const char *user, gid_t group, long *start,
              long int *size, gid_t * groups, long int limit,int *errnop);
NSS_STATUS _nss_registry_setgrent (void);
NSS_STATUS _nss_registry_endgrent (void);
NSS_STATUS _nss_registry_getgrent_r (struct group *gr,
                char * buffer, size_t buflen,int * errnop);
NSS_STATUS _nss_registry_getgrnam_r (const char * name, struct group *gr,
                char * buffer, size_t buflen,int *errnop);
NSS_STATUS _nss_registry_getgrgid_r (const gid_t gid, struct group *gr,
                char * buffer, size_t buflen,int *errnop);

NSS_STATUS _nss_registry_initgroups (const char *user, gid_t group, long *start,
              long int *size, gid_t * groups, long int limit,int *errnop)
{

return NSS_STATUS_UNAVAIL;
}

/* getgrnam
 * looks for a group by its name
 * Arguments:
 * name: user's name
 * result: struct we'll fill
 * buffer:
 * buflen: sizeof(buffer)
 * errnop: ptr on the application errno
 */

NSS_STATUS _nss_registry_getgrnam_r (const char *name, struct group * gr,
                char *buffer, size_t buflen, int *errnop) 
{
int i, ret;
char *tmpbuf=NULL, *end_of_buf;
char **addrptr=NULL;
Key *key;
KeySet ks;
char *grname=NULL;
int namesize;

*errnop = ENOENT;

/* Open registry connection */
registryOpen();
if(_nss_registry_findgroupbyname(name) == NSS_STATUS_NOTFOUND) return NSS_STATUS_NOTFOUND;
/* Yay! the group exists, lets continue */
gr->gr_name = (char *)_nss_registry_copy_to_buffer(&buffer,&buflen,name);
if(! gr->gr_name)
	goto out_nomem;
tmpbuf = _nss_registry_get_string(REGISTRYGROUP, gr->gr_name,"gid");
gr->gr_gid =_nss_registry_strtol(tmpbuf,
                                        FALLBACK ,&i);
if(tmpbuf != NULL)
	free(tmpbuf);
tmpbuf = _nss_registry_get_string(REGISTRYGROUP, gr->gr_name, "passwd");
if(_nss_registry_isempty)
{
	/* Password isn't set so set it to "x" */
	gr->gr_passwd = _nss_registry_copy_to_buffer(&buffer,&buflen, "x");
} else
{
	gr->gr_passwd = _nss_registry_copy_to_buffer(&buffer,&buflen, tmpbuf);
	free(tmpbuf);
}
if (!gr->gr_passwd)
	goto out_nomem;

/* Member list...How the hell do I do that? */
/* registrygetchildkeys (system/groups/<groupname>/members) 
 * with options RG_O_STATONLY since all we need is the names of the keys 
 * i.e. keyGetBaseName for each key in keyset */
/* Mainly taken from nss-registry */
 
addrptr = (char **)buffer;
gr->gr_mem = addrptr;
end_of_buf = buffer+buflen-1;
/*_nss_registry_log(LOG_ERR, "nss_registry_getgrnam: "
			   "addr %p, data %p", addrptr,
				buffer);*/

ksInit(&ks);
tmpbuf = (char *)malloc(1024);
snprintf(tmpbuf,1023,"system/groups/%s/members",gr->gr_name);
ret = registryGetChildKeys(tmpbuf,&ks,RG_O_STATONLY);
free(tmpbuf);
if(ret == 0 && ks.size > 0)
{
	for(key=ks.start; key; key=key->next)
	{
		char *p, *tmp;
		namesize = keyGetBaseNameSize(key);
		grname = (char *)malloc(namesize);
		keyGetBaseName(key,grname,namesize);
		end_of_buf -= namesize;
		if ((void *) addrptr >= (void *) end_of_buf)
			goto out_nomem;

		tmp = end_of_buf;
		p = _nss_registry_copy_to_buffer(&tmp, NULL, grname);
		if (! p)
			goto out_nomem;
		*addrptr = p;
		++addrptr;
		free(grname);
	}
}
ksClose(&ks);

        if ((void *) addrptr >= (void *) end_of_buf)
                goto out_nomem;
        /* end */
        *addrptr = NULL;

/* Woo! this means it was successfull. Go on! tell everyone :) */

*errnop = 0;
registryClose();
return NSS_STATUS_SUCCESS;


/* Taken from nss-mysql */
out_nomem:
        /* if we're here, that means that the buffer is too small, so
         * we return ERANGE
         */
	if(!grname)
		free(grname);
        *errnop = ERANGE;
	registryClose();
        return NSS_STATUS_TRYAGAIN;

}

NSS_STATUS _nss_registry_getgrgid_r (gid_t gid, struct group *gr,
        char *buffer, size_t buflen, int *errnop)
{
char *groupname;
NSS_STATUS tmpstatus;
registryOpen();
if((_nss_registry_findgroupbygid(gid,&groupname)) == NSS_STATUS_NOTFOUND) return NSS_STATUS_NOTFOUND;
/* Due to the way the registry is made it's far more efficient to work with
 * usernames only, hence once we have the username for a uid we might as well 
 * just pass it on to getspnam
*/
registryClose();
tmpstatus = _nss_registry_getgrnam_r(groupname, gr, buffer, buflen, errnop);
free(groupname);
return tmpstatus;
}


NSS_STATUS _nss_registry_setgrent (void)
{
int ret;
/* We need to first open registry, then get a KeySet of all keys in system/users
 * and store it globally, ready for returning the first key
 */
registryOpen();
groupks = (KeySet *)malloc(sizeof(KeySet));
ksInit(groupks);
ret = registryGetChildKeys("system/groups",groupks,RG_O_DIR);
if(!ret)
{
	if(groupks->size <= 0)
	{
		ksClose(groupks);
		free(groupks);
		groupks = NULL;
		registryClose();
		return NSS_STATUS_NOTFOUND;
	}
	/* No error, return success! */
	groupkey = groupks->start;
	registryClose();
	return NSS_STATUS_SUCCESS;
}
 
/* If we get here it usually means that system/users doesn't exist,
 * which means this function is unavailable :) as well as the other 
 * related ones */
 registryClose();
return NSS_STATUS_UNAVAIL;
}

NSS_STATUS _nss_registry_endgrent (void)
{
if (groupks!=NULL || groupkey!=NULL)
{
ksClose(groupks);
free(groupks);
/*keyClose(groupkey);
free(groupkey);
free(groupks);*/
groupks = NULL;
groupkey = NULL;
}
return NSS_STATUS_SUCCESS;
}


NSS_STATUS _nss_registry_getgrent_r (struct group *gr, char * buffer, 
		size_t buflen,int * errnop)
{
Key *tempkey;
int groupnamesize;
char *groupname;
NSS_STATUS tmpstatus;
/* Hmm..I wonder if I should start it implicitly when this function is
 * called without setent */

if(groupks==NULL)
	return NSS_STATUS_UNAVAIL;
if(groupkey==NULL)
{
	/* End of list */
	return NSS_STATUS_NOTFOUND;
}
groupnamesize = keyGetBaseNameSize(groupkey);
groupname = (char *)malloc(groupnamesize);
keyGetBaseName(groupkey, groupname, groupnamesize);
tmpstatus = _nss_registry_getgrnam_r(groupname, gr, buffer, buflen, errnop);
free(groupname);
tempkey = groupkey;
groupkey = groupkey->next;
return tmpstatus;
}
