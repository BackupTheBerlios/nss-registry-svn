/* Nss-registry
*  Copyright (C) 2004 Jens Andersen <rayman@skumler.net>
*  Portions taken from nss-mysql is copyrighted as below :
*  Copyright (C) 2000 Steve Brown
*  Copyright (C) 2000,2001,2002 Guillaume Morin, Alc▒ve
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


/* Not quite sure if I need this yet, but I'll leave it for now.
 * needed to use vasprintf ... 
*/
#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include "lib.h"

/*taken from nss-mysql */
void _nss_registry_log(int err,const char *format, ...) 
{
	static int openlog_ac = 0;
	va_list args;

	va_start(args, format);
	if (! openlog_ac) 
	{
		++openlog_ac;
		openlog("nss-registry", LOG_PID, LOG_AUTH);
	}
	vsyslog(err, format, args);
	va_end(args);
}	

/* _nss_registry_get_string
 * Parameters:
 * int type : Type of value to retrieve, Can be GROUP or USER. 
 * char *username username/groupname to retrieve data for.
 * char *keyname name of value to retrieve
 * returns pointer to string containing the contents of the key.
*/ 
char *_nss_registry_get_string(int type, char *username, char *keyname)
{
int ret,size;
Key key;
char *value=NULL;
char keypath[256];
if(type==REGISTRYGROUP)
{
snprintf(keypath, 1023,"system/groups/%s/%s",username,keyname);
} else 
{
snprintf(keypath, 1023, "system/users/%s/%s",username,keyname);
}

registryOpen();
keyInit(&key);
keySetName(&key,keypath);
ret = registryGetKey(&key);
/* Key doesn't exist. This shouldn't really happen due to the check earlier */
if(ret)
	return NULL;
size=keyGetDataSize(&key);
/* If size is zero or less then return NULL) */
if(size<=0) return NULL;
/* We only want strings! Abort otherwise */
if(keyGetType(&key) != RG_KEY_TYPE_STRING) return NULL;
value = (char *)malloc(size);
keyGetString(&key,value,size);
keyClose(&key);
registryClose();
return value;
}

/* Function to check if user exists.
 * Name version
*/
NSS_STATUS _nss_registry_finduserbyname(const char *name)
{
char keypath[256];
Key key;
int ret;
sprintf(keypath,"system/users/%s",name);
keyInit(&key);
keySetName(&key,keypath);
ret = registryGetKey(&key);
keyClose(&key);
if(ret==0) return NSS_STATUS_SUCCESS;
else return NSS_STATUS_NOTFOUND;
}

/* Function to check if user exists.
 * uid version
*/
NSS_STATUS _nss_registry_finduserbyuid(uid_t uid, char **name)
{
Key key;
char keyname[1024];
int ret;
/* Where to store where the link points to */
int linksize;
char *link;
char *p;
NSS_STATUS status = NSS_STATUS_NOTFOUND;

snprintf(keyname, 1023, "system/users/.ByID/%li", uid);
keyInit(&key);
keySetName(&key, keyname);
ret = registryStatKey(&key);
if(ret != 0) return NSS_STATUS_NOTFOUND;
if(keyGetType(&key) != RG_KEY_TYPE_LINK) 
{
_nss_registry_log(LOG_ERR,"finduserbyuid: Error: key %s is not a link!\n",keyname);
keyClose(&key);
return NSS_STATUS_NOTFOUND;
}
/* Woo! it's a link and stuff...return basename of link */
linksize = keyGetDataSize(&key);
link = (char *)malloc(linksize);
keyGetLink(&key, link, linksize);
p = rindex(link, '/');
if(p != NULL)
{
p++;
*name = strdup(p);
status = NSS_STATUS_SUCCESS;
}
keyClose(&key);
p = NULL;
free(link);

return status;
}

/* Function to check if group exists.
 * Name version
*/
NSS_STATUS _nss_registry_findgroupbyname(const char *name)
{
char keypath[256];
Key key;
int ret;
sprintf(keypath,"system/groups/%s",name);
keyInit(&key);
keySetName(&key,keypath);
ret = registryGetKey(&key);
keyClose(&key);
if(ret==0) return NSS_STATUS_SUCCESS;
else return NSS_STATUS_NOTFOUND;
}


/* Function to check if group exists.
 * returns NSS_STATUS_SUCCESS when user found and sets name to point at a string
 * containing the name of the group 
 * gid version
*/
NSS_STATUS _nss_registry_findgroupbygid(gid_t gid, char **name)
{
Key key;
char keyname[1024];
int ret;
/* Where to store where the link points to */
int linksize;
char *link;
char *p;
NSS_STATUS status = NSS_STATUS_NOTFOUND;;

snprintf(keyname, 1023, "system/groups/.ByID/%li", gid);
keyInit(&key);
keySetName(&key, keyname);
ret = registryStatKey(&key);
if(ret != 0) return NSS_STATUS_NOTFOUND;
if(keyGetType(&key) != RG_KEY_TYPE_LINK)
{
_nss_registry_log(LOG_ERR,"findgroupbyuid: Error: key %s is not a link!\n",keyname);
keyClose(&key);
return NSS_STATUS_NOTFOUND;
}
/* Woo! it's a link and stuff...return basename of link */
linksize = keyGetDataSize(&key);
link = (char *)malloc(linksize);
keyGetLink(&key, link, linksize);
p = rindex(link, '/');
if(p != NULL)
{
p++;
*name = strdup(p);
status = NSS_STATUS_SUCCESS;
}
keyClose(&key);
p = NULL;
free(link);

return status;
}



/* Taken from nss-mysql */
/* _nss_registry_copy_to_buffer
 * copy a string to the buffer given as arguments
 * returns a pointer to the address in the buffer
 */

char * _nss_registry_copy_to_buffer(char ** buffer,size_t * buflen,
                const char * string) {
        size_t len = strlen(string) + 1;
        char * ptr;


        if (buflen && len > *buflen) {
                return NULL;
        }
        memcpy(*buffer,string,len);
        if (buflen)
                *buflen -= len;
        ptr = *buffer;
        (*buffer) += len;
        return ptr;
}

/* Taken from nss-mysql
 * However, there isn't a very big chance of this going wrong so it's
 * just there for backup
*/

/* _nss_registry_strtol
 * nss-registry strtol version
 * Converts ascii into long
 * str: string to convert
 * fallback: fallback to this value if strtol is not happy
 * error: if (*error), an error has occured, we have fallback.
 */

long _nss_registry_strtol(char * str, long fallback, int * error) {
        char * endptr;
        long toreturn;


        /* sanity checks */
        if (!str) {
                _nss_registry_log(LOG_ERR,"_nss_registry_strol: string pointer "
                                "is NULL.");
                *error = 1;
                return fallback;
        }
        if (*str == '\0') {
                _nss_registry_log(LOG_ERR,"_nss_registry_strtol: string is empty.");
                *error = 1;
                return fallback;
        }

        toreturn = strtol(str,&endptr,10);

        if (endptr == str) {
                _nss_registry_log(LOG_ERR,"_nss_registry_strtol: can't convert %s",
                                str);
                *error = 1;
                return fallback;
        }

        if (*endptr != '\0') {
                _nss_registry_log(LOG_ERR,"_nss_registry_strtol_: incomplete "
                                "conversion of %s to %ld. Falling back "
                                "to %ld.",str,toreturn,fallback);
                *error = 1;
                return fallback;
        }

        if (errno != ERANGE) {
                *error = 0;
                return toreturn;
        }

        _nss_registry_log(LOG_ERR,"_nss_registry_strol: overflow when converting %s. "
                        "Fix your registry entries.",str);
        *error = 1;
        return toreturn;
}

/* Taken from nss-mysql */
/* _nss_registry_isempty
 * checks if a string only contains spaces
 * Returns:
 * 0, string is not empty
 * 1, string is empty
 */

int _nss_registry_isempty(char * str) 
{
        if (!str) return 1;
        while(*str != '\0')
                if (!isspace((unsigned char)*(str++))) return 0;
        return 1;
}

