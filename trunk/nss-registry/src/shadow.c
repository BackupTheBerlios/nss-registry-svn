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
 * $Id: shadow.c,v 1.7 2004/05/22 13:26:28 rayman Exp $ 
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <shadow.h>
#include <stdio.h>

#include "nss-registry.h"

#include "nss-shadow.h"
#include "lib.h"

/* Taken from nss-mysql */
#define FALLBACK -1		/* if the last change coloum can't be read,
				   fall back to -1.(This is what the nss-files does so) */

/* Global keyset & key for setspent, getspent and endspent */
KeySet *shadowks = NULL;
Key *shadowkey = NULL;

NSS_STATUS _nss_registry_getspuid_r (uid_t, struct spwd *, char *, size_t,
				     int *);
NSS_STATUS _nss_registry_setspent (void);
NSS_STATUS _nss_registry_getspent_r (struct spwd *pw, char *buffer,
				     size_t buflen, int *errnop);
NSS_STATUS _nss_registry_endspent (void);
NSS_STATUS _nss_registry_getspnam_r (const char *, struct spwd *, char *,
				     size_t, int *);


/* getspnam
 * looks for an user by its name
 * Arguments:
 * name: user's name
 * result: struct we'll fill
 * buffer:
 * buflen: sizeof(buffer)
 * errnop: ptr on the application errno
 */

NSS_STATUS
_nss_registry_getspnam_r (const char *name, struct spwd *pw,
			  char *buffer, size_t buflen, int *errnop)
{
  int i;
  char *tmpbuf = NULL;
  Key *tmpkey;

  *errnop = ENOENT;

/* Open registry connection */
  registryOpen ();
  if (_nss_registry_finduserbyname (name) == NSS_STATUS_NOTFOUND)
    return NSS_STATUS_NOTFOUND;
/* Yay! the users exists, lets continue */
  pw->sp_namp =
    (char *) _nss_registry_copy_to_buffer (&buffer, &buflen, name);
  if (!pw->sp_namp)
    goto out_nomem;

  tmpbuf =
    _nss_registry_get_string (REGISTRYUSER, pw->sp_namp, "shadowPassword",&i);
  if(tmpbuf == NULL && i > 0)
  {
	/* Only give error and return if any other error than File not found */
	if(i != ENOENT)
	{
	*errnop = i;
	return NSS_STATUS_UNAVAIL;
	}
  }
  if (!_nss_registry_isempty (tmpbuf))
    {
      pw->sp_pwdp =
	(char *) _nss_registry_copy_to_buffer (&buffer, &buflen, tmpbuf);
      free (tmpbuf);
    }
  else
    {
/* If password is empty, set it to ! indication no password */
      pw->sp_pwdp =
	(char *) _nss_registry_copy_to_buffer (&buffer, &buflen, "!");
      if (tmpbuf != NULL)
	free (tmpbuf);
    }

  if (!pw->sp_pwdp)
    goto out_nomem;

  tmpbuf = (char *) malloc (255);
  sprintf (tmpbuf, "system/users/%s/shadowPassword", pw->sp_namp);
  tmpkey = (Key *) malloc (sizeof (Key));
  memset(tmpkey, 0, sizeof(Key));
  keyInit (tmpkey);
  keySetName (tmpkey, tmpbuf);
  registryStatKey (tmpkey);
  pw->sp_lstchg = keyGetMTime (tmpkey) / (60 * 60 * 24);
  keyClose (tmpkey);
  free (tmpkey);
  free (tmpbuf);

  tmpbuf =
    _nss_registry_get_string (REGISTRYUSER, pw->sp_namp,
			      "passwdChangeBefore",&i);
  if(tmpbuf == NULL && i > 0)
  {
        /* Only give error and return if any other error than File not found */
        if(i != ENOENT)
        {
        *errnop = i;
        return NSS_STATUS_UNAVAIL;
        }
  }
  pw->sp_min = _nss_registry_strtol (tmpbuf, FALLBACK, &i);
  if (i)
    {
      _nss_registry_log (LOG_ERR,
			 "User %s has invalid passwdChangeBefore (%s). "
			 " Reverted to %d. Fix you registry entries.",
			 pw->sp_namp, tmpbuf, pw->sp_min);
    }
  if (tmpbuf != NULL)
    free (tmpbuf);

  tmpbuf =
    _nss_registry_get_string (REGISTRYUSER, pw->sp_namp, "passwdChangeAfter",&i);
  if(tmpbuf == NULL && i > 0)
  {
        /* Only give error and return if any other error than File not found */
        if(i != ENOENT)
        {
        *errnop = i;
        return NSS_STATUS_UNAVAIL;
        }
  }
  pw->sp_max = _nss_registry_strtol (tmpbuf, FALLBACK, &i);
  if (i)
    {
      _nss_registry_log (LOG_ERR,
			 "User %s has invalid passwdChangeAfter (%s). "
			 " Reverted to %d. Fix you registry entries.",
			 pw->sp_namp, tmpbuf, pw->sp_max);
    }
  if (tmpbuf != NULL)
    free (tmpbuf);

  tmpbuf =
    _nss_registry_get_string (REGISTRYUSER, pw->sp_namp, "passwdWarnBefore",&i);
  if(tmpbuf == NULL && i > 0)
  {
        /* Only give error and return if any other error than File not found */
        if(i != ENOENT)
        {
        *errnop = i;
        return NSS_STATUS_UNAVAIL;
        }
  }  
  pw->sp_warn = _nss_registry_strtol (tmpbuf, FALLBACK, &i);
  if (i)
    {
      _nss_registry_log (LOG_ERR,
			 "User %s has invalid passwdWarnBefore (%s). "
			 " Reverted to %d. Fix you registry entries.",
			 pw->sp_namp, tmpbuf, pw->sp_warn);
    }
  if (tmpbuf != NULL)
    free (tmpbuf);

  tmpbuf =
    _nss_registry_get_string (REGISTRYUSER, pw->sp_namp,
			      "passwdDisableAfter",&i);
  if(tmpbuf == NULL && i > 0)
  {
        /* Only give error and return if any other error than File not found */
        if(i != ENOENT)
        {
        *errnop = i;
        return NSS_STATUS_UNAVAIL;
        }
  }
  pw->sp_inact = _nss_registry_strtol (tmpbuf, FALLBACK, &i);
/* Don't warn in this case since it seems quite normal to not have that set..
 * At least on my system */
  if (tmpbuf != NULL)
    free (tmpbuf);

  tmpbuf =
    _nss_registry_get_string (REGISTRYUSER, pw->sp_namp,
			      "passwdDisabledSince",&i);
  if(tmpbuf == NULL && i > 0)
  {
        /* Only give error and return if any other error than File not found */
        if(i != ENOENT)
        {
        *errnop = i;
        return NSS_STATUS_UNAVAIL;
        }
  }
  pw->sp_expire = _nss_registry_strtol (tmpbuf, FALLBACK, &i);
/* Don't warn in this case since it seems quite normal to not have that set..
 * At least on my system */
  if (tmpbuf != NULL)
    free (tmpbuf);

  tmpbuf =
    _nss_registry_get_string (REGISTRYUSER, pw->sp_namp, "passwdReserved",&i);
  if(tmpbuf == NULL && i > 0)
  {
        /* Only give error and return if any other error than File not found */
        if(i != ENOENT)
        {
        *errnop = i;
        return NSS_STATUS_UNAVAIL;
        }
  }
  pw->sp_flag = _nss_registry_strtol (tmpbuf, FALLBACK, &i);
/* Don't warn in this case since it seems quite normal to not have that set..
 * At least on my system */
  if (tmpbuf != NULL)
    free (tmpbuf);

/* Woo! this means it was successfull. Go on! tell everyone :) */

  *errnop = 0;
  registryClose ();
  return NSS_STATUS_SUCCESS;


/* Taken from nss-mysql */
out_nomem:
  /* if we're here, that means that the buffer is too small, so
   * we return ERANGE
   */
  *errnop = ERANGE;
  registryClose ();
  return NSS_STATUS_TRYAGAIN;

}

NSS_STATUS
_nss_registry_getspuid_r (uid_t uid, struct spwd * pw,
			  char *buffer, size_t buflen, int *errnop)
{
  char *username;
  NSS_STATUS tmpstatus;
  registryOpen ();
  if ((_nss_registry_finduserbyuid (uid, &username)) == NSS_STATUS_NOTFOUND)
    return NSS_STATUS_NOTFOUND;
/* Due to the way the registry is made it's far more efficient to work with
 * usernames only, hence once we have the username for a uid we might as well 
 * just pass it on to getspnam
 *
 * Again caching would be nice (just of uid/username combination)..
 * Perhaps in the finduserbyuid function..
*/
  registryClose ();
  tmpstatus = _nss_registry_getspnam_r (username, pw, buffer, buflen, errnop);
  free (username);
  return tmpstatus;
}


NSS_STATUS
_nss_registry_setspent (void)
{
  int ret;
/* We need to first open registry, then get a KeySet of all keys in system/users
 * and store it globally, ready for returning the first key
 */
  registryOpen ();
  shadowks = (KeySet *) malloc (sizeof (KeySet));
  memset(shadowks, 0, sizeof(KeySet));
  ksInit (shadowks);
  ret = registryGetChildKeys ("system/users", shadowks, RG_O_DIR);
  if (!ret)
    {
      if (shadowks->size <= 0)
	{
	  _nss_registry_log (LOG_ERR, "_nss_registry_setspent: No users found."
                         "Fix your registry.");
	  ksClose (shadowks);
	  free (shadowks);
	  shadowks = NULL;
	  registryClose ();
	  return NSS_STATUS_NOTFOUND;
	}
      /* No error, return success! */
      shadowkey = shadowks->start;
      registryClose ();
      return NSS_STATUS_SUCCESS;
    }

/* If we get here it usually means that system/users doesn't exist,
 * which means this function is unavailable :) as well as the other 
 * related ones */
  registryClose ();
  return NSS_STATUS_UNAVAIL;
}

NSS_STATUS
_nss_registry_endspent (void)
{
  if (shadowks != NULL)
    {
      ksClose (shadowks);
      if (shadowks != NULL)
	free (shadowks);
      shadowks = NULL;
      shadowkey = NULL;
    } else if(shadowkey != NULL)
    {
      keyClose(shadowkey);
      free(shadowkey);
    }
  return NSS_STATUS_SUCCESS;
}


NSS_STATUS
_nss_registry_getspent_r (struct spwd * pw, char *buffer,
			  size_t buflen, int *errnop)
{
  Key *tempkey = NULL;
  int usernamesize;
  char *username = NULL;
  NSS_STATUS tmpstatus;
/* Hmm..I wonder if I should start it implicitly when this function is
 * called without setent */

  if (shadowks == NULL)
    return NSS_STATUS_UNAVAIL;
  if (shadowkey == NULL)
    {
      /* End of list */
      return NSS_STATUS_NOTFOUND;
    }
  usernamesize = keyGetBaseNameSize (shadowkey);
  username = (char *) malloc (usernamesize);
  keyGetBaseName (shadowkey, username, usernamesize);
  tmpstatus = _nss_registry_getspnam_r (username, pw, buffer, buflen, errnop);
  free (username);
  tempkey = shadowkey;
  shadowkey = tempkey->next;
  return tmpstatus;
}
