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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <registry.h>
#include <string.h>

void addusers(int options);
void adduser(struct passwd *pw, struct spwd *spw);
void addgroups(int options);
void addgroup(struct group *grp);

void SetValue(char *key, char *value, int mode);

#define USERFLAG 0x1
#define SHADOWFLAG 0x2
#define GROUPFLAG 0x4
#define UPDATEFLAG 0x8

int main(int argc, char *argv[])
{
int options=0;
int opt;
options = (SHADOWFLAG | GROUPFLAG | USERFLAG | UPDATEFLAG);
/* Options 
Blah. We assume add all & update if existing */

while((opt = getopt(argc, argv, "ogsur:")) != -1)
{
	switch(opt)
	{
		/* o = -userflag */
		case 'o':	options &= ~USERFLAG;
			break;
		/* -groupflag */
		case 'g':	options &= ~GROUPFLAG;
			break;
		/* -shadowflag */
		case 's':	options &= ~SHADOWFLAG;
			break;
		/* -updateflag */
		case 'u':	options &= ~UPDATEFLAG;
			break;
		/* Set root to something else...for testing purposes 
		 * Tells the program to add all entries under <root>/users 
		 * and <root>/groups
		 */
		case 'r':	printf("Using root %s\n",optarg);
				break;
	}
}
if(options == 0 || options == UPDATEFLAG)
	options = (SHADOWFLAG | GROUPFLAG | USERFLAG | UPDATEFLAG);

printf("Starting... Options = %d\n",options);
registryOpen();
addusers(options);
addgroups(options);
registryClose();
return 0;
}

void addusers(int options)
{
struct passwd *pw = NULL;
struct spwd *spw = NULL;
if(options & USERFLAG)
{
printf("Adding User entries...\n");
	setpwent();
	while((pw = getpwent()) != NULL)
	{
		/*if(userexists(pw->pw_name))*/
		if (options & SHADOWFLAG)
		{
			printf("Retrieving Shadow entry for %s\n",pw->pw_name);
			spw = getspnam(pw->pw_name);
		}
		adduser(pw, spw);
/*		pw = NULL;
		spw = NULL;*/
	}
	endpwent();
} else if(options & SHADOWFLAG)
{
	printf("Adding only shadow entries...\n");
        setpwent();
        while((spw = getspent()) != NULL)
        {
                adduser(NULL, spw);
        }
	if(errno)
		printf("Error: %s\n",strerror(errno));
        endspent();

}

}

void adduser(struct passwd *pw, struct spwd *spw)
{
char key[1024];
char value[1024];
/* Add Passwd entries */
if(pw != NULL)
{
printf("Adding user: %s\n",pw->pw_name);
snprintf(key,1023,"system/users/%s/password",pw->pw_name);
SetValue(key, pw->pw_passwd, -1);

snprintf(key,1023,"system/users/%s/uid",pw->pw_name);
snprintf(value,1023,"%li",pw->pw_uid);
SetValue(key, value,-1);

snprintf(key,1023,"system/users/%s/gid",pw->pw_name);
snprintf(value,1023,"%li",pw->pw_gid);
SetValue(key, value, -1);

snprintf(key,1023,"system/users/%s/home",pw->pw_name);
SetValue(key, pw->pw_dir,-1);

snprintf(key,1023,"system/users/%s/gecos",pw->pw_name);
SetValue(key, pw->pw_gecos,-1);

snprintf(key,1023,"system/users/%s/shell",pw->pw_name);
SetValue(key, pw->pw_shell,-1);

}

/* Add Shadow Entries 
   We add those with mode 0600 */
if(spw != NULL)
{
	printf("Adding shadow entry for %s\n",spw->sp_namp);

	snprintf(key,1023,"system/users/%s/shadowPassword",spw->sp_namp);
	SetValue(key, spw->sp_pwdp, 0600);
	
        snprintf(key,1023,"system/users/%s/passwdChangeBefore",spw->sp_namp);
        snprintf(value,1023, "%li", spw->sp_min);
        SetValue(key, value, 0600);

        snprintf(key,1023,"system/users/%s/passwdChangeAfter",spw->sp_namp);
        snprintf(value,1023, "%li", spw->sp_max);
        SetValue(key, value, 0600);

        snprintf(key,1023,"system/users/%s/passwdWarnBefore",spw->sp_namp);
        snprintf(value,1023, "%li", spw->sp_warn);
        SetValue(key, value, 0600);

        snprintf(key,1023,"system/users/%s/passwdDisableAfter",spw->sp_namp);
        snprintf(value,1023, "%li", spw->sp_inact);
        SetValue(key, value, 0600);

        snprintf(key,1023,"system/users/%s/passwdDisabledSince",spw->sp_namp);
        snprintf(value,1023, "%li", spw->sp_expire);
        SetValue(key, value, 0600);

        snprintf(key,1023,"system/users/%s/passwdReserved",spw->sp_namp);
        snprintf(value,1023, "%li", spw->sp_flag);
        SetValue(key, value, 0600);
}
}

void SetValue(char *keyname, char *value, int mode)
{
Key *key;
/* mode -1 = standard access permissions */
if(mode == -1)
{
	registrySetValue(keyname,value);
} else
{
/* Special Access permissions */
	key = (Key *)malloc(sizeof(Key));
	keyInit(key);
	keySetName(key, keyname);
	keySetString(key, value);
	keySetAccess(key, mode);
	registrySetKey(key);
	keyClose(key);
	free(key);
}
}

void addgroups(int options)
{
struct group *gr;

if(options & GROUPFLAG)
{
	printf("Adding Groups...\n");
	setgrent();
	while((gr = getgrent()) != NULL)
	{
		addgroup(gr);
	}
}
}

void addgroup(struct group *grp)
{
char key[1024];
char value[1024];
char **members;

if(grp!=NULL)
{
	printf("Adding group %s\n",grp->gr_name);

	snprintf(key,1023,"system/groups/%s/passwd",grp->gr_name);
	SetValue(key,grp->gr_passwd, -1);

	snprintf(key,1023, "system/groups/%s/gid",grp->gr_name);
	snprintf(value,1023, "%li",grp->gr_gid);
	SetValue(key, value, -1);

	/* Group has at least one member */
	if(*(grp->gr_mem) != NULL)
	{
	members = grp->gr_mem;
	while((*members) != NULL)
	{
		/* Not sure of ideal way to do this...
		 * Either commaseperated in one file like /etc/group
		 * or seperated entries for each member. */
		printf("Adding member %s of group %s\n",*members,grp->gr_name);
		snprintf(key,1023, "system/groups/%s/members/%s",grp->gr_name,(*members));
		SetValue(key,*members, -1);
		members++;
	}
	}
}
}
