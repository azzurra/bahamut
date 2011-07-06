/************************************************************************
 *   IRC - Internet Relay Chat, src/as.c
 *   Copyright (C) 2001-2002 Barnaba Marcello <vjt@users.sf.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* i LOVE *p ! */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include <sys/stat.h>
#include <fcntl.h>
#include "h.h"

#ifdef ADMINSERV

#if defined( __APPLE__ ) && !defined( __darwin__ )
#define __darwin__
#endif

#if defined( __FreeBSD__ ) || defined( __NetBSD__ ) || defined( __OpenBSD__ ) || defined( __darwin__ )
#include <sys/sysctl.h>
#endif
#ifdef sun
#include <utmpx.h>
#endif
#include <sys/utsname.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include "as.h"

#ifndef RUSAGE_SELF
#define RUSAGE_SELF	0
#endif
#ifndef RUSAGE_CHILDREN
#define RUSAGE_CHLDREN	-1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

static unsigned int    as_filesiz;
static char **as_text;
static unsigned short  as_lines;
unsigned short  as_bufflag = AS_BUF_FREE;
char  *as_bufname = NULL;

const unsigned short as_text_chunk = 16;

extern int errno;

static int as_filecommand(aClient *, aClient *, char *, char *,
	u_short, int, char **);
static int as_getsysinfo(aClient*, aClient*, char *, char *, u_short,
	int, char **);
static int as_rehash(aClient*, aClient*, char *, char *, u_short,
	int, char **); /* 27/05/02 -tsk */

typedef struct As_Cmd
{
   char		 *cmd;
   char		 *file;
   u_short	  filetok;
   u_short	  params;
   int		(*handler)(aClient*, aClient*, char *, char *,
	   		u_short, int, char **);
} as_cmd;

as_cmd as_cmds[] = {
   {"CONF", CPATH, AS_BUF_CONF, 5, as_filecommand},
   {"MOTD", MPATH, AS_BUF_MOTD, 5, as_filecommand},
   {"OPERMOTD", OPATH, AS_BUF_OPERMOTD, 5, as_filecommand},
   {"AZZURRA", KPATH, AS_BUF_KLINE, 5, as_filecommand},
   {"REHASH", NULL, 0, 1, as_rehash}, /* 27/05/02 -tsk */
   {"SYS", NULL, 0, 1, as_getsysinfo},
   {NULL, NULL, 0, 0, NULL}
};

/* Template string for mkstemp */
#define AS_TEMPTPL DPATH "/as.XXXXXXXX"

/* sendto_one wrapper for AS */
void as_msg(aClient *sptr, char type, char *fmt, ...) {
    va_list vl;
    u_short len = strlen(me.name) +
	strlen(sptr->name) + strlen(fmt) + 23;
    char *f = MyMalloc(len);

    memset(f, 0x0, len);
    f[0] = ':';
    ircsprintf(f, ":%s NOTICE %s :%s -- %s", me.name, sptr->name,
	    type == AS_SUCCESS ? "Success" : "Failure", fmt);
    
    va_start(vl, fmt);
    vsendto_one(sptr, f, vl);
    va_end(vl);
}

inline void as_free_buf() {
    register unsigned short x = 0;
    
    while(x < as_lines)
	MyFree(as_text[x++]);
    MyFree(as_text);
    as_bufflag = AS_BUF_FREE;
    as_bufname = NULL;
}

static inline void as_realloc(size_t s) {
    char **new = (char **)
	MyMalloc((s + as_text_chunk) * sizeof(char **));
    while(--s != -1)
	new[s] = as_text[s];
    MyFree((void*)as_text);
    as_text = new;
}

static int as_loadfile(char *f)
{
    int fd;
    unsigned short i = 0;
    register char *p = NULL, *q = NULL;
    char *as_filebuf;
    struct stat st;

    if(stat(f, &st) < 0)
	return AS_FILE_ERROR;
    
    if ((fd = open(f, O_RDONLY, 0)) == -1)
	return AS_FILE_ERROR;
    
    as_filesiz = st.st_size;
    as_filebuf = MyMalloc(as_filesiz+2);	/*maybe noeol*/
    if (read(fd, (void*)as_filebuf, as_filesiz) == -1) {
	MyFree(as_filebuf);
	close(fd);
	return AS_FILE_ERROR;
    }
    if(as_filebuf[as_filesiz - 1] != '\n')	/*if noeol*/
	as_filebuf[as_filesiz++] = '\n';
    as_filebuf[as_filesiz] = '\0';
    close(fd);

    as_text = (char **) MyMalloc(as_text_chunk * sizeof(char **));
    p = q = as_filebuf;

    while((p = strchr(p, '\n'))) {
	*p++ = '\0';
	as_text[i] = MyMalloc(strlen(q) + 1);
	strcpy(as_text[i++], q);
	q = p;

	if(i % as_text_chunk == 0)
	    as_realloc(i);
    }

    MyFree(as_filebuf);
    as_text[i] = NULL;
    as_lines = i - 1;

    /* f is a valid pointer into as_cmds array */
    as_bufname = f;

    return (as_filesiz == 0 ? AS_FILE_EMPTY : AS_FILE_OK);
}


static int as_savefile(char *f)
{
    int fd, rv, oerrno;
    unsigned short i;
    char *p, *as_filebuf;
    char templ[PATH_MAX];

    /* DON'T clobber the original file */
    strncpyzt(templ, AS_TEMPTPL, sizeof(templ));
    if((fd = mkstemp(templ)) < 0)
	return 0;

    p = as_filebuf = MyMalloc(as_filesiz);
    memset((void*) as_filebuf, 0x0, as_filesiz);
    
    for(i = 0; i <= as_lines; i++) {
	if(as_text[i] != NULL) {
	    strcpy(p, as_text[i]);
	    p += strlen(as_text[i]);
	}
	*p++ = '\n';
    }

    if ((rv = write(fd, as_filebuf, as_filesiz)) != -1)
	rv = ftruncate(fd, as_filesiz);
    /* Save errno from file operations so that AS XXX SAVE sends useful error messages */
    oerrno = errno;
    MyFree(as_filebuf);
    as_free_buf();

    if (close(fd) == -1 || rv == -1) {
	/* File writing failed, unlink the temporary file and bail out */
	if (rv == -1)
	    /* An operation before close(fd) failed, restore proper errno */
	    errno = oerrno;
	goto bailout;
    } else {
	/* Move the temporary file in place of the original one */
	if (rename(templ, f) == -1)
	    goto bailout;
	return 1;
    }
bailout:
    /* Ignore errno and return value for unlink() */
    oerrno = errno;
    rv = unlink(templ);
    errno = oerrno;
    return 0;
}

static int as_viewfile(aClient *cptr, aClient *sptr)
{
    short i = 1;
    int fln = 1;

    while((i *= 10) <= as_lines)
	fln++;

    i = -1;
    while(i++ < as_lines)
	sendto_one(sptr, ":%s NOTICE %s :[%*d] %s",
		 me.name, sptr->name, fln, i, as_text[i]);

    as_msg(sptr, AS_SUCCESS, "EOF");
    
    return 0;
}

static int as_createfile(aClient *cptr, aClient *sptr, char *f, u_short ft)
{
    int fd;

    if(as_bufflag & ft) {
	as_msg(sptr, AS_FAILURE, "file already exists, and it is loaded. delete it first");
	return -1;
    }
    
    if((fd = open(f, O_RDWR | O_CREAT, 0600)) < 0) {
	as_msg(sptr, AS_FAILURE, "cannot creat(): %s", strerror(errno));
	return -1;
    } else
	fchmod(fd, 0600);

    as_msg(sptr, AS_SUCCESS, "file created");
    return 0;
}

static int as_remline(aClient *cptr, aClient *sptr, unsigned short l)
{
    if (as_lines == 0) {
	as_msg(sptr, AS_FAILURE, "File is empty");
	return 0;
    }

    if (l > as_lines) {
	as_msg(sptr, AS_FAILURE, "Line must be an integer between 0 and %i",
		as_lines);
	return 0;
    } else {
	unsigned short i;

	as_filesiz -= (strlen(as_text[l]) + 1);
	MyFree(as_text[l]);

	for(i = l; i < as_lines; i++)
	    as_text[i] = as_text[i + 1];

	as_lines--;
	as_bufflag |= AS_BUF_NEED_UPD;

	as_msg(sptr, AS_SUCCESS, "line %i removed", l);
    }
    return 0;
}


static int as_repline(aClient *cptr, aClient *sptr, unsigned short l, char *s)
{
    
    if(as_lines == 0) {
	as_msg(sptr, AS_FAILURE, "file is empty");
	return 0;
    }
    if(l > as_lines) {
	as_msg(sptr, AS_FAILURE, "Line must be an integer between 0 and %i", as_lines);
	return 0;
    } else {

	as_filesiz += (strlen(s) - strlen(as_text[l]));
	
	MyFree(as_text[l]);
	DupString(as_text[l], s);
	
	as_bufflag |= AS_BUF_NEED_UPD;

	as_msg(sptr, AS_SUCCESS, "line %i replaced", l);

    	return 1;
    }

}
	
static int as_addline(aClient *cptr, aClient *sptr, unsigned short l, char *s)
{
    if (l > as_lines + 1) {
	as_msg(sptr, AS_FAILURE, "line must be an integer between 0 and %d",
	       as_lines + 1);
	 return 0;
    } else {
	char *p;
	unsigned short i;
	if(++as_lines % as_text_chunk)
	    as_realloc(as_lines);
	DupString(p, s);
	as_filesiz += (strlen(p) + 1);
	for(i = as_lines; i > l; i--)
	    as_text[i] = as_text[i - 1];
	as_text[l] = p;
	
	as_bufflag |= AS_BUF_NEED_UPD;

	as_msg(sptr, AS_SUCCESS, "line %i inserted", l);

	return 1;
    }
}

#define h '-'
#define r 'r'
#define w 'w'
#define x 'x'
#define s 's'
#define t 't'

static inline char *as_perms(register mode_t m) {
    static char mdbuf[10];

    mdbuf[0] = m & S_IRUSR ? r : h;
    mdbuf[1] = m & S_IWUSR ? w : h;
    mdbuf[2] = m & S_ISUID ? s : m & S_IXUSR ? x : h;
    mdbuf[3] = m & S_IRGRP ? r : h;
    mdbuf[4] = m & S_IWGRP ? w : h;
    mdbuf[5] = m & S_ISGID ? s : m & S_IXGRP ? x : h;
    mdbuf[6] = m & S_IROTH ? r : h;
    mdbuf[7] = m & S_IWOTH ? w : h;
    mdbuf[8] = m & S_ISVTX ? t : m & S_IXOTH ? x : h;
    mdbuf[9] = '\0';

    return mdbuf;
}

#undef h
#undef r
#undef w
#undef x
#undef s
#undef t

static int as_getsysinfo(aClient *cptr, aClient *sptr, char *s, char *f,
	u_short ft, int pc, char **pv)
{
    /* XXX
    const short nelem = 3;
    double load[nelem];
    */
    uint32_t uptime = 0xffffffff;
    uint32_t ttime = 0xffffffff;
    u_short hrs, mins, secs, days;
    struct utsname un;
    struct passwd *pw;
    uid_t uid;
    char wd[64];
    struct stat st;
    struct rusage ru;
#if defined( __FreeBSD__ ) || defined( __NetBSD__ ) || defined( __OpenBSD__ ) || defined( __darwin__ )
    struct timeval boottime;
    int mib[2];
    size_t len;
    extern time_t NOW;
#elif defined( __linux__ )
    int fd;
    char bf[14];
#elif defined( sun )
    struct utmpx *u, id;
#else
#error "boot time retrieval is not implemented for your platform!"
#endif
    
    as_msg(sptr, AS_SUCCESS, "server PID is `%d'", getpid());

/* XXX    if(getloadavg(load, nelem))
	as_msg(sptr, AS_SUCCESS, "server load averages are: %.2f, %.2f, %.2f",
		load[0], load[1], load[2]);
    else
	as_msg(sptr, AS_FAILURE, "failed to compute load average: %s",
		strerror(errno));
*/

#if defined( __FreeBSD__ ) || defined( __NetBSD__ ) || defined( __OpenBSD__ ) || defined( __darwin__ )
    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    len = sizeof(boottime);
    if(sysctl(mib, 2, &boottime, &len, NULL, 0) != -1) {
	uptime = NOW - boottime.tv_sec;
    }
#endif
#ifdef __linux__
    if((fd = open("/proc/uptime", O_RDONLY, 0)) >= 0) {
	memset(bf, 0x0, sizeof(bf));
	if (read(fd, (void *) bf, 14) != -1)
	    uptime = strtoul(bf, NULL, 10);
	close(fd);
    }
#endif
#ifdef sun
    id.ut_type = BOOT_TIME;
    if((u = getutxid(&id))) {
	uptime = NOW - u->ut_xtime;
    }
#endif
    if (uptime != 0xffffffff) {
	if (uptime > 60)
	    uptime += 30;
	days = uptime / 86400;
	uptime %= 86400;
	hrs = uptime / 3600;
	uptime %= 3600;
	mins = uptime / 60;
	secs = uptime % 60;
	as_msg(sptr, AS_SUCCESS, "server uptime: %i day%s, %i hr%s, %i min%s, %i sec%s",
		days, days > 1 ? "s" : "", hrs, hrs > 1 ? "s" : "",
		mins, mins > 1 ? "s" : "", secs, secs > 1 ? "s" : "");
    } else {
	as_msg(sptr, AS_FAILURE, "failed to compute uptime: %s",
		strerror(errno));
    }
    
    if(getrusage(RUSAGE_SELF, &ru) == 0) {
	ttime = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec;
	as_msg(sptr, AS_SUCCESS, "server CPU time used: "
		"%02d:%02d [total], %02d:%02d [system]",
		ttime / 60, ttime % 60,
		ru.ru_stime.tv_sec / 60, ru.ru_stime.tv_sec % 60);
    } else
	as_msg(sptr, AS_FAILURE, "failed to compute process CPU time usage: %s",
		strerror(errno));
    uid = getuid();

    if((pw = getpwuid(uid)))
	as_msg(sptr, AS_SUCCESS, "server is running as uid %d [%s]",
		uid, pw->pw_name);
    else
	as_msg(sptr, AS_FAILURE, "failed to compute pwent: %s",
		strerror(errno));
    endpwent();

    if((getcwd(wd, sizeof(wd))) != NULL) {
	as_msg(sptr, AS_SUCCESS, "server current working directory: %s", wd);
	if(stat(wd, &st) != -1)
	    as_msg(sptr, AS_SUCCESS, "server cwd permissions: %s",
		    as_perms(st.st_mode));
	else
	    as_msg(sptr, AS_FAILURE, "failed to stat %s: %s", wd, strerror(errno));
    }
    else
	as_msg(sptr, AS_FAILURE, "failed to obtain current working directory: %s",
		strerror(errno));

    

    if(stat(SPATH, &st) != -1)
	as_msg(sptr, AS_SUCCESS, "server binary [%s] permissions: %s",
		SPATH, as_perms(st.st_mode));
    else
	as_msg(sptr, AS_FAILURE, "failed to stat %s: %s", SPATH, strerror(errno));

    if(stat(CPATH, &st) != -1)
	as_msg(sptr, AS_SUCCESS, "server configuration file [%s] permissions: %s",
		CPATH, as_perms(st.st_mode));
    else
	as_msg(sptr, AS_FAILURE, "failed to stat %s: %s", CPATH, strerror(errno));
    
    if(uname(&un) >= 0)
	as_msg(sptr, AS_SUCCESS, "server os: %s %s %s %s %s",
		un.sysname, un.nodename, un.release,
		un.version, un.machine);
    else
	as_msg(sptr, AS_FAILURE, "failed to compute uname: %s",
		strerror(errno));

    return 0;
}

#define AS_FILE_COMMAND_LIST "ADD, DEL, INSERT, REPLACE, CREATE, LIST, SAVE, DISCARD"

static int as_filecommand(aClient *cptr, aClient *sptr, char *s, char *f,
	u_short ft, int parc, char **parv)
{
    if (parc < 3) {
	as_msg(sptr, AS_FAILURE, "valid commands for %s are:", s);
	as_msg(sptr, AS_FAILURE, AS_FILE_COMMAND_LIST);
	return 0;
    }

    if (as_bufflag & AS_BUF_NEED_UPD && !(as_bufflag & ft)) {
	as_msg(sptr, AS_FAILURE, "currently loaded `%s', save  or discard your settings first",
	       as_bufname);
	return 0;
    } 
    else if (as_bufflag == AS_BUF_FREE || !(as_bufflag & ft)) {
	if(strcasecmp("DISCARD", parv[2]) == 0)
	{
	    as_msg(sptr, AS_FAILURE, "no file loaded");
	    return -1;
	}
	switch(as_loadfile(f)) {
	    case AS_FILE_EMPTY:
		as_msg(sptr, AS_SUCCESS, "empty file `%s' loaded", as_bufname);
		return 0;
		break;
	    case AS_FILE_ERROR:
		if (strcasecmp("CREATE", parv[2]) == 0) {
		    as_createfile(cptr, sptr, f, ft);
		    return 0;
		}
		else
		{
		    as_msg(sptr, AS_FAILURE, "cannot load file: %s", strerror(errno));
		    return -1;
		}
		break;
	    case AS_FILE_OK:
		as_msg(sptr, AS_SUCCESS, "%s loaded successfully [%d byte%s]",
			as_bufname, as_filesiz, as_filesiz > 1 ? "s" : "");
		as_bufflag = ft;
		break;
	}
    } else if(as_bufflag & AS_BUF_NEED_UPD)
	as_msg(sptr, AS_SUCCESS, "`%s' currently modified . .",
		as_bufname);

    if (strcasecmp("ADD", parv[2]) == 0)
	as_addline(cptr, sptr, as_lines + 1, parc > 3 ? parv[3] : "");
    else if (strcasecmp("DEL", parv[2]) == 0)
	(parc > 3) ? as_remline(cptr, sptr, atoi(parv[3])) :
	      	     as_msg(sptr, AS_FAILURE, "Valid syntax is: %s del <n>", s);
    else if (strcasecmp("INSERT", parv[2]) == 0) {
	(parc < 4) ?
	    as_msg(sptr, AS_FAILURE, "Valid syntax is: %s insert <n> [:text]", s) :
	    as_addline(cptr, sptr, atoi(parv[3]), parc < 5 ? "" : parv[4]);
    }
    else if (strcasecmp("REPLACE", parv[2]) == 0) {
	(parc < 4) ?
	    as_msg(sptr, AS_FAILURE, "Valid syntax is: %s replace <n> [:text]", s):
	    as_repline(cptr, sptr, atoi(parv[3]), parc < 5 ? "" : parv[4]);
    }
    else if (strcasecmp("LIST", parv[2]) == 0)
	as_viewfile(cptr, sptr);
    else if (strcasecmp("SAVE", parv[2]) == 0) {
	if((as_bufflag & ft) && (as_bufflag & AS_BUF_NEED_UPD))
	{
	    if(as_savefile(f))
		as_msg(sptr, AS_SUCCESS, "file saved");
	    else
		as_msg(sptr, AS_FAILURE, "write(2): %s", strerror(errno));
	}
	else
	    as_msg(sptr, AS_FAILURE, "`%s' not currently modifiyed", as_bufname);
    }
    else if (strcasecmp("DISCARD", parv[2]) == 0) {
	if(as_bufflag & ft)
	{
	    as_free_buf();
	    as_msg(sptr, AS_SUCCESS, "buffers cleaned");
	}
    }
    else
    {
	as_msg(sptr, AS_FAILURE, "Valid commands for %s are:", s);
	as_msg(sptr, AS_FAILURE, AS_FILE_COMMAND_LIST);
	return -1;
    }
    return 0;
}

static char **as_do_parv(char **parv, u_short max)
{
   char      **ret = parv;

   ret[max] = NULL;
   return ret;
}

as_cmd *as_findcommand(char *str) {
    as_cmd     *trav;
    
    for (trav = as_cmds; trav->cmd; ++trav)
	if ((strncasecmp(trav->cmd, str, strlen(trav->cmd))) == 0)
	    return trav;
    return NULL;
}

static void as_send_cmd_list(aClient *sptr)
{
   register as_cmd *trav;
   register u_short len = 1;
   char *ret = MyMalloc(len), *p;

   memset(ret, 0x0, len);
   for (trav = as_cmds; trav->cmd; ++trav) {
      len += (strlen(trav->cmd) + 2);
      ret = MyRealloc(ret, len);
      p = (ret + len - 3);
      strcat(ret, trav->cmd);
      if ((trav + 1)->cmd) {
	 *p++ = ',';
	 *p++ = ' ';
      }
      *p = '\0';
   }

   as_msg(sptr, AS_FAILURE, "Valid commands are: %s", ret);
   MyFree(ret);
   return;
}

static int as_rehash(aClient *cptr, aClient *sptr, char *s, char *f,
	u_short ft, int pc, char **pv)
{
    as_msg (sptr, (rehash (cptr, sptr, 0) ? AS_FAILURE : AS_SUCCESS), "ircd.conf Rehashing");
    return 0;
}

#endif

/* AdminServ configuration tool -- INT 12/6/99 */
/* complete rewrite -- vejeta Thu Jan 24 02:59:29 CET 2002 */

int m_as(aClient *cptr, aClient *sptr, int parc, char **parv)
{
    if (!IsAdmin(sptr))
    {
	sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, sptr->name);
	return 0;
    }

#ifdef ADMINSERV
    if (parc < 2) {
	as_send_cmd_list(sptr);
	return 0;
    }
    else
    {
	as_cmd     *cmd;

	if ((cmd = as_findcommand(parv[1])) != NULL)
	     cmd->handler(cptr, sptr, cmd->cmd, cmd->file, cmd->filetok,
		          parc > cmd->params ? cmd->params : parc,
			  as_do_parv(parv, cmd->params));
	else
	    as_send_cmd_list(sptr);
    }
#else
    sendto_one(sptr,
	       ":%s NOTICE %s :AdminServ is not available on this server.",
	       me.name, sptr->name);
#endif
   return 0;
}
