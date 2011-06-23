/************************************************************************
 *   IRC - Internet Relay Chat, include/patchlevel.h
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

/* $Id$ */

#ifndef __patchlevel_header__
#define __patchlevel_header__

/* these don't go in the version itself, but they're importany anyways */
#define CURRENT 1
#define RELEASE 2
#define STABLE  3
#define BETA    4

#define BRANCHSTATUS CURRENT
#define BRANCH "perimeter"

#define BASENAME "bahamut"
#define MAJOR 1
#define MINOR 4
#define PATCH 34
#ifndef INET6
#define PATCH1 ""
#else
#define PATCH1 "-inet6(1.0a)"
#endif
#define PATCH2 "-azzurra(4.7)"
#ifndef USE_SSL
#define PATCH3 ""
#else
#define PATCH3 "-ssl(1.1)"
#endif
#ifndef WEBIRC
#define PATCH4 ""
#else
#define PATCH4 "-webirc(1.2)"
#endif

#define PATCH5 ""

#define PATCH6 ""

#define PATCH7 ""

#define PATCH8 ""

#define PATCH9 ""

#define PATCHES PATCH1 PATCH2 PATCH3 PATCH4 PATCH5 PATCH6 PATCH7 PATCH8 PATCH9

void build_version(void);

#endif

