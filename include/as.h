/************************************************************************
 *   IRC - Internet Relay Chat, include/as.h
 *   Copyright (C) 2001-2002 vejeta
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

#define OPATH "opers.txt"
#define AS_FAILURE 0
#define AS_SUCCESS 1

#define AS_BUF_FREE	0x00
#define AS_BUF_NEED_UPD	0x01
#define AS_BUF_CONF	0x02
#define AS_BUF_MOTD	0x04
#define AS_BUF_OPERMOTD	0x08
#define AS_BUF_KLINE	0x10

#define AS_FILE_EMPTY	-2
#define AS_FILE_ERROR	-1
#define AS_FILE_OK	1

inline void as_free_buf();
void as_msg(aClient *, char, char *, ...);
