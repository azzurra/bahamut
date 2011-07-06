/************************************************************************
 *   IRC - Internet Relay Chat, include/sys.h
 *   Copyright (C) 1990 University of Oulu, Computing Center
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
 *
 */

/* $Id$ */

#ifndef	__sys_include__
#define __sys_include__
#ifdef ISC202
#include <net/errno.h>
#else
#include <sys/errno.h>
#endif
#include "setup.h"
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_SYS_LIMITS_H
#include <sys/limits.h>
#endif
#include <sys/param.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if defined( HAVE_UNISTD_H )
#include <unistd.h>
#endif

#if defined( HAVE_STDLIB_H )
#include <stdlib.h>
#endif

#if defined( HAVE_STRINGS_H )
#include <strings.h>
#endif

#if defined( HAVE_STRING_H )
#include <string.h>
#endif

#if defined( HAVE_SYS_UIO_H )
#include <sys/uio.h>
#endif

#define	strcasecmp	mycmp
#define	strncasecmp	myncmp

#if !defined( HAVE_INDEX )
#define   index   strchr
#define   rindex  strrchr
#endif

#ifdef AIX
#include <sys/select.h>
#endif
#if defined(AIX)
#include <time.h>
#ifdef AIX
#include <sys/time.h>
#endif
#else
#include <sys/time.h>
#endif

#if ((__GNU_LIBRARY__ == 6) && (__GLIBC__ >=2) && (__GLIBC_MINOR__ >= 2))
#include <time.h>
#endif

#define MyFree(x)       if ((x) != NULL) free(x)

#ifdef NEXT
#define VOIDSIG int		/* whether signal() returns int of void */
#else
#define VOIDSIG void		/* whether signal() returns int of void */
#endif

extern VOIDSIG dummy();

#ifndef HAVE_U_CHAR
typedef unsigned char u_char;
#endif
#ifndef HAVE_U_SHORT
typedef unsigned short u_short;
#endif
#ifndef HAVE_U_LONG
typedef unsigned long u_long;
#endif
#ifndef HAVE_U_INT
typedef unsigned int u_int;
#endif

/* Integer types magic - ripped wholesale from TOR's torint.h */
#if (SIZEOF_INT8_T != 0)
#define HAVE_INT8_T
#endif
#if (SIZEOF_INT16_T != 0)
#define HAVE_INT16_T
#endif
#if (SIZEOF_INT32_T != 0)
#define HAVE_INT32_T
#endif
#if (SIZEOF_INT64_T != 0)
#define HAVE_INT64_T
#endif
#if (SIZEOF_UINT8_T != 0)
#define HAVE_UINT8_T
#endif
#if (SIZEOF_UINT16_T != 0)
#define HAVE_UINT16_T
#endif
#if (SIZEOF_UINT32_T != 0)
#define HAVE_UINT32_T
#endif
#if (SIZEOF_UINT64_T != 0)
#define HAVE_UINT64_T
#endif
#if (SIZEOF_INTPTR_T != 0)
#define HAVE_INTPTR_T
#endif
#if (SIZEOF_UINTPTR_T != 0)
#define HAVE_UINTPTR_T
#endif

#if (SIZEOF_CHAR == 1)
#ifndef HAVE_INT8_T
typedef signed char int8_t;
#define HAVE_INT8_T
#endif
#ifndef HAVE_UINT8_T
typedef unsigned char uint8_t;
#define HAVE_UINT8_T
#endif
#endif

#if (SIZEOF_SHORT == 2)
#ifndef HAVE_INT16_T
typedef signed short int16_t;
#define HAVE_INT16_T
#endif
#ifndef HAVE_UINT16_T
typedef unsigned short uint16_t;
#define HAVE_UINT16_T
#endif
#endif

#if (SIZEOF_INT == 2)
#ifndef HAVE_INT16_T
typedef signed int int16_t;
#define HAVE_INT16_T
#endif
#ifndef HAVE_UINT16_T
typedef unsigned int uint16_t;
#define HAVE_UINT16_T
#endif
#elif (SIZEOF_INT == 4)
#ifndef HAVE_INT32_T
typedef signed int int32_t;
#define HAVE_INT32_T
#endif
#ifndef HAVE_UINT32_T
typedef unsigned int uint32_t;
#define HAVE_UINT32_T
#endif
#ifndef UINT32_MAX
#define UINT32_MAX 0xffffffffu
#endif
#ifndef INT32_MAX
#define INT32_MAX 0x7fffffffu
#endif
#endif

#if (SIZEOF_LONG == 4)
#ifndef HAVE_INT32_T
typedef signed long int32_t;
#define HAVE_INT32_T
#endif
#ifndef HAVE_UINT32_T
typedef unsigned long uint32_t;
#define HAVE_UINT32_T
#ifndef UINT32_MAX
#define UINT32_MAX 0xfffffffful
#endif
#endif
#elif (SIZEOF_LONG == 8)
#ifndef HAVE_INT64_T
typedef signed long int64_t;
#define HAVE_INT64_T
#endif
#ifndef HAVE_UINT32_T
typedef unsigned long uint64_t;
#define HAVE_UINT32_T
#endif
#ifndef UINT64_MAX
#define UINT64_MAX 0xfffffffffffffffful
#endif
#endif

#if (SIZEOF_LONG_LONG == 8)
#ifndef HAVE_INT64_T
typedef signed long long int64_t;
#define HAVE_INT64_T
#endif
#ifndef HAVE_UINT64_T
typedef unsigned long long uint64_t;
#define HAVE_UINT64_T
#endif
#ifndef UINT64_MAX
#define UINT64_MAX 0xffffffffffffffffull
#endif
#ifndef INT64_MAX
#define INT64_MAX 0x7fffffffffffffffll
#endif
#endif

#if (SIZEOF___INT64 == 8)
#ifndef HAVE_INT64_T
typedef signed __int64 int64_t;
#define HAVE_INT64_T
#endif
#ifndef HAVE_UINT64_T
typedef unsigned __int64 uint64_t;
#define HAVE_UINT64_T
#endif
#ifndef UINT64_MAX
#define UINT64_MAX 0xffffffffffffffffui64
#endif
#ifndef INT64_MAX
#define INT64_MAX 0x7fffffffffffffffi64
#endif
#endif

#ifndef HAVE_SSIZE_T
#if SIZEOF_SIZE_T == 8
typedef int64_t ssize_t;
#elif SIZEOF_SIZE_T == 4
typedef int32_t ssize_t;
#else
#error "Can't define ssize_t."
#endif
#endif

#if (SIZEOF_VOID_P > 4 && SIZEOF_VOID_P <= 8)
#ifndef HAVE_INTPTR_T
typedef int64_t intptr_t;
#endif
#ifndef HAVE_UINTPTR_T
typedef uint64_t uintptr_t;
#endif
#elif (SIZEOF_VOID_P > 2 && SIZEOF_VOID_P <= 4)
#ifndef HAVE_INTPTR_T
typedef int32_t intptr_t;
#endif
#ifndef HAVE_UINTPTR_T
typedef uint32_t uintptr_t;
#endif
#else
#error "void * is either >8 bytes or <= 2.  In either case, I am confused."
#endif

#ifndef HAVE_INT8_T
#error "Missing type int8_t"
#endif
#ifndef HAVE_UINT8_T
#error "Missing type uint8_t"
#endif
#ifndef HAVE_INT16_T
#error "Missing type int16_t"
#endif
#ifndef HAVE_UINT16_T
#error "Missing type uint16_t"
#endif
#ifndef HAVE_INT32_T
#error "Missing type int32_t"
#endif
#ifndef HAVE_UINT32_T
#error "Missing type uint32_t"
#endif
#ifndef HAVE_INT64_T
#error "Missing type int64_t"
#endif
#ifndef HAVE_UINT64_T
#error "Missing type uint64_t"
#endif

/* This assumes a sane (2's-complement) representation.  But if you
 * aren't 2's complement, and you don't define LONG_MAX, then you're so
 * bizarre that I want nothing to do with you. */
#ifndef USING_TWOS_COMPLEMENT
#error "Seems that your platform doesn't use 2's complement arithmetic. Argh."
#endif
#ifndef LONG_MAX
#if (SIZEOF_LONG == 4)
#define LONG_MAX 0x7fffffffL
#elif (SIZEOF_LONG == 8)
#define LONG_MAX 0x7fffffffffffffffL
#else
#error "Can't define LONG_MAX"
#endif
#endif

#ifndef INT_MAX
#if (SIZEOF_INT == 4)
#define INT_MAX 0x7fffffffL
#elif (SIZEOF_INT == 8)
#define INT_MAX 0x7fffffffffffffffL
#else
#error "Can't define INT_MAX"
#endif
#endif

#ifndef UINT_MAX
#if (SIZEOF_INT == 2)
#define UINT_MAX 0xffffu
#elif (SIZEOF_INT == 4)
#define UINT_MAX 0xffffffffu
#elif (SIZEOF_INT == 8)
#define UINT_MAX 0xffffffffffffffffu
#else
#error "Can't define UINT_MAX"
#endif
#endif

#ifndef SHORT_MAX
#if (SIZEOF_SHORT == 2)
#define SHORT_MAX 0x7fff
#elif (SIZEOF_SHORT == 4)
#define SHORT_MAX 0x7fffffff
#else
#error "Can't define SHORT_MAX"
#endif
#endif

#ifndef TIME_MAX

#ifdef TIME_T_IS_SIGNED

#if (SIZEOF_TIME_T == SIZEOF_INT)
#define TIME_MAX ((time_t)INT_MAX)
#elif (SIZEOF_TIME_T == SIZEOF_LONG)
#define TIME_MAX ((time_t)LONG_MAX)
#elif (SIZEOF_TIME_T == 8)
#define TIME_MAX ((time_t)INT64_MAX)
#else
#error "Can't define (signed) TIME_MAX"
#endif

#else
/* Unsigned case */
#if (SIZEOF_TIME_T == 4)
#define TIME_MAX ((time_t)UINT32_MAX)
#elif (SIZEOF_TIME_T == 8)
#define TIME_MAX ((time_t)UINT64_MAX)
#else
#error "Can't define (unsigned) TIME_MAX"
#endif
#endif /* time_t_is_signed */
#endif /* ifndef(TIME_MAX) */

#ifndef SIZE_T_MAX
#if (SIZEOF_SIZE_T == 4)
#define SIZE_T_MAX UINT32_MAX
#elif (SIZEOF_SIZE_T == 8)
#define SIZE_T_MAX UINT64_MAX
#else
#error "Can't define SIZE_T_MAX"
#endif
#endif

/* Any size_t larger than this amount is likely to be an underflow. */
#define SIZE_T_CEILING (sizeof(char)<<(sizeof(size_t)*8 - 1))

#endif /* __sys_include__ */
