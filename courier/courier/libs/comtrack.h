#ifndef	comtrack_h
#define	comtrack_h

/*
** Copyright 2005 Double Precision, Inc.
** See COPYING for distribution information.
*/

#if	HAVE_CONFIG_H
#include	"config.h"
#endif
#include	<time.h>

#ifdef	__cplusplus
extern "C" {
#endif


#define TRACK_NHOURS 2

void trackpurge();

int track_find(const char *address, time_t *timestamp);
#define TRACK_ADDRACCEPTED 'A'
#define TRACK_ADDRDEFERRED 'D'
#define TRACK_ADDRFAILED   'F'
#define TRACK_NOTFOUND 0

void track_save(const char *address, int status);

int track_read(int (*cb_func)(time_t timestamp, int status,
			      const char *address, void *voidarg),
	       void *voidarg);

#ifdef	__cplusplus
}
#endif
#endif
