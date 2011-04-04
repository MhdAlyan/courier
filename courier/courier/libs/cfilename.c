/*
** Copyright 1998 - 1999 Double Precision, Inc.
** See COPYING for distribution information.
*/

#include	"courier.h"
#include	"sysconfdir.h"

#include	<stdlib.h>
#include	<string.h>

char	*config_localfilename(const char *p)
{
char	*c=courier_malloc(sizeof(SYSCONFDIR "/")+strlen(p));

	return (strcat(strcpy(c, SYSCONFDIR "/"), p));
}
