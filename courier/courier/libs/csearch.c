/*
** Copyright 1998 - 1999 Double Precision, Inc.
** See COPYING for distribution information.
*/

#include	"courier.h"
#include	<stdlib.h>
#if	HAVE_UNISTD_H
#include	<unistd.h>
#endif

/*
	Return pathname to the requested configuration file.

	Search first in config/local, if not found, assume it's in config.
*/

char	*config_search(const char *p)
{
char	*c=config_localfilename(p);

	return (c);
}
