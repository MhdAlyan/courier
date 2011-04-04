/*
** Copyright 1998 - 1999 Double Precision, Inc.
** See COPYING for distribution information.
*/

#include	"comconfig.h"
#include	"courier.h"
#include	<stdlib.h>
#include	<stdio.h>

int config_retrybeta()
{
char	*p=config_read1l("retrybeta");
int	n=3;

	if (p)
	{
		n=atoi(p);
		free(p);
	}
	return (n);
}

int config_retrymaxdelta()
{
char	*p=config_read1l("retrymaxdelta");
int	n=3;

	if (p)
	{
		n=atoi(p);
		free(p);
	}
	return (n);
}
