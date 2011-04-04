/*
** Copyright 1998 - 2005 Double Precision, Inc.
** See COPYING for distribution information.
*/

#include	"config.h"
#include	"courier.h"
#include	"rfc1035/config.h"
#include	"rfc1035/rfc1035.h"
#include	"rfc1035/rfc1035mxlist.h"
#include	"rfc1035/rfc1035_res.h"
#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<arpa/inet.h>


static void setns(const char *p)
{
#if	RFC1035_IPV6
struct in6_addr ia[4];
#else
struct in_addr ia[4];
#endif
int	i=0;
char	*q=malloc(strlen(p)+1), *r;

	strcpy(q, p);
	for (r=q; (r=strtok(r, ", ")) != 0; r=0)
		if (i < 4)
			if (rfc1035_aton(r, &ia[i]) == 0)
				++i;

	rfc1035_init_ns(&rfc1035_default_resolver, ia, i);
}

int main(int argc, char **argv)
{
int	argn;
const char *q_name;
struct rfc1035_mxlist *mxlist, *p;

	argn=1;
	srand(time(NULL));
	while (argn < argc)
	{
		if (argv[argn][0] == '@')
		{
			setns(argv[argn]+1);
			++argn;
			continue;
		}

		break;
	}

	if (argn >= argc)	exit(0);

	q_name=argv[argn++];

	switch (rfc1035_mxlist_create(&rfc1035_default_resolver,
		q_name, &mxlist))	{
	case	RFC1035_MX_OK:
		break;
	case	RFC1035_MX_SOFTERR:
		printf("Soft error.\n");
		exit(0);
	case	RFC1035_MX_HARDERR:
		printf("Hard error.\n");
		exit(0);
	case	RFC1035_MX_INTERNAL:
		printf("Internal error.\n");
		exit(0);
	case	RFC1035_MX_BADDNS:
		printf("Bad DNS records (recursive CNAME).\n");
		exit(0);
	}

	printf("Domain %s:\n", q_name);
	for (p=mxlist; p; p=p->next)
	{
	RFC1035_ADDR	addr;
	char	buf[RFC1035_NTOABUFSIZE];

		if (rfc1035_sockaddrip(&p->address, sizeof(p->address),
			&addr)<0)
			continue;
		rfc1035_ntoa(&addr, buf);

		printf("Relay: %s, Priority: %d, Address: %s%s%s\n",
		       p->hostname,
		       p->priority, buf,
		       config_islocal(p->hostname, NULL) ? " [ LOCAL ]":"",
		       strcmp(p->hostname, buf) ? "":" [ ERROR ]");
	}

	rfc1035_mxlist_free(mxlist);
	return (0);
}
