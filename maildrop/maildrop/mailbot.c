/*
** Copyright 2001-2010 Double Precision, Inc.
** See COPYING for distribution information.
*/

#include "config.h"
#include "dbobj.h"
#include "liblock/config.h"
#include "liblock/liblock.h"
#include "unicode/unicode.h"
#include "numlib/numlib.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#if HAVE_LOCALE_H
#include <locale.h>
#endif
#include <langinfo.h>
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include "rfc822/rfc822.h"
#include "rfc2045/rfc2045.h"
#include "rfc2045/rfc2045charset.h"
#include <sys/types.h>
#include "mywait.h"
#include <signal.h>
#if HAVE_SYSEXITS_H
#include <sysexits.h>
#endif

#ifndef EX_TEMPFAIL
#define EX_TEMPFAIL	75
#endif

static const char *recips=0;
static const char *dbfile=0;
static const char *charset;
static unsigned interval=1;
static char *sender;

struct header {
	struct header *next;
	char *buf;
} ;

static struct header *header_list;

static struct header *extra_headers=0;


void rfc2045_error(const char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(1);
}

static void usage()
{
	fprintf(stderr,
		"Usage: mailbot [ options ] [ $MAILER arg arg... ]\n"
		"\n"
		"    -t filename        - text autoresponse\n"
		"    -c charset         - text MIME character set (default %s)\n"
		"    -m filename        - text autoresponse with a MIME header\n"
		"    -r addr1,addr2...  - any 'addr' required in a To/Cc header\n",
		charset);

	fprintf(stderr,
		"    -e                 - Prefer replies to Errors-To: or Return-Path: instead\n"
		"                         of From:\n"
		"    -T type            - \"type\": reply, replyall, replydsn, forward, forwardatt\n"
		"    -N                 - Omit contents of the original message from replies\n"
		"    -F \"separator\"     - Set the forwarding separator\n"
		"    -S \"salutation\"    - Set salutation for replies\n"
		"    -d $pathname       - database to prevent duplicate autoresponses\n"
		"    -D x               - at least 'x' days before dupes (default: 1)\n");

	fprintf(stderr,
		"    -s subject         - Subject: on autoresponses\n"
		"    -A \"Header: stuff\" - Additional header on the autoresponse\n"
		"    -M recipient       - format \"replydsn\" as a DSN from 'recipient'\n"
		"    -fuser@domain      - Set responding address for replydsn\n"
		"    -f                 - Set responding address from $SENDER\n"
		"    -n                 - only show the resulting message, do not send it\n"
		"    $MAILER arg arg... - run $MAILER (sendmail) to mail the autoresponse\n"
		);

	exit(EX_TEMPFAIL);
}

static void read_headers(FILE *tmpfp)
{
	char buf[BUFSIZ];
	struct header **lasthdr= &header_list, *prevhdr=0;

	while (fgets(buf, sizeof(buf), tmpfp))
	{
		size_t l=strlen(buf);

		if (l > 0 && buf[l-1] == '\n')
			--l;
		if (l > 0 && buf[l-1] == '\r')
			--l;
		buf[l]=0;

		if (l == 0)
		{
			/* Eat rest of message from stdin */

			while (getc(stdin) != EOF)
				;
			break;
		}

		if (isspace((int)(unsigned char)buf[0]) && prevhdr)
		{
			if ( (prevhdr->buf=
			     realloc( prevhdr->buf,
				      strlen (prevhdr->buf)+2+strlen(buf)))
			     == NULL)
			{
				perror("malloc");
				exit(EX_TEMPFAIL);
			}
			strcat(strcat( prevhdr->buf, "\n"), buf);
		}
		else
		{
			if ((*lasthdr=(struct header *)
			     malloc(sizeof(struct header))) == NULL ||
			    ((*lasthdr)->buf=strdup(buf)) == NULL)
			{
				perror("malloc");
				exit(EX_TEMPFAIL);
			}

			prevhdr= *lasthdr;
			lasthdr= &(*lasthdr)->next;
		}
	}

	*lasthdr=NULL;
}

const char *hdr(const char *hdrname)
{
	struct header *h;
	size_t l=strlen(hdrname);

	for (h=header_list; h; h=h->next)
	{
		if (strncasecmp(h->buf, hdrname, l) == 0 &&
		    h->buf[l] == ':')
		{
			const char *p=h->buf+l+1;

			while (*p && isspace((int)(unsigned char)*p))
				++p;
			return (p);
		}
	}

	return ("");
}

/*
** Get the sender's address
*/

static void check_sender()
{
	const char *h=hdr("reply-to");
	struct rfc822t *t;
	struct rfc822a *a;

	if (!h || !*h)
		h=hdr("from");

	if (!h || !*h)
		exit(0);

	t=rfc822t_alloc_new(h, NULL, NULL);

	if (!t || !(a=rfc822a_alloc(t)))
	{
		perror("malloc");
		exit(EX_TEMPFAIL);
	}

	if (a->naddrs <= 0)
		exit (0);
	sender=rfc822_getaddr(a, 0);
	rfc822a_free(a);
	rfc822t_free(t);

	if (!sender || !*sender)
		exit(0);
}

/*
** Do not autorespond to DSNs
*/

static void check_dsn()
{
	static const char ct[]="multipart/report;";

	const char *p=hdr("content-type");

	if (strncasecmp(p, ct, sizeof(ct)-1) == 0)
		exit(0);

	p=hdr("precedence");

	if (strncasecmp(p, "junk", 4) == 0 ||
	    strncasecmp(p, "bulk", 4) == 0 ||
	    strncasecmp(p, "list", 4) == 0)
		exit(0);	/* Just in case */

	p=hdr("auto-submitted");

	if (*p && strcmp(p, "no"))
		exit(0);

	p=hdr("list-id");

	if (*p)
		exit(0);
}

/*
** Check for a required recipient
*/

static void check_recips()
{
	char *buf;
	struct rfc822t *t;
	struct rfc822a *a;
	struct header *h;

	if (!recips || !*recips)
		return;

	buf=strdup(recips);
	if (!buf)
	{
		perror("strdup");
		exit(EX_TEMPFAIL);
	}

	for (h=header_list; h; h=h->next)
	{
		int i;

		if (strncasecmp(h->buf, "to:", 3) &&
		    strncasecmp(h->buf, "cc:", 3))
			continue;

		t=rfc822t_alloc_new(h->buf+3, NULL, NULL);
		if (!t || !(a=rfc822a_alloc(t)))
		{
			perror("malloc");
			exit(EX_TEMPFAIL);
		}

		for (i=0; i<a->naddrs; i++)
		{
			char *p=rfc822_getaddr(a, i);
			char *q;

			strcpy(buf, recips);

			for (q=buf; (q=strtok(q, ", ")) != 0; q=0)
			{
				if (p && strcasecmp(p, q) == 0)
				{
					free(p);
					free(buf);
					rfc822a_free(a);
					rfc822t_free(t);
					return;
				}
			}

			free(p);
		}
		rfc822a_free(a);
		rfc822t_free(t);
	}
	free(buf);
	exit(0);
}

/*
** Check the dupe database.
*/

#ifdef DbObj
static void check_db()
{
	char *dbname;
	char *lockname;
	int lockfd;
	struct dbobj db;
	time_t now;
	char *sender_key, *p;

	size_t val_len;
	char *val;

	if (!dbfile || !*dbfile)
		return;

	sender_key=strdup(sender);
	dbname=malloc(strlen(dbfile)+ sizeof( "." DBNAME));
	lockname=malloc(strlen(dbfile)+ sizeof(".lock"));

	for (p=sender_key; *p; p++)
		*p=tolower((int)(unsigned char)*p);

	if (!dbname || !lockname || !sender)
	{
		perror("malloc");
		exit(EX_TEMPFAIL);
	}

	strcat(strcpy(dbname, dbfile), "." DBNAME);
	strcat(strcpy(lockname, dbfile), ".lock");

	lockfd=open(lockname, O_RDWR|O_CREAT, 0666);

	if (lockfd < 0 || ll_lock_ex(lockfd))
	{
		perror(lockname);
		exit(EX_TEMPFAIL);
	}

	dbobj_init(&db);

	if (dbobj_open(&db, dbname, "C") < 0)
	{
		perror(dbname);
		exit(EX_TEMPFAIL);
	}

	time(&now);

	val=dbobj_fetch(&db, sender_key, strlen(sender_key), &val_len, "");

	if (val)
	{
		time_t t;

		if (val_len >= sizeof(t))
		{
			memcpy(&t, val, sizeof(t));

			if (t >= now - interval * 60 * 60 * 24)
			{
				free(val);
				dbobj_close(&db);
				close(lockfd);
				exit(0);
			}
		}
		free(val);
	}

	dbobj_store(&db, sender_key, strlen(sender_key),
		    (void *)&now, sizeof(now), "R");
	dbobj_close(&db);
	close(lockfd);
}
#endif

static void opensendmail(int argn, int argc, char **argv)
{
	char **newargv;
	int i;

	if (argn >= argc)
	{
		static char *sendmail_argv[]={"sendmail", "-f", ""};

		argn=0;
		argc=3;
		argv=sendmail_argv;
	}

	newargv=(char **)malloc( sizeof(char *)*(argc-argn+1));
	if (!newargv)
	{
		perror("malloc");
		exit(EX_TEMPFAIL);
	}

	for (i=0; argn+i < argc; i++)
		newargv[i]=argv[argn+i];
	newargv[i]=0;
	signal(SIGCHLD, SIG_DFL);

	execvp(newargv[0], newargv);
	perror(newargv[0]);
	exit(EX_TEMPFAIL);
}

static struct rfc2045 *savemessage(FILE *tmpfp)
{
	struct rfc2045 *rfcp=rfc2045_alloc();
	char buf[BUFSIZ];
	int n;

	if (!rfcp)
	{
		perror("rfc2045_alloc");
		exit(1);
	}

	while ((n=fread(buf, 1, sizeof(buf), stdin)) > 0)
	{
		if (fwrite(buf, n, 1, tmpfp) != 1)
		{
			perror("fwrite(tempfile)");
			exit(1);
		}

		rfc2045_parse(rfcp, buf, n);
	}

	if (n < 0)
	{
		perror("tempfile");
		exit(1);
	}
	return rfcp;
}


struct mimeautoreply_s {
	struct rfc2045_mkreplyinfo info;
	FILE *outf;

	FILE *contentf;
};

static void mimeautoreply_write_func(const char *str, size_t cnt, void *ptr)
{
	if (cnt &&
	    fwrite(str, cnt, 1, ((struct mimeautoreply_s *)ptr)->outf) != 1)
	{
		perror("tmpfile");
		exit(1);
	}
}

static void mimeautoreply_writesig_func(void *ptr)
{
}

static int mimeautoreply_myaddr_func(const char *addr, void *ptr)
{
	return 0;
}

static void copy_headers(void *ptr)
{
	struct mimeautoreply_s *p=(struct mimeautoreply_s *)ptr;
	char buf[BUFSIZ];

	static const char ct[]="Content-Transfer-Encoding:";

	while (fgets(buf, sizeof(buf), p->contentf) != NULL)
	{
		if (buf[0] == '\n')
			break;

		if (strncasecmp(buf, ct, sizeof(ct)-1) == 0)
			continue;

		mimeautoreply_write_func(buf, strlen(buf), ptr);

		while (strchr(buf, '\n') == NULL)
		{
			if (fgets(buf, sizeof(buf), p->contentf) == NULL)
				break;

			mimeautoreply_write_func(buf, strlen(buf), ptr);
		}
	}
}

static void copy_body(void *ptr)
{
	struct mimeautoreply_s *p=(struct mimeautoreply_s *)ptr;
	char buf[BUFSIZ];

	while (fgets(buf, sizeof(buf), p->contentf) != NULL)
	{
		mimeautoreply_write_func(buf, strlen(buf), ptr);
	}
}

int main(int argc, char **argv)
{
	int argn;
	FILE *tmpfp;
	struct rfc2045 *rfcp;
	struct mimeautoreply_s replyinfo;
	const char *subj=0;
	const char *txtfile=0, *mimefile=0;
	const char *mimedsn=0;
	int nosend=0;
	const char *replymode="reply";
	int replytoenvelope=0;
	int donotquote=0;
	const char *forwardsep="--- Forwarded message ---";
	const char *replysalut="%F writes:";
	struct rfc2045src *src;

	setlocale(LC_ALL, "");
	charset=unicode_default_chset();

	sender=NULL;
	for (argn=1; argn < argc; argn++)
	{
		char optc;
		char *optarg;

		if (argv[argn][0] != '-')
			break;

		if (strcmp(argv[argn], "--") == 0)
		{
			++argn;
			break;
		}

		optc=argv[argn][1];
		optarg=argv[argn]+2;

		if (!*optarg)
			optarg=NULL;

		switch (optc) {
		case 'c':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			if (optarg && *optarg)
			{
				char *p=libmail_u_convert_tobuf("",
								optarg,
								libmail_u_ucs4_native,
								NULL);

				if (!p)
				{
					fprintf(stderr, "Unknown charset: %s\n",
						charset);
					exit(1);
				}
				free(p);
				charset=optarg;
			}
			continue;
		case 't':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			txtfile=optarg;
			continue;
		case 'm':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			mimefile=optarg;
			continue;
		case 'r':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			recips=optarg;
			continue;
		case 'M':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			mimedsn=optarg;
			continue;
		case 'd':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			dbfile=optarg;
			continue;
		case 'e':
			replytoenvelope=1;
			continue;
		case 'T':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			if (optarg && *optarg)
				replymode=optarg;
			continue;
		case 'N':
			donotquote=1;
			continue;
		case 'F':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			if (optarg && *optarg)
				forwardsep=optarg;
			continue;
		case 'S':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			if (optarg && *optarg)
				replysalut=optarg;
			continue;
		case 'D':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			interval=optarg ? atoi(optarg):1;
			continue;
		case 'A':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			if (optarg)
			{
				struct header **h;

				for (h= &extra_headers; *h;
				     h= &(*h)->next)
					;

				if ((*h=malloc(sizeof(struct header))) == 0 ||
				    ((*h)->buf=strdup(optarg)) == 0)
				{
					perror("malloc");
					exit(EX_TEMPFAIL);
				}
				(*h)->next=0;
			}
			continue;
		case 's':
			if (!optarg && argn+1 < argc)
				optarg=argv[++argn];

			subj=optarg;
			continue;

		case 'f':
			if (optarg && *optarg)
			{
				sender=strdup(optarg);
			}
			else
			{
				sender=getenv("SENDER");
				if (!sender)
					continue;
				sender=strdup(sender);
			}
			if (sender == NULL)
			{
				perror("malloc");
				exit(1);
			}
			continue;
		case 'n':
			nosend=1;
			continue;
		default:
			usage();
		}
	}

	if (!txtfile && !mimefile)
		usage();

	if (txtfile && mimefile)
		usage();

	tmpfp=tmpfile();

	if (!tmpfp)
	{
		perror("tmpfile");
		exit(1);
	}

	rfcp=savemessage(tmpfp);

	if (fseek(tmpfp, 0L, SEEK_SET) < 0)
	{
		perror("fseek(tempfile)");
		exit(1);
	}

	read_headers(tmpfp);

	if (sender == NULL || *sender == 0)
		check_sender();

	check_dsn();
	check_recips();
#ifdef DbObj
	check_db();
#endif

	src=rfc2045src_init_fd(fileno(tmpfp));

	memset(&replyinfo, 0, sizeof(replyinfo));

	replyinfo.info.src=src;
	replyinfo.info.rfc2045partp=rfcp;
	replyinfo.info.voidarg=&replyinfo;

	replyinfo.info.write_func=mimeautoreply_write_func;

	replyinfo.info.writesig_func=mimeautoreply_writesig_func;

	replyinfo.info.myaddr_func=mimeautoreply_myaddr_func;

	replyinfo.info.replymode=replymode;
	replyinfo.info.replytoenvelope=replytoenvelope;
	replyinfo.info.donotquote=donotquote;

	replyinfo.info.replysalut=replysalut;
	replyinfo.info.forwarddescr="Forwarded message";
	replyinfo.info.mailinglists="";
	replyinfo.info.charset=charset;
	replyinfo.info.subject=subj;
	replyinfo.info.forwardsep=forwardsep;

	if (mimedsn && *mimedsn)
	{
		replyinfo.info.dsnfrom=mimedsn;
		replyinfo.info.replymode="replydsn";
	}

	if (mimefile)
	{
		if ((replyinfo.contentf=fopen(mimefile, "r")) == NULL)
		{
			perror(mimefile);
			exit(1);
		}

		{
			struct rfc2045 *rfcp=rfc2045_alloc();
			static const char mv[]="Mime-Version: 1.0\n";
			char buf[BUFSIZ];
			int l;
			const char *content_type;
			const char *content_transfer_encoding;
			const char *charset;

			rfc2045_parse(rfcp, mv, sizeof(mv)-1);

			while ((l=fread(buf, 1, sizeof(buf), replyinfo.contentf)
				) > 0)
			{
				rfc2045_parse(rfcp, buf, l);
			}

			if (l < 0 ||
			    fseek(replyinfo.contentf, 0L, SEEK_SET) < 0)
			{
				perror(mimefile);
				exit(1);
			}

			rfc2045_mimeinfo(rfcp, &content_type,
					 &content_transfer_encoding,
					 &charset);

			if (strcasecmp(content_type, "text/plain"))
			{
				fprintf(stderr,
					"%s must specify text/plain MIME type\n",
					mimefile);
				exit(1);
			}
			{
				char *p=NULL;

				if (charset)
					p=libmail_u_convert_tobuf("",
								  charset,
								  libmail_u_ucs4_native,
								  NULL);

				if (!p)
				{
					fprintf(stderr, "Unknown charset in %s\n",
						mimefile);
					exit(1);
				}
				free(p);
				replyinfo.info.charset=strdup(charset);
			}
			rfc2045_free(rfcp);
		}
		replyinfo.info.content_set_charset=copy_headers;
		replyinfo.info.content_specify=copy_body;
	}
	else if (txtfile)
	{
		if ((replyinfo.contentf=fopen(txtfile, "r")) == NULL)
		{
			perror(mimefile);
			exit(1);
		}
		replyinfo.info.content_specify=copy_body;
	}

	if (replyinfo.contentf)
		fcntl(fileno(replyinfo.contentf), F_SETFD, FD_CLOEXEC);

	if (nosend)
		replyinfo.outf=stdout;
	else
	{
		replyinfo.outf=tmpfile();

		if (replyinfo.outf == NULL)
		{
			perror("tmpfile");
			exit(1);
		}
	}

	{
		struct header *h;

		for (h=extra_headers; h; h=h->next)
			fprintf(replyinfo.outf, "%s\n", h->buf);
	}
	fprintf(replyinfo.outf,
		"Precedence: junk\n"
		"Auto-Submitted: auto-replied\n");

	if (rfc2045_makereply(&replyinfo.info) < 0 ||
	    fflush(replyinfo.outf) < 0 || ferror(replyinfo.outf) ||
	    (!nosend &&
	     (
	      fseek(replyinfo.outf, 0L, SEEK_SET) < 0 ||
	      (close(0), dup(fileno(replyinfo.outf))) < 0)
	     ))
	{
		perror("tempfile");
		exit(1);
	}
	fclose(replyinfo.outf);
	fcntl(0, F_SETFD, 0);

	rfc2045_free(rfcp);
	rfc2045src_deinit(src);

	if (!nosend)
		opensendmail(argn, argc, argv);
	return (0);
}
