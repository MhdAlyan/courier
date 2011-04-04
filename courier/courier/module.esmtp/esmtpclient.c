/*
** Copyright 1998 - 2010 Double Precision, Inc.
** See COPYING for distribution information.
*/

#if	HAVE_CONFIG_H
#include	"config.h"
#endif
#include	"soxwrap/soxwrap.h"
#include	"soxwrap/sconnect.h"
#include	"courier.h"
#include	"smtproutes.h"
#include	"localstatedir.h"
#include	"moduledel.h"
#include	"comctlfile.h"
#include	"comreadtime.h"
#include	"comqueuename.h"
#include	"maxlongsize.h"
#include	"comverp.h"
#include	"rfc1035/rfc1035.h"
#include	"rfc1035/rfc1035mxlist.h"
#include	"rfc822.h"
#include	"rfc2045/rfc2045.h"
#include	"numlib/numlib.h"
#include	"tcpd/spipe.h"
#include	"tcpd/tlsclient.h"
#include	<courierauthsaslclient.h>

#define	mybuf_readfunc	sox_read
#include	"mybuf.h"
#include	"rw.h"
#include	"esmtpconfig.h"

#include	<sys/types.h>
#include	<sys/uio.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/wait.h>
#if	HAVE_NETINET_TCP_H
#include	<netinet/tcp.h>
#endif
#if	HAVE_UTIME
#include	<utime.h>
#endif


#include	<ctype.h>
#include	<string.h>
#if HAVE_SYS_STAT_H
#include	<sys/stat.h>
#endif
#if HAVE_FCNTL_H
#include	<fcntl.h>
#endif

#if TIME_WITH_SYS_TIME
#include	<sys/time.h>
#include	<time.h>
#else
#if HAVE_SYS_TIME_H
#include	<sys/time.h>
#else
#include	<time.h>
#endif
#endif
#if HAVE_UNISTD_H
#include	<unistd.h>
#endif
#include	<stdio.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<errno.h>

static time_t esmtpkeepaliveping;
static time_t connect_timeout;
static time_t cmd_timeout;
static time_t helo_timeout;
static time_t quit_timeout;
static time_t data_timeout;

#ifdef	TCP_CORK

static int esmtp_cork;
static int corked;

#define	cork(n) \
	{\
	int flag=(n);\
\
		if (esmtp_cork && sockfd >= 0 && corked != flag) \
		{ \
			setsockopt(sockfd, SOL_TCP, TCP_CORK, &flag, \
							sizeof(flag));\
		} \
		corked=flag;\
	}
#else
#define	cork(n)
#endif

static time_t net_timeout;
	/*
	** If all MXs are unreachable, wait until this tick before attempting
	** any new connections.
	*/
static int net_error;

static void sendesmtp(struct moduledel *, struct ctlfile *);
static const char *readline();
static int sockfd;
static void quit();
static int dowritestr(const char *);
static int writeflush();
static void sock_timeout(unsigned);

#define	ISFINALLINE(p)	( isdigit((int)(unsigned char)p[0]) && \
			isdigit((int)(unsigned char)p[1]) && \
			isdigit((int)(unsigned char)p[2]) \
				&& p[3] == ' ')

extern struct rw_list *esmtp_rw_install(const struct rw_install_info *);
extern int isloopback(const char *);

static void (*rewrite_func)(struct rw_info *, void (*)(struct rw_info *));

void rfc2045_error(const char *p)
{
	clog_msg_start_err();
	clog_msg_str(p);
	clog_msg_send();
	_exit(1);
}

/* We get here as a new child process of the courieresmtp driver */

void esmtpchild(unsigned childnum)
{
struct	moduledel *del;
struct	ctlfile	ctf;
unsigned long mypid=(unsigned long)getpid();

	signal(SIGPIPE, SIG_IGN);
	srand(time(NULL));
	rw_init_courier("esmtp");
	rewrite_func=rw_search_transport("esmtp")->rw_ptr->rewrite;

	if (chdir(courierdir()))
		clog_msg_errno();
	sockfd= -1;

	esmtpkeepaliveping=config_time_esmtpkeepaliveping();
	cmd_timeout=config_time_esmtptimeout();
	connect_timeout=config_time_esmtpconnect();
	cmd_timeout=config_time_esmtptimeout();
	helo_timeout=config_time_esmtphelo();
	data_timeout=config_time_esmtpdata();
	quit_timeout=config_time_esmtpquit();

	net_timeout=0;

#ifdef	TCP_CORK

	{
	const char *p=getenv("ESMTP_CORK");

		esmtp_cork=p ? atoi(p):0;
		corked=0;
	}

#endif

	/* Retrieve delivery request until courieresmtp closes the pipe */

	while ((del=module_getdel()) != 0)
	{
	fd_set	fdr;
	struct	timeval	tv;
	const char *p;

#if 0
		clog_msg_start_info();
		clog_msg_str("Process ");
		clog_msg_uint(getpid());
		clog_msg_str(" ready to be grabbed.");
		clog_msg_send();
		sleep(60);
#endif

		/*
		** Open the message control file, send the message, close
		** the control file, we're done.
		*/

		if (ctlfile_openi(del->inum, &ctf, 0) == 0)
		{
			sendesmtp(del, &ctf);
			ctlfile_close(&ctf);
		}
		{
		char	pidbuf[NUMBUFSIZE];

			printf("%u %s\n", childnum, libmail_str_pid_t(mypid, pidbuf));
			fflush(stdout);
		}

		/*
		** While waiting for the next message, push a RSET every
		** so-so seconds
		*/

		while (esmtpkeepaliveping && sockfd >= 0)
		{
			FD_ZERO(&fdr);
			FD_SET(0, &fdr);
			tv.tv_sec=esmtpkeepaliveping;
			tv.tv_usec=0;

			if ( sox_select(1, &fdr, 0, 0, &tv) > 0)
				break;
			sock_timeout(data_timeout);
			if (dowritestr("RSET\r\n") || writeflush())
				break;

			while ( (p=readline()) != 0 && !ISFINALLINE(p))
				;

			if (p == 0)
			{
				quit();
				break;
			}
		}
	}
	if (sockfd >= 0)
		quit();
}

static RFC1035_ADDR sockfdaddr;
static char *sockfdaddrname=0;
static char *auth_key=0;
static struct mybuf sockbuf;
static char writebuf[BUFSIZ];
static char *writebufptr;
static unsigned writebufleft;
static time_t	timeout_time;
static char socklinebuf[sizeof(sockbuf.buffer)+1];
static unsigned socklinesize;
static char *host;
static char *authsasllist=0;
static int is_secure_connection=0;
static int smtproutes_flags=0;

static int hasdsn, haspipelining, has8bitmime, hasverp, hassize, hasexdata,
	hascourier, hasstarttls, hassecurity_starttls;

static void hard_error(struct moduledel *, struct ctlfile *, const char *);
static void soft_error(struct moduledel *, struct ctlfile *, const char *);
static void connect_error(struct moduledel *, struct ctlfile *);

static int hello(struct moduledel *, struct ctlfile *);
static int starttls(struct moduledel *, struct ctlfile *, const char *);
static int authclient(struct moduledel *, struct ctlfile *, const char *);

static int rset(struct moduledel *, struct ctlfile *);
static int smtpreply(const char *, struct moduledel *, struct ctlfile *, int);
static int dowrite(const char *, unsigned);
static void push(struct moduledel *, struct ctlfile *);

static const char *want_security(struct ctlfile *ctf)
{
	const char *sec;

	if (smtproutes_flags & ROUTE_NOSECURITY)
		return (0);

	if (smtproutes_flags & ROUTE_STARTTLS)
		return ("STARTTLS");

	sec=ctlfile_security(ctf);

	if (!sec)
		return (0);
	if (strcmp(sec, "STARTTLS") == 0)
		return (sec);
	return (0);
}

static int get_sourceaddr(int af,
			  const RFC1035_ADDR *dest_addr,
			  RFC1035_NETADDR *addrbuf,
			  const struct sockaddr **addrptr, int *addrptrlen)
{
	int rc;
	RFC1035_ADDR in;
	const char *buf=getenv(
#if RFC1035_IPV6

			       !IN6_IS_ADDR_V4MAPPED(dest_addr)
			       ? "SOURCE_ADDRESS_IPV6":
#endif
			       "SOURCE_ADDRESS");

	if (buf && strcmp(buf, "0")) {
		rc = rfc1035_aton(buf, &in);
		if (rc != 0)
			return rc;
	} else
		in = RFC1035_ADDRANY;

	rc = rfc1035_mkaddress(af, addrbuf, &in, htons(0),
			addrptr, addrptrlen);
	if (rc != 0)
		return rc;

	return 0;
}

static int backscatter(const char *src)
{
	char buf[1024];
	const char *env;
	char *p;

	buf[0]=0;

	env=getenv("ESMTP_BLOCKBACKSCATTER");

	strncat(buf, env ? env:"", 1000);

	for (p=buf; (p=strtok(p, ",")); p=NULL)
	{
		if (strcmp(p, src) == 0)
			return 1;
	}
	return 0;
}

/* Attempt to deliver a message */

static void sendesmtp(struct moduledel *del, struct ctlfile *ctf)
{
	char *smtproute;
	int cn;

	if (!host)
		host=strcpy(courier_malloc(strlen(del->host)+1), del->host);

	/* Sanity check */

	if (strcmp(host, del->host))
	{
		clog_msg_start_err();
		clog_msg_str("Internal failure in courieresmtp - daemon mixup.");
		clog_msg_send();
		_exit(1);
	}

	/* If we're connected, send a RSET to make sure the socket is working */

	if (sockfd >= 0)
	{
		sock_timeout(helo_timeout);
		if (dowritestr("RSET\r\n") == 0 && writeflush() == 0)
		{
			if (smtpreply("RSET", del, ctf, -1))
			{
				quit();
				return;
			}
		}
	}

	if (sockfd < 0 && net_timeout)
	{
	time_t	t;

		time (&t);
		if (t < net_timeout)
		{
			errno=net_error;
			if (!errno)	errno=ENETDOWN;
			connect_error(del, ctf);
			return;
		}
		net_timeout=0;
	}

	if ((cn=ctlfile_searchfirst(ctf, COMCTLFILE_MSGSOURCE)) >= 0 &&
	    backscatter(ctf->lines[cn]+1))
	{
		int i;

		for (i=0; i<del->nreceipients; i++)
		{
			ctlfile_append_connectioninfo(ctf,
						      (unsigned)
						      atol(del->receipients
							   [i*2]),
						      COMCTLFILE_DELINFO_REPLYTYPE,
						      "smtp");

			ctlfile_append_connectioninfo(ctf,
						      (unsigned)
						      atol(del->receipients
							   [i*2]),
						      COMCTLFILE_DELINFO_REPLY,
						      "250 Backscatter bounce dropped.");

			ctlfile_append_reply(ctf,
					     (unsigned)atol( del->receipients[i*2]),
					     "delivered: backscatter bounce dropped",
					     COMCTLFILE_DELSUCCESS_NOLOG,
					     (hasdsn ? "":" r"));
		}
		return;
	}

	/*
	** If the message wants a secured connection, and the current
	** connection has not been secured, close it, so it can be reopened.
	*/

	smtproute=smtproutes(host, &smtproutes_flags);

	if (sockfd >= 0 && want_security(ctf) && !is_secure_connection)
		quit();

	if (sockfd < 0)	/* First time, connect to a server */
	{
		struct rfc1035_mxlist *mxlist, *p, *q;
		int static_route= smtproute != NULL;

		errno=0;	/* Detect network failures */

		if (auth_key)
			free(auth_key);

		auth_key=strdup(smtproute ? smtproute:host);

		if (!auth_key)
			clog_msg_errno();

		rfc1035_init_resolv(&rfc1035_default_resolver);
		switch (rfc1035_mxlist_create(&rfc1035_default_resolver,
			auth_key, &mxlist))	{
		case RFC1035_MX_OK:
			break;
		case RFC1035_MX_HARDERR:
			if (smtproute)	free(smtproute);
			hard_error(del, ctf, "No such domain.");
			return;
		case RFC1035_MX_BADDNS:
			if (smtproute)	free(smtproute);
			hard_error(del, ctf,
				"This domain's DNS violates RFC 1035.");
			return;
		default:
			if (smtproute)	free(smtproute);
			soft_error(del, ctf, "DNS lookup failed.");

			if (errno)
			{
				net_error=errno;
				time (&net_timeout);
				net_timeout += config_time_esmtpdelay();
			}
			return;
		}
		if (smtproute)	free(smtproute);

		/* Check for broken MX records - BOFH */

		q=0;	/* Also see if I'm in the MX list */

		for (p=mxlist; p; p=p->next)
		{
		RFC1035_ADDR    addr;
		char    buf[RFC1035_NTOABUFSIZE];

			if (rfc1035_sockaddrip(&p->address,
					sizeof(p->address), &addr))
				continue;

			rfc1035_ntoa(&addr, buf);
			if (strcmp(buf, p->hostname) == 0)
			{
				hard_error(del, ctf,
					"This domain's DNS violates RFC 1035.");
				rfc1035_mxlist_free(mxlist);
				return;
			}
		
			if (!q && !static_route &&
			    (config_islocal(p->hostname, 0)
			     || isloopback(buf)))
				q=p;
		}

		if (q && q->priority == mxlist->priority)
		{
			hard_error(del, ctf, "configuration error: mail loops back to myself (MX problem).");
			rfc1035_mxlist_free(mxlist);
			return;
		}

		/* Ok, try each MX server until we get through */

		for (p=mxlist; p; p=p->next)
		{
		RFC1035_ADDR addr;
		int	port;
		int	af;
		RFC1035_NETADDR addrbuf, saddrbuf;
		const struct sockaddr *addrptr, *saddrptr;
		int	addrptrlen, saddrptrlen;

			if (q && q->priority == p->priority)
				break;
			/*
			** We're a backup MX for this domain, ignore MXs
			** with same, or higher, priority than us
			*/

			if (rfc1035_sockaddrip(&p->address,
				sizeof(p->address), &addr) ||
				rfc1035_sockaddrport(&p->address,
				sizeof(p->address), &port))
				continue;
 
			sockfdaddr=addr;
			if (sockfdaddrname)	free(sockfdaddrname);
			sockfdaddrname=strcpy(
				courier_malloc(strlen(p->hostname)+1),
				p->hostname);	/* Save this for later */

			is_secure_connection=0;
			if ((sockfd=rfc1035_mksocket(SOCK_STREAM, 0, &af))
					>= 0 &&
			    rfc1035_mkaddress(af, &addrbuf, &addr, port,
					      &addrptr, &addrptrlen) == 0 &&
			    get_sourceaddr(af, &addr, &saddrbuf, &saddrptr,
					   &saddrptrlen) == 0 &&
			    rfc1035_bindsource(sockfd, saddrptr,
					       saddrptrlen) == 0 &&
			    s_connect(sockfd, addrptr, addrptrlen,
				      connect_timeout) == 0)
			{
				/*
				** If we're connected, make sure EHLO or HELO
				** is cool, before blessing the connection.
				*/

			int	rc=hello(del, ctf);

				if (rc == 0)
				{
					if (hasstarttls && starttls(del, ctf,
						p->hostname))
					{
						sox_close(sockfd);
						return;
					}
					if (authclient(del, ctf, auth_key))
					{
						sox_close(sockfd);
						return;
					}
					break;
				}
				quit();	/* We don't want to talk to him */
				if (rc < 0)
					return;	/* HELO failed, perm error */
			}
			if (sockfd >= 0)
				sox_close(sockfd);
			sockfd= -1;

#if 0
			if (p->next && p->priority == p->next->priority &&
				strcmp(p->hostname, p->next->hostname) == 0)
			{
				continue; /* Another IP address for same MX */
			}

			/* Skip other MX records with the same priority */
			while (p->next && p->priority == p->next->priority)
				p=p->next;
#endif
		}

		rfc1035_mxlist_free(mxlist);
		if (sockfd < 0)	/* Couldn't find an active server */
		{
			net_error=errno;
			connect_error(del, ctf);
			time (&net_timeout);
			net_timeout += config_time_esmtpdelay();
			return;
		}
	}
	else
	{
		if (smtproute)
			free(smtproute);
	}

	/*
	** Ok, we now have a connection.  We want to call push() to deliver
	** this message, but if the VERP flag is set but the remote server
	** does not grok VERPs, we need to do a song-n-dance routine.
	*/

	if (hasverp || ctlfile_searchfirst(ctf, COMCTLFILE_VERP) < 0)
	{
		push(del, ctf);	/* ... but not this time */
		return;
	}

	/*
	** Ok, so what we do is to call push() individually for each
	** recipient, manually munging the return address each time, and
	** fudging the delivery record setting it for that one recipient
	** only.
	*/

	{
	unsigned i;
	unsigned real_recip=del->nreceipients;

		del->nreceipients=1;
		for (i=0; i<real_recip; i++, del->receipients += 2)
		{
		char	*verp_sender;

			if (i && sockfd >= 0)	/* Call RSET in between */
			{
				if (rset(del, ctf))
				{
					quit();
					continue;
				}
			}
			if (sockfd < 0)
			{
				connect_error(del, ctf);
				continue;
			}

			verp_sender=verp_getsender(ctf, del->receipients[1]);

			del->sender=verp_sender;
			push(del, ctf);
			free(verp_sender);
		}
	}
}

/* Record a permanent failure for one, or all, recipients */

static void hard_error1(struct moduledel *del, struct ctlfile *ctf,
		const char *msg, int n)
{
unsigned        i;

	if (n >= 0)
		ctlfile_append_reply(ctf,
			(unsigned)atol(del->receipients[n*2]), msg,
			COMCTLFILE_DELFAIL, 0);
	else for (i=0; i<del->nreceipients; i++)
		ctlfile_append_reply(ctf,
			(unsigned)atol(del->receipients[i*2]), msg,
			COMCTLFILE_DELFAIL, 0);
}

static void hard_error(struct moduledel *del, struct ctlfile *ctf,
		const char *msg)
{
	hard_error1(del, ctf, msg, -1);
}

/* Record a temporary failure for one, or all, the recipients */

static void soft_error1(struct moduledel *del, struct ctlfile *ctf,
	const char *msg, int n)
{
unsigned        i;

	if (n >= 0)
		ctlfile_append_reply(ctf,
			(unsigned)atol(del->receipients[n*2]), msg,
			COMCTLFILE_DELDEFERRED, 0);
	else for (i=0; i<del->nreceipients; i++)
		ctlfile_append_reply(ctf,
			(unsigned)atol(del->receipients[i*2]), msg,
			COMCTLFILE_DELDEFERRED, 0);
}

static void soft_error(struct moduledel *del, struct ctlfile *ctf,
	const char *msg)
{
	soft_error1(del, ctf, msg, -1);
}

static void connection_closed(struct moduledel *del, struct ctlfile *ctf)
{
	soft_error(del, ctf, "Connection unexpectedly closed by remote host.");
}

/* Record an SMTP error for all the recipients */

static void smtp_error1(struct moduledel *del, struct ctlfile *ctf,
	const char *msg, int n)
{
	if (*msg == '5')
		hard_error1(del, ctf, msg, n);
	else
		soft_error1(del, ctf, msg, n);
}

static void smtp_error(struct moduledel *del, struct ctlfile *ctf,
	const char *msg)
{
	smtp_error1(del, ctf, msg, -1);
}


/* Record our peer in the message's control file, for error messages */

static void sockipname(char *buf)
{
	rfc1035_ntoa( &sockfdaddr, buf);

#if	RFC1035_IPV6

	if (IN6_IS_ADDR_V4MAPPED(&sockfdaddr))
	{
	char	*p, *q;

		if ((p=strrchr(buf, ':')) != 0)
		{
			++p;
			q=buf;
			while ( (*q++ = *p++ ) )
				;
		}
	}
#endif
}

static void talking2(struct moduledel *del, struct ctlfile *ctf, int n)
{
char	buf[RFC1035_NTOABUFSIZE];
unsigned i;
char	*p;

	sockipname(buf);
	p=courier_malloc(strlen(sockfdaddrname)+strlen(buf)+
		sizeof(" []"));
	strcat(strcat(strcat(strcpy(p, sockfdaddrname), " ["),
		buf), "]");

	if (n >= 0)
		ctlfile_append_connectioninfo(ctf,
			(unsigned)atol(del->receipients[n*2]),
			COMCTLFILE_DELINFO_PEER, p);
	else for (i=0; i<del->nreceipients; i++)
		ctlfile_append_connectioninfo(ctf,
			(unsigned)atol(del->receipients[i*2]),
			COMCTLFILE_DELINFO_PEER, p);
	free(p);
}

static void talking(struct moduledel *del, struct ctlfile *ctf)
{
	talking2(del, ctf, -1);
}

/* TCP/IP error */

static void connect_error1(struct moduledel *del, struct ctlfile *ctf, int n)
{
#if	HAVE_STRERROR

	if (errno)
		soft_error1(del, ctf, strerror(errno), n);
	else
#endif
		soft_error1(del, ctf, "Connection closed by remote host.", n);
}

static void connect_error(struct moduledel *del, struct ctlfile *ctf)
{
	connect_error1(del, ctf, -1);
}

/* Log reply received */

static void smtp_msg(struct moduledel *del, struct ctlfile *ctf)
{
unsigned	i;

	for (i=0; i<del->nreceipients; i++)
		ctlfile_append_connectioninfo(ctf,
			(unsigned)atol(del->receipients[i*2]),
			COMCTLFILE_DELINFO_REPLYTYPE, "smtp");
}

static void reply(struct moduledel *del, struct ctlfile *ctf, const char *msg)
{
unsigned        i;

	for (i=0; i<del->nreceipients; i++)
		ctlfile_append_connectioninfo(ctf,
			(unsigned)atol(del->receipients[i*2]),
			COMCTLFILE_DELINFO_REPLY, msg);
}

/* Log the command sent to remote server */

static void sent(struct moduledel *del, struct ctlfile *ctf, const char *msg)
{
unsigned        i;

	for (i=0; i<del->nreceipients; i++)
		ctlfile_append_connectioninfo(ctf,
			(unsigned)atol(del->receipients[i*2]),
				COMCTLFILE_DELINFO_SENT, msg);
}

/***************************************************************************

  Socket stuff.  All socket operations have a timeout which is set separately,
  then we wait for the socket to be ready for reading or writing, then
  closing the socket if the timeout expires before the socket is ready.

***************************************************************************/

/* Set the timeout */

static void sock_timeout(unsigned nsecs)
{
	time(&timeout_time);
	timeout_time += nsecs;
}

/* Wait for either a response, or availability for write, until we time out */

static void wait_rw(int *waitr, int *waitw)
{
fd_set	fdr, fdw;
struct	timeval	tv;
time_t	current_time;

	time( & current_time );
	if (waitr)	*waitr=0;
	if (waitw)	*waitw=0;

	if (current_time >= timeout_time || sockfd < 0)
	{
		errno=ETIMEDOUT;
		if (sockfd >= 0)
			sox_close(sockfd);
		sockfd= -1;
		return;
	}

	FD_ZERO(&fdr);
	FD_ZERO(&fdw);

	if (waitr)
		FD_SET(sockbuf.fd, &fdr);

	if (waitw)
		FD_SET(sockbuf.fd, &fdw);

	tv.tv_sec= timeout_time - current_time;
	tv.tv_usec=0;

	if ( sox_select(sockbuf.fd+1, &fdr, &fdw, 0, &tv) > 0)
	{
		if (waitw && FD_ISSET(sockbuf.fd, &fdw))
			*waitw=1;
		if (waitr && FD_ISSET(sockbuf.fd, &fdr))
			*waitr=1;
		return;
	}

	errno=ETIMEDOUT;
	sox_close(sockfd);
	sockfd= -1;
}

static int wait_read()
{
int	flag;

	wait_rw(&flag, 0);
	return (flag ? 0:-1);
}

static int wait_write()
{
int	flag;

	wait_rw(0, &flag);
	return (flag ? 0:-1);
}

static void swallow(unsigned);
static void burp(const char *, unsigned);

/* Receive a CRLF-terminated reply from the remote server */

static const char *readline()
{
int	c;
char	cc;
char	*p;
unsigned cnt, i;

	socklinesize=0;
	if (sockfd < 0)	return (0);
	for (;;)
	{
		p=mybuf_ptr( &sockbuf );
		cnt=mybuf_ptrleft( &sockbuf );
		if (cnt == 0)
		{
			if (wait_read())	return (0);

			/* Check for unexpected shutdown */

			if ((c=mybuf_get( &sockbuf )) < 0)
			{
				sox_close(sockfd);
				sockfd= -1;
				return (0);
			}
			p = --mybuf_ptr( &sockbuf );
			cnt = ++mybuf_ptrleft( &sockbuf );
		}
		for (i=0; i<cnt; i++)
			if (p[i] == '\r')
				break;

		if (i < cnt)
		{
			swallow(i);
			(void)mybuf_get( &sockbuf );	/* Skip the CR */

			for (;;)	/* Skip continuous CRs */
			{
				if (mybuf_ptrleft( &sockbuf ) == 0 &&
					wait_read())	return (0);

				if ((c=mybuf_get( &sockbuf )) != '\r')
					break;
				burp("\r", 1);
			}

			if (c < 0)
			{
				sox_close(sockfd);
				sockfd= -1;
				return (0);
			}
			if (c == '\n')	break;	/* Seen CRLF */
			cc=c;
			burp(&cc, 1);
			continue;
		}
		swallow(i);
	}

	socklinebuf[socklinesize]=0;
	return (socklinebuf);
}

/* Flush out anything that's waiting to be written out */

static void doflush()
{
int	n;
int	i;

	if (wait_write())
	{
		if (sockfd >= 0)
			sox_close(sockfd);
		sockfd= -1;
		return;
	}
	if ((n=sox_write(sockfd, writebuf, writebufptr-writebuf)) <= 0)
	{
		if (sockfd >= 0)
			sox_close(sockfd);
		sockfd= -1;
		return;
	}

	for (i=n; writebuf+i < writebufptr; i++)
		writebuf[i-n]=writebuf[i];
	writebufptr -= n;
	writebufleft += n;
}

/* Write various stuff to the socket */

static int dowrite(const char *p, unsigned l)
{
	while (l)
	{
	int n;

		if (sockfd < 0)	return (-1);

		if (writebufleft == 0)
		{
			doflush();
			continue;
		}
		if (writebufleft < l)
			n=writebufleft;
		else
			n=l;

		memcpy(writebufptr, p, n);
		p += n;
		l -= n;
		writebufptr += n;
		writebufleft -= n;
	}
	return (0);
}

static int dowritestr(const char *p)
{
	return (dowrite(p, strlen(p)));
}

static int writeflush()
{
	while (writebufptr > writebuf && sockfd >= 0)
		doflush();
	if (sockfd < 0)	return (-1);
	return (0);
}

/* Copy stuff read from socket into the line buffer */

static void swallow(unsigned l)
{
	burp(mybuf_ptr( &sockbuf ), l);

	mybuf_ptr( &sockbuf ) += l;
	mybuf_ptrleft( &sockbuf ) -= l;
}

/* Replies are collected into a fixed length line buffer. */

static void burp(const char *p, unsigned n)
{
	if (n > sizeof(socklinebuf)-1-socklinesize)
		n=sizeof(socklinebuf)-1-socklinesize;
	memcpy(socklinebuf+socklinesize, p, n);
	socklinesize += n;
}

/*
	Try EHLO then HELO, and see what the other server says.
*/

static RFC1035_ADDR laddr;

static int hello2(struct moduledel *, struct ctlfile *, int);

static int hello(struct moduledel *del, struct ctlfile *ctf)
{
	const char *p;
	RFC1035_NETADDR lsin;
	socklen_t i;

	i=sizeof(lsin);
	if (sox_getsockname(sockfd, (struct sockaddr *)&lsin, &i) ||
	    rfc1035_sockaddrip(&lsin, i, &laddr))
	{
		soft_error1(del, ctf, "Cannot obtain local socket IP address.",
			    -1);
		return -1;
	}

	mybuf_init(&sockbuf, sockfd);
	writebufptr=writebuf;
	writebufleft=sizeof(writebuf);
	sock_timeout(helo_timeout);
	if ((p=readline()) == 0)	/* Wait for server first */
		return (1);

	if (*p == '5')	/* Hard error */
	{
		talking(del, ctf);
		smtp_msg(del, ctf);
		while (!ISFINALLINE(p))	/* Skip multiline replies */
		{
			reply(del, ctf, p);
			if ((p=readline()) == 0)
				return (1);
				/* Caller will report the error */
		}
		hard_error(del, ctf, p);
		return (-1);
	}

	if (*p != '1' && *p != '2' && *p != '3')	/* Soft error */
	{
		for (;;)
		{
			if (ISFINALLINE(p))
				break;

			if ((p=readline()) == 0)
			{
				talking(del, ctf);
				return (1);
			}
		}
		quit();
		return (-1);	/*
				** Let caller handle this as a hard error,
				** so that it does not try the next MX.
				*/
	}

	/* Skip multiline good response. */

	while (!ISFINALLINE(p))
	{
		if ((p=readline()) == 0)
		{
			talking(del, ctf);
			return (1);
		}
	}

	return (hello2(del, ctf, 0));
}

	/* Try an EHLO */

static int hello2(struct moduledel *del, struct ctlfile *ctf, int using_tls)
{
	const	char *p;
	char	hellobuf[512];
	char buf[RFC1035_MAXNAMESIZE+128];

	haspipelining=hasdsn=has8bitmime=hasverp=hassize=hasexdata=hascourier=
	hasstarttls=hassecurity_starttls=0;
	if (authsasllist)	free(authsasllist);
	authsasllist=0;

	p=config_esmtphelo();

	/*
	** If the remote host is "*", use reverse DNS from the local IP addr.
	*/

	if (strcmp(p, "*") == 0)
	{
		p=buf;
		if (rfc1035_ptr(&rfc1035_default_resolver, &laddr, buf) != 0)
		{
			char *q;

			rfc1035_ntoa(&laddr, buf+1);

			q=buf+1;

			if (strncmp(q, "::ffff:", 7) == 0)
				q += 7;
			*--q='[';
			strcat(q, "]");
			p=q;
		}
	}

	strcpy(hellobuf, "EHLO ");
	strncat(hellobuf, p, sizeof(hellobuf)-10);
	strcat(hellobuf, "\r\n");

	if (dowritestr(hellobuf) || writeflush())
	{
		talking(del, ctf);
		return (1);
	}

	if ((p=readline()) == 0)
	{
		talking(del, ctf);
		return (1);
	}

	if (*p == '5')	/* Hard error, let's try a HELO */
	{
		while (!ISFINALLINE(p))	/* Skip multiline error */
		{
			if ((p=readline()) == 0)
			{
				talking(del, ctf);
				return (1);
			}
		}
		hellobuf[0]='H';
		hellobuf[1]='E';

		sock_timeout(helo_timeout);
		if (dowritestr(hellobuf) || writeflush())
		{
			talking(del, ctf);
			return (1);
		}

		if ((p=readline()) == 0)
		{
			talking(del, ctf);
			return (1);
		}
	}

	if (*p != '1' && *p != '2' && *p != '3') /* Some kind of an error */
	{
		talking(del, ctf);
		sent(del, ctf, hellobuf);
		smtp_msg(del, ctf);
		while (!ISFINALLINE(p))
		{
			reply(del, ctf, p);
			if ((p=readline()) == 0)
				return (1);
		}
		smtp_error(del, ctf, p);
		quit();
		return (-1);	/*
				** Let the caller consider this a hard error,
				** so that it doesn't try the next MX.
				*/
	}

	/*
	** If we're here after a HELO, just eat it up, otherwise, we want to
	** parse available ESMTP keywords.
	*/

	if (hellobuf[0] == 'H')
	{
		while (!ISFINALLINE(p))
		{
			if ((p=readline()) == 0)
			{
				talking(del, ctf);
				return (1);
			}
		}
		return (0);
	}

	if (!ISFINALLINE(p))
	{
/*
**	Read remaining lines, parse the keywords.
*/
		do
		{
		const char *q;
		unsigned l;

			if ((p=readline()) == 0)
			{
				talking(del, ctf);
				return (1);
			}

			if (!isdigit((int)(unsigned char)p[0]) ||
				!isdigit((int)(unsigned char)p[1]) ||
				!isdigit((int)(unsigned char)p[2]) ||
				(p[3] != ' ' && p[3] != '-'))
			{
				continue;
			}
			q=p+4;
			for (l=0; q[l] && q[l] != ' '; l++)
			{
				if (l >= sizeof(hellobuf)-1)	break;
				hellobuf[l]=toupper(q[l]);
			}
			hellobuf[l]=0;

			if (strcmp(hellobuf, "PIPELINING") == 0)
				haspipelining=1;
			if (strcmp(hellobuf, "DSN") == 0)
				hasdsn=1;
			if (strcmp(hellobuf, "8BITMIME") == 0)
				has8bitmime=1;
			if (strcmp(hellobuf, "SIZE") == 0)
				hassize=1;
			if (strcmp(hellobuf, "STARTTLS") == 0 && !(smtproutes_flags & ROUTE_NOSECURITY))
				hasstarttls=1;

			if (strcmp(hellobuf, "AUTH") == 0
				|| strncmp(hellobuf, "AUTH=", 5) == 0)
			{
			const char *p=q+4;

				if (isspace((int)(unsigned char)*p)||*p == '=')
				{
				char	*s;
				unsigned	l=(authsasllist ?
					strlen(authsasllist)+1: 0)+strlen(p)+1;

					if (l > 10000)	continue;
							/* Script kiddies... */
					++p;
					s=courier_malloc(l);
					*s=0;
					if (authsasllist)
						strcat(strcpy(s, authsasllist),
							" ");
					strcat(s, p);
					if (authsasllist)
						free(authsasllist);
					authsasllist=s;
				}
			}


#define	KEYWORD(x)	(strcmp(hellobuf, x) == 0)
#define KEYWORDARG(x)	(strncmp(hellobuf, x, sizeof(x)-1) == 0)

			if (IS_EXDATA_KEYWORD)
				hasexdata=1;

			if (IS_VERP_KEYWORD)
			{
				char *p=strchr(hellobuf, '=');

				if (p)
				{
					for (++p; (p=strtok(p, ",")) != 0; p=0)
						if (strcasecmp(p, "Courier")
						    == 0)
							hasverp=1;
				}
			}

			if (IS_COURIER_EXTENSIONS)
				hascourier=1;

			if (IS_SECURITY_KEYWORD)
			{
				char *p=strchr(hellobuf, '=');

				if (p)
				{
					for (++p; (p=strtok(p, ",")) != 0; p=0)
						if (strcmp(p, "STARTTLS") == 0 && !(smtproutes_flags & ROUTE_NOSECURITY))
							hassecurity_starttls=1;
				}
			}
		} while (!ISFINALLINE(p));

		if (!hascourier) /* No courier extensions, no EXDATA or VERP */
			hasexdata=hasverp=hassecurity_starttls=0;
	}

	if (hasstarttls)
	{
		const char *q=getenv("COURIERTLS");
		struct	stat stat_buf;

		if (!q || stat(q, &stat_buf))
			hasstarttls=0;
	}

	if ((p=want_security(ctf)) != 0)
	{
		if ( strcmp(p, "STARTTLS") == 0)
		{
			if ((hasstarttls || using_tls) && hassecurity_starttls)
				return (0);
		}

		talking(del, ctf);
		sent(del, ctf, "SECURITY=STARTTLS REQUESTED FOR THIS MESSAGE");
		smtp_msg(del, ctf);
		smtp_error(del, ctf,
			   "500 Unable to set minimum security level.");
		quit();
		return (-1);
	}

	if (hasstarttls)
	{
		const char *p=getenv("ESMTP_USE_STARTTLS");

		if (!p || !atoi(p))
			hasstarttls=0;
	}

	if (getenv("COURIER_ESMTP_DEBUG_NO8BITMIME"))
		has8bitmime=0;
	return (0);
}

static int starttls(struct moduledel *del, struct ctlfile *ctf,
	const char *hostname)
{
	const char *p;
	int	pipefd[2];
	int rc;
	const char *sec;
	struct couriertls_info cinfo;
	char	*verify_domain=0;
	char	localfd_buf[NUMBUFSIZE+30];
	char	remotefd_buf[NUMBUFSIZE+30];
	char	miscbuf[NUMBUFSIZE];

	static char *trustcert_buf=0;
	static char *origcert_buf=0;

	char *argvec[10];

	int restore_origcert=0;
	int n;

	if (libmail_streampipe(pipefd))
	{
		perror("libmail_streampipe");
		return (-1);
	}

	if (dowritestr("STARTTLS\r\n") || writeflush() ||
		(p=readline()) == 0)
	{
		talking(del, ctf);
		connect_error(del, ctf);
		close(pipefd[0]);
		close(pipefd[1]);
		return (1);
	}

	if (*p != '1' && *p != '2' && *p != '3')
	{
		talking(del, ctf);
		sent(del, ctf, "STARTTLS");
		smtp_msg(del, ctf);
		while (!ISFINALLINE(p))
		{
			reply(del, ctf, p);
			if ((p=readline()) == 0)
				break;
		}
		smtp_error(del, ctf, p);
		close(pipefd[0]);
		close(pipefd[1]);
		return (-1);
	}

	sec=want_security(ctf);

	couriertls_init(&cinfo);

	/*
	** Make sure that our side of the pipe is closed when couriertls
	** is execed by the child process.
	*/

	fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);

	strcat(strcpy(localfd_buf, "-localfd="),
	       libmail_str_size_t(pipefd[1], miscbuf));
	strcat(strcpy(remotefd_buf, "-remotefd="),
	       libmail_str_size_t(sockfd, miscbuf));

	p=getenv("ESMTP_TLS_VERIFY_DOMAIN");

	if (sec != 0)
	{
		char *q, *r;

		/*
		** Replace TLS_TRUSTCERTS with TLS_TRUSTSECURITYCERTS,
		** until couriertls is execed.
		*/

		q=getenv("TLS_TRUSTCERTS");

		r=courier_malloc(strlen(q ? q:"")+40);
		strcat(strcpy(r, "TLS_TRUSTCERTS="), q ? q:"");

		if (origcert_buf)
			free(origcert_buf);
		origcert_buf=r;
		restore_origcert=1;

		p=getenv("TLS_TRUSTSECURITYCERTS");
		if (!p || !*p)
		{
			static const char fail[]=
				"Unable to set minimum security"
				" level.\n";

			talking(del, ctf);
			sent(del, ctf, "STARTTLS");
			smtp_msg(del, ctf);
			smtp_error(del, ctf, fail);
			sox_close(sockfd);
			sockfd= -1;
			close(pipefd[0]);
			close(pipefd[1]);
			return (-1);
		}

		q=courier_malloc(strlen(p)+40);

		strcat(strcpy(q, "TLS_TRUSTCERTS="), p);
		putenv(q);
		p="1";

		if (trustcert_buf)
			free(trustcert_buf);
		trustcert_buf=q;
	}

	if (p && atoi(p))
	{
		verify_domain=courier_malloc(sizeof("-verify=")
					     +strlen(hostname));
		strcat(strcpy(verify_domain, "-verify="), hostname);
	}


	n=0;

	argvec[n++]=localfd_buf;
	argvec[n++]=remotefd_buf;
	if (verify_domain)
	{
		argvec[n++]=verify_domain;
	}
	argvec[n]=0;

	n=couriertls_start(argvec, &cinfo);

	if (restore_origcert)
		putenv(origcert_buf);
	if (verify_domain)
		free(verify_domain);

	close(sockfd);
	sockfd=pipefd[0];
	close(pipefd[1]);

	if (!n && fcntl(sockfd, F_SETFL, O_NONBLOCK))
	{
		perror("fcntl");
		n= -1;
		strcpy(cinfo.errmsg, "fcntl() failed");
	}

	if (n)
	{
		char tmperrbuf[sizeof(cinfo.errmsg)+10];

		talking(del, ctf);
		sent(del, ctf, "STARTTLS");

		smtp_msg(del, ctf);
		strcat(strcpy(tmperrbuf, "500 "), cinfo.errmsg);
		smtp_error(del, ctf, tmperrbuf);
		sox_close(sockfd);
		sockfd= -1;
		couriertls_destroy(&cinfo);
		return (-1);
	}
	couriertls_destroy(&cinfo);

	/* Reset the socket buffer structure given the new filedescriptor */

	mybuf_init(&sockbuf, sockfd);
	writebufptr=writebuf;
	writebufleft=sizeof(writebuf);

	/* Ask again for an EHLO, because the capabilities may differ now */

	rc=hello2(del, ctf, 1);

	if (rc > 0)
		connection_closed(del, ctf);	/* Make sure to log it */
	else
		is_secure_connection= sec != 0;
	return (rc);

}
/*
** Send a QUIT, and shut down the connection
*/

static void quit()
{
const char *p;

	if (sockfd < 0)	return;

	sock_timeout(quit_timeout);
	if (dowritestr("QUIT\r\n") || writeflush())	return;

	while ((p=readline()) != 0 && !ISFINALLINE(p))
		;
	if (sockfd >= 0)
		sox_close(sockfd);
	sockfd= -1;
}

/* Parse a reply to a SMTP command that applies to all recipients */

static int smtpreply(const char *cmd,
	struct moduledel *del, struct ctlfile *ctf, int istalking)
{
const char *p;
unsigned line_num;

	if ((p=readline()) == 0)
	{
		if (istalking < 0)	return (0);

		if (!istalking)
			talking(del, ctf);
		connect_error(del, ctf);
		quit();
		return (-1);
	}

	line_num=0;

	switch (SMTPREPLY_TYPE(p))	{
	case COMCTLFILE_DELDEFERRED:
	case COMCTLFILE_DELFAIL:

		if (!istalking || istalking < 0)
			talking(del, ctf);
		sent(del, ctf, cmd);
		smtp_msg(del, ctf);
		while (!ISFINALLINE(p))
		{
			if (line_num < 10)	/* We record up to 10 lines
						** of the reply in our log
						** files.
						*/
			{
				reply(del, ctf, p);
				++line_num;
			}
			if ((p=readline()) == 0)
			{
				connect_error(del, ctf);
				quit();
				return (-1);
			}
		}
		smtp_error(del, ctf, p);
		return (-1);
	}

	while (!ISFINALLINE(p))
	{
		if ((p=readline()) == 0)
		{
			if (!istalking || istalking < 0)
				talking(del, ctf);
			connect_error(del, ctf);
			quit();
			return (-1);
		}
	}
	return (0);
}

/* Send an SMTP command that applies to all recipients, then wait for a reply */

static int smtpcommand(const char *cmd,
	struct moduledel *del, struct ctlfile *ctf, int istalking)
{
	if (dowritestr(cmd) || writeflush())
	{
		if (!istalking)
			talking(del, ctf);
		connect_error(del, ctf);
		quit();
		return (-1);
	}
	return (smtpreply(cmd, del, ctf, istalking));
}


static int rset(struct moduledel *del, struct ctlfile *ctf)
{
	sock_timeout(helo_timeout);
	return (smtpcommand("RSET\r\n", del, ctf, 0));
}

static void pushdsn(struct moduledel *, struct ctlfile *);

/*
**	We now resolved issues with VERP support.  Resolve issues with
**	DSNs.  The next function to call is pushdsn.  The following issue
**	is resolved here: sending a message to a server that does not
**	support DSNs.  In this situation what we want to do is to send
**	all recipients with a NOTIFY=NEVER in a transaction where MAIL FROM
**	is <>.  Everyone else is sent in a separate transaction.
**
**	If this is not applicable (the remote server supports DSNs), we
**	simply call pushdsn() to continue with the delivery attempt.
**	Otherwise we call pushdsn() twice.
*/

static void push(struct moduledel *del, struct ctlfile *ctf)
{
unsigned	i;
char	**real_receipients;
const char	*real_sender;
int	pass;
unsigned real_nreceipients;

	real_sender=del->sender;
	real_receipients=del->receipients;
	real_nreceipients=del->nreceipients;

	if (real_nreceipients == 0)	return;

	/* If the sender is <> already, I don't care */

	if (hasdsn || real_sender == 0 || *real_sender == '\0')
	{
		pushdsn(del, ctf);
		return;
	}

	/*
	** If the remote MTA does not support DSNs, and we have some
	** receipients with NOTIFY=NEVER, what we do is set the MAIL FROM:
	** for those recipients to <>.  We call pushdsn twice, once for
	** receipients with NOTIFY=NEVER, and once more for ones without
	** NOTIFY=NEVER.
	*/

	del->receipients=(char **)courier_malloc(
			sizeof(char *)*2*del->nreceipients);

	for (pass=0; pass<2; pass++)
	{
		if (pass)	del->sender="";
		del->nreceipients=0;

		for (i=0; i<real_nreceipients; i++)
		{
		const char *dsnptr=ctf->dsnreceipients[
			atol(real_receipients[i*2])];

			if (dsnptr && strchr(dsnptr, 'N'))
			{
				if (pass == 0)	continue;
			}
			else
			{
				if (pass == 1)	continue;
			}
			del->receipients[del->nreceipients*2]=
				real_receipients[i*2];
			del->receipients[del->nreceipients*2+1]=
				real_receipients[i*2+1];
			++del->nreceipients;
		}
		if (del->nreceipients == 0)	continue;
		pushdsn(del, ctf);
	}
	free(del->receipients);
	del->receipients=real_receipients;
	del->nreceipients=real_nreceipients;
	del->sender=real_sender;
}

/*
** Construct the MAIL FROM: command, taking into account ESMTP capabilities
** of the remote server.
*/

static char *mailfrom(struct moduledel *del, struct ctlfile *ctf,
	int messagefd, int is8bitmsg)
{
char	*bodyverb="", *verpverb="", *retverb="";
char	*oenvidverb="", *sizeverb="";
const char *seclevel="";
char	*mailfromcmd;
int	n;
struct	stat stat_buf;
const char *sec=want_security(ctf);

static const char seclevel_starttls[]=" SECURITY=STARTTLS";

	if (has8bitmime)	/* ESMTP 8BITMIME capability */
		bodyverb= is8bitmsg ? " BODY=8BITMIME":" BODY=7BIT";

	if (hasverp && ctlfile_searchfirst(ctf, COMCTLFILE_VERP) >= 0)
		verpverb=" VERP";	/* ESMTP VERP capability */

	/* ESMTP DSN capability */
	if (hasdsn && (n=ctlfile_searchfirst(ctf, COMCTLFILE_DSNFORMAT)) >= 0)
		retverb=strchr(ctf->lines[n]+1, 'F') ? " RET=FULL":
			strchr(ctf->lines[n]+1, 'H') ? " RET=HDRS":"";
	if (hasdsn && (n=ctlfile_searchfirst(ctf, COMCTLFILE_ENVID)) >= 0 &&
			ctf->lines[n][1])
	{
		oenvidverb=courier_malloc(sizeof(" ENVID=")+
			strlen(ctf->lines[n]+1));
		strcat(strcpy(oenvidverb, " ENVID="), ctf->lines[n]+1);
	}

	/* ESMTP SIZE capability */

	if (fstat(messagefd, &stat_buf) == 0)
	{
		ctf->msgsize=stat_buf.st_size;

		if (hassize)
		{
			off_t s=stat_buf.st_size;
			char	buf[MAXLONGSIZE+1];

			s= s/75 * 77+256;	/* Size estimate */
			if (!has8bitmime && is8bitmsg)
				s=s/70 * 100;
			sprintf(buf, "%lu", (unsigned long)s);
			sizeverb=courier_malloc(sizeof(" SIZE=")+strlen(buf));
			strcat(strcpy(sizeverb, " SIZE="), buf);
		}
	}

	/* SECURITY extension */

	if (sec && strcmp(sec, "STARTTLS") == 0)
		seclevel=seclevel_starttls;

	mailfromcmd=courier_malloc(sizeof("MAIL FROM:<>\r\n")+
				   strlen(del->sender)+
				   strlen(bodyverb)+
				   strlen(verpverb)+
				   strlen(retverb)+
				   strlen(oenvidverb)+
				   strlen(sizeverb)+
				   strlen(seclevel));

	strcat(strcat(strcat(strcat(strcat(
		strcat(strcat(strcat(strcat(strcpy(
						   mailfromcmd, "MAIL FROM:<"),
					    del->sender),
				     ">"),
			      bodyverb),
		       verpverb),
		retverb),
				    oenvidverb),
			     sizeverb),
		      seclevel),
	       "\r\n");

	if (*oenvidverb)	free(oenvidverb);
	if (*sizeverb)		free(sizeverb);
	return (mailfromcmd);
}

/*
** Construct the RCPT TO command along the same lines.
*/

static char *rcptcmd(struct moduledel *del,
	struct ctlfile *ctf, unsigned rcptnum)
{
char notify[sizeof(" NOTIFY=SUCCESS,FAILURE,DELAY")];
char *orcpt="";
const char *p;
char	*q;
unsigned n=atol(del->receipients[rcptnum*2]);

	notify[0]=0;
	if ((p=ctf->dsnreceipients[n]) != 0 && *p && hasdsn)
	{
	int s=0,f=0,d=0,n=0;

		while (*p)
			switch (*p++)	{
			case 'N':
				n=1;
				break;
			case 'D':
				d=1;
				break;
			case 'F':
				f=1;
				break;
			case 'S':
				s=1;
				break;
			}
		if (n)
			strcpy(notify, " NOTIFY=NEVER");
		else
		{
			p=" NOTIFY=";
			if (s)
			{
				strcat(strcat(notify, p), "SUCCESS");
				p=",";
			}
			if (f)
			{
				strcat(strcat(notify, p), "FAILURE");
				p=",";
			}
			if (d)
				strcat(strcat(notify, p), "DELAY");
		}
	}

	if ((p=ctf->oreceipients[n]) != 0 && *p && hasdsn)
	{
		orcpt=courier_malloc(sizeof(" ORCPT=")+strlen(p));
		strcat(strcpy(orcpt, " ORCPT="), p);
	}

	p=del->receipients[rcptnum*2+1];

	q=courier_malloc(sizeof("RCPT TO:<>\r\n")+strlen(p)+strlen(notify)+
		strlen(orcpt));

	strcat(strcat(strcat(strcat(strcat(strcpy(q,
		"RCPT TO:<"),
		p),
		">"),
		notify),
		orcpt),
		"\r\n");
	if (*orcpt)	free(orcpt);
	return (q);
}

/***************************************************************************/
/*                             RCPT TO                                     */
/***************************************************************************/

/*
** do_pipeline_rcpt handles a pipeline RCPT TO command set.  That is, all
** the RCPT TOs are written at once, and we read the reply from the server
** in parallel.
**
** If the remote server does not support PIPELINING, a tiny hack in the
** write logic arranges for non-pipelined RCPT TO command set.
**
** ( DATA is also pipelined! )
*/

static const char *readpipelinercpt( struct iovec **, unsigned *);

static int parsedatareply(struct moduledel *, struct ctlfile *,
	int *, struct iovec **, unsigned *, int);

static int do_pipeline_rcpt(struct moduledel *del,
	struct ctlfile *ctf,
	int *rcptok)
{
char	**cmdarray;
struct iovec *iov;
struct iovec *	iovw;
unsigned	niovw;

unsigned i;
const char *p;

int	rc=0;

	/* Construct all the RCPT TOs we'll issue. */

	cmdarray=(char **)courier_malloc(sizeof(char *)*
		(del->nreceipients+1));	/* 1 extra PTR for the DATA */
	iov=(struct iovec *)courier_malloc(sizeof(struct iovec)*
		(del->nreceipients+1));

	/* Allocate cmdarray[], also set up iovecs to point to each cmd */

	for (i=0; i <= del->nreceipients; i++)
	{
		cmdarray[i]= i < del->nreceipients ?  rcptcmd(del, ctf, i):
				strcpy(courier_malloc(sizeof("DATA\r\n")),
						"DATA\r\n");
		iov[i].iov_base=(caddr_t)cmdarray[i];
		iov[i].iov_len=strlen(cmdarray[i]);
	}

	iovw=iov;
	niovw= i;

	if (haspipelining)	/* One timeout */
		sock_timeout(cmd_timeout);

	/* Read replies for the RCPT TO commands */

	for (i=0; i<del->nreceipients; i++)
	{
	char	err_code=0;
	unsigned line_num=0;

		/* If server can't do pipelining, just set niovw to one!!! */

		if (!haspipelining)
		{
			iovw=iov+i;
			niovw=1;
			sock_timeout(cmd_timeout);
		}

		do
		{
			if ((p=readpipelinercpt( &iovw, &niovw)) == 0)
				break;

			if (line_num == 0)
				err_code= *p;

			if ( SMTPREPLY_TYPE(&err_code) ==
				COMCTLFILE_DELSUCCESS)
				continue;

			if (line_num >= 10)	continue;
			/* Ignore SMTP replies longer than 10 lines */

			if (line_num == 0)
			{
				ctlfile_append_connectioninfo(ctf,
					(unsigned)atol(del->receipients[i*2]),
					COMCTLFILE_DELINFO_SENT,
					cmdarray[i]);
				ctlfile_append_connectioninfo(ctf,
					(unsigned)atol(del->receipients[i*2]),
					COMCTLFILE_DELINFO_REPLYTYPE,
					"smtp");
			}
			ctlfile_append_connectioninfo(ctf,
				(unsigned)atol(del->receipients[i*2]),
					COMCTLFILE_DELINFO_REPLY, p);
		} while (!ISFINALLINE(p));

		if (!p)
		{
			while (i < del->nreceipients)
				rcptok[i++]=1;
			break;
		}

		if ( SMTPREPLY_TYPE(&err_code) == COMCTLFILE_DELSUCCESS)
		{
			rcptok[i]=1;	/* This recipient was accepted */
			continue;
		}

		/* Failed.  Report it */

		rcptok[i]=0;

		if (SMTPREPLY_TYPE(&err_code) == COMCTLFILE_DELFAIL)
			hard_error1(del, ctf, 0, i);
		else
			soft_error1(del, ctf, 0, i);
	}

/* ------------------- Read the reply to the DATA ----------------- */

	if (sockfd >= 0)
	{
		if (!haspipelining)	/* DATA hasn't been sent yet */
		{
			for (i=0; i<del->nreceipients; i++)
				if (rcptok[i])	break;

			if (i >= del->nreceipients)	return (-1);
					/* All RCPT TOs failed */

			iovw=iov+del->nreceipients;
			niovw=1;
			sock_timeout(cmd_timeout);
		}
		rc=parsedatareply(del, ctf, rcptok, &iovw, &niovw, 0);
			/* One more reply */
	}

	if (sockfd < 0)
	{
		for (i=0; i<del->nreceipients; i++)
		{
			if (!rcptok[i])	continue;
			connect_error1(del, ctf, i);
		}
		rc= -1;
	}

	for (i=0; i<del->nreceipients; i++)
		free(cmdarray[i]);
	free(cmdarray);
	free(iov);
	return (rc);
}

/* Sigh... When SOCKSv5 supports writev, I'll be happy... */

static int my_writev(int fd, const struct iovec *vector, size_t count)
{
char	buf[BUFSIZ];
size_t	i=0;

	while (count)
	{
		if (vector->iov_len > sizeof(buf)-i)	break;

		memcpy(buf+i, vector->iov_base, vector->iov_len);
		i += vector->iov_len;
		++vector;
		--count;
	}
	if (i)
		return (sox_write(fd, buf, i));

	return (sox_write(fd, vector->iov_base, vector->iov_len));
}

/* Read an SMTP reply line in pipeline mode */

static const char *readpipelinercpt(
		struct iovec **iovw,	/* Write pipeline */
		unsigned *niovw)
{
int	read_flag, write_flag, *writeptr;

	if (sockfd < 0)	return (0);

	if (mybuf_more(&sockbuf))
		return (readline());	/* We have the reply buffered */

	do
	{
		write_flag=0;
		writeptr= &write_flag;
		if (iovw == 0 || niovw == 0 || *niovw == 0)
			writeptr=0;

		wait_rw(&read_flag, writeptr);

		if (write_flag)	/* We can squeeze something out now */
		{
		int	n=my_writev(sockfd, *iovw, *niovw);

			if (n < 0)
			{
				sox_close(sockfd);
				sockfd=-1;
				return (0);
			}

			/* Update iovecs to reflect # bytes written */

			while (n)
			{
				if (n < (*iovw)->iov_len)
				{
					(*iovw)->iov_base=(caddr_t)
						( (char *)(*iovw)->iov_base+n);
					(*iovw)->iov_len -= n;
					break;
				}
				n -= (*iovw)->iov_len;
				++*iovw;
				--*niovw;
			}
		}
	} while (!read_flag && sockfd >= 0);

	return (readline());
}

/***************************************************************************/
/*                               DATA                                      */
/***************************************************************************/

/*
** Parse the reply to the DATA command.
** This is called to parse both the first reply (isfinal=0), and the
** second reply after the message has been sent (isfinal=1).
**
** When isfinal=0, if this is called as part of pipelined commands,
** iovw/niovw must be initialized appropriately, otherwise they must be null.
*/

static int parseexdatareply(const char *, struct moduledel *, struct ctlfile *,
	int *);

static char *logsuccessto()
{
char	buf[RFC1035_NTOABUFSIZE];
char	*p;

	sockipname(buf);
	p=courier_malloc(sizeof("delivered:  []")+
		(sockfdaddrname ?
			strlen(sockfdaddrname):0)+strlen(buf));

	strcpy(p, "delivered: ");
	if (sockfdaddrname && *sockfdaddrname)
		strcat(strcat(p, sockfdaddrname), " ");
	strcat(p, "[");
	strcat(p, buf);
	strcat(p, "]");
	return (p);
}

static int parsedatareply(struct moduledel *del, struct ctlfile *ctf,
	int *rcptok, struct iovec **iovw, unsigned *niovw, int isfinal)
{
const char *p;
unsigned line_num=0;
unsigned i;

	p=readpipelinercpt(iovw, niovw);

	if (!p)	return (-1);

	if (SMTPREPLY_TYPE(p) == COMCTLFILE_DELSUCCESS)
	{
		/*
		** DATA went through.  What we do depends on whether this is
		** the first or the last DATA.
		*/

		for (;;)
		{
			if (isfinal && line_num < 10)
			{
				/* We want to record the final DATA reply in
				** the log.
				*/

				for (i=0; i<del->nreceipients; i++)
				{
					if (!rcptok[i])	continue;

					if (line_num == 0)
						ctlfile_append_connectioninfo(
							ctf,
						(unsigned)atol(
							del->receipients[i*2]),
						COMCTLFILE_DELINFO_REPLYTYPE,
						"smtp");

					ctlfile_append_connectioninfo(ctf,
						(unsigned)atol(
							del->receipients[i*2]),
						COMCTLFILE_DELINFO_REPLY, p);
				}
				++line_num;
			}
			if (ISFINALLINE(p))	break;
			if ((p=readline()) == 0)
				return (-1);
		}

		if (isfinal)
		{
		char	*p=logsuccessto();

			/*
			** Final reply - record a success for recipients that
			** haven't previously failed (in RCPT TO).
			*/

			for (i=0; i<del->nreceipients; i++)
			{
				if (!rcptok[i])	continue;

				ctlfile_append_reply(ctf,
					(unsigned)atol(del->receipients[i*2]),
					p, COMCTLFILE_DELSUCCESS_NOLOG,
					(hasdsn ? "":" r"));
			}
			free(p);
		}
		else
		{
			/* Good response to the first DATA */

			for (i=0; i<del->nreceipients; i++)
				if (rcptok[i]) break;

			if (i >= del->nreceipients)
				/* Stupid server wants message with no
				** receipients
				*/
			{
				sock_timeout(data_timeout);
				if (dowritestr(".\r\n") || writeflush())
					return (-1);
				do
				{
					p=readline();
					if (!p)	return (-1);
				} while (!ISFINALLINE(p));
				return (-1);
			}
		}
		return (0);
	}

	/* DATA error */

	if (hasexdata && isfinal && *p == '5' && p[1] == '5'  && p[2] == '8')
		return (parseexdatareply(p, del, ctf, rcptok));
		/* Special logic for EXDATA extended replies */

	/* Fail the recipients that haven't been failed already */

	for (i=0; i<del->nreceipients; i++)
	{
		if (!rcptok[i])	continue;
		ctlfile_append_connectioninfo(ctf,
			(unsigned)atol(del->receipients[i*2]),
			COMCTLFILE_DELINFO_SENT, "DATA");

		ctlfile_append_connectioninfo(ctf,
			(unsigned)atol(del->receipients[i*2]),
			COMCTLFILE_DELINFO_REPLYTYPE, "smtp");
	}

	for (;;)
	{
		if (line_num < 10)
		{
			for (i=0; i<del->nreceipients; i++)
			{
				if (!rcptok[i])	continue;

				ctlfile_append_connectioninfo(ctf,
					(unsigned)atol(
						del->receipients[i*2]),
					COMCTLFILE_DELINFO_REPLY, p);
			}
			++line_num;
		}
		if (ISFINALLINE(p))
		{
			for (i=0; i<del->nreceipients; i++)
			{
				if (!rcptok[i])	continue;

				if (SMTPREPLY_TYPE(p) == COMCTLFILE_DELFAIL)
					hard_error1(del, ctf, "", i);
				else
					soft_error1(del, ctf, "", i);
				rcptok[i]=0;
			}
			break;
		}
		if ((p=readline()) == 0)
			return (-1);
	}
	return (-1);
}

/*
** Parse EXDATA 558 reply.
**
** See draft-varshavchik-exdata-smtpext.txt for more information.
*/

static int parseexdatareply(const char *p,
	struct moduledel *del, struct ctlfile *ctf, int *rcptok)
{
unsigned i;
char err_code=0;
unsigned line_num=0;

	for (i=0; i<del->nreceipients; i++)
		if (rcptok[i])	break;

	/* i is the next recipient that's getting an extended reply */

	for (;;p=readline())
	{
		if (!p)	return (-1);

		if (!isdigit((int)(unsigned char)*p) ||
			!isdigit((int)(unsigned char)p[1]) ||
			!isdigit((int)(unsigned char)p[2]) || !p[3])
			continue;

		if (line_num == 0)
			err_code=p[4];

		if (i >= del->nreceipients)	/* Bad extended reply */
		{
			if (ISFINALLINE(p))	break;
			continue;
		}

		if (line_num == 0 &&
			SMTPREPLY_TYPE(&err_code) != COMCTLFILE_DELSUCCESS)
		{
			ctlfile_append_connectioninfo( ctf,
				(unsigned)atol(del->receipients[i*2]),
				COMCTLFILE_DELINFO_SENT, "DATA");
		}

		if (line_num == 0)
			ctlfile_append_connectioninfo( ctf,
				(unsigned)atol(del->receipients[i*2]),
				COMCTLFILE_DELINFO_REPLYTYPE, "smtp");


		if (line_num < 10)
		{
			ctlfile_append_connectioninfo(ctf,
				(unsigned)atol(del->receipients[i*2]),
				COMCTLFILE_DELINFO_REPLY, p+4);
			++line_num;
		}

		if (ISFINALLINE((p+4)))
		{
			switch (SMTPREPLY_TYPE( &err_code))	{
			case COMCTLFILE_DELFAIL:
				hard_error1(del, ctf, "", i);
				rcptok[i]=0;
				break;
			case COMCTLFILE_DELSUCCESS:
				{
				char	*p=logsuccessto();

				ctlfile_append_reply(ctf,
					(unsigned)atol( del->receipients[i*2]),
					p, COMCTLFILE_DELSUCCESS_NOLOG,
					(hasdsn ? "":" r"));

					free(p);
				}
				break;
			default:
				soft_error1(del, ctf, "", i);
				rcptok[i]=0;
				break;
			}

			/* Find next recipient that gets an extended reply */

			while (i < del->nreceipients &&
				!rcptok[++i])
				;
			line_num=0;
		}
		if (ISFINALLINE(p))	break;
	}

	while (i < del->nreceipients)
		if (rcptok[++i])
		{
			hard_error1(del, ctf,
				"Invalid 558 response from server.", i);
			rcptok[i]=0;
		}

	return (0);
}

static void call_rewrite_func(struct rw_info *p, void (*f)(struct rw_info *),
		void *arg)
{
	(*rewrite_func)(p, f);
}

/* Write out .\r\n, then wait for the DATA reply */

static int data_wait(struct moduledel *del, struct ctlfile *ctf, int *rcptok)
{
	sock_timeout(data_timeout);
	if (dowrite(".\r\n", 3) || writeflush())	return (-1);

	cork(0);

	(void)parsedatareply(del, ctf, rcptok, 0, 0, 1);

	if (sockfd < 0)	return (-1);
	return (0);
}

static void parserfc(int fd, struct rfc2045 *rfcp)
{
char	buf[8192];
int	n;

	while ((n=sox_read(fd, buf, sizeof(buf))) > 0)
		rfc2045_parse(rfcp, buf, n);
}

/*
** Ok, everything above is collected into a nice, tight, package.
*/

struct rw_for_esmtp {

	/* State flags for converting msg to ESMTP format */

	int	is_sol;

	unsigned byte_counter;
	} ;

static int convert_to_crlf(const char *, unsigned, void *);

static void pushdsn(struct moduledel *del, struct ctlfile *ctf)
{
unsigned i;
int	*rcptok;
int	fd;
char	*mailfroms;
struct rfc2045 *rfcp=0;
int	is8bitmsg;

	if ((fd=open(qmsgsdatname(del->inum), O_RDONLY)) < 0)
	{
		connect_error1(del, ctf, -1);
		return;
	}

	is8bitmsg=ctlfile_searchfirst(ctf, COMCTLFILE_8BIT) >= 0;
	if ((mailfroms=mailfrom(del, ctf, fd, is8bitmsg)) == 0)
	{
		sox_close(fd);
		return;
	}

	talking(del, ctf);
	sock_timeout(cmd_timeout);

	if (dowritestr(mailfroms) || writeflush())
	{
		sox_close(fd);
		free(mailfroms);
		connect_error(del, ctf);
		quit();
		return;
	}

	/*
	** While waiting for MAIL FROM to come back, check if the message
	** needs to be converted to quoted-printable.
	*/

	if (!has8bitmime && is8bitmsg)
	{
		rfcp=rfc2045_alloc_ac();
		if (!rfcp)	clog_msg_errno();
		parserfc(fd, rfcp);

		rfc2045_ac_check(rfcp, RFC2045_RW_7BIT);
	}

	if (smtpreply(mailfroms, del, ctf, 1))	/* MAIL FROM rejected */
	{
		if (rfcp)	rfc2045_free(rfcp);
		sox_close(fd);

		free(mailfroms);
		return;
	}
	free(mailfroms);

	rcptok=courier_malloc(sizeof(int)*(del->nreceipients+1));

	if ( do_pipeline_rcpt(del, ctf, rcptok) )
	{
		if (rfcp)	rfc2045_free(rfcp);
		free(rcptok);
		sox_close(fd);
		return;
	}

	{
	struct rw_for_esmtp rfe;

		rfe.is_sol=1;
		rfe.byte_counter=0;

		cork(1);

		if ((rfcp ?
			rw_rewrite_msg_7bit(fd, rfcp,
				&convert_to_crlf,
				&call_rewrite_func,
				&rfe):
			rw_rewrite_msg(fd,
				&convert_to_crlf,
				&call_rewrite_func,
				&rfe))
			|| data_wait(del, ctf, rcptok))
			for (i=0; i<del->nreceipients; i++)
				if (rcptok[i])
					connect_error1(del, ctf, i);
		free(rcptok);
		sox_close(fd);
		cork(0);
	}
	if (rfcp)	rfc2045_free(rfcp);
}


static int escape_dots(const char *, unsigned,
	struct rw_for_esmtp *);

static int convert_to_crlf(const char *msg, unsigned l, void *voidp)
{
unsigned i, j;
int	rc;

	for (i=j=0; i < l; i++)
	{
		if (msg[i] != '\n')
			continue;
		if ((rc=escape_dots(msg+j, i-j,
			(struct rw_for_esmtp *)voidp)) != 0 ||
			(rc=escape_dots("\r", 1,
				(struct rw_for_esmtp *)voidp)) != 0)
			return (rc);
		j=i;
	}
	return (escape_dots(msg+j, i-j, (struct rw_for_esmtp *)voidp));
}

static int escape_dots(const char *msg, unsigned l, struct rw_for_esmtp *ptr)
{
unsigned i, j;
int	rc;

	if ( (ptr->byte_counter += l) >= BUFSIZ)
		ptr->byte_counter=0;

	if (ptr->byte_counter == 0)
		sock_timeout(data_timeout);

	for (i=j=0; i<l; i++)
	{
		if (ptr->is_sol && msg[i] == '.')
		{
			if ((rc=dowrite(msg+j, i-j)) != 0 ||
				(rc=dowrite(".", 1)) != 0)
				return (rc);
			j=i;
		}
		ptr->is_sol= msg[i] == '\n' ? 1:0;
	}

	return (dowrite(msg+j, i-j));
}

/****************************************************************************/
/* Authenticated ESMTP client                                               */
/****************************************************************************/

static const char *start_esmtpauth(const char *, const char *, void *);
static const char *esmtpauth(const char *, void *);
static int final_esmtpauth(const char *, void *);
static int plain_esmtpauth(const char *, const char *, void *);

struct esmtpauthinfo {
	struct moduledel *del;
	struct ctlfile *ctf;
	int error_sent;
	} ;

static int authclient(struct moduledel *del, struct ctlfile *ctf,
		      const char *auth_key)
{
FILE	*configfile;
char	uidpwbuf[256];
char	*q;
const char *p;
struct authsaslclientinfo info;
struct esmtpauthinfo xinfo;
int	rc;

	q=config_localfilename("esmtpauthclient");
	configfile=fopen( q, "r");
	free(q);

	if (!configfile)	return (0);

	xinfo.del=del;
	xinfo.ctf=ctf;
	xinfo.error_sent=0;

	for (;;)
	{
		if (fgets(uidpwbuf, sizeof(uidpwbuf), configfile) == 0)
		{
			fclose(configfile);
			return (0);
		}
		q=strtok(uidpwbuf, " \t\r\n");

		if (!sockfdaddrname || !q)	continue;

#if	HAVE_STRCASECMP
		if (strcasecmp(q, auth_key) == 0)
			break;
#else
		if (stricmp(q, auth_key) == 0)
			break;
#endif
	}
	fclose(configfile);
	memset(&info, 0, sizeof(info));
	info.userid=strtok(0, " \t\r\n");
	info.password=strtok(0, " \t\r\n");

	info.sasl_funcs=authsasllist;

	info.start_conv_func= &start_esmtpauth;
	info.conv_func= &esmtpauth;
	info.final_conv_func= &final_esmtpauth;
	info.plain_conv_func= &plain_esmtpauth;
	info.conv_func_arg= &xinfo;

	rc=auth_sasl_client(&info);
	if (rc == AUTHSASL_NOMETHODS)
	{
		talking(del, ctf);
		hard_error(del, ctf,
			"Compatible SASL authentication not available.");
		return (-1);
	}

	if (rc && !xinfo.error_sent)
	{
		talking(del, ctf);
		soft_error(del, ctf, "Temporary SASL authentication error.");
	}

	if (rc)
		return (-1);

	if ((p=readline()) == 0)
	{
		talking(del, ctf);
		connect_error(del, ctf);
		return (-1);
	}

	if (*p != '1' && *p != '2' && *p != '3') /* Some kind of an error */
	{
		talking(del, ctf);
		sent(del, ctf, "AUTH");
		smtp_msg(del, ctf);
		while (!ISFINALLINE(p))
		{
			reply(del, ctf, p);
			if ((p=readline()) == 0)
			{
				connection_closed(del, ctf);
				return (-1);
			}
		}
		smtp_error(del, ctf, p);
		quit();
		return (-1);
	}

	return (0);
}

static const char *getresp(struct esmtpauthinfo *x)
{
const char *p=readline();

	if (p && *p == '3')
	{
		do
		{
			++p;
		} while ( isdigit((int)(unsigned char)*p));

		do
		{
			++p;
		} while ( isspace((int)(unsigned char)*p));
		return (p);
	}
	x->error_sent=1;
	talking(x->del, x->ctf);
	sent(x->del, x->ctf, "AUTH");
	smtp_msg(x->del, x->ctf);

	if (!p)
	{
		connection_closed(x->del, x->ctf);
		return (0);
	}

	while (!ISFINALLINE(p))
	{
		reply(x->del, x->ctf, p);
		if ((p=readline()) == 0)
		{
			connection_closed(x->del, x->ctf);
			return (0);
		}
	}
	smtp_error(x->del, x->ctf, p);
	return (0);
}

static const char *start_esmtpauth(const char *method, const char *arg,
	void *voidp)
{
	if (arg && !*arg)
		arg="=";

	if (dowritestr("AUTH ") || dowritestr(method) ||
			(arg && (dowritestr(" ") || dowritestr(arg))) ||
			dowritestr("\r\n") ||
		writeflush())
		return (0);

	return (getresp((struct esmtpauthinfo *)voidp));
}

static const char *esmtpauth(const char *msg, void *voidp)
{
	if (dowritestr(msg) || dowritestr("\r\n") || writeflush())
		return (0);
	return (getresp((struct esmtpauthinfo *)voidp));
}

static int final_esmtpauth(const char *msg, void *voidp)
{
	if (dowritestr(msg) || dowritestr("\r\n") || writeflush())
		return (AUTHSASL_CANCELLED);
	return (0);
}

static int plain_esmtpauth(const char *method, const char *arg,
	void *voidp)
{
	if (arg && !*arg)
		arg="=";

	if (dowritestr("AUTH ") || dowritestr(method) ||
			(arg && (dowritestr(" ") || dowritestr(arg))) ||
			dowritestr("\r\n") ||
		writeflush())
		return (AUTHSASL_CANCELLED);

	return (0);
}
