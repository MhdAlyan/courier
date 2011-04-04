#
# Copyright 1998 - 2011 Double Precision, Inc.  See COPYING for
# distribution information.
#
# The correct ownership and permissions of installed files is set by
# setperms.sh.  To prevent even the slightest chance of a security breach,
# we'll install with all group and world permissions OFF, and let setperms.sh
# fix it.  configure.in changes the INSTALL macro for us.

@SET_MAKE@


CLEANFILES=$(BUILT_SOURCES) modules.lst.la makedat \
	mkimapdcert mkpop3dcert webgpg modules.ctl \
	pop3d.authpam imapd.authpam webmail.authpam imapd.cnf pop3d.cnf \
	imapd.dist imapd-ssl.dist pop3d.dist pop3d-ssl.dist \
	qutoawarnmsg.example quotawarnmsg.example \
	sharedindexsplit sharedindexinstall permissions.dat

DISTCLEANFILES=uidgid

DEBUGLIB=@DEBUGLIB@

BUILT_SOURCES=prefix.h exec_prefix.h sysconfdir.h localstatedir.h \
	libexecdir.h bindir.h sbindir.h datadir.h filtersocketdir.h \
	uidgid.h configargs.h sort.h

extrapkglib=makedatprog courierpop3login pcpd
pkglibexecdir=$(libexecdir)/courier
pkglibexec_PROGRAMS=aliasexp aliascombine aliascreate \
		sqwebmaild submit @EXTRAPKGLIB@

webmaildir=$(libexecdir)/courier/webmail
webmail_PROGRAMS=webmail webmlm

webmail_SOURCES=
sqwebmaild_SOURCES=

# Don't forget to change perms.sh.in, if webmailimagedir moves.

webmailimagedir=$(datadir)/sqwebmail/images

EXTRA_PROGRAMS=courierldapaliasd

extrabin=maildrop lockmail reformail reformime mailbot mimegpg \
	imapd makemime deliverquota maildirmake maildiracl maildirkw

bin_PROGRAMS=cancelmsg mailq sendmail \
	testmxlookup dotforward \
	couriermlm webmlmd \
	courier-config @couriertls@ @EXTRABIN@

bin_SCRIPTS=webmlmd.rc

extrasbin=couriertcpd$(EXEEXT)

sbinscripts=sharedindexsplit sharedindexinstall webmaild

sbin_SCRIPTS=@SBINSCRIPTS@
EXTRA_SCRIPTS=

sbin_PROGRAMS=courier showconfig showmodules aliaslookup \
	@COURIERLDAPALIASD@ @EXTRASBIN@

sysconf_DATA=pop3d.authpam imapd.authpam webmail.authpam imapd.cnf pop3d.cnf \
	courierd.dist @LDAPALIASRC@ \
	imapd.dist imapd-ssl.dist pop3d.dist pop3d-ssl.dist \
	quotawarnmsg.example webmlmrc.dist

databindir=$(datadir)
databin_SCRIPTS=courierctl.start makedat makealiases makehosteddomains \
	pop3d pop3d-ssl	mkimapdcert mkpop3dcert

mlmdatadir=$(datadir)/couriermlm
mlmdata_DATA=\
	adminrequest.tmpl \
	confsubj.tmpl \
	digestsubj.tmpl \
	fetchsubj.tmpl \
	fetch.tmpl \
	help.tmpl \
	idxheader2html.tmpl \
	idxheaderhtml.tmpl \
	idxheadertxt.tmpl \
	idxsubject.tmpl \
	modrejbody.tmpl \
	modrejheader.tmpl \
	modsubject.tmpl \
	modtext2.tmpl \
	modtext.tmpl \
	sub2.tmpl \
	sub3.tmpl \
	sub4.tmpl \
	sub5.tmpl \
	suback.tmpl \
	subjrequest.tmpl \
	subreportfooter.tmpl \
	subreporthdr1.tmpl \
	subreporthdr2.tmpl \
	subreporthdr3.tmpl \
	subreporthdr.tmpl \
	sub.tmpl \
	unsub2.tmpl \
	unsub3.tmpl \
	unsub.tmpl \
	warn1headers.tmpl \
	warn1text2.tmpl \
	warn1text.tmpl \
	warn2msg.tmpl \
	webmlm.tmpl \
\
	style.css.tmpl \
	webmlmconfirm.html \
	webmlmerror.tmpl.html \
	webmlmidx.html \
	webmlmlistadmin.tmpl.html \
	webmlmlistadminmod.tmpl.html \
	webmlmlistadminpw.tmpl.html \
	webmlmlistindex.tmpl.html \
	webmlmnotprocessed.html \
	webmlmpleasewait.tmpl.html \
	webmlmprocessed.html \
	webmlmrequestreceived.tmpl.html \
	webmlmsubinfo.tmpl.html \
	webmlmsublist.tmpl.html \
	webmlm.tmpl.html

extracmdlib=courierpop3d imaplogin
cmdlibdir=@libexecdir@/courier
cmdlib_PROGRAMS=submitmkdir courierd @EXTRACMDLIB@

# Subdirectories

SUBDIRS=libs filters doc webadmin @dirlist@

DIST_SUBDIRS=libs filters doc webadmin @distdirlist@

############################################################################
#
# Compile a list of core libraries.
#
############################################################################

# These are all the dependencies

COURIERDEPENDENCIES=libs/libmodule.la ../rfc822/librfc822.la libs/libcommon.la \
	libs/libcourier.la \
	modules.lst.la @dblibrary@ \
	../numlib/libnumlib.la \
	../unicode/libunicode.la

COURIERLDADD=libs/libmodule.la `cat modules.lst.la` \
	libs/libcommon.la \
	libs/libcourier.la \
	../rfc822/librfc822.la @dblibrary@ ../numlib/libnumlib.la \
	../unicode/libunicode.la

modules.lst.la: create-modules.lst
	@:

create-modules.lst:
	@chmod +x mkmodules.sh		# autoconf sucks
	@./mkmodules.sh @dirlist@


# showmodules utility - shows module configuration

showmodules_SOURCES=cppmain.C showmodules.C
showmodules_DEPENDENCIES=$(COURIERDEPENDENCIES) ../tcpd/libspipe.la ../soxwrap/libsoxwrap.a ../soxwrap/soxlibs.dep
showmodules_LDADD=$(COURIERLDADD) ../tcpd/libspipe.la ../soxwrap/libsoxwrap.a `cat ../soxwrap/soxlibs.dep` -lcourierauth
showmodules_LDFLAGS=`@COURIERAUTHCONFIG@ --ldflags`

# showconfig utility - shows configuration

showconfig_SOURCES=cppmain.C showconfig.C
showconfig_DEPENDENCIES=$(COURIERDEPENDENCIES) module.esmtp/esmtpconfig.o
showconfig_LDADD=$(COURIERLDADD) module.esmtp/esmtpconfig.o
showconfig_LDFLAGS=$(COURIERLDFLAGS)

# submit - message submission

submit_SOURCES=bofh.c bofh.h cppmain.C submit.h submit.C submit2.C submit3.C \
	cdfilters.C cdfilters.h ldapaliasdrc.h ldapaliasdrc.c

submit_DEPENDENCIES=../rfc1035/librfc1035.a \
	../rfc2045/librfc2045.la \
	$(COURIERDEPENDENCIES) \
	../afx/libafx.a \
	../tcpd/libspipe.la \
	../md5/libmd5.la ../random128/librandom128.la \
	../soxwrap/libsoxwrap.a \
	../soxwrap/soxlibs.dep

submit_LDADD=../rfc1035/librfc1035.a \
	../rfc2045/librfc2045.la \
	$(COURIERLDADD) \
	../tcpd/libspipe.la \
	../md5/libmd5.la ../random128/librandom128.la \
	../soxwrap/libsoxwrap.a \
	../unicode/libunicode.la \
	`cat ../soxwrap/soxlibs.dep` \
	../afx/libafx.a @NETLIBS@ -lcourierauth

submit_LDFLAGS=`@COURIERAUTHCONFIG@ --ldflags`

# aliaslook - resolve aliases

aliaslookup_SOURCES=aliaslookup.C ldapaliasdrc.c
aliaslookup_DEPENDENCIES=libs/libcommon.la libs/libcourier.la ../afx/libafx.a
aliaslookup_LDADD=libs/libcommon.la libs/libcourier.la ../afx/libafx.a\
	@dblibrary@ @NETLIBS@

# ldapaliasd - resolve aliases via LDAP

courierldapaliasd_SOURCES=ldapaliasd.c ldapaliasdrc.h ldapaliasdrc.c
courierldapaliasd_DEPENDENCIES=../liblock/liblock.la ../numlib/libnumlib.la
courierldapaliasd_LDADD=../liblock/liblock.la ../numlib/libnumlib.la \
	-lcourierauthcommon @LDAPLIBS@ @NETLIBS@
courierldapaliasd_LDFLAGS=`@COURIERAUTHCONFIG@ --ldflags`

# submitmkdir - create subdirectory in tmp for submit (needs +s privs)

submitmkdir_SOURCES=submitmkdir.c
submitmkdir_DEPENDENCIES=libs/libcourier.la
submitmkdir_LDADD=libs/libcourier.la

# sendmail - sendmail wrapper for submit (needs +g privs)

sendmail_SOURCES=sendmail.c sendmail-esmtpd-wrapper.c
sendmail_DEPENDENCIES=libs/libcommon.la libs/libcourier.la ../rfc822/librfc822.la\
	../numlib/libnumlib.la ../unicode/libunicode.la
sendmail_LDADD=$(sendmail_DEPENDENCIES)

# makedat - generic GDBM file create tool

makedatprog$(EXEEXT): ../makedat/makedatprog$(EXEEXT)
	cp -f ../makedat/makedatprog$(EXEEXT) .

makedat: ../makedat/makedat
	cp -f ../makedat/makedat .

# testmxlookup - look up MX records

testmxlookup_SOURCES=testmxlookup.c
testmxlookup_DEPENDENCIES=../rfc1035/librfc1035.a ../soxwrap/libsoxwrap.a ../soxwrap/soxlibs.dep libs/libcourier.la \
	../md5/libmd5.la ../random128/librandom128.la

testmxlookup_LDADD=../rfc1035/librfc1035.a ../soxwrap/libsoxwrap.a `cat ../soxwrap/soxlibs.dep` libs/libcourier.la \
	../md5/libmd5.la ../random128/librandom128.la \
	@dblibrary@ @NETLIBS@

# maildirmake - create a maildir


maildirmake$(EXEEXT): ../maildir/maildirmake$(EXEEXT)
	cp -f ../maildir/maildirmake$(EXEEXT) .

maildiracl$(EXEEXT): ../maildir/maildiracl$(EXEEXT)
	cp -f ../maildir/maildiracl$(EXEEXT) .

# maildirkw - set maildir keywords

maildirkw$(EXEEXT): ../maildir/maildirkw$(EXEEXT)
	cp -f ../maildir/maildirkw$(EXEEXT) .

# aliasexp - first step in building an alias list, normalize alias file

aliasexp_SOURCES=cppmain.C aliasexp.C
aliasexp_DEPENDENCIES=$(COURIERDEPENDENCIES) ../tcpd/libspipe.la ../soxwrap/libsoxwrap.a ../soxwrap/soxlibs.dep ../afx/libafx.a
aliasexp_LDADD=$(COURIERLDADD) ../tcpd/libspipe.la ../soxwrap/libsoxwrap.a `cat ../soxwrap/soxlibs.dep` ../afx/libafx.a -lcourierauth
aliasexp_LDFLAGS=`@COURIERAUTHCONFIG@ --ldflags`

# aliascombine - Merge alias specifications

aliascombine_SOURCES=cppmain.C aliascombine.C
aliascombine_DEPENDENCIES=@dblibrary@ libs/libcommon.la libs/libcourier.la ../afx/libafx.a ../numlib/libnumlib.la
aliascombine_LDADD=@dblibrary@ libs/libcommon.la libs/libcourier.la ../afx/libafx.a ../numlib/libnumlib.la

# aliascreate - create GDBM alias database

aliascreate_SOURCES=cppmain.C aliascreate.C
aliascreate_DEPENDENCIES=libs/libcommon.la libs/libcourier.la @dblibrary@ ../afx/libafx.a
aliascreate_LDADD=libs/libcommon.la libs/libcourier.la @dblibrary@ ../afx/libafx.a

# pop3d - Maildir POP3 server.

courierpop3d$(EXEEXT): ../imap/pop3d$(EXEEXT)
	cp -f ../imap/pop3d$(EXEEXT) courierpop3d$(EXEEXT)

# mailq - show mail queue

mailq_SOURCES=mailq.c
mailq_DEPENDENCIES=libs/libcommon.la libs/libcourier.la ../numlib/libnumlib.la
mailq_LDADD=libs/libcommon.la libs/libcourier.la ../numlib/libnumlib.la

# courierd

courierd_SOURCES=cddrvinfo.C cddrvinfo.h\
	cddlvrhost.C cddlvrhost.h\
	cddelinfo.C cddelinfo.h\
	cdmsgq.C cdmsgq.h cdmsgq2.C cdmsgq3.C \
	cdpendelinfo.C cdpendelinfo.h\
	cdrcptinfo.C cdrcptinfo.h\
	courierdb.C courierd.C courierd.h mydirent.h

courierd_DEPENDENCIES=$(COURIERDEPENDENCIES) ../afx/libafx.a ../liblock/liblock.la ../tcpd/libspipe.la ../soxwrap/libsoxwrap.a ../soxwrap/soxlibs.dep
courierd_LDADD=$(COURIERLDADD) ../afx/libafx.a ../liblock/liblock.la ../tcpd/libspipe.la ../soxwrap/libsoxwrap.a `cat ../soxwrap/soxlibs.dep` $(DEBUGLIB) -lcourierauth
courierd_LDFLAGS=`@COURIERAUTHCONFIG@ --ldflags`

# tcpd

couriertcpd$(EXEEXT): ../tcpd/couriertcpd$(EXEEXT)
	cp -f ../tcpd/couriertcpd$(EXEEXT) .

couriertls$(EXEEXT): ../tcpd/couriertls$(EXEEXT)
	cp -f ../tcpd/couriertls$(EXEEXT) .

# pop3 login

courierpop3login$(EXEEXT): ../imap/pop3login$(EXEEXT)
	cp -f ../imap/pop3login$(EXEEXT) courierpop3login$(EXEEXT)

# couriermlm

couriermlm_SOURCES= cmlm.C cmlm.h cmlm2.C cmlm3.C cmlmarchive.C cmlmarchive.h \
	cmlmbounce.C cmlmbounce.h cmlmcleanup.C cmlmcleanup.h cmlmcmdmisc.C \
	cmlmcmdmisc.h cmlmdigest.C cmlmfetch.C cmlmfetch.h cmlmmoderate.C \
	cmlmmoderate.h cmlmstartmail.C cmlmstartmail.h cmlmsublist.C \
	cmlmsublist.h cmlmsubunsub.C cmlmsubunsub.h cmlmsubunsubmsg.C \
	cmlmsubunsubmsg.h

couriermlm_DEPENDENCIES=../afx/libafx.a ../rfc822/librfc822.la \
	../liblock/liblock.la ../random128/librandom128.la ../md5/libmd5.la \
	../numlib/libnumlib.la ../unicode/libunicode.la @dblibrary@
couriermlm_LDADD=$(couriermlm_DEPENDENCIES)

# webmlm

webmlm_SOURCES=webmlm.c
webmlm_DEPENDENCIES=../cgi/libcgi.la
webmlm_LDADD=$(webmlm_DEPENDENCIES) @NETLIBS@

# webmlmd

webmlmd_SOURCES=webmlmd.C webmlmd.H \
		webmlmdcmlm.C webmlmdcmlm.H \
		webmlmddirs.C webmlmddirs.H \
		webmlmdhandlers.C webmlmdhandlers.H webmlmdhandlerslist.H \
\
		webmlmdmod.C \
		webmlmdsublist.C \
		cmlm2.C cmlmsublist.C

webmlmd_DEPENDENCIES=../webmail/libwebmail.la \
			../cgi/libcgi.la ../rfc2045/librfc2045.la \
			../rfc822/librfc822.la ../numlib/libnumlib.la \
			../liblock/liblock.la \
			../unicode/libunicode.la @dblibrary@
webmlmd_LDADD=$(webmlmd_DEPENDENCIES) @NETLIBS@

BUILT_SOURCES += webmlmdhandlerslist.H

sort.h:
	echo '#define SORT "$(SORT)"' >sort.h

webmlmdhandlerslist.H: update-handler-list

.PHONY: update-handler-list

update-handler-list:
	cat $(srcdir)/webmlmd*C | sed -n '/^HANDLER(/'p >webmlmdhandlerslist.H.tmp
	cmp -s webmlmdhandlerslist.H.tmp webmlmdhandlerslist.H || mv -f webmlmdhandlerslist.H.tmp webmlmdhandlerslist.H
	rm -f webmlmdhandlerslist.H.tmp

# dotforward

dotforward_SOURCES=dotforward.c
dotforward_DEPENDENCIES=../rfc822/librfc822.la libs/libcourier.la \
			../unicode/libunicode.la @dblibrary@
dotforward_LDADD=$(dotforward_DEPENDENCIES)

# courier - start, stop, restart courier

courier_SOURCES=courier.c courier2.C
courier_DEPENDENCIES=libs/libcommon.la libs/libcourier.la ../liblock/liblock.la \
		../numlib/libnumlib.la
courier_LDADD=$(courier_DEPENDENCIES)

cancelmsg_SOURCES=cancelmsg.c
cancelmsg_DEPENDENCIES=libs/libcommon.la libs/libcourier.la ../numlib/libnumlib.la
cancelmsg_LDADD=$(cancelmsg_DEPENDENCIES)

# courier-config

courier_config_SOURCES=courier-config.c

EXTRA_DIST= testsuite.alias testsuite.alias1.in testsuite.alias2.in \
		aliases.config smtpaccess.config \
		dotforward.tst dotforward.tst.chk \
		webmaild.in ldapaliasrc.dist \
		$(mlmdata_DATA)

sharedindexsplit: ../maildir/sharedindexsplit
	cp -f ../maildir/sharedindexsplit .

sharedindexinstall: ../maildir/sharedindexinstall
	cp -f ../maildir/sharedindexinstall .

uidgid.h: config.status
	echo "#define MAILUSER \"$(mailuser)\"" >uidgid.h
	echo "#define MAILGROUP \"$(mailgroup)\"" >>uidgid.h
	echo "#define MAILUID $(mailuid)" >>uidgid.h
	echo "#define MAILGID $(mailgid)" >>uidgid.h

configargs.h: ../configure.args
	echo "#define CONFIGURE_ARGS \"`cat ../configure.args`\"" >configargs.h

prefix.h: config.status
	echo "#define PREFIX \"$(prefix)\"" >prefix.h

exec_prefix.h: config.status
	echo "#define EXEC_PREFIX \"$(exec_prefix)\"" >exec_prefix.h

sysconfdir.h: config.status
	echo "#define SYSCONFDIR \"$(sysconfdir)\"" >sysconfdir.h

localstatedir.h: config.status
	echo "#define LOCALSTATEDIR \"$(localstatedir)\"" >localstatedir.h

libexecdir.h: config.status
	echo "#define LIBEXECDIR \"$(libexecdir)\"" >libexecdir.h

bindir.h: config.status
	echo "#define BINDIR \"$(bindir)\"" >bindir.h

mkimapdcert: ../imap/mkimapdcert
	cp -f ../imap/mkimapdcert .

mkpop3dcert: ../imap/mkpop3dcert
	cp -f ../imap/mkpop3dcert .

imapd.cnf: ../imap/imapd.cnf
	cp -f ../imap/imapd.cnf .

pop3d.cnf: ../imap/pop3d.cnf
	cp -f ../imap/pop3d.cnf .

imapd.dist: ../imap/imapd.dist
	cp -f ../imap/imapd.dist .

imapd-ssl.dist: ../imap/imapd-ssl.dist
	cp -f ../imap/imapd-ssl.dist .

pop3d.dist: ../imap/pop3d.dist
	cp -f ../imap/pop3d.dist .

pop3d-ssl.dist: ../imap/pop3d-ssl.dist
	cp -f ../imap/pop3d-ssl.dist .

quotawarnmsg.example: ../maildir/quotawarnmsg
	cp -f $(srcdir)/../maildir/quotawarnmsg quotawarnmsg.example

filtersocketdir=$(localstatedir)/filters
allfiltersocketdir=$(localstatedir)/allfilters

filtersocketdir.h: config.status
	echo '#define FILTERSOCKETDIR "$(filtersocketdir)"' >filtersocketdir.h
	echo '#define ALLFILTERSOCKETDIR "$(allfiltersocketdir)"' >>filtersocketdir.h

sbindir.h: config.status
	echo "#define SBINDIR \"$(sbindir)\"" >sbindir.h

datadir.h: config.status
	echo "#define DATADIR \"$(datadir)\"" >datadir.h

#
# modules.lst should contain a list of additional static libraries that
# any program that uses rewriting should link with.
#
# We want to always execute the mkmodules.sh script, but only relink if
# modules.lst is modified.
#

# Copy over imap

imapd$(EXEEXT): ../imap/imapd$(EXEEXT)
	cp -f ../imap/imapd$(EXEEXT) .

imaplogin$(EXEEXT): ../imap/imaplogin$(EXEEXT)
	cp -f ../imap/imaplogin$(EXEEXT) .

pop3d.authpam: ../imap/pop3d.pam
	cp -f ../imap/pop3d.pam pop3d.authpam

imapd.authpam: ../imap/imapd.pam
	cp -f ../imap/imapd.pam imapd.authpam

webmail.authpam: ../webmail/webmail.authpam
	cp -f ../webmail/webmail.authpam .

# pcpd - groupware calendaring daemon

pcpd$(EXEEXT): ../pcp/pcpd$(EXEEXT)
	cp -f ../pcp/pcpd$(EXEEXT) .

# Copy over maildrop

maildrop$(EXEEXT): ../maildrop/maildrop$(EXEEXT)
	cp -f ../maildrop/maildrop$(EXEEXT) .

lockmail$(EXEEXT): ../liblock/lockmail$(EXEEXT)
	cp -f ../liblock/lockmail .

reformail$(EXEEXT): ../maildrop/reformail$(EXEEXT)
	cp -f ../maildrop/reformail$(EXEEXT) .

mailbot$(EXEEXT): ../maildrop/mailbot$(EXEEXT)
	cp -f ../maildrop/mailbot$(EXEEXT) .

reformime$(EXEEXT): ../rfc2045/reformime$(EXEEXT)
	cp -f ../rfc2045/reformime$(EXEEXT) .

mimegpg$(EXEEXT): ../gpglib/mimegpg$(EXEEXT)
	cp -f ../gpglib/mimegpg$(EXEEXT) .

makemime$(EXEEXT): ../rfc2045/makemime$(EXEEXT)
	cp -f ../rfc2045/makemime$(EXEEXT) .

../webmail/sqwebmail$(EXEEXT):
	:

 ../webmail/sqwebmaild$(EXEEXT):
	:

webmail$(EXEEXT): ../webmail/sqwebmail$(EXEEXT)
	cp -f ../webmail/sqwebmail$(EXEEXT) webmail$(EXEEXT)

sqwebmaild$(EXEEXT): ../webmail/sqwebmaild$(EXEEXT)
	cp -f ../webmail/sqwebmaild$(EXEEXT) sqwebmaild$(EXEEXT)

deliverquota$(EXEEXT): ../maildir/deliverquota$(EXEEXT)
	cp -f ../maildir/deliverquota$(EXEEXT) deliverquota$(EXEEXT)


dist-hook:
	rm -f $(distdir)/lcrwstatic.h

install-exec-hook:
	for d in $(bindir) $(sbindir) $(libexecdir) $(libexecdir)/courier \
		$(sysconfdir)/filters \
		$(localstatedir) $(localstatedir)/tmp\
		$(webmaildir)\
		$(localstatedir)/track\
		$(localstatedir)/msgs $(localstatedir)/msgq ; do \
			$(mkinstalldirs) $(DESTDIR)$$d || :; done
	$(INSTALL_SCRIPT) imapd.rc $(DESTDIR)$(datadir)/imapd
	$(INSTALL_SCRIPT) imapd-ssl.rc $(DESTDIR)$(datadir)/imapd-ssl
	rm -f $(DESTDIR)$(sbindir)/imapd
	$(LN_S) $(datadir)/imapd $(DESTDIR)$(sbindir)/imapd
	rm -f $(DESTDIR)$(sbindir)/imapd-ssl
	$(LN_S) $(datadir)/imapd-ssl $(DESTDIR)$(sbindir)/imapd-ssl
	rm -f $(DESTDIR)$(sbindir)/mkimapdcert
	$(LN_S) $(datadir)/mkimapdcert $(DESTDIR)$(sbindir)/mkimapdcert
	rm -f $(DESTDIR)$(sbindir)/mkpop3dcert
	$(LN_S) $(datadir)/mkpop3dcert $(DESTDIR)$(sbindir)/mkpop3dcert
	rm -f $(DESTDIR)$(bindir)/makedat
	$(LN_S) $(datadir)/makedat $(DESTDIR)$(bindir)/makedat
	for f in makealiases makehosteddomains pop3d pop3d-ssl \
		; do rm -f $(DESTDIR)$(sbindir)/$$f ; \
		$(LN_S) $(datadir)/$$f $(DESTDIR)$(sbindir)/$$f ; done
	rm -f $(DESTDIR)$(sbindir)/webgpg ; $(LN_S) $(datadir)/sqwebmail/webgpg $(DESTDIR)$(sbindir)/webgpg
	$(INSTALL_PROGRAM) ../webadmin/webadmin $(DESTDIR)$(webmaildir)/webadmin
	mkdir -p $(DESTDIR)$(sysconfdir)/shared
	chmod 755 $(DESTDIR)$(sysconfdir)/shared
	mkdir -p $(DESTDIR)$(sysconfdir)/shared.tmp
	chmod 755 $(DESTDIR)$(sysconfdir)/shared.tmp


install-data-hook:
	-$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/aliases
	-$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/smtpaccess
	-$(mkinstalldirs) $(DESTDIR)$(sysconfdir)/aliasdir
	echo @MAILDROP@ >$(DESTDIR)$(sysconfdir)/maildrop
	test -f $(DESTDIR)$(sysconfdir)/enablefiltering && exit 0; \
		echo esmtp >$(DESTDIR)$(sysconfdir)/enablefiltering
	test -f $(DESTDIR)$(sysconfdir)/aliases/system && exit 0; \
		$(INSTALL_DATA) $(srcdir)/aliases.config \
			$(DESTDIR)$(sysconfdir)/aliases/system
	test -f $(DESTDIR)$(sysconfdir)/smtpaccess/default && exit 0; \
		$(INSTALL_DATA) $(srcdir)/smtpaccess.config \
			$(DESTDIR)$(sysconfdir)/smtpaccess/default
	rm -f $(DESTDIR)$(bindir)/rmail
	$(LN_S) sendmail $(DESTDIR)$(bindir)/rmail
	-$(mkinstalldirs) $(DESTDIR)@mandir@/man8
	-$(mkinstalldirs) $(DESTDIR)$(webmailimagedir)
	for f in `cat ../webmail/images/filelist` ; do \
		$(INSTALL_DATA) $(srcdir)/../webmail/images/$$f \
			$(DESTDIR)$(webmailimagedir) ; done

install-permissions: perms.sh
	@chmod +x perms.sh setperms.sh
	@MAKE=$(MAKE) ./setperms.sh "$(DESTDIR)"

uninstall-local:
	rm -f $(DESTDIR)$(bindir)/makedat
	for f in makealiases makehosteddomains webgpg pop3d pop3d-ssl \
		; do rm -f $(DESTDIR)$(sbindir)/$$f \
		; done
	rm -f $(DESTDIR)$(sysconfdir)/aliases/system
	rm -f $(DESTDIR)$(sysconfdir)/smtpaccess/default
	rm -f $(DESTDIR)$(bindir)/rmail
	rm -f $(DESTDIR)$(sbindir)/imapd
	rm -f $(DESTDIR)$(sbindir)/imapd-ssl
	rm -f $(DESTDIR)$(datadir)/imapd
	rm -f $(DESTDIR)$(datadir)/imapd-ssl
	rm -f $(DESTDIR)$(sbindir)/mkimapdcert
	rm -f $(DESTDIR)$(sbindir)/mkpop3dcert
	rm -f $(DESTDIR)$(sysconfdir)/maildrop
	rm -f $(DESTDIR)$(sysconfdir)/enablefiltering
	for f in `cat ../webmail/images/filelist` ; do \
		rm -f $(DESTDIR)$(webmailimagedir)/$$f ; done
	rm -f $(DESTDIR)$(webmaildir)/webadmin

install-perms:
	@$(MAKE) install-perms-recursive
	@$(MAKE) install-perms-local

install-perms-recursive:
	@>permissions.dat
	@SUBDIRS="$(SUBDIRS)" ; for f in $$SUBDIRS ; do ( cd $$f && $(MAKE) $(AM_MAKEFLAGS) install-perms ) ; cat /dev/null >>$$f/permissions.dat ; cat $$f/permissions.dat >>permissions.dat ; done

install-perms-local:
	@chmod +x perms.sh
	@./perms.sh >>permissions.dat
#
# Lame regression test.
#
check-am:
	./aliascreate -tmp=./testsuite.tmp -dump=1 <$(srcdir)/testsuite.alias1.in | sed '/^$$/d' | sort | cmp -s $(srcdir)/testsuite.alias -
	./aliascreate -tmp=./testsuite.tmp -dump=1 <$(srcdir)/testsuite.alias2.in | sed '/^$$/d' | sort | cmp -s $(srcdir)/testsuite.alias -
	$(srcdir)/dotforward.tst | cmp -s $(srcdir)/dotforward.tst.chk -
