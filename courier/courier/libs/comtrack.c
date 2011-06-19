#include "comtrack.h"
#include "courier.h"
#include "localstatedir.h"
#include "numlib/numlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void trackpurge()
{
	DIR *dirp;
	struct dirent *de;
	time_t curTime=time(NULL) / 3600;
	char namebuf[sizeof(TRACKDIR) + NUMBUFSIZE+2];

	dirp=opendir(TRACKDIR);

	if (!dirp)
	{
		clog_msg_start_err();
		clog_msg_str("Cannot open ");
		clog_msg_str(TRACKDIR);
		clog_msg_send();
		clog_msg_prerrno();
		return;
	}

	while ((de=readdir(dirp)) != NULL)
	{
		if (de->d_name[0] == '.')
			continue;

		if (atoi(de->d_name) >= curTime - (TRACK_NHOURS+2))
			continue;


		strcat(strcpy(namebuf, TRACKDIR "/"), de->d_name);
		unlink(namebuf);
	}
	closedir(dirp);
}

int track_find(const char *address, time_t *timestamp)
{
	char namebuf[sizeof(TRACKDIR) + NUMBUFSIZE+2];
	char buf2[NUMBUFSIZE];
	FILE *fp;
	time_t curTime=time(NULL) / 3600;
	int i;
	char linebuf[BUFSIZ];
	char *p;
	char *addrbuf=strdup(address);
	int results=TRACK_NOTFOUND;

	if (!addrbuf)
		return TRACK_NOTFOUND;

	domainlower(addrbuf);

	for (i=0; i <= TRACK_NHOURS; ++i)
	{
		strcat(strcpy(namebuf, TRACKDIR "/"),
		       libmail_str_time_t(curTime - i, buf2));

		if ((fp=fopen(namebuf, "r")) == NULL)
			continue;

		while (fgets(linebuf, sizeof(linebuf), fp))
		{
			p=strchr(linebuf, '\n');
			if (p) *p=0;

			p=strchr(linebuf, ' ');
			if (!p)
				continue;
			++p;

			if (*p && strcmp(p+1, addrbuf) == 0)
			{
				if ((*timestamp=libmail_atotime_t(linebuf))
				    != 0)
					results=*p;
			}
		}
		fclose(fp);
		if (results != TRACK_NOTFOUND)
			break;
	}
	free(addrbuf);
	return results;
}

void track_save(const char *address, int status)
{
	char namebuf[sizeof(TRACKDIR) + NUMBUFSIZE+2];
	char buf2[NUMBUFSIZE];
	FILE *fp;
	time_t curTime=time(NULL);
	time_t t=curTime / 3600;
	char *addrbuf=strdup(address);

	if (!addrbuf)
		return;

	domainlower(addrbuf);

	strcat(strcpy(namebuf, TRACKDIR "/"), libmail_str_time_t(t, buf2));
	libmail_str_time_t(curTime, buf2);

	fp=fopen(namebuf, "a");
	if (fp)
	{
		fprintf(fp, "%s %c%s\n", buf2, (char)status, addrbuf);
		fclose(fp);
	}
	free(addrbuf);
}

int track_read(int (*cb_func)(time_t timestamp, int status,
			      const char *address, void *voidarg),
	       void *voidarg)
{
	char namebuf[sizeof(TRACKDIR) + NUMBUFSIZE+2];
	char buf2[NUMBUFSIZE];
	FILE *fp;
	time_t curTime=time(NULL) / 3600;
	int i;
	char linebuf[BUFSIZ];
	char *p;

	for (i=0; i <= TRACK_NHOURS; ++i)
	{
		strcat(strcpy(namebuf, TRACKDIR "/"),
		       libmail_str_time_t(curTime - i, buf2));

		if ((fp=fopen(namebuf, "r")) == NULL)
			continue;

		while (fgets(linebuf, sizeof(linebuf), fp))
		{
			p=strchr(linebuf, '\n');
			if (p) *p=0;

			p=strchr(linebuf, ' ');
			if (!p)
				continue;
			++p;

			if (*p)
			{
				int rc=(*cb_func)(libmail_atotime_t(linebuf),
						  *p, p+1, voidarg);

				if (rc)
				{
					fclose(fp);
					return rc;
				}
			}
		}
		fclose(fp);
	}

	return (0);
}
