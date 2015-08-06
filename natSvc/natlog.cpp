/*
 * Copyright (C) 2015 Maxim Nestratov
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#define _CRT_SECURE_NO_WARNINGS

#include <wtypes.h>
#include <io.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
  

#include "natlog.h"

NATCL_LOG			*namp_log = NULL;					// logging device interface class

VOID natvDbgOut(TCHAR *psz_data)
{
	TCHAR tsz_buffer[1024];
	if (_tcslen(psz_data) > 1000)
	{
		_tcsncpy(tsz_buffer,psz_data,1000);
		tsz_buffer[1000] = _T('\0');
		tsz_buffer[1001] = _T('\0');
	}
	else 
	{
		_tcscpy(tsz_buffer,psz_data);
	}
	_tcscat(tsz_buffer,_T("\n"));
	OutputDebugString(tsz_buffer);
	printf(tsz_buffer);
}


NATCL_LOG::NATCL_LOG(const CHAR _s_app_name[], const CHAR _suffix[],const CHAR _bin_dir[])
{
	InitializeCriticalSection(&cs);

	strcpy(s_bin_dir,_bin_dir);
	strcpy(s_suffix,_suffix);
	strcpy(s_appname,_s_app_name);

	// default logging
	u_log_msg_mask = NATLOG_ERROR | NATLOG_GENERAL | NATLOG_WARNING;

	u_log_msg_mask |= NATLOG_RULE;
	u_log_msg_mask |= NATLOG_NAT;

#ifdef _DEBUG

	u_log_msg_mask |= NATLOG_DUMP;
	u_log_msg_mask |= NATLOG_DEBUG;
#endif

	u_log_days = 10;

	memset(&time_stamp,0,sizeof(time_stamp));
}

NATCL_LOG::~NATCL_LOG()
{
	EnterCriticalSection(&cs);

	if(flog){
		fflush(flog);
		fclose(flog);
	}

	LeaveCriticalSection(&cs);

	DeleteCriticalSection(&cs);
}


void  NATCL_LOG::vMakeFileName()
{
	SYSTEMTIME st;

	GetLocalTime(&st);

	EnterCriticalSection(&cs);
	sprintf(s_file_name,"%s\\Log\\%s.log",s_bin_dir,s_suffix);
	LeaveCriticalSection(&cs);
}

ULONG NATCL_LOG::eInitializeLog()
{
	char tmpstr[MAX_PATH];

	vMakeFileName();

	flog = fopen(s_file_name, "wt");
	if(!flog)
	{
		strcpy(tmpstr,s_bin_dir);
		strcat(tmpstr,"\\log");
		CreateDirectory(tmpstr,NULL);

		flog = fopen(s_file_name, "wt");
		if(!flog)
			return -1;
	}

	GetLocalTime(&time_stamp);
	return 0;
}

int NATCL_LOG::iGetDateByFilename (char *fname, WORD *year, WORD *month, WORD *day)
{
	int rc = 0;
	int d,m,y;
	char tmpname[50];

	strcpy(tmpname,fname);
	
	if (tmpname[8] != '.') return 1;
	tmpname[2] = tmpname[5] = tmpname[8] = ' ';

	rc = sscanf (tmpname, "%d%d%d",&y, &m, &d);

	if (rc != 3 || m > 12 || d > 31) return 1;

	*year  = (WORD)y;
	*month = (WORD)m;
	*day   = (WORD)d;

	return 0;
}

void NATCL_LOG::vFindFirstLeftDate (SYSTEMTIME* st)
{
	FILETIME ft;
	ULARGE_INTEGER uli0, uli1;

	SystemTimeToFileTime (st, &ft);
	memcpy(&uli0,&ft,sizeof(FILETIME));

	uli1.QuadPart = uli0.QuadPart - Int32x32To64(u_log_days*24*60*60, 1000*1000*10);

	memcpy(&ft,&uli1,sizeof(FILETIME));
	FileTimeToSystemTime(&ft, st);
}

int NATCL_LOG::iCompareSYSTEMTIME (SYSTEMTIME time1, SYSTEMTIME time2)
{
	// Returns:
	//	1	- if time1 > time2; 
	//	0	- if time1 = time2; 
	//	-1	- if time1 < time2}
	FILETIME ft1, ft2;
	ULARGE_INTEGER uli1, uli2;

	SystemTimeToFileTime (&time1, &ft1);
	memcpy(&uli1,&ft1,sizeof(FILETIME));

	SystemTimeToFileTime (&time2, &ft2);
	memcpy(&uli2,&ft2,sizeof(FILETIME));

	if (uli1.QuadPart > uli2.QuadPart) return 1;
	else
		if (uli1.QuadPart < uli2.QuadPart) return -1;
		else return 0;
}

void NATCL_LOG::vDeleteOldLogFiles ()
{
	_finddata_t	fdata_t;
	char*		fname;
	char		del_name[MAX_PATH];
	char		filename[MAX_PATH];
	SYSTEMTIME	st, fst;
	char		tmpstr[300];
	long		shandle;
	int			rc = 0;

	GetLocalTime(&st);
	vFindFirstLeftDate (&st);
	fst = st;

	sprintf(filename,"%s\\..\\Log\\??_??_??_%s.log",s_bin_dir,s_suffix);
	shandle = _findfirst (filename, &fdata_t);
	if (shandle == -1) return;

	do
	{
		fname = fdata_t.name;
		rc = iGetDateByFilename (fname, &fst.wYear, &fst.wMonth, &fst.wDay);
		if(rc)	continue;

		if (iCompareSYSTEMTIME (fst, st) == -1) 
		{
			sprintf(del_name,"%s\\..\\Log\\%s",s_bin_dir,fname);
			remove(del_name);

			sprintf(tmpstr, "Remove %s",del_name);
			vWriteLog(tmpstr, NATLOG_GENERAL);
		}

	} while ( -1 != _findnext (shandle, &fdata_t) );

	return;
}

void NATCL_LOG::vChangeLog()
{
	vWriteLog("The file is closed. A new log file is created",NATLOG_GENERAL);
	vMakeFileName();
	vWriteLog("",NATLOG_GENERAL);

	vDeleteOldLogFiles();
}


void NATCL_LOG::vWriteLog(char* text, int msgtype)
{

__try
{
	char timebuf[40], msg_name[10], msgbuf[NAT_MAX_STR_LEN];
	
	if( (u_log_msg_mask & msgtype) == 0) 
		return;

	SYSTEMTIME st;
	GetLocalTime(&st);

	sprintf(timebuf,
			"%02u:%02u:%02u:%03u",
			st.wHour,
			st.wMinute,
			st.wSecond,
			st.wMilliseconds);

  
	EnterCriticalSection(&cs);

	if(time_stamp.wDay != st.wDay){

		time_stamp = st;
	}

	if(NULL == flog){

		LeaveCriticalSection(&cs);
		return;
	}

	INT i_str_len;

	switch(msgtype)
	{
	case NATLOG_ERROR:		strcpy(msg_name,"ERROR   :"); break;
	case NATLOG_GENERAL:	strcpy(msg_name,"GENERAL :"); break;
	case NATLOG_WARNING:	strcpy(msg_name,"WARNING :"); break;
	case NATLOG_DEBUG:		strcpy(msg_name,"DEBUG   :"); break;
	case NATLOG_NAT:		strcpy(msg_name,"NAT     :"); break;
	case NATLOG_RULE:		strcpy(msg_name,"FIREWALL:"); break;
	case NATLOG_DUMP:		strcpy(msg_name,"DUMP    :"); break;
	default:					strcpy(msg_name,"???     :"); 
	}

	sprintf(msgbuf,"[%s,%s][%s] ",timebuf,s_appname,msg_name);

	i_str_len = strlen(msgbuf);

	if((INT)strlen(text) >= NAT_MAX_STR_LEN - i_str_len){
		strncpy(msgbuf + i_str_len,text,NAT_MAX_STR_LEN - i_str_len - 1);
		msgbuf[NAT_MAX_STR_LEN - 1] = 0;
	}
	else
		strcat(msgbuf,text);

    fprintf(flog,"%s\n",msgbuf);

	fflush(flog);

#ifdef _DEBUG
	natvDbgOut(msgbuf);
#endif // _DEBUG


}//__try
__except (( GetExceptionCode() )? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_EXECUTE_HANDLER)
{
}

	LeaveCriticalSection(&cs);
}

VOID natvLog(ULONG mask, char* format, ...)
{
	va_list	marker;
	char	text[NAT_MAX_STR_LEN];

	va_start( marker, format );
	vsprintf( text, format, marker );
	va_end( marker );

	namp_log->vWriteLog( text, mask);
}

VOID natvLogV(char* func, int line, ULONG mask, char* format, ...)
{
	va_list	marker;
	char	text[NAT_MAX_STR_LEN];

	va_start( marker, format );
	vsprintf( text, format, marker );
	va_end( marker );

	namp_log->vWriteLog( text, mask);
}

VOID natvDumpBYTE(PVOID p_data, ULONG u_len)
{
	CHAR text[NAT_MAX_STR_LEN];
	CHAR tmpstr[NAT_MAX_STR_LEN];

	text[0] = 0;

	for(ULONG i = 0; i<u_len;i++){

		if(strlen(text) + 5 >= NAT_MAX_STR_LEN){

			namp_log->vWriteLog( text, NATLOG_DUMP);
			namp_log->vWriteLog( "DUMP ABORTED", NATLOG_DUMP);
			return;
		}

		sprintf(tmpstr,"0x%02X ",((PUCHAR)p_data)[i]);
		strcat(text,tmpstr);
	}
		
	namp_log->vWriteLog( text, NATLOG_DUMP);
}


VOID natvDumpWORD(PVOID p_data, ULONG u_len)
{
	CHAR text[NAT_MAX_STR_LEN];
	CHAR tmpstr[NAT_MAX_STR_LEN];

	text[0] = 0;

	for(ULONG i = 0; i<u_len/sizeof(USHORT);i++){

		if(strlen(text) + 7 >= NAT_MAX_STR_LEN){

			namp_log->vWriteLog( text, NATLOG_DUMP);
			namp_log->vWriteLog( "DUMP ABORTED", NATLOG_DUMP);
			return;
		}

		sprintf(tmpstr,"0x%04X ",((PUSHORT)p_data)[i]);
		strcat(text,tmpstr);
	}
		
	namp_log->vWriteLog( text, NATLOG_DUMP);
}

VOID natvDumpDWORD(PVOID p_data, ULONG u_len)
{
	CHAR text[NAT_MAX_STR_LEN];
	CHAR tmpstr[NAT_MAX_STR_LEN];

	text[0] = 0;

	for(ULONG i = 0; i<u_len/sizeof(ULONG);i++){

		if(strlen(text) + 11 >= NAT_MAX_STR_LEN){

			namp_log->vWriteLog( text, NATLOG_DUMP);
			namp_log->vWriteLog( "DUMP ABORTED", NATLOG_DUMP);
			return;
		}

		sprintf(tmpstr,"0x%08X ",((PULONG)p_data)[i]);
		strcat(text,tmpstr);
	}
		
	namp_log->vWriteLog( text, NATLOG_DUMP);
}

