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

#ifndef _NATLOG_HEADER_
#define _NATLOG_HEADER_

// LOGMASK values
#define NATLOG_ERROR	0x80000000	// Non maskable fatal error message
#define NATLOG_GENERAL	0x40000000	// Non maskable general message
#define NATLOG_WARNING	0x00000001	// Maskable warning messages (non-critical error)
#define NATLOG_DEBUG	0x00000002	// debug build messages
#define NATLOG_NAT		0x00000008	// Maskable traffic messages
#define NATLOG_RULE		0x00000010	// Maskable rules messages
#define NATLOG_DUMP		0x00000100	// Maskable memory dump

class NATCL_LOG{

public:
	 NATCL_LOG(const CHAR s_app_name[], const CHAR s_prefix[],const CHAR s_bin_dir[]);
	~NATCL_LOG();

	VOID		vSetLogDays(ULONG _log_days) {u_log_days = _log_days;}
	ULONG		eInitializeLog();
	VOID		vWriteLog(char* text, int msgtype);
	const CHAR		*sGetBinDir() const {return s_bin_dir;}
	const CHAR		*sGetFileName() const {return s_file_name;}

private:

	VOID	vChangeLog();
	VOID	vMakeFileName();
	VOID	vDeleteOldLogFiles();
	INT		iGetDateByFilename(char *fname, WORD *year, WORD *month, WORD *day);
	VOID	vFindFirstLeftDate(SYSTEMTIME* st);
	INT		iCompareSYSTEMTIME(SYSTEMTIME time1, SYSTEMTIME time2);

	CHAR	s_file_name[MAX_PATH];
	CHAR	s_suffix[50];
	CHAR	s_appname[10];
	FILE*	flog;
	CRITICAL_SECTION cs;

	CHAR	s_bin_dir[MAX_PATH];
	ULONG	u_log_days;
	ULONG	u_log_msg_mask;
	SYSTEMTIME time_stamp;

};

extern	VOID natvLogV(char* function, int line, ULONG mask, char* format, ...);
extern	VOID natvLog(ULONG mask, char* format, ...);

extern	VOID natvDumpBYTE(PVOID p_data, ULONG u_len); 
extern	VOID natvDumpWORD(PVOID p_data, ULONG u_len);
extern	VOID natvDumpDWORD(PVOID p_data, ULONG u_len);

extern VOID natvDbgOut(TCHAR *psz_data);

#define NATSVC_PRINT_MAC(addr) *(PUCHAR)(addr),*((PUCHAR)(addr)+1),*((PUCHAR)(addr)+2),*((PUCHAR)(addr)+3),*((PUCHAR)(addr)+4),*((PUCHAR)(addr)+5)

#define LOG_ERROR(fmt) natvLogV(__FUNCTION__, __LINE__, NATLOG_ERROR, fmt)
#define LOG_DEBUG(fmt) natvLogV(__FUNCTION__, __LINE__, NATLOG_DEBUG, fmt)
#define LOG_GEN(fmt) natvLogV(__FUNCTION__, __LINE__, NATLOG_GENERAL, fmt)
#define LOG_WARNING(fmt) natvLogV(__FUNCTION__, __LINE__, NATLOG_WARNING, fmt)

extern NATCL_LOG *namp_log;

#define NAT_MAX_STR_LEN 255

#endif // _NATLOG_HEADER_