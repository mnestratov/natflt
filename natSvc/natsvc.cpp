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
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <winsvc.h>

#include "..\natDrvCommon\natdrvio.h"
#include "natlog.h"
#include "natcfg.h"

NATCL_CONFIG nam_cfg;

SERVICE_STATUS svc_status;
SERVICE_STATUS_HANDLE svc_status_handle;
HANDLE nath_app_exit_event = NULL;
VOID WINAPI natvServiceMain(DWORD dw_argc, LPTSTR *p_argv);
VOID natMainThread();
VOID WINAPI natvServiceCtrlHandler(DWORD dw_opcode);
BOOLEAN bLoadNatTable(ULONGLONG *pCustomerMac);
BOOLEAN bLoadFirewall(ULONGLONG *pCustomerMac);
BOOLEAN bInitHostAdapters(BOOLEAN bStart, ULONGLONG *pCustomerMac);


#define NAT_SVC_NAME_STR "natSvc"

int main(int argc, char* argv[])
{
	SERVICE_TABLE_ENTRY svc_table[] = {{_T(NAT_SVC_NAME_STR),natvServiceMain},{NULL,NULL}};

	if (argc >= 2){

		if (_tcscmp(argv[1],_T("console")) == 0)
			natvServiceMain(argc,argv);
	}else
		StartServiceCtrlDispatcher(svc_table);

	return 0;
}

VOID WINAPI natvServiceMain(DWORD dw_argc, LPTSTR *p_argv)
{
	ULONG err = -1;
	BOOLEAN b_debug = (2 == dw_argc && _tcscmp(p_argv[1],_T("console")) == 0);
	HANDLE h_single_instance = CreateMutex(NULL, FALSE, "{DE35821E-2317-5427-DA5F-45D9A456B8F0}");
	if(NULL == h_single_instance)
		return;

	if(WAIT_OBJECT_0 != WaitForSingleObject(h_single_instance,1000))
		return;

	if (!b_debug){

	    svc_status.dwServiceType        = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	    svc_status.dwCurrentState       = SERVICE_START_PENDING;
		svc_status.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
		svc_status.dwWin32ExitCode      = 0;
		svc_status.dwServiceSpecificExitCode = 0;
		svc_status.dwCheckPoint         = 0;
		svc_status.dwWaitHint           = 0;
		svc_status_handle = RegisterServiceCtrlHandler(_T(NAT_SVC_NAME_STR),natvServiceCtrlHandler);
		if ((SERVICE_STATUS_HANDLE)0 == svc_status_handle){
			
			goto finish;
		}

		svc_status.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(svc_status_handle,&svc_status);
	}

	do{

		HWINSTA hWinsta;
		HDESK hDesk;

		SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
		SECURITY_DESCRIPTOR sd;

		namp_log = new NATCL_LOG("natfw", "SVC", nam_cfg.sGetBinPath());
		if(NULL == namp_log)
			break;

		err = namp_log->eInitializeLog();
		if(err)
			break;

		LOG_GEN("");
		LOG_GEN("Initializing...");

		hWinsta = GetProcessWindowStation();
		if(hWinsta == NULL){
			LOG_ERROR("GetProcessWindowStation failed");
			break;
		}

		hDesk = GetThreadDesktop(GetCurrentThreadId());
		if(hDesk == NULL){
			LOG_ERROR("GetThreadDesktop failed");
			break;
		}

		InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&sd, TRUE, (PACL)NULL, FALSE);
		
		if(!SetUserObjectSecurity(hWinsta, &si, &sd)){ 
			LOG_ERROR("SetUserObjectSecurity failed");
			break;
		}
		
		if(!SetUserObjectSecurity(hDesk, &si, &sd)){
			LOG_ERROR("SetUserObjectSecurity failed");
			break;
		}

		nath_app_exit_event = CreateEvent(NULL,TRUE,FALSE,NULL);

		//
		// Create main thread
		//

		LOG_GEN("Initializing DONE");

		LOG_GEN("Services is STARTED");

		natMainThread();

	}while(FALSE);

	LOG_GEN("Releasing resources...");

	if (!b_debug){
		
		svc_status.dwCurrentState = SERVICE_STOPPED;
		if (!SetServiceStatus(svc_status_handle,&svc_status)){
			
			LOG_ERROR("SetServiceStatus failed");
		}
	}

	if(nath_app_exit_event)
		CloseHandle(nath_app_exit_event);

	LOG_GEN("Releasing resources DONE");

	LOG_GEN("");
	LOG_GEN("Service is STOPPED");

finish:

	if(h_single_instance){

		ReleaseMutex(h_single_instance);
		CloseHandle(h_single_instance);
	}

}

VOID WINAPI natvServiceCtrlHandler(DWORD dw_opcode)
{
	switch(dw_opcode){
	case SERVICE_STOP_PENDING:

		LOG_GEN("Got request to stop service");

		svc_status.dwCurrentState = SERVICE_STOP_PENDING;
		svc_status.dwWin32ExitCode = 0;
		svc_status.dwWaitHint = 0;
		if (!SetServiceStatus(svc_status_handle,&svc_status))
		{
			LOG_ERROR("SetServiceStatus failed");
		}

		if(nath_app_exit_event){
			SetEvent(nath_app_exit_event);
			Sleep(100);
		}

		break;

	case SERVICE_CONTROL_STOP:

		LOG_GEN("Got request to stop service");

		svc_status.dwCurrentState = SERVICE_STOPPED;
		svc_status.dwWin32ExitCode = 0;
		svc_status.dwWaitHint = 0;
		if (!SetServiceStatus(svc_status_handle,&svc_status))
		{
			LOG_ERROR("SetServiceStatus failed");
		}

		if(nath_app_exit_event){
			SetEvent(nath_app_exit_event);
			Sleep(100);
		}

		break;

	case SERVICE_CONTROL_SHUTDOWN:

		LOG_GEN("Got request to shutdown");

		if(nath_app_exit_event){
			SetEvent(nath_app_exit_event);
			Sleep(100);
		}

		break;

	case SERVICE_INTERROGATE:
		break;
	}
}

VOID natMainThread()
{
	ULONGLONG customerMac;

	if(!natbOpenFile()){
		LOG_ERROR("natbOpenFile failed. DRIVER seems to be stopped");
		return;
	}

	LOG_GEN("Driver was open successfully");

	if(!bInitHostAdapters(FALSE, &customerMac)){

		LOG_ERROR("bInitHostAdapters failed");
		goto finish;
	}

	if(!bLoadNatTable(&customerMac)){

		LOG_ERROR("bLoadNat failed");
		goto finish;
	}

	LOG_GEN("NAT table was initialized successfully");

	if(!bLoadFirewall(&customerMac)){

		LOG_ERROR("bLoadFirewall failed");
		goto finish;
	}

	LOG_GEN("Firewall rules were initialized successfully");

	if(!bInitHostAdapters(TRUE, NULL)){

		LOG_ERROR("bInitHostAdapters failed");
		goto finish;
	}

	LOG_GEN("Driver was initialized successfully");

	while(WAIT_TIMEOUT == WaitForSingleObject(nath_app_exit_event, 1000)){

		//
		// Do nothing. Wait for stop request
		//
	}

finish:

	natbRelease();

	LOG_GEN("Driver was uninitialized successfully");

	natvCloseFile();
}