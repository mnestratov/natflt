sc stop natsvc
sc delete natsvc
mkdir "%ProgramFiles%\natsvc"
sc create natsvc start= auto error= normal binPath= "%ProgramFiles%\natsvc\natsvc.exe"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v Default /t REG_DWORD /d 0xffffffff
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 1 
copy firewall.ini "%ProgramFiles%\natsvc\firewall.ini"
copy nat1x1.ini "%ProgramFiles%\natsvc\nat1x1.ini"
copy natsvc.exe "%ProgramFiles%\natsvc\natsvc.exe"
sc start natsvc