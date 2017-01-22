# natdrv

NDIS5/NDIS6 based simple firewall and 1x1 NAT engine

* How to build x64 version of NDIS6 driver (Win7, Win8, Win10)

  > _envVS2015.cmd

  > cd natDrv.6

  > msbuild /t:Clean /t:Rebuild /p:Configuration=Release /p:Platform=x64

* How to build x64 NAT/Firewall system service

  > _envVS2015.cmd

  > cd natSvc

  > msbuild /t:Clean /t:Rebuild /p:Configuration=Release /p:Platform=x64

* How to self sign a driver

  You need to sign the driver every time you rebuild it in order to make it possible to load it on a Win10 x64 machine

  > cd natDrv.6

  > SignTool sign /v /s Natdrv6CertStore /n Natdrv6Cert /t http://timestamp.verisign.com/scripts/timstamp.dll x64\Release\netgw\natdrv6.sys

* How to create a certificate

  You need to do this just once on a build machine

  > MakeCert -r -pe -ss Natdrv6CertStore -n "CN=Natdrv6Cert" Natdrv6.cer

* How to make it possible to load a self signed driver

  You need to do this just once on a destinaation machine

  > bcdedit -set loadoptions DDISABLE_INTEGRITY_CHECKS

  > bcdedit -set TESTSIGNING ON

* How to install generated certificate on a destination machine

  You need to do this just once on a destinaation machine

  > certmgr.exe /add Natdrv6.cer /s /r localMachine root

  > certmgr.exe /add Natdrv6.cer /s /r localMachine trustedpublisher

* How to enable kernel mode debugging

  On a windbg client machine run the following, assuming your destination host is a VM with serial port

  > windbg -k com:port=\\.\pipe\com_1,pipe

  Set symbol path

  > srv*c:\websymbols*http://msdl.microsoft.com/download/symbols

  On a debuggee VM run

  > bcdedit /debug on

  > bcdedit /dbgsettings serial debugport:1 baudrate:115200
