# natflt
NDIS5/NDIS6 based simple firewall and 1x1 NAT engine

* How to build x64 version of NDIS6 driver (Win7, Win8, Win10)

  > _envVS2015.cmd

  > cd natDrv.6

  > msbuild /t:Clean /t:Rebuild /p:Configuration=Release /p:Platform=x64

* How to build x64 NAT/Firewall system service

  > _envVS2015.cmd

  > cd natSvc

  > msbuild /t:Clean /t:Rebuild /p:Configuration=Release /p:Platform=x64
