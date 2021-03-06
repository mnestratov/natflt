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

  You need to do this just once on a target machine

  > bcdedit -set loadoptions DDISABLE_INTEGRITY_CHECKS

  > bcdedit -set TESTSIGNING ON

* How to install generated certificate on a target machine

  You need to do this just once on a target machine

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

Deployment
----------

Before you deploy a self signed driver, you must turn on test signing and install a certificate on the target computer as described above

Natdrv6 is installed as a service. To install it, prepare an installation directory on the target computer and copy these files from the host computer into the directory:
```
    natdrv6.cat
    natdrv6.inf
    natdrv6.sys
    Natdrv6.cer
    natSvc.exe
    firewall.ini
    nat1x1.ini
    installsvc.cmd

```
And do the following:

1.  Open **Windows Settings**.
2.  Click **Network and Internet** then click **Change Adapter Options** and click the connection listed under **Connections**: and click **Properties**.
3.  Click **Install**, then **Service**, then **Add**, then **Have Disk**.
4.  Browse to the installation directory. Highlight the natdrv6.inf file and click **Open**, then click OK. Highlight **NAT/Firewall Filter Driver** in a list of Network Services and click OK.
5.  Rename Network connection to "Customer Interface" in order to add it to **NAT/Firewall Filter Driver** processing
6.  Run cmd.exe as Administrator and then run installsvc.cmd

Example configuration
---------------------

* nat1x1.ini

```
            #Private IP        Public IP
            192.168.139.128    192.168.190.138
            192.168.139.129    192.168.190.139
            192.168.139.130    192.168.190.140
```

* firewall.ini

```
            #Private IP        Public IP          Proto    Port(s)      Direction
            192.168.139.0/24   192.168.190.1/32   tcp      21           in

```

Example Network Topology
------------------------


```

            +-------------------+                 ==========================================
            |                   |                 || **NAT/Firewall Filter Driver** Host  ||
            |  External host    |                 ||                                      ||
            |                   |                 ||                                      ||
            |  192.168.190.1    |                 ||                                      ||
            |                   |                 ||                                      ||
            +-------------------+                 ||   +---------------------------+      ||
                      |                           ||   |                           |      ||
                      |                           ||   | "Customer Interface"      |      ||
                      |                           ||   |                           |      ||
                      +---------------------------||---+  The first IP address:    |      ||
                                                  ||   |  --------------------     |      ||
                                                  ||   |  192.168.190.137          |      ||
                                                  ||   |                           |      ||
                                                  ||   |  Host 192.168.139.128     |      ||
                                                  ||   |  1x1 NAT IP address:      |      ||
                                                  ||   |  ------------------       |      ||
                                                  ||   |  192.168.190.138          |      ||
                                                  ||   |                           |      ||
                                                  ||   |  Host 192.168.139.129     |      ||
                                                  ||   |  1x1 NAT IP address:      |      ||
                                                  ||   |  ------------------       |      ||
                                                  ||   |  192.168.190.139          |      ||
                                                  ||   |                           |      ||
                                                  ||   |  Host 192.168.139.130     |      ||
                                                  ||   |  1x1 NAT IP address:      |      ||
                                                  ||   |  ------------------       |      ||
                                                  ||   |  192.168.190.140          |      ||
                                                  ||   |                           |      ||
                                                  ||   |  ...                      |      ||
                                                  ||   |                           |      ||
                                                  ||   +---------------------------+      ||
                                                  ||                |                     ||
                                                  ||                | IP Routing          ||
                                                  ||                |                     ||
                                                  ||   +---------------------------+      ||
                                                  ||   |                           |      ||
                                                  ||   | Private Network interface |      ||
                      +---------------------------||---|                           |-------------+
                      |                     |     ||   | IP address:               |      ||     |
                      |                     |     ||   | 192.168.139.1             |      ||     |
                      |                     |     ||   |                           |      ||     |
                      |                     |     ||   +---------------------------+      ||     |
                      |                     |     ||                                      ||     |
                      |                     |     ==========================================     |
                      |                     |                                                    |
            +-----------------------+  +-----------------------+              +------------------------+
            |                       |  |                       |              |                        |
            |  Destination host #1  |  |  Destination Host #2  |              |  Destination Host #3   |
            |                       |  |                       |              |                        |
            |  192.168.139.128      |  |  192.168.139.129      |              |  192.168.139.130       |
            |                       |  |                       |              |                        |
            +-----------------------+  +-----------------------+              +------------------------+



```


Incoming packet flow
--------------------


```
                              tcpip driver
                 =========================
                 ||                     ||
                 ||                     ||
                 ||      IP engine      ||
                 ||                     ||
                 =========================
                            |
                            |
                            | natdrv6 filter driver
                 =========================
                 ||         |           ||
                 ||      3  |           ||
                 ||         |           ||
                 ||   +-------------+   ||
                 ||   |             |   ||
                 ||   |  Firewall   |   ||
                 ||   |   engine    |   ||
                 ||   |             |   ||
                 ||   +-------------+   ||
                 ||         |           ||
                 ||      2  |           ||
                 ||         |           ||
                 ||   +-------------+   ||
                 ||   |             |   ||
                 ||   |             |   ||
                 ||   | NAT engine  |   ||
                 ||   |             |   ||
                 ||   |             |   ||
                 ||   +-------------+   ||
                 ||         |           ||
                 ||      1  |           ||
                 ||         |           ||
                 =========================

           +----------------+-----------------+---------------+--------------+
      1.   | src IP address |  dst IP address | src TCP port  | dst TCP port |
           +----------------+-----------------+---------------+--------------+
           | 192.168.190.1  | 192.168.190.138 |   10122       |     21       |
           +----------------+-----------------+---------------+--------------+

           +----------------+-----------------+---------------+--------------+
      2.   | src IP address |  dst IP address | src TCP port  | dst TCP port |
           +----------------+-----------------+---------------+--------------+
           | 192.168.190.1  | 192.168.139.128 |   10122       |     21       |
           +----------------+-----------------+---------------+--------------+

           +----------------+-----------------+---------------+--------------+
      3.   | src IP address |  dst IP address | src TCP port  | dst TCP port |
           +----------------+-----------------+---------------+--------------+
           | 192.168.190.1  | 192.168.139.128 |   10122       |     21       |
           +----------------+-----------------+---------------+--------------+

```

Outgoing packet flow
--------------------


```
                              tcpip driver
                 =========================
                 ||                     ||
                 ||                     ||
                 ||      IP engine      ||
                 ||                     ||
                 =========================
                            |
                            |
                            | natdrv6 filter driver
                 =========================
                 ||         |           ||
                 ||      1  |           ||
                 ||         |           ||
                 ||   +-------------+   ||
                 ||   |             |   ||
                 ||   |  Firewall   |   ||
                 ||   |   engine    |   ||
                 ||   |             |   ||
                 ||   +-------------+   ||
                 ||         |           ||
                 ||      2  |           ||
                 ||         |           ||
                 ||   +-------------+   ||
                 ||   |             |   ||
                 ||   |             |   ||
                 ||   | NAT engine  |   ||
                 ||   |             |   ||
                 ||   |             |   ||
                 ||   +-------------+   ||
                 ||         |           ||
                 ||      3  |           ||
                 ||         |           ||
                 =========================

           +-----------------+-----------------+---------------+--------------+
      1.   | src IP address  |  dst IP address | src TCP port  | dst TCP port |
           +-----------------+-----------------+---------------+--------------+
           | 192.168.139.128 | 192.168.190.1   |   21          |   10122      |
           +-----------------+-----------------+---------------+--------------+

           +-----------------+-----------------+---------------+--------------+
      2.   | src IP address  |  dst IP address | src TCP port  | dst TCP port |
           +-----------------+-----------------+---------------+--------------+
           | 192.168.139.128 | 192.168.190.1   |   21          |   10122      |
           +-----------------+-----------------+---------------+--------------+

           +-----------------+-----------------+---------------+--------------+
      3.   | src IP address  |  dst IP address | src TCP port  | dst TCP port |
           +-----------------+-----------------+---------------+--------------+
           | 192.168.190.138 | 192.168.139.128 |   21          |    10122     |
           +-----------------+-----------------+---------------+--------------+

```
