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

