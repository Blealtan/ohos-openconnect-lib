# --csd-wrapper support for Windows

- The specified file will be launched via CreateProcessW.
- I successfully connect to my vpn headend with a simple .cmd batch file based on the output of [hostscan-bypass](https://gilks.github.io/post/cisco-hostscan-bypass/) tool (see example below).
- In my example I show how to submit the hostscan-bypass.txt which holds a flat list all of the properties captured.

## example hostscan-bypass.cmd

```batch
@echo off
::notes
::  %~1 syntax removes surrounding double quotes
::  %~dp0 is the currently running script's directory path

echo pwd: %~dp0
echo host: %~1
echo token: %~2

curl ^
    --data-ascii "@%~dp0hostscan-bypass.txt" ^
    --insecure ^
    --user-agent "AnyConnect Windows 4.7.00136" ^
    --header "X-Transcend-Version: 1" ^
    --header "X-Aggregate-Auth: 1" ^
    --header "X-AnyConnect-Platform: win" ^
    --cookie "sdesktop=%~2" ^
    https://%~1/+CSCOE+/sdesktop/scan.xml?reusebrowser=1

```

## example openconnect.exe command line
```shell
openconnect.exe --os=win --csd-wrapper=hostscan-bypass.cmd hostname
```

## building openconnect.exe for Windows
- the easiest way I found was to follow the Fedora based [yaml build script](https://gitlab.com/brentanderson/openconnect/blob/master/.gitlab-ci.yml)... "MinGW64/GnuTLS" worked the best for me... 
  ```bash
  # initial setup
  dnf update -y

  dnf install -y git autoconf automake libtool python gettext make     mingw64-gnutls mingw64-openssl mingw64-libxml2 mingw64-zlib mingw64-gcc wine.i686 make iproute iputils nuttcp

  ./autogen.sh

  mingw64-configure CFLAGS=-g
  ```
  ```bash
  # subsequent builds
  make -j4
  ```
- I chose to use Windows Subsystem for Linux (WSL) and loaded a free [Fedora Remix distro](https://github.com/WhitewaterFoundry/Fedora-Remix-for-WSL/releases).
- once your make finishes, there will be openconnect.exe & libopenconnect-5.dll in .libs folder
- to run on Windows, I had to copy the following DLLs from the WSL Fedora MinGW `usr\x86_64-w64-mingw32\sys-root\mingw\bin` to be alongside openconnect.exe
  ```
  libffi-6.dll
  libgcc_s_seh-1.dll
  libgmp-10.dll
  libgnutls-30.dll
  libnettle-6.dll
  libopenconnect-5.dll
  libp11-kit-0.dll
  libtasn1-6.dll
  libwinpthread-1.dll
  libxml2-2.dll
  libhogweed-4.dll
  iconv.dll
  zlib1.dll
  ```

# Misc Tips
- we can browse to WSL filesystem with Windows File Explorer by `explorer.exe .` from our WSL bash terminal
- I had to run openconnect.exe elevated (as Admin) for the tunnel to be active
