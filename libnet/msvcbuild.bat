@echo off

@rem Script to build libnet under "VS2013 x64 Cross Tools Command Prompt" or "VS2013 x64 Native Tools Command Prompt 
@rem Dependencies are:
@rem winpcap, specifically, the winpcap developer pack
@rem We assume WpdPack\ and libnet-master\ to have the same path, and that this script is executed from a VS Developer Command Prompt

@if "%1" == "" goto x86
@setlocal
@set userinput=%1
@if not "%1"=="x86" @if not "%1"=="x64" @if not "%1"=="x86_x64" goto usage
@if "%1"=="x86"  goto x86
@if "%1"=="x64" goto x64
@if "%1"=="x86_x64" goto x86_x64
@endlocal

:x86
if not exist "%VCINSTALLDIR%bin\vcvars32.bat" goto missing32
call "%VCINSTALLDIR%bin\vcvars32.bat"
goto msvcbuild32

:x64
if not exist "%VCINSTALLDIR%bin\amd64\vcvars64.bat" goto missing64
call "%VCINSTALLDIR%bin\amd64\vcvars64.bat"
goto msvcbuild64

:x86_x64
if not exist "%VCINSTALLDIR%vcvarsall.bat" goto missingCross
call "%VCINSTALLDIR%vcvarsall.bat" x86_amd64
goto msvcbuild64

:msvcbuild32
@echo on
@setlocal
@set MYCOMPILE=cl /nologo /MD /O2 /W3 /c /D_CRT_SECURE_NO_DEPRECATE /Fo..\..\win32\
@set MYLINK=link /nologo
@set MYMT=mt /nologo

@rem relative to C code in src/
@set WINPCAP=..\..\..\WpdPack

if not exist "..\win32\" mkdir "..\win32\"

copy win32\libnet.h include\
copy win32\stdint.h include\libnet\
copy win32\config.h include\
copy win32\getopt.h include\

cd src
%MYCOMPILE% /I..\include /I%WINPCAP%\Include libnet_a*.c libnet_build_*.c libnet_c*.c libnet_dll.c libnet_error.c libnet_i*.c libnet_link_win32.c libnet_p*.c libnet_raw.c libnet_resolve.c libnet_version.c libnet_write.c
%MYLINK% /DLL /libpath:%WINPCAP%\Lib  /out:..\..\win32\libnet.dll ..\..\win32\*.obj Advapi32.lib
if exist libnet.dll.manifest^
  %MYMT% -manifest libnet.dll.manifest -outputresource:libnet.dll;2
cd ..

exit /b %errorlevel%

:msvcbuild64
@echo on
@setlocal
@set MYCOMPILE=cl /nologo /MD /O2 /W3 /c /D_CRT_SECURE_NO_DEPRECATE /Fo..\..\win64\
@set MYLINK=link /nologo
@set MYMT=mt /nologo

@rem relative to C code in src/
@set WINPCAP=..\..\..\WpdPack

if not exist "..\win64\" mkdir "..\win64\"

copy win32\libnet.h include\
copy win32\stdint.h include\libnet\
copy win32\config.h include\
copy win32\getopt.h include\

cd src
%MYCOMPILE% /I..\include /I%WINPCAP%\Include libnet_a*.c libnet_build_*.c libnet_c*.c libnet_dll.c libnet_error.c libnet_i*.c libnet_link_win32.c libnet_p*.c libnet_raw.c libnet_resolve.c libnet_version.c libnet_write.c
%MYLINK% /DLL /libpath:%WINPCAP%\Lib\x64  /out:..\..\win64\libnet.dll ..\..\win64\*.obj Advapi32.lib
if exist libnet.dll.manifest^
  %MYMT% -manifest libnet.dll.manifest -outputresource:libnet.dll;2
cd ..

exit /b %errorlevel%

:usage
echo Invalid option "%*". The correct usage is:
echo     %0 [option]
echo :
echo where [option] is: x86 ^| x64 ^| x86_x64
echo :
echo The script will verify and set the appropriate environment variables.
echo If no options are provided, x86 is assumed.
echo :
echo Usage examples:
echo     %0 x86
echo     %0 x64
echo     %0 x86_x64
echo :
echo If your build computer is 32-bit and you want to build for 64-bit 
echo (aka Cross), choose "x86_x64"
echo :
echo Please make sure Visual Studio or the C++ Build SKU is installed,
echo and that this script is executed from a Developer Command Prompt.
echo :
goto end

:missing32
echo Could not find vcvars32.bat. 
echo Either Visual Studio or the C++ Build SKU is not installed,
echo or this script is not executed from a Developer Command Prompt.
goto end

:missing64
echo Could not find vcvars64.bat. 
echo Either Visual Studio or the C++ Build SKU is not installed,
echo or this script is not executed from a Developer Command Prompt.
goto end

:missingCross
echo Could not find vcvarsall.bat. 
echo Either Visual Studio or the C++ Build SKU is not installed,
echo or this script is not executed from a Developer Command Prompt.
goto end

:end