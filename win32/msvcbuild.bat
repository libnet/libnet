@echo off

@rem Script to build libnet with MSVC.
@rem Dependencies are:
@rem Npcap SDK in ..\npcap-sdk
@rem
@rem Helpful links for non-Windows users:
@rem https://github.com/microsoft/vswhere/wiki/Find-VC#batch
@rem https://renenyffenegger.ch/notes/Windows/dirs/Program-Files-x86/Microsoft-Visual-Studio/version/edition/Common7/Tools/VsDevCmd_bat
@rem https://renenyffenegger.ch/notes/Windows/development/Visual-Studio/environment-variables/index

:start
for /f "usebackq tokens=*" %%i in (`vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath -nologo`) do (
  set InstallDir=%%i
)
if not exist "%InstallDir%\Common7\Tools\VsDevCmd.bat" (goto fail)

@rem Set up common files, paths, and envs
@rem relative to C code in src/
@set NPCAP=..\..\npcap-sdk
mkdir src\win64 src\win32 lib\x64 lib\x86
copy win32\*.h include\

@if "%1" == "" goto x86
@setlocal
@set userinput=%1
@if not "%1"=="x86" @if not "%1"=="x64" @if not "%1"=="x86_x64" goto usage
@if "%1"=="x86"  goto x86
@if "%1"=="x64" goto x64
@if "%1"=="x86_64" goto x86_64
@if "%1"=="x86_x64" goto x86_64
@endlocal

:x86
call "%InstallDir%\Common7\Tools\VsDevCmd.bat" -arch=x86
set PCAPLIB=%NPCAP%\Lib
set PCAPINC=%NPCAP%\Include
set BUILDDIR=win32
set LIBDIR=..\lib\x86
goto msvcbuild

:x64
call "%InstallDir%\Common7\Tools\VsDevCmd.bat" -arch=x64
set PCAPLIB=%NPCAP%\Lib\x64
set PCAPINC=%NPCAP%\Include
set BUILDDIR=win64
set LIBDIR=..\lib\x64
goto msvcbuild

:x86_64
call "%InstallDir%\Common7\Tools\VsDevCmd.bat" -arch=amd64
set PCAPLIB=%NPCAP%\Lib\x64
set PCAPINC=%NPCAP%\Include
set BUILDDIR=win64
set LIBDIR=..\lib\x64
goto msvcbuild

:msvcbuild
@echo on
@setlocal
@set CC=cl /nologo /MD /O2 /W4 /c /D_CRT_SECURE_NO_DEPRECATE /Fo%BUILDDIR%\
@set LD=link /nologo
@set MT=mt /nologo
@set VERSION=1.2

cd src
%CC% /I..\include /I%PCAPINC% libnet_a*.c libnet_build_*.c libnet_c*.c libnet_dll.c libnet_error.c libnet_i*.c libnet_link_win32.c libnet_p*.c libnet_raw.c libnet_resolve.c libnet_version.c libnet_write.c
%LD% /DLL /libpath:%PCAPLIB% /out:%LIBDIR%\libnet%VERSION%.dll %BUILDDIR%\*.obj Advapi32.lib

if exist libnet.dll.manifest^
  %MT% -manifest libnet.dll.manifest -outputresource:libnet.dll;2
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

:fail
echo Visual Studio or the C++ Build SKU do not seem to be installed.
echo Please Install either of them or try to executed this script
echo from a Developer Command Prompt.
goto end

:end
