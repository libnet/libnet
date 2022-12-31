@echo off

@rem Script to build libnet with MSVC.
@rem Dependencies are:
@rem winpcap, specifically, the winpcap developer pack
@rem We assume WpdPack\ and libnet-master\ to have the same path,
@rem and that this script is executed from either a VS2015 Developer Command Prompt
@rem or an elevated Command Prompt.
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

@if "%1" == "" goto x86
@setlocal
@set userinput=%1
@if not "%1"=="x86" @if not "%1"=="x64" @if not "%1"=="x86_x64" goto usage
@if "%1"=="x86"  goto x86
@if "%1"=="x64" goto x64
@if "%1"=="x86_x64" goto x86_x64
@endlocal

:x86
call "%InstallDir%\Common7\Tools\VsDevCmd.bat" -arch=x86
goto msvcbuild32

:x64
call "%InstallDir%\Common7\Tools\VsDevCmd.bat" -arch=x64
goto msvcbuild64

:x86_x64
call "%InstallDir%\Common7\Tools\VsDevCmd.bat" -arch=x86_amd64
goto msvcbuild64

:msvcbuild32
@echo on
@setlocal
@set MYCOMPILE=cl /nologo /MD /O2 /W4 /c /D_CRT_SECURE_NO_DEPRECATE /Fowin32\
@set MYLINK=link /nologo
@set MYMT=mt /nologo
@set VERSION=1.2

@rem relative to C code in src/
@set WINPCAP=..\..\WpdPack

if not exist "src\win32\" mkdir "src\win32\"

if not exist "lib\x86\" mkdir "lib\x86\"

copy win32\libnet.h include\
copy win32\stdint.h include\libnet\
copy win32\config.h include\
copy win32\getopt.h include\

cd src
%MYCOMPILE% /I..\include /I%WINPCAP%\Include libnet_a*.c libnet_build_*.c libnet_c*.c libnet_dll.c libnet_error.c libnet_i*.c libnet_link_win32.c libnet_p*.c libnet_raw.c libnet_resolve.c libnet_version.c libnet_write.c
%MYLINK% /DLL /libpath:%WINPCAP%\Lib  /out:..\lib\x86\libnet%VERSION%.dll win32\*.obj Advapi32.lib
if exist libnet.dll.manifest^
  %MYMT% -manifest libnet.dll.manifest -outputresource:libnet.dll;2
cd ..

exit /b %errorlevel%

:msvcbuild64
@echo on
@setlocal
@set MYCOMPILE=cl /nologo /MD /O2 /W4 /c /D_CRT_SECURE_NO_DEPRECATE /Fowin64\
@set MYLINK=link /nologo
@set MYMT=mt /nologo
@set VERSION=1.2

@rem relative to C code in src/
@set WINPCAP=..\..\WpdPack

if not exist "src\win64\" mkdir "src\win64\"

if not exist "lib\x64\" mkdir "lib\x64\"

copy win32\libnet.h include\
copy win32\stdint.h include\libnet\
copy win32\config.h include\
copy win32\getopt.h include\

cd src
dir ..\..\..\
dir ..\..\..\WpdPack
dir ..\..\
dir ..\..\WpdPack
dir ..\..\WpdPack\Include
@echo "Foo"
dir "%WINPCAP%\Include\"
%MYCOMPILE% /I..\include /I%WINPCAP%\Include libnet_a*.c libnet_build_*.c libnet_c*.c libnet_dll.c libnet_error.c libnet_i*.c libnet_link_win32.c libnet_p*.c libnet_raw.c libnet_resolve.c libnet_version.c libnet_write.c
%MYLINK% /DLL /libpath:%WINPCAP%\Lib\x64  /out:..\lib\x64\libnet%VERSION%.dll win64\*.obj Advapi32.lib
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

:fail
echo Visual Studio or the C++ Build SKU do not seem to be installed.
echo Please Install either of them or try to executed this script
echo from a Developer Command Prompt.
goto end

:end
