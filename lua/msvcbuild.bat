@rem Script to build Lua under "Visual Studio .NET Command Prompt".
@rem Dependencies are:
@rem   Lua
@rem   winpcap, specifically, the winpcap developer pack
@rem   dnet, Dug Song's net library, aka libdumbnet

@setlocal
@set MYCOMPILE=cl /nologo /MD /O2 /W3 /c /D_CRT_SECURE_NO_DEPRECATE
@set MYLINK=link /nologo
@set MYMT=mt /nologo

@set LUA=..\..\lua-5.1\src
@set WINPCAP=..\..\WpdPack
@set DNET=..\..\libdnet-1.11-win32

%MYCOMPILE% /I..\libnet\include\win32 /I..\libnet\include /I%LUA% /I%WINPCAP%\Include /I%DNET%\include *.c
%MYLINK% /DLL /libpath:%WINPCAP%\Lib  /out:net.dll *.obj %LUA%\lua51.lib ..\libnet\win32\Debug\Libnet.lib %DNET%\lib\dnet.lib
if exist net.dll.manifest^
  %MYMT% -manifest net.dll.manifest -outputresource:net.dll;2

