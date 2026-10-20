@echo off
rem Sets up MSVC 2022 Build Tools + Windows SDK without vcvars64.bat (whose vswhere
rem lookup fails on this machine), then runs the given command.
rem   tools\msvc.bat cmake -S . -B build-msvc -G "NMake Makefiles"
set "VCT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKV=10.0.26100.0"
set "INCLUDE=%VCT%\include;%SDK%\Include\%SDKV%\ucrt;%SDK%\Include\%SDKV%\shared;%SDK%\Include\%SDKV%\um;%SDK%\Include\%SDKV%\winrt"
set "LIB=%VCT%\lib\x64;%SDK%\Lib\%SDKV%\ucrt\x64;%SDK%\Lib\%SDKV%\um\x64"
set "PATH=%VCT%\bin\Hostx64\x64;%SDK%\bin\%SDKV%\x64;%PATH%"
%*
