@echo off
rem tools\build_msvc.bat [build-dir] [extra cmake args...]   (default build-msvc, RelWithDebInfo)
set "BDIR=%~1"
if "%BDIR%"=="" set "BDIR=build-msvc"
call "%~dp0msvc.bat" cmake -S "%~dp0.." -B "%BDIR%" -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo %2 %3 %4 || exit /b 1
call "%~dp0msvc.bat" cmake --build "%BDIR%"
