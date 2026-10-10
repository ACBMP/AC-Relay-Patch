@echo off
setlocal

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release

echo building ac_relay (%CONFIG%) with vs2026...

cmake -B build -G "Visual Studio 18 2026" -A Win32
cmake --build build --config %CONFIG%

echo.
echo build complete: build\bin\%CONFIG%\ac_relay.asi
