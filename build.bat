@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
set VCPKG_ROOT=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\vcpkg
cd /d D:\binsnake\picanha
if exist build\msvc-release rmdir /s /q build\msvc-release
echo Running CMake configure...
cmake --preset=msvc-release
if %ERRORLEVEL% NEQ 0 (
    echo CMake configuration failed!
    exit /b %ERRORLEVEL%
)
echo Running CMake build...
cmake --build build/msvc-release --config Release -j
