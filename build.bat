@echo off
setlocal enabledelayedexpansion

echo ==================================================
echo                Builder (Windows)
echo ==================================================
echo.
echo Select Toolchain (Will perform a clean build):
echo  [1] MSVC (Visual Studio)
echo      - Recommended for Windows
echo      - Auto-detects VS installation
echo.
echo  [2] MinGW (GCC)
echo      - Requires MinGW-w64
echo      - Requires Rust GNU target
echo.
set /p choice="Enter choice [1-2]: "
if "%choice%"=="1" goto check_msvc_env
if "%choice%"=="2" goto setup_mingw
echo [ERROR] Invalid choice. Exiting.
exit /b 1

:check_msvc_env
echo.
echo [SETUP] Checking MSVC Environment...
where cl.exe >nul 2>nul
if %errorlevel% equ 0 goto set_msvc_vars
echo [INFO] Attempting auto-discovery...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] Visual Studio not found.
    exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    set "VS_INSTALL_DIR=%%i"
)
if not defined VS_INSTALL_DIR (
    echo [ERROR] No C++ tools found in Visual Studio.
    exit /b 1
)
echo [INFO] Loading: !VS_INSTALL_DIR!
call "!VS_INSTALL_DIR!\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo
:set_msvc_vars
set "CMAKE_GENERATOR=Visual Studio 17 2022"
if not defined CMAKE_GENERATOR set "CMAKE_GENERATOR=" 
set "RUST_TARGET="
goto clean_and_build

:setup_mingw
echo.
echo [SETUP] Checking MinGW Environment...
where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] GCC not found in PATH.
    exit /b 1
)
set "CMAKE_GENERATOR=MinGW Makefiles"
set "RUST_TARGET=x86_64-pc-windows-gnu"
rustup target list --installed | findstr "%RUST_TARGET%" >nul
if %errorlevel% neq 0 (
    echo [AUTO] Installing Rust target: %RUST_TARGET%
    rustup target add %RUST_TARGET%
)
goto clean_and_build
:clean_and_build

echo.
echo [1/4] Cleaning CMake Artifacts...
if exist "build" (
    echo   - Removing existing 'build' directory...
    rmdir /s /q "build"
)
mkdir "build"

echo.
echo [2/4] Building Rust Core...
cd core
if defined RUST_TARGET (
    echo   - Target: %RUST_TARGET%
    cargo build --release --target %RUST_TARGET%
    echo [INFO] Copying library to standard location...
    if not exist "target\release" mkdir "target\release"
    copy /Y "target\%RUST_TARGET%\release\libre_tools.a" "target\release\libre_tools.a" >nul
) else (
    echo   - Target: Default (MSVC)
    cargo build --release
)
if %errorlevel% neq 0 (
    echo [ERROR] Rust build failed.
    cd ..
    exit /b 1
)
cd ..

echo.
echo [3/4] Configuring CMake...
cd build
if defined CMAKE_GENERATOR (
    if "%choice%"=="2" (
        cmake .. -G "%CMAKE_GENERATOR%" -DCMAKE_BUILD_TYPE=Release
    ) else (
        cmake ..
    )
) else (
    cmake ..
)
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    cd ..
    exit /b 1
)

echo.
echo [4/4] Compiling C++ CLI...
cmake --build . --config Release --parallel
if %errorlevel% neq 0 (
    echo [ERROR] Compilation failed.
    cd ..
    exit /b 1
)

echo.
echo ==================================================
echo  BUILD SUCCESSFUL
echo ==================================================
if "%choice%"=="1" (
    echo  Binary: .\build\bin\Release\retools_cli.exe
) else (
    echo  Binary: .\build\bin\retools_cli.exe
)
echo ==================================================
cd ..
endlocal