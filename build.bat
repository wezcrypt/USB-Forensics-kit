@echo off
rem ===========================================================================
rem  WezCrypt USB Forensics Kit - one-command portable build (Windows 10/11 x64)
rem  Usage:  build.bat            (build + tests)
rem          build.bat notest     (skip the test suite)
rem  Output: dist\WezCryptUFK\    copy this whole folder to the USB drive
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (where python >nul 2>&1 && set "PY=python")
if not defined PY (
  echo [ERROR] Python 3.12+ x64 was not found. Install it from https://www.python.org/downloads/windows/
  exit /b 1
)

%PY% -c "import sys,struct; sys.exit(0 if sys.version_info>=(3,12) and struct.calcsize('P')==8 else 1)"
if errorlevel 1 (
  echo [ERROR] Python 3.12 or newer, 64-bit, is required.
  exit /b 1
)

if not exist ".venv-build\Scripts\python.exe" (
  echo [1/6] Creating build virtual environment...
  %PY% -m venv .venv-build || exit /b 1
)
set "VPY=.venv-build\Scripts\python.exe"

echo [2/6] Installing dependencies...
"%VPY%" -m pip install --disable-pip-version-check -q --upgrade pip || exit /b 1
"%VPY%" -m pip install --disable-pip-version-check -q -r requirements.txt -r requirements-dev.txt || exit /b 1

if /I "%~1"=="notest" (
  echo [3/6] Tests skipped by request.
) else (
  echo [3/6] Running test suite...
  "%VPY%" -m pytest -q || (echo [ERROR] Tests failed - build aborted. & exit /b 1)
)

echo [4/6] Building portable executables with PyInstaller...
"%VPY%" -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\WezCryptUFK.spec || exit /b 1

echo [5/6] Adding documentation and helpers...
set "OUT=dist\WezCryptUFK"
copy /Y README.md "%OUT%\" >nul
copy /Y LICENSE "%OUT%\" >nul
copy /Y CHANGELOG.md "%OUT%\" >nul
copy /Y SECURITY.md "%OUT%\" >nul
copy /Y packaging\Run_as_Administrator.bat "%OUT%\" >nul
if not exist "%OUT%\examples" mkdir "%OUT%\examples"
copy /Y examples\iocs_example.txt "%OUT%\examples\" >nul

echo [6/6] Writing SHA256SUMS.txt for the kit...
"%VPY%" packaging\make_checksums.py "%OUT%" || exit /b 1

echo.
echo Build complete: %CD%\%OUT%
echo Copy the whole WezCryptUFK folder to the USB drive. Launch WezCryptUFK.exe (GUI) or WezCryptUFK-cli.exe (CLI).
endlocal
exit /b 0
