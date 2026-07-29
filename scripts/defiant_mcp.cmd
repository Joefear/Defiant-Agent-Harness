@echo off
setlocal

if defined DAH_PYTHON if exist "%DAH_PYTHON%" goto run_configured_python

python -c "import yaml" >nul 2>&1
if not errorlevel 1 (
  python -m defiant_agent_harness.cli.main %*
  exit /b %errorlevel%
)

for /f "delims=" %%P in ('dir /b /ad /o-n "%LOCALAPPDATA%\Programs\Python\Python*" 2^>nul') do (
  call :probe_python "%LOCALAPPDATA%\Programs\Python\%%P\python.exe"
  if defined DAH_SELECTED_PYTHON goto run_selected_python
)

if exist "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" (
  "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" -3 -c "import yaml" >nul 2>&1
  if not errorlevel 1 (
    "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" -3 -m defiant_agent_harness.cli.main %*
    exit /b %errorlevel%
  )
)

if exist "%WINDIR%\py.exe" (
  "%WINDIR%\py.exe" -3 -c "import yaml" >nul 2>&1
  if not errorlevel 1 (
    "%WINDIR%\py.exe" -3 -m defiant_agent_harness.cli.main %*
    exit /b %errorlevel%
  )
)

echo Defiant Agent Harness could not find a working Python interpreter. 1>&2
exit /b 9009

:run_configured_python
"%DAH_PYTHON%" -m defiant_agent_harness.cli.main %*
exit /b %errorlevel%

:run_selected_python
"%DAH_SELECTED_PYTHON%" -m defiant_agent_harness.cli.main %*
exit /b %errorlevel%

:probe_python
if not exist "%~1" exit /b
"%~1" -c "import yaml" >nul 2>&1
if errorlevel 1 exit /b
set "DAH_SELECTED_PYTHON=%~1"
exit /b
