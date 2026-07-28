@echo off
setlocal

if defined DAH_PYTHON if exist "%DAH_PYTHON%" goto run_python

if exist "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" (
  "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" -3 -m defiant_agent_harness.cli.main %*
  exit /b %errorlevel%
)

if exist "%WINDIR%\py.exe" (
  "%WINDIR%\py.exe" -3 -m defiant_agent_harness.cli.main %*
  exit /b %errorlevel%
)

python -m defiant_agent_harness.cli.main %*
exit /b %errorlevel%

:run_python
"%DAH_PYTHON%" -m defiant_agent_harness.cli.main %*
exit /b %errorlevel%
