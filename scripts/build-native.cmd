@echo off
setlocal
set "ROOT=%~dp0.."
set "STAGE=%ROOT%\artifacts\native-stage"

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1

if not exist "%STAGE%" mkdir "%STAGE%"

set "COMMON=/nologo /std:c++20 /O2 /EHsc /W4 /DUNICODE /D_UNICODE /MT /permissive- /D_WIN32_WINNT=0x0A00"

cl %COMMON% "%ROOT%\native\runner\main.cpp" /Fe:"%STAGE%\GLPI.Agent.Deployer.RemoteRunner.exe" /Fo:"%STAGE%\runner.obj" /link /incremental:no advapi32.lib msi.lib
if errorlevel 1 exit /b 1

"%STAGE%\GLPI.Agent.Deployer.RemoteRunner.exe" --self-test
if errorlevel 1 exit /b 1

cl %COMMON% "%ROOT%\native\service\main.cpp" "%ROOT%\native\common\common.cpp" /Fe:"%STAGE%\GLPI.Agent.Deployer.Service.exe" /Fo:"%STAGE%\\" /link /incremental:no advapi32.lib ws2_32.lib netapi32.lib activeds.lib adsiid.lib ole32.lib oleaut32.lib shell32.lib winsqlite3.lib bcrypt.lib crypt32.lib msi.lib
if errorlevel 1 exit /b 1

"%STAGE%\GLPI.Agent.Deployer.Service.exe" --self-test
if errorlevel 1 exit /b 1

cl %COMMON% "%ROOT%\native\tests\main.cpp" "%ROOT%\native\common\common.cpp" /Fe:"%STAGE%\GLPI.Agent.Deployer.Tests.exe" /Fo:"%STAGE%\\" /link /incremental:no shell32.lib ole32.lib
if errorlevel 1 exit /b 1

pushd "%STAGE%"
copy /y "%ROOT%\native\setup\setup.manifest" "%STAGE%\setup.manifest" >nul
rc /nologo /I "%ROOT%\native\setup" /fo setup.res "%ROOT%\native\setup\setup.rc"
if errorlevel 1 (popd & exit /b 1)
popd

cl %COMMON% "%ROOT%\native\setup\main.cpp" "%ROOT%\native\common\common.cpp" "%STAGE%\setup.res" /Fe:"%ROOT%\artifacts\GLPI-Agent-Deployer.exe" /Fo:"%STAGE%\\" /link /incremental:no advapi32.lib shell32.lib ole32.lib crypt32.lib
if errorlevel 1 exit /b 1

"%STAGE%\GLPI.Agent.Deployer.Tests.exe"
if errorlevel 1 exit /b 1

for %%F in ("%ROOT%\artifacts\GLPI-Agent-Deployer.exe") do echo Built %%~fF ^(%%~zF bytes^)
exit /b 0
