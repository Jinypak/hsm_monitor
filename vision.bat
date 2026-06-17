@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "APP_DIR=%SCRIPT_DIR%java-app"

set "CMD=%~1"
if "%CMD%"=="" set "CMD=help"
shift

if /i "%CMD%"=="start"     goto :cmd_start
if /i "%CMD%"=="cli"       goto :cmd_cli
if /i "%CMD%"=="test"      goto :cmd_test
if /i "%CMD%"=="build"     goto :cmd_build
if /i "%CMD%"=="algolist"  goto :cmd_algolist
if /i "%CMD%"=="pqctest"   goto :cmd_pqctest
if /i "%CMD%"=="rsatest"   goto :cmd_rsatest
if /i "%CMD%"=="certtest"  goto :cmd_certtest
if /i "%CMD%"=="probeluna" goto :cmd_probeluna
if /i "%CMD%"=="version"   goto :cmd_version
if /i "%CMD%"=="help"      goto :cmd_help
if /i "%CMD%"=="-h"        goto :cmd_help
if /i "%CMD%"=="--help"    goto :cmd_help

echo [vision] Unknown command: %CMD%
echo.
goto :cmd_help

:cmd_start
echo [vision] Starting HSM Monitor GUI...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" run %1 %2 %3 %4 %5 %6 %7 %8 %9
goto :eof

:cmd_cli
echo [vision] Starting HSM Monitor CLI...
call "%APP_DIR%\gradlew.bat" hsmCli -q --console=plain -PskipJavafx
goto :eof

:cmd_test
echo [vision] Running tests...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" test --console=plain %1 %2 %3 %4 %5 %6 %7 %8 %9
if errorlevel 1 (echo [vision] FAILED) else (echo [vision] OK)
goto :eof

:cmd_build
echo [vision] Building...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" build %1 %2 %3 %4 %5 %6 %7 %8 %9
if errorlevel 1 (echo [vision] FAILED) else (echo [vision] OK)
goto :eof

:cmd_algolist
echo [vision] Probing HSM algorithm availability...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" algoList -q %1 %2 %3 %4 %5 %6 %7 %8 %9
goto :eof

:cmd_pqctest
set "SLOT=0"
set "PIN="
:pqc_loop
if "%~1"=="" goto :pqc_run
if /i "%~1"=="-s"     ( set "SLOT=%~2" & shift & shift & goto :pqc_loop )
if /i "%~1"=="--slot" ( set "SLOT=%~2" & shift & shift & goto :pqc_loop )
if /i "%~1"=="-p"     ( set "PIN=%~2"  & shift & shift & goto :pqc_loop )
if /i "%~1"=="--pin"  ( set "PIN=%~2"  & shift & shift & goto :pqc_loop )
shift
goto :pqc_loop
:pqc_run
if "!PIN!"=="" (
    echo [vision] ERROR: -p ^<PIN^> required.  e.g.  vision pqctest -s 0 -p YOUR_PIN
    exit /b 1
)
echo [vision] PQC HSM test (slot=!SLOT!)...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" pqcHsmTest -q "-Pslot=!SLOT!" "-Ppin=!PIN!"
goto :eof

REM [임시] RSA 키 라이프사이클 샘플 테스트
:cmd_rsatest
set "SLOT=0"
set "PIN="
set "LABEL=rsa_test"
:rsa_loop
if "%~1"=="" goto :rsa_run
if /i "%~1"=="-s"     ( set "SLOT=%~2"  & shift & shift & goto :rsa_loop )
if /i "%~1"=="--slot" ( set "SLOT=%~2"  & shift & shift & goto :rsa_loop )
if /i "%~1"=="-p"     ( set "PIN=%~2"   & shift & shift & goto :rsa_loop )
if /i "%~1"=="--pin"  ( set "PIN=%~2"   & shift & shift & goto :rsa_loop )
if /i "%~1"=="-l"     ( set "LABEL=%~2" & shift & shift & goto :rsa_loop )
if /i "%~1"=="--label"( set "LABEL=%~2" & shift & shift & goto :rsa_loop )
shift
goto :rsa_loop
:rsa_run
if "!PIN!"=="" (
    echo [vision] ERROR: -p ^<PIN^> required.  e.g.  vision rsatest -s 0 -p YOUR_PIN -l mykey
    exit /b 1
)
echo [vision] [temp] RSA key lifecycle test (slot=!SLOT!, label=!LABEL!)...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" rsaLifecycle -q --console=plain "-Pslot=!SLOT!" "-Ppin=!PIN!" "-Plabel=!LABEL!"
goto :eof

REM [임시] 인증서 유효기간 테스트 (기존 키 사용)
:cmd_certtest
set "SLOT=0"
set "PIN="
set "LABEL=KEY_ALIAS"
:cert_loop
if "%~1"=="" goto :cert_run
if /i "%~1"=="-s"     ( set "SLOT=%~2"  & shift & shift & goto :cert_loop )
if /i "%~1"=="--slot" ( set "SLOT=%~2"  & shift & shift & goto :cert_loop )
if /i "%~1"=="-p"     ( set "PIN=%~2"   & shift & shift & goto :cert_loop )
if /i "%~1"=="--pin"  ( set "PIN=%~2"   & shift & shift & goto :cert_loop )
if /i "%~1"=="-l"     ( set "LABEL=%~2" & shift & shift & goto :cert_loop )
if /i "%~1"=="--label"( set "LABEL=%~2" & shift & shift & goto :cert_loop )
shift
goto :cert_loop
:cert_run
if "!PIN!"=="" (
    echo [vision] ERROR: -p ^<PIN^> required.  e.g.  vision certtest -s 0 -p YOUR_PIN -l KEY_ALIAS
    exit /b 1
)
echo [vision] [temp] cert validity test (existing key=!LABEL!)...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" certValidityTest -q --console=plain "-Pslot=!SLOT!" "-Ppin=!PIN!" "-Plabel=!LABEL!"
goto :eof

:cmd_probeluna
echo [vision] Dumping LunaProvider services...
cd /d "%APP_DIR%"
call "%APP_DIR%\gradlew.bat" probeLuna -q %1 %2 %3 %4 %5 %6 %7 %8 %9
goto :eof

:cmd_version
echo vision / HSM Monitor
java -version
goto :eof

:cmd_help
echo.
echo  vision -- HSM Monitor launcher
echo.
echo  Usage:
echo    vision ^<command^> [options]
echo.
echo  Commands:
echo    start                        Run GUI (display required)
echo    cli                          Interactive HSM CLI (slot/PIN entered at runtime)
echo    test                         Run unit tests
echo    build                        Build (with tests)
echo    algolist                     Probe HSM algorithm availability
echo    pqctest  -s ^<slot^> -p ^<pin^>  PQC HSM verification (ML-DSA/ML-KEM)
echo    rsatest  -s ^<slot^> -p ^<pin^> -l ^<label^>  [temp] RSA key gen/read/export test
echo    probeluna                    Dump LunaProvider services
echo    version                      Version info
echo    help                         This help
echo.
echo  Examples:
echo    vision cli -s 0 -p 12341234
echo    vision start
echo    vision test
echo    vision algolist
echo    vision pqctest -s 0 -p 12341234
echo    vision start -PlunaClientPath="C:\MyLuna\client"
echo.
goto :eof

endlocal
