@echo off
REM === Testowy plik batch do podświetlania składni ===
:: Drugi typ komentarza — podwójny dwukropek

setlocal enabledelayedexpansion

:: Zmienne
set "USER_NAME=%USERNAME%"
set COUNT=10
set /a RESULT=%COUNT% + 5

echo Witaj %USER_NAME%! Wynik obliczeń to: %RESULT%

:: Prosty warunek
if "%RESULT%"=="15" (
    echo Wynik jest równy 15
) else (
    echo Wynik NIE jest równy 15
)

:: Etykieta i pętla FOR
:loop
for /L %%i in (1,1,5) do (
    echo Iteracja %%i
    if %%i==3 goto skip
)
goto end

:skip
echo Skoczono do etykiety :skip

:: Polecenia wbudowane
copy "C:\Windows\System32\cmd.exe" "%TEMP%\cmd_copy.exe" >nul
del "%TEMP%\cmd_copy.exe" /f /q

echo %~dp0 - aktualny katalog skryptu

pause
:end
echo Skrypt zakończony.
exit /b 0
