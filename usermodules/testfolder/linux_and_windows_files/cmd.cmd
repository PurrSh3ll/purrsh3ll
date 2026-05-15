@echo off
REM ==============================================================================
REM Skrypt: Windows System Diagnostics and Cleanup (WinDiagnoClean)
REM Opis: Narzędzie do sprawdzania kluczowych informacji systemowych,
REM        monitorowania dysku i czyszczenia plików tymczasowych.
REM Autor: AI Assistant
REM Data: 2025-10-22
REM Wersja: 1.0.0
REM ==============================================================================

REM Ustawienie tytułu okna i kolorów
title WinDiagnoClean - Narzędzie Diagnostyczne
color 1F

REM ==============================================================================
REM 1. ZMIENNE GLOBALNE I STAŁE
REM ==============================================================================

set LOG_FILE=%TEMP%\system_report_%date:~6,4%%date:~3,2%%date:~0,2%.log
set DISK_THRESHOLD=90
set TEMP_FOLDERS="%TEMP%" "%WINDIR%\Temp"

REM ==============================================================================
REM 2. FUNKCJE (Emulacja za pomocą GOTO)
REM ==============================================================================

:ShowHelp
echo.
echo =========================================================
echo Uzycie: %~n0 [OPCJA] [PARAMETR]
echo =========================================================
echo Opcje:
echo   /INFO             Wyswietla podstawowe informacje o systemie.
echo   /DISK             Sprawdza wykorzystanie dysku C: i generuje alarm.
echo   /CLEAN [DNI]      Usuwa pliki starsze niz [DNI] z katalogow tymczasowych.
echo   /REPORT           Generuje pelny raport do pliku logu.
echo   /H lub /?         Wyswietla ten komunikat pomocy.
echo.
GOTO :EOF

:MonitorDiskUsage
echo.
echo [DIAGNOSTYKA] Sprawdzanie wykorzystania dysku C:
echo -------------------------------------------------

REM Uzycie WMIC do pobrania danych o partycji C:
for /f "skip=1" %%d in ('wmic logicaldisk where "deviceid='C:'" get freespace /value') do (
    set FreeSpace=%%d
)

for /f "skip=1" %%t in ('wmic logicaldisk where "deviceid='C:'" get size /value') do (
    set TotalSize=%%t
)

REM Usunięcie etykiet zmiennych
set FreeSpace=%FreeSpace:FreeSpace=%
set TotalSize=%TotalSize:Size=%

REM Upewnienie sie, ze zmienne nie sa puste i konwersja na MB (dla czytelnosci)
IF "%TotalSize%"=="" GOTO ErrorDisk

set /a UsedSpace=%TotalSize% - %FreeSpace%
set /a UsagePercent=^(%UsedSpace% * 100^) / %TotalSize%
set /a FreeGB=%FreeSpace% / 1024 / 1024 / 1024
set /a TotalGB=%TotalSize% / 1024 / 1024 / 1024

echo Rozmiar calkowity: %TotalGB% GB
echo Wolne miejsce: %FreeGB% GB
echo Uzycie: %UsagePercent%%%

IF %UsagePercent% GTR %DISK_THRESHOLD% (
    echo.
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo ALARM KRYTYCZNY: Wykorzystanie dysku przekracza %DISK_THRESHOLD%%%!
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
) ELSE (
    echo.
    echo Status: OK. Wykorzystanie dysku jest akceptowalne.
)

GOTO :EOF

:CleanTempFiles
set Days=%1
echo.
echo [CZYSZCZENIE] Usuwanie plikow starszych niz %Days% dni.
echo -------------------------------------------------

REM Walidacja argumentu (sprawdzenie, czy to liczba)
echo %Days%| findstr /r "[^0-9]" >nul
IF %errorlevel% EQU 0 (
    echo Blad: Parametr dni musi byc liczba calkowita.
    GOTO :EOF
)

IF %Days% LSS 1 (
    echo Blad: Liczba dni musi byc wieksza niz 0.
    GOTO :EOF
)

set TotalDeleted=0

REM Glowna petla czyszczaca
FOR %%F IN (%TEMP_FOLDERS%) DO (
    echo.
    echo Czyszczenie katalogu: %%F
    
    REM Uzycie FORFILES do znajdowania i usuwania plikow
    REM /P - sciezka
    REM /S - podkatalogi
    REM /M - maska (wszystkie pliki)
    REM /D - dni starsze niz
    
    FORFILES /P %%F /S /M *.* /D -%Days% /C "cmd /c if @isdir==FALSE echo OSTRZEZENIE: Usuwam plik @path && del /q @path" 2>nul
    
    REM Liczenie usunietych elementow jest trudne w czystym cmd, wiec ten krok pomijamy
    echo Czyszczenie katalogu %%F zakonczone.
)

echo.
echo [CZYSZCZENIE] Przeszukano i usunieto pliki tymczasowe.
GOTO :EOF

:GenerateReport
echo.
echo [RAPORTOWANIE] Generowanie raportu do pliku: %LOG_FILE%
echo -------------------------------------------------

REM Przekierowanie calej diagnostyki do pliku logu
echo ========================================================= > %LOG_FILE%
echo RAPORT SYSTEMOWY - WINDIAGNOCLEAN >> %LOG_FILE%
echo Data: %date% %time% >> %LOG_FILE%
echo ========================================================= >> %LOG_FILE%

REM Podstawowe informacje
echo. >> %LOG_FILE%
echo --- Podstawowe Informacje o Systemie --- >> %LOG_FILE%
systeminfo | findstr /v "Hotfix(s)" >> %LOG_FILE%

REM Procesy
echo. >> %LOG_FILE%
echo --- Lista Uruchomionych Procesow (Top 10) --- >> %LOG_FILE%
tasklist | sort /r | head -n 10 >> %LOG_FILE%

REM Stan Dysku
echo. >> %LOG_FILE%
echo --- Stan Dysku C: --- >> %LOG_FILE%
call :MonitorDiskUsage >> %LOG_FILE%

echo. >> %LOG_FILE%
echo RAPORT ZAKONCZONY. >> %LOG_FILE%
echo.

echo Raport zapisany pomyslnie w %LOG_FILE%
GOTO :EOF

:ErrorDisk
echo.
echo Blad Krytyczny: Nie udalo sie pobrac danych WMIC o dysku.
GOTO :EOF

:EOF
REM Koniec symulacji funkcji

REM ==============================================================================
REM 3. GLOWNA LOGIKA SKRYPTU
REM ==============================================================================

REM Sprawdzanie argumentow wejsciowych
IF "%1"=="/H" GOTO ShowHelp
IF "%1"=="/?" GOTO ShowHelp
IF "%1"=="" GOTO ShowHelp

IF /I "%1"=="/INFO" (
    echo.
    echo [INFO] System:
    systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Total Physical Memory"
    echo.
    GOTO :EOF
)

IF /I "%1"=="/DISK" (
    call :MonitorDiskUsage
    GOTO :EOF
)

IF /I "%1"=="/CLEAN" (
    IF "%2"=="" (
        echo Blad: Opcja /CLEAN wymaga podania liczby dni.
        GOTO ShowHelp
    )
    call :CleanTempFiles %2
    GOTO :EOF
)

IF /I "%1"=="/REPORT" (
    call :GenerateReport
    GOTO :EOF
)

REM Jesli nie znaleziono opcji
echo Blad: Nieznana opcja "%1".
GOTO ShowHelp
