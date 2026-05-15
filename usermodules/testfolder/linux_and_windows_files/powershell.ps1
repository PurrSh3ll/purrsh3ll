<#
    =========================================
      TEST SKRYPT DLA PowerShellHighlighter
    =========================================
    - komentarze liniowe i blokowe
    - here-strings (@" "@ i @' '@)
    - zmienne i subexpressions
    - funkcje i cmdlety
    - liczby, stringi i operatory
#>

# --- Komentarze liniowe ---
# To jest zwykły komentarz
# $var tutaj nie powinien być podświetlony jako zmienna

# --- Deklaracje zmiennych ---
$UserName = "Alice"
$Today = Get-Date
$Sum = 3 + 7
$EnvPath = $env:PATH
$Nested = "$(hostname)-$($UserName.ToUpper())"

# --- Funkcja testowa ---
function Show-Info {
    param(
        [string]$Name,
        [datetime]$Date
    )

    Write-Host "Użytkownik: $Name"
    Write-Host "Data: $($Date.ToLongDateString())"
}

# --- Wywołanie funkcji ---
Show-Info -Name $UserName -Date $Today

# --- Here-string (podwójny cudzysłów, z ekspansją zmiennych) ---
$info = @"
Użytkownik: $UserName
Data: $(Get-Date -Format "yyyy-MM-dd")
To jest here-string z ekspansją zmiennych i komend.
"@

# --- Here-string (pojedynczy cudzysłów, bez ekspansji) ---
$rawInfo = @'
Zmienna $UserName NIE zostanie rozwinięta.
Polecenie $(Get-Date) również nie.
'@

# --- Pętla i warunki ---
for ($i = 1; $i -le 5; $i++) {
    if ($i -eq 3) {
        Write-Output "To jest trzecia iteracja!"
    } else {
        Write-Output "Iteracja $i"
    }
}

# --- Blokowy komentarz ---
<#
To jest blokowy komentarz
który może zajmować kilka linii.
#>

# --- Przykład subexpressions i here-string w jednej linii ---
Write-Output $("Dzisiaj jest: $(Get-Date -Format 'dddd')")

# --- Koniec testu ---
Write-Host "=== KONIEC TESTU ==="
