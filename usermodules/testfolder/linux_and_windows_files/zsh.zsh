#!/bin/zsh

# ----------------------------------------------
# 1. Funkcje i zmienne specyficzne dla Zsh
# ----------------------------------------------

# Włączenie rozszerzonych opcji globbing, jeśli jeszcze nie są włączone
# W Zsh jest to często włączone domyślnie, ale dla bezpieczeństwa skryptu
setopt EXTENDED_GLOB

echo "--- Użycie zaawansowanego globbingu w Zsh ---"

# Rozwinięcie nazw plików: znalezienie wszystkich plików
# które nie mają rozszerzenia .txt i .log w bieżącym katalogu
# Używamy operatora negacji ^
# Pliki, których nazwy nie kończą się na (.txt|.log)
files_to_process=(*(^.txt|^.log))

if [[ ${#files_to_process[@]} -gt 0 ]]; then
    echo "Znaleziono pliki, które nie są .txt ani .log:"
    # Użycie zmiennej tablicowej Zsh
    for file in "${files_to_process[@]}"; do
        echo "- $file"
    done
else
    echo "Nie znaleziono żadnych innych plików do przetworzenia."
fi


# ----------------------------------------------
# 2. Standardowe polecenia (działające też w .sh/.bash)
# ----------------------------------------------

echo ""
echo "--- Standardowe polecenia (kompatybilne) ---"

# Sprawdzenie, czy katalog 'backup' istnieje, i utworzenie go, jeśli nie
BACKUP_DIR="~/moj_backup_zsh"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "Katalog $BACKUP_DIR nie istnieje. Tworzę go..."
    mkdir -p "$BACKUP_DIR"
else
    echo "Katalog $BACKUP_DIR już istnieje."
fi

# Wyświetlenie aktualnej daty
echo "Aktualna data i czas: $(date +%Y-%m-%d_%H:%M:%S)"


# ----------------------------------------------
# 3. Zsh-specyficzne funkcje interaktywne
#    (często używane w pliku .zshrc, ale w skrypcie też możliwe)
# ----------------------------------------------

echo ""
echo "--- Zmienne Zsh ---"
# Sprawdzenie i wyświetlenie nazwy aktualnej powłoki (powinno być 'zsh')
echo "Nazwa powłoki (SHELL): $SHELL"
echo "Nazwa wykonywanego skryptu (0): $0"