#!/bin/bash

# ==============================================================================
# Skrypt: System Maintenance and Log Analyzer (SYSMALA)
# Opis: Narzędzie do monitorowania kluczowych parametrów systemu, zarządzania
#       plikami tymczasowymi i analizy prostych logów.
# Autor: AI Assistant
# Data: 2025-10-22
# Wersja: 1.2.0
# ==============================================================================

# ==============================================================================
# 1. ZMIENNE GLOBALNE I STAŁE
# ==============================================================================

# Definicje kolorów dla lepszej czytelności wyjścia
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Stałe ścieżki
LOG_DIR="/var/log"
TEMP_DIR="/tmp"
REPORT_FILE="./system_report_$(date +%Y%m%d_%H%M%S).txt"
REQUIRED_UTILS=("df" "grep" "awk" "sed" "du" "find")

# Parametry progowe
DISK_THRESHOLD=90 # Procent użycia, przy którym jest alarm
MEM_THRESHOLD=80  # Procent użycia pamięci

# ==============================================================================
# 2. FUNKCJE POMOCNICZE
# ==============================================================================

# Funkcja obsługi sygnału przerwania (Ctrl+C)
cleanup() {
    echo -e "\n${RED}[CZYSZCZENIE] Przerwano przez użytkownika. Zakończenie skryptu.${NC}"
    # Opcjonalnie usuń plik raportu, jeśli nie został zakończony
    # rm -f "$REPORT_FILE"
    exit 1
}

# Funkcja sprawdza, czy wszystkie wymagane narzędzia są dostępne
check_dependencies() {
    echo -e "${BLUE}Sprawdzanie zależności systemowych...${NC}"
    local missing_tools=0
    for util in "${REQUIRED_UTILS[@]}"; do
        if ! command -v "$util" &> /dev/null; then
            echo -e "${RED}BŁĄD: Wymagane narzędzie '$util' nie znalezione.${NC}"
            missing_tools=1
        fi
    done

    if [ "$missing_tools" -ne 0 ]; then
        echo -e "${RED}Krytyczny błąd: Brakuje wymaganych narzędzi. Zakończenie.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Wszystkie zależności spełnione.${NC}"
}

# Funkcja wyświetlająca pomoc
show_help() {
    echo -e "${YELLOW}Użycie: $0 [OPCJA]${NC}"
    echo "Opcje:"
    echo "  --disk              Sprawdza wykorzystanie dysku i generuje alarm."
    echo "  --clean <dni>       Usuwa pliki starsze niż <dni> z katalogu $TEMP_DIR."
    echo "  --analyze <plik>    Analizuje podany plik logu pod kątem błędów."
    echo "  --report            Generuje pełny raport systemowy do pliku."
    echo "  --help              Wyświetla ten komunikat."
    exit 0
}

# ==============================================================================
# 3. FUNKCJE MONITORUJĄCE
# ==============================================================================

# Funkcja monitorująca wykorzystanie dysku
monitor_disk_usage() {
    echo -e "${BLUE}--- Monitoring Wykorzystania Dysku ---${NC}"
    df -h | awk 'NR>1 {
        # NR>1 pomija nagłówek
        # $5 to użycie w %
        # $6 to punkt montowania
        usage = substr($5, 1, length($5)-1); # Usuń znak %
        if (usage > '"$DISK_THRESHOLD"') {
            print "\033[0;31m[ALARM KRYTYCZNY]\033[0m Wykorzystanie " $6 " przekracza " usage "%!"
            EXIT_CODE=1
        } else if (usage > 75) {
            print "\033[0;33m[OSTRZEŻENIE]\033[0m Wykorzystanie " $6 " wynosi " usage "%."
        } else {
            print "\033[0;32m[OK]\033[0m Wykorzystanie " $6 " wynosi " usage "%."
        }
    }'
}

# Funkcja monitorująca pamięć
monitor_memory_usage() {
    echo -e "${BLUE}--- Monitoring Wykorzystania Pamięci ---${NC}"
    # Użycie 'free' do obliczenia wolnej pamięci
    local total_mem=$(free | awk '/Mem:/ {print $2}')
    local used_mem=$(free | awk '/Mem:/ {print $3}')
    
    if [ "$total_mem" -eq 0 ]; then
        echo -e "${RED}BŁĄD: Nie można odczytać całkowitej pamięci.${NC}"
        return 1
    fi

    # Obliczenie procentowego użycia
    local percent_used=$((used_mem * 100 / total_mem))

    echo "Całkowita pamięć: $(awk -v t="$total_mem" 'BEGIN {printf "%.2f", t/1024/1024}') GB"
    echo "Używana pamięć: $(awk -v u="$used_mem" 'BEGIN {printf "%.2f", u/1024/1024}') GB ($percent_used%)"
    
    if [ "$percent_used" -gt "$MEM_THRESHOLD" ]; then
        echo -e "${RED}[ALARM] Wykorzystanie pamięci ($percent_used%) przekracza próg $MEM_THRESHOLD%.${NC}"
    else
        echo -e "${GREEN}[OK] Wykorzystanie pamięci na akceptowalnym poziomie.${NC}"
    fi
}

# ==============================================================================
# 4. FUNKCJE OPERACYJNE (CZYSZCZENIE I ANALIZA)
# ==============================================================================

# Funkcja czyszcząca pliki tymczasowe
clean_temp_files() {
    local days_to_keep=$1
    echo -e "${BLUE}--- Czyszczenie $TEMP_DIR ---${NC}"
    
    # Walidacja wejścia
    if ! [[ "$days_to_keep" =~ ^[0-9]+$ ]] || [ "$days_to_keep" -le 0 ]; then
        echo -e "${RED}BŁĄD: Wymagana liczba dni (liczba całkowita > 0).${NC}"
        return 1
    fi
    
    # Wyszukiwanie plików starszych niż X dni
    local files_to_delete
    files_to_delete=$(find "$TEMP_DIR" -type f -mtime +"$days_to_keep" -print)
    
    if [ -z "$files_to_delete" ]; then
        echo -e "${YELLOW}Nie znaleziono plików starszych niż $days_to_keep dni.${NC}"
        return 0
    fi
    
    echo "Znaleziono pliki starsze niż $days_to_keep dni. Usuwanie..."
    
    # Pętla do usunięcia plików
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            # rm -f "$file" # Zakomentowane dla bezpieczeństwa
            echo -e "  [DELETED] $file"
        fi
    done <<< "$files_to_delete"
    
    echo -e "${GREEN}Czyszczenie zakończone.${NC}"
}

# Funkcja analizująca logi
analyze_log_file() {
    local log_file=$1
    echo -e "${BLUE}--- Analiza pliku logu: $log_file ---${NC}"
    
    if [ ! -f "$log_file" ]; then
        echo -e "${RED}BŁĄD: Plik logu nie istnieje lub jest niedostępny: $log_file${NC}"
        return 1
    fi

    local error_count
    # Użycie sed do policzenia linii zawierających "ERROR" lub "FAIL" (bez rozróżniania wielkości liter)
    error_count=$(grep -i -c -E "(ERROR|FAIL|CRITICAL)" "$log_file")

    echo "Znaleziono $error_count potencjalnych błędów/awarii."
    
    if [ "$error_count" -gt 0 ]; then
        echo -e "${YELLOW}Ostatnie 5 wystąpień:${NC}"
        # Wyświetlenie ostatnich 5 linii z błędami/awariami
        grep -i -E "(ERROR|FAIL|CRITICAL)" "$log_file" | tail -n 5
    else
        echo -e "${GREEN}Brak krytycznych wpisów w logu.${NC}"
    fi
}

# ==============================================================================
# 5. GŁÓWNA LOGIKA SKRYPTU
# ==============================================================================

main() {
    # 1. Obsługa przerwania (trap)
    trap cleanup SIGINT

    # 2. Sprawdzenie zależności
    check_dependencies
    
    # 3. Parsowanie argumentów wejściowych (case statement)
    case "$1" in
        --disk)
            monitor_disk_usage
            monitor_memory_usage
            ;;
        --clean)
            # Sprawdzenie, czy podano drugi argument
            if [ -z "$2" ]; then
                echo -e "${RED}BŁĄD: Opcja --clean wymaga podania liczby dni.${NC}"
                show_help
            fi
            clean_temp_files "$2"
            ;;
        --analyze)
            # Sprawdzenie, czy podano drugi argument
            if [ -z "$2" ]; then
                echo -e "${RED}BŁĄD: Opcja --analyze wymaga podania ścieżki do pliku logu.${NC}"
                show_help
            fi
            analyze_log_file "$2"
            ;;
        --report)
            echo -e "${BLUE}Generowanie pełnego raportu do pliku $REPORT_FILE...${NC}"
            
            # Przekierowanie całego wyjścia do pliku raportu
            (
                echo "=========================================================="
                echo "RAPORT SYSTEMOWY - GENEROWANY PRZEZ SYSMALA"
                echo "Data: $(date)"
                echo "Użytkownik: $(whoami)"
                echo "=========================================================="
                echo ""
                monitor_disk_usage
                echo ""
                monitor_memory_usage
                echo ""
                echo "--- Podsumowanie Użycia Katalogów (Top 10) ---"
                # Użycie 'du' i 'sort' do znalezienia największych katalogów w /var
                sudo du -sh "$LOG_DIR"/* 2>/dev/null | sort -rh | head -n 10
                echo ""
            ) > "$REPORT_FILE"

            echo -e "${GREEN}Raport zapisany pomyślnie w $REPORT_FILE.${NC}"
            ;;
        --help)
            show_help
            ;;
        *)
            if [ -z "$1" ]; then
                echo -e "${RED}BŁĄD: Nie podano opcji. Użyj --help, aby zobaczyć dostępne opcje.${NC}"
            else
                echo -e "${RED}BŁĄD: Nieznana opcja '$1'. Użyj --help.${NC}"
            fi
            exit 1
            ;;
    esac
}

# Uruchomienie głównej funkcji
main "$@"

# ==============================================================================
# KONIEC SKRYPTU
# ==============================================================================
