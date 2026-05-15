-- game_config_manager.lua - Złożony przykład kodu Lua z Tabela i Symulacją Preprocesora

-- -------------------------------------------------------------------------
-- 1. Symulacja Preprocesora (Globalne Stałe i Warunkowe Ładowanie)
-- -------------------------------------------------------------------------

-- GLOBALNA STAŁA (Symuluje dyrektywę #define DEBUG)
-- Zmienia zachowanie kodu w zależności od trybu
_G.ENVIRONMENT = "PRODUCTION"  -- Możliwe wartości: "DEVELOPMENT", "PRODUCTION"
_G.LOG_LEVEL = 2               -- 0: Brak logów, 1: Błędy, 2: Ostrzeżenia, 3: Info

-- Funkcja pomocnicza do logowania
local function log_message(level_required, message)
    if _G.LOG_LEVEL >= level_required then
        local level_name = "INFO"
        if level_required == 1 then level_name = "ERROR"
        elseif level_required == 2 then level_name = "WARN" end

        -- Użycie interpolacji (string.format) i konkatenacji (..)
        print(string.format("[%s][%s] %s", level_name, _G.ENVIRONMENT, message))
    end
end

-- Warunkowe Ładowanie (Symulacja #ifdef)
if _G.ENVIRONMENT == "DEVELOPMENT" then
    log_message(3, "Tryb DEVELOPMENT AKTYWNY. Włączono pełne logowanie.")
    local function dev_debug_hook()
        -- Ta funkcja istnieje tylko w trybie deweloperskim
        log_message(3, "Developer Hook: Sprawdzanie zmiennych globalnych...")
    end
    _G.run_dev_hook = dev_debug_hook
else
    log_message(3, "Tryb PRODUCTION AKTYWNY. Zredukowana wydajność logowania.")
    -- Definicja pustej funkcji w trybie produkcyjnym (dla bezpieczeństwa i wydajności)
    _G.run_dev_hook = function() end
end

-- -------------------------------------------------------------------------
-- 2. Złożona Tabela Konfiguracyjna (Configuration Table)
-- -------------------------------------------------------------------------

-- Główna tabela przechowująca całą konfigurację gry (Hash of Hashes/Arrays)
local GameConfig = {
    -- Tabela (Hash) z ustawieniami podstawowymi
    General = {
        title = "Aetheria Chronicles",
        version = 1.45,
        max_players = 32,
        server_ip = (_G.ENVIRONMENT == "DEVELOPMENT" and "127.0.0.1") or "prod.aetheria.net",
        enable_tutorials = true
    },

    -- Tabela (Hash) z regułami gry
    Rules = {
        friendly_fire = false,
        max_score = 1000,
        round_time_limit = 1200 -- w sekundach
    },

    -- Tabela (Array of Hashes) z definicjami poziomów
    Levels = {
        [1] = { name = "Green Valley", environment = "Forest", difficulty = 1, unlock_score = 0 },
        [2] = { name = "Shadow Peaks", environment = "Mountain", difficulty = 4, unlock_score = 500 },
        [3] = { name = "Sunken City", environment = "Underwater", difficulty = 8, unlock_score = 1500 }
    },

    -- Tabela (Hash) z ustawieniami graficznymi (zagnieżdżone tabele)
    Graphics = {
        resolution = { width = 1920, height = 1080, refresh_rate = 60 },
        shadow_quality = (_G.ENVIRONMENT == "PRODUCTION" and "Medium") or "High", -- Warunek w tabeli
        fxaa_enabled = true
    }
}

-- -------------------------------------------------------------------------
-- 3. Funkcja do walidacji i modyfikacji tabeli
-- -------------------------------------------------------------------------

local function validate_and_normalize_config(config_table)
    log_message(3, "Walidacja i normalizacja konfiguracji...")

    -- I. Walidacja sekcji General
    if type(config_table.General.title) ~= "string" or #config_table.General.title < 3 then
        log_message(1, "Błąd: Tytuł gry jest nieprawidłowy.")
        config_table.General.title = "Default Title"
    end

    -- II. Iteracja i modyfikacja tabeli Levels
    local total_difficulty = 0
    -- Użycie ipairs do iteracji po tabelach (jako Array)
    for i, level in ipairs(config_table.Levels) do
        -- Interpolacja dla logowania
        log_message(3, string.format("Sprawdzanie poziomu %d: %s (Trudność: %d)", i, level.name, level.difficulty))

        -- Zabezpieczenie danych
        if level.difficulty < 1 then
            level.difficulty = 1
            log_message(2, "Ostrzeżenie: Zresetowano trudność na 1.")
        end
        total_difficulty = total_difficulty + level.difficulty
    end

    -- III. Dodanie dynamicznego pola do głównej tabeli
    config_table.OverallDifficulty = total_difficulty

    -- IV. Iteracja po hashu (sekcji Rules)
    for key, value in pairs(config_table.Rules) do
        if type(value) == "boolean" then
            log_message(3, string.format("Reguła logiczna '%s' jest ustawiona na %s.", key, tostring(value)))
        end
    end

    return config_table
end

-- -------------------------------------------------------------------------
-- 4. Główna Funkcja Aplikacji
-- -------------------------------------------------------------------------

local function run_game_manager()
    log_message(3, "Uruchamianie Managera...")

    -- Krok 1: Walidacja i modyfikacja tabeli
    local validated_config = validate_and_normalize_config(GameConfig)

    -- Uruchomienie preprocesorowego haka
    _G.run_dev_hook()

    print("\n--- Zgłoszenie Końcowe (Odczyt Tabeli) ---")

    -- Krok 2: Odczyt danych z tabeli
    local title = validated_config.General.title
    local ip = validated_config.General.server_ip
    local total_diff = validated_config.OverallDifficulty
    local shadow_setting = validated_config.Graphics.shadow_quality
    local level_count = #validated_config.Levels -- Odczyt długości Array

    -- Finalna interpolacja
    local report = string.format([[
Tytuł Gry: %s
Wersja: %.2f
Adres Serwera (%s): %s
Liczba Poziomów: %d
Ustawienia Grafiki (Cienie): %s
Łączna Trudność: %d
]],
        title,
        validated_config.General.version,
        _G.ENVIRONMENT,
        ip,
        level_count,
        shadow_setting,
        total_diff
    )

    print(report)

    -- Warunek używający danych z tabeli
    if total_diff > 10 then
        log_message(2, "Złożoność gry jest wysoka; zalecany jest test wydajności.")
    end

    -- Demonstracja dostępu do zagnieżdżonej tabeli
    log_message(3, "Rozdzielczość: " .. validated_config.Graphics.resolution.width .. "x" .. validated_config.Graphics.resolution.height)
end

-- Wywołanie głównej funkcji
run_game_manager()