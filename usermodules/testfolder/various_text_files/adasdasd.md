# 🚀 Projekt System Monitor (SysMon)

## 📝 Opis Projektu

**System Monitor (SysMon)** to lekkie narzędzie wiersza poleceń służące do ciągłego monitorowania kluczowych zasobów systemowych, takich jak użycie CPU, pamięć oraz obciążenie dysku. Jest napisane w Pythonie i ma na celu zapewnienie natychmiastowej, czytelnej diagnostyki.

## ✨ Cechy Główne

* **Monitorowanie w czasie rzeczywistym:** Wyświetlanie danych co 2 sekundy.
* **Wieloplatformowość:** Działa na systemach Linux, macOS i Windows.
* **Niski narzut:** Zaprojektowany, aby zużywać minimalne zasoby.
* **Kolorowe ostrzeżenia:** Wizualne powiadomienia o przekroczeniu progów.

## 🛠 Instalacja

Aby zainstalować projekt, wykonaj następujące kroki:

1.  **Klonowanie repozytorium:**
    ```bash
    git clone [https://github.com/example/SysMon.git](https://github.com/example/SysMon.git)
    cd SysMon
    ```
2.  **Instalacja zależności:**
    ```bash
    pip install -r requirements.txt
    ```

## 🏃 Użycie

### 1. Podstawowe Uruchomienie

Użyj flagi `-c` lub `--continuous` do monitorowania ciągłego.

```bash
python monitor.py --continuous
