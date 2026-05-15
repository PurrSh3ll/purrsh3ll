// processor.go - Przykład kodu Go z 'rune', 'method', 'package' i 'preprocesorem'

// 1. PACKAGE (Pakiet)
// Każdy plik Go musi należeć do pakietu. Pakiet 'main' jest używany dla aplikacji wykonywalnych.
package main

import (
	"fmt"
	"strings"
)

// 2. PREPROCESOR (Symulacja poprzez stałe i tagi kompilacji)
// Go nie ma tradycyjnego preprocesora jak C/C++, ale używa stałych i tagów kompilacji.

// Stała symbolizująca tryb debugowania (jak definicja preprocesora)
const DEBUG_MODE = true

// Tag kompilacji (zwykle na początku pliku, ale tutaj dla kontekstu)
// //go:build debug

// -------------------------------------------------------------------------
// 3. STRUKTURA I METODA (Struct and Method)
// -------------------------------------------------------------------------

// Definicja struktury (jak klasa bez metod)
type TextProcessor struct {
	SourceText string
	Processed  bool
}

// METHOD (Metoda)
// Funkcja powiązana ze strukturą TextProcessor.
// Odbiorca (receiver) 'tp' oznacza, że to jest metoda tej struktury.
func (tp *TextProcessor) Process() {
	if DEBUG_MODE {
		fmt.Println("[DEBUG] Rozpoczynanie przetwarzania tekstu...")
	}

	if tp.SourceText == "" {
		fmt.Println("[WARN] Tekst źródłowy jest pusty. Przetwarzanie przerwane.")
		tp.Processed = true
		return
	}

	// Wykonanie przetwarzania (np. zmiana na duże litery)
	tp.SourceText = strings.ToUpper(tp.SourceText)

	// Użycie runy w pętli
	tp.CountVowels()

	tp.Processed = true
	fmt.Println("[INFO] Przetwarzanie zakończone.")
}

// METHOD (Metoda)
// Metoda demonstracyjna używająca run.
func (tp *TextProcessor) CountVowels() {
	vowelCount := 0

	// 4. RUNE (Typ znaku)
	// 'range' nad stringiem iteruje po runach (kodach Unicode), nie bajtach.
	for _, charRune := range tp.SourceText {
		// Konwersja runy na małą literę dla łatwiejszego porównania
		// W Go 'rune' to alias dla int32, więc może być używany w instrukcji 'switch'.
		switch charRune {
		case 'A', 'E', 'I', 'O', 'U': // W tym przypadku duże litery, ponieważ tekst jest UPPERCASE
			vowelCount++
		}
	}

	// Interpolacja ciągu znaków (użycie fmt.Sprintf)
	fmt.Printf("[INFO] Przetworzony tekst zawiera %d samogłosek.\n", vowelCount)
}

// -------------------------------------------------------------------------
// 5. Główna Funkcja Uruchomieniowa
// -------------------------------------------------------------------------

// Główna funkcja, od której zaczyna się wykonanie programu 'main'.
func main() {
	fmt.Println("=== Go Language Demo ===")

	// Utworzenie instancji struktury
	processor := TextProcessor{
		SourceText: "To jest przykładowy tekst do przetworzenia.",
		Processed:  false,
	}

	// Wywołanie metody
	processor.Process()

	// Wyświetlenie wyniku (interpolacja ciągu znaków)
	fmt.Println("--- Wynik ---")
	fmt.Printf("Oryginalny tekst (przetworzony): %s\n", processor.SourceText)
	fmt.Printf("Status przetworzenia: %t\n", processor.Processed)
}