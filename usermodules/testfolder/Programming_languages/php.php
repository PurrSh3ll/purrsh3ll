<?php
/**
 * data_processing_system.php
 *
 * Zaawansowany skrypt PHP do symulacji przetwarzania danych użytkowników,
 * obliczania statystyk i generowania raportu HTML.
 * Używa wielu zmiennych skalarnych, tablic i obiektów.
 *
 * Ten skrypt nie łączy się z bazą danych, używa danych wbudowanych w tablice
 * dla celów demonstracyjnych.
 */

// 1. Zmienne Konfiguracyjne (Skalarne)
// --------------------------------------------------------------------------
$system_name = "System Raportowania Danych Użytkowników v2.1";
$report_date = date("Y-m-d H:i:s");
$company_name = "ACME Data Solutions";
$default_status = "Aktywny";
$tax_rate = 0.23; // 23% VAT111
$max_records_to_process = 50;

// 2. Zmienne Tablicowe: Wbudowane Dane (Array)
// --------------------------------------------------------------------------
$user_data_raw = [
    ['id' => 101, 'name' => 'Anna Kowalska', 'city' => 'Warszawa', 'monthly_sales' => 5200.50, 'is_premium' => true],
    ['id' => 102, 'name' => 'Piotr Nowak', 'city' => 'Kraków', 'monthly_sales' => 3100.00, 'is_premium' => false],
    ['id' => 103, 'name' => 'Krzysztof Zając', 'city' => 'Gdańsk', 'monthly_sales' => 8500.75, 'is_premium' => true],
    ['id' => 104, 'name' => 'Ewa Słoń', 'city' => 'Warszawa', 'monthly_sales' => 1200.00, 'is_premium' => false],
    ['id' => 105, 'name' => 'Tomasz Wilk', 'city' => 'Wrocław', 'monthly_sales' => 4700.25, 'is_premium' => true],
];

// Tablica miast do filtrowania
$target_cities = ['Warszawa', 'Wrocław'];

// 3. Klasa Użytkownika (Zmienna Obiektowa)
// --------------------------------------------------------------------------
class UserReport
{
    // Zmienne publiczne obiektu (właściwości)
    public $user_id;
    public $full_name;
    public $location;
    public $sales_netto;
    public $sales_brutto;
    public $status;
    public $is_premium;

    // Metoda konstrukcyjna
    public function __construct($id, $name, $city, $sales, $premium, $tax_rate)
    {
        // Przypisanie wartości do zmiennych obiektu
        $this->user_id = (int) $id;
        $this->full_name = (string) $name;
        $this->location = (string) $city;
        $this->sales_netto = (float) $sales;
        $this->is_premium = (bool) $premium;
        $this->status = "Aktywny"; // Domyślna wartość

        // Obliczenie sprzedaży brutto i przypisanie do zmiennej obiektu
        $this->sales_brutto = $this->calculateBrutto($tax_rate);
    }

    // Metoda obiektu do obliczeń
    private function calculateBrutto($tax)
    {
        // Zmienna lokalna wewnątrz metody
        $vat_amount = $this->sales_netto * $tax;
        return round($this->sales_netto + $vat_amount, 2);
    }
}

// 4. Inicjalizacja Zmiennych Obliczeniowych
// --------------------------------------------------------------------------
$total_net_sales = 0.00;        // Suma sprzedaży netto (float)
$total_brutto_sales = 0.00;     // Suma sprzedaży brutto (float)
$premium_count = 0;             // Licznik użytkowników Premium (integer)
$processed_records_count = 0;   // Licznik przetworzonych rekordów (integer)
$processed_users = [];          // Tablica przechowująca obiekty UserReport

// 5. Pętla Przetwarzania Danych (Główna Logika)
// --------------------------------------------------------------------------

// Zmienna logiczna do warunku kontynuacji
$processing_active = true;

if (count($user_data_raw) > $max_records_to_process) {
    // Ustawienie zmiennej ostrzegawczej
    $processing_message = "OSTRZEŻENIE: Przekroczono maksymalną liczbę rekordów do przetworzenia. Przetworzono tylko $max_records_to_process.";
    // Zmiana zmiennej logicznej
    $processing_active = false;
} else {
     $processing_message = "Przetwarzanie danych zakończone pomyślnie.";
}

// Pętla foreach do iteracji po surowych danych
foreach ($user_data_raw as $user_row) {

    // Zmienna lokalna wewnątrz pętli
    $current_id = $user_row['id'];

    // Warunek: Przetwarzaj tylko, jeśli ID jest mniejsze niż 105 i przetwarzanie jest aktywne
    if ($current_id < 105 && $processing_active) {

        // Warunek: Filtrowanie po mieście
        if (in_array($user_row['city'], $target_cities)) {

            // Utworzenie nowej zmiennej obiektowej (instancji klasy)
            $user_obj = new UserReport(
                $current_id,
                $user_row['name'],
                $user_row['city'],
                $user_row['monthly_sales'],
                $user_row['is_premium'],
                $tax_rate
            );

            // Dodanie obiektu do tablicy
            $processed_users[] = $user_obj;

            // Aktualizacja zmiennych sumujących
            $total_net_sales += $user_obj->sales_netto;
            $total_brutto_sales += $user_obj->sales_brutto;

            // Warunek: Sprawdzenie statusu premium
            if ($user_obj->is_premium) {
                $premium_count++; // Zwiększenie zmiennej licznika
            }

            $processed_records_count++; // Inkrementacja zmiennej

        }
    } else {
        // Zmienna pomocnicza (boolean)
        $skipped_user = true;
    }
}

// 6. Obliczenia Statystyczne i Zmienne Wynikowe
// --------------------------------------------------------------------------
// Zmienna warunkowa do zapobiegania dzieleniu przez zero
if ($processed_records_count > 0) {
    $average_net_sales = $total_net_sales / $processed_records_count;
    $premium_percentage = ($premium_count / $processed_records_count) * 100;
} else {
    // Zmienne domyślne, jeśli nie przetworzono rekordów
    $average_net_sales = 0.00;
    $premium_percentage = 0.00;
    $processing_message = "Brak rekordów do przetworzenia w filtrach.";
}

// Zaokrąglenie zmiennej
$average_net_sales = round($average_net_sales, 2);
$premium_percentage = round($premium_percentage, 1);

// 7. Generowanie Raportu HTML (Prezentacja Zmiennych)
// --------------------------------------------------------------------------
?>

<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title><?php echo $system_name; ?></title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .summary { margin-top: 30px; padding: 15px; border: 1px solid #ccc; background-color: #f9f9f9; }
        .success { color: green; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
    </style>
</head>
<body>

    <h1>Raport: <?php echo $system_name; ?></h1>
    <p><strong>Firma:</strong> <?php echo $company_name; ?></p>
    <p><strong>Wygenerowano:</strong> <?php echo $report_date; ?></p>
    <p class="<?php echo ($processing_active) ? 'success' : 'warning'; ?>">
        Status Przetwarzania: <?php echo $processing_message; ?>
    </p>

    <h2>1. Statystyki Ogólne</h2>
    <div class="summary">
        <p>Łączna Sprzedaż Netto (przetworzona): <strong><?php echo number_format($total_net_sales, 2, ',', ' '); ?> PLN</strong></p>
        <p>Łączna Sprzedaż Brutto (przetworzona): <strong><?php echo number_format($total_brutto_sales, 2, ',', ' '); ?> PLN</strong></p>
        <p>Średnia Sprzedaż Netto na Użytkownika: <strong><?php echo number_format($average_net_sales, 2, ',', ' '); ?> PLN</strong></p>
        <p>Przetworzone Rekordy (w ramach filtrów): <strong><?php echo $processed_records_count; ?></strong></p>
        <p>Użytkownicy Premium (Udział): <strong><?php echo $premium_count; ?> (<?php echo $premium_percentage; ?>%)</strong></p>
    </div>

    <h2>2. Szczegółowa Lista Przetworzonych Użytkowników</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Imię i Nazwisko</th>
                <th>Miasto</th>
                <th>Sprzedaż Netto</th>
                <th>Sprzedaż Brutto</th>
                <th>Status</th>
                <th>Premium</th>
            </tr>
        </thead>
        <tbody>
            <?php
            // Pętla foreach do iteracji po zmiennej tablicowej z obiektami
            foreach ($processed_users as $user) {
                // Zmienna pomocnicza do klasy CSS
                $premium_class = $user->is_premium ? 'style="background-color: #e6ffe6;"' : '';
                ?>
                <tr <?php echo $premium_class; ?>>
                    <td><?php echo $user->user_id; ?></td>
                    <td><?php echo $user->full_name; ?></td>
                    <td><?php echo $user->location; ?></td>
                    <td><?php echo number_format($user->sales_netto, 2, ',', ' '); ?> PLN</td>
                    <td><?php echo number_format($user->sales_brutto, 2, ',', ' '); ?> PLN</td>
                    <td><?php echo $user->status; ?></td>
                    <td><?php echo $user->is_premium ? 'Tak' : 'Nie'; ?></td>
                </tr>
            <?php } ?>
        </tbody>
    </table>

    <hr>
    <footer>
        <p>Raport wygenerowany przez <?php echo $company_name; ?>. Wszystkie prawa zastrzeżone.</p>
    </footer>

</body>
</html>