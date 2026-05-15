// DigitalCity.cs - Rozbudowany przykład kodu C#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Timers; // Użycie standardowej biblioteki dla zdarzeń czasowych
using Newtonsoft.Json; // Wymaga zainstalowania pakietu NuGet: Newtonsoft.Json

namespace ComplexDigitalCity
{
    // -------------------------------------------------------------------------
    // 1. Definicje typów, delegatów i interfejsów
    // -------------------------------------------------------------------------

    /// <summary>
    /// Definicja delegata dla zdarzeń miejskich
    /// </summary>
    public delegate void CityEventHandler(string eventName, object data);

    /// <summary>
    /// Interfejs dla każdej jednostki, która może generować raporty
    /// </summary>
    public interface IReportable
    {
        string GenerateReport(int detailLevel);
    }

    /// <summary>
    /// Statyczny obiekt symulujący bazę danych (prosta kolekcja)
    /// </summary>
    public static class DigitalDB
    {
        public static List<Citizen> Citizens { get; set; } = new List<Citizen>();
        public static List<Building> Buildings { get; set; } = new List<Building>();
    }

    // -------------------------------------------------------------------------
    // 2. Klasy bazowe i dziedziczenie
    // -------------------------------------------------------------------------

    /// <summary>
    /// Abstrakcyjna klasa bazowa dla wszystkich bytów w mieście
    /// </summary>
    public abstract class CityEntity : IReportable
    {
        // Prywatne pole (backing field) dla właściwości
        private Guid _id = Guid.NewGuid();

        // Właściwość automatyczna (auto-implemented property)
        public string Name { get; set; }

        // Właściwość tylko do odczytu
        public Guid ID => _id;

        // Abstrakcyjna metoda, musi być zaimplementowana w klasach pochodnych
        public abstract void SimulateActivity(int durationInHours);

        // Metoda interfejsu
        public abstract string GenerateReport(int detailLevel);

        // Wirtualna metoda, którą można nadpisać
        public virtual void DisplayInfo()
        {
            Console.WriteLine($"--- {GetType().Name} Info ---");
            Console.WriteLine($"ID: {ID.ToString().Substring(0, 8)} | Name: {Name}");
        }
    }

    /// <summary>
    /// Klasa reprezentująca mieszkańca miasta
    /// Dziedziczy po CityEntity.
    /// </summary>
    public class Citizen : CityEntity
    {
        public int Age { get; private set; }
        public string JobTitle { get; set; }
        public decimal Savings { get; set; }
        public bool IsEmployed { get; set; }
        public Dictionary<string, int> SkillScores { get; set; } = new Dictionary<string, int>();

        // Konstruktor
        public Citizen(string name, int age, string job)
        {
            Name = name;
            Age = age;
            JobTitle = job;
            IsEmployed = true;
            Savings = 1000.00m;
        }

        // Implementacja metody abstrakcyjnej
        public override void SimulateActivity(int durationInHours)
        {
            if (IsEmployed)
            {
                Savings += 10.50m * durationInHours;
            }
            else
            {
                Savings -= 5.00m * durationInHours; // Tracenie oszczędności
            }
        }

        // Nadpisanie metody wirtualnej
        public override void DisplayInfo()
        {
            base.DisplayInfo();
            Console.WriteLine($"Age: {Age} | Job: {JobTitle} | Savings: ${Savings:N2}");
        }

        // Implementacja metody interfejsu
        public override string GenerateReport(int detailLevel)
        {
            if (detailLevel >= 2)
            {
                return $"Citizen Report (Detailed): {Name} is {Age} years old. Employed: {IsEmployed}. Skills: {string.Join(", ", SkillScores.Keys)}";
            }
            return $"Citizen Report (Summary): {Name} ({ID.ToString().Substring(0, 8)})";
        }
    }

    /// <summary>
    /// Klasa reprezentująca budynek w mieście
    /// Dziedziczy po CityEntity.
    /// </summary>
    public class Building : CityEntity
    {
        public string Address { get; set; }
        public int Floors { get; set; }
        public decimal Value { get; private set; }

        // Właściwość obliczeniowa
        public decimal YearlyTax => Value * 0.015m;

        public Building(string name, string address, int floors, decimal value)
        {
            Name = name;
            Address = address;
            Floors = floors;
            Value = value;
        }

        public void Appraise(decimal valueIncrease)
        {
            Value += valueIncrease;
        }

        // Implementacja metody abstrakcyjnej
        public override void SimulateActivity(int durationInHours)
        {
            // Budynek generuje pasywny dochód (np. czynsz)
            Value += (Value * 0.00001m) * durationInHours;
        }

        // Implementacja metody interfejsu
        public override string GenerateReport(int detailLevel)
        {
            return $"Building Report: {Name} at {Address}. Value: ${Value:N0}. Tax: ${YearlyTax:N0}";
        }
    }

    // -------------------------------------------------------------------------
    // 3. Główna klasa systemu (Centralne zarządzanie)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Główna klasa zarządzająca miastem cyfrowym, używająca zdarzeń i asynchroniczności.
    /// </summary>
    public class DigitalCityManager
    {
        // 3.1. Zdarzenia i Delegaty
        public event CityEventHandler CityEventOccurred;
        private readonly System.Timers.Timer _simulationTimer;

        // 3.2. Właściwości i Pola
        public string CityName { get; }
        public int Year { get; private set; }
        public int SimulationSpeedHours { get; set; } = 24; // Prędkość symulacji (godziny na tick)

        // 3.3. Konstruktor
        public DigitalCityManager(string cityName)
        {
            CityName = cityName;
            Year = 2024;

            // Inicjalizacja Danych (dla długości kodu)
            InitializeData();

            // Inicjalizacja Timera dla zdarzeń cyklicznych
            _simulationTimer = new System.Timers.Timer(1000); // Takt co 1 sekundę (symulacja dnia)
            _simulationTimer.Elapsed += OnSimulationTick;
        }

        private void InitializeData()
        {
            DigitalDB.Citizens.Add(new Citizen("Alice Smith", 35, "Programmer"));
            DigitalDB.Citizens.Add(new Citizen("Bob Johnson", 45, "Architect"));
            DigitalDB.Citizens.Add(new Citizen("Charlie Brown", 22, "Student"));
            DigitalDB.Citizens.Last().IsEmployed = false; // Charlie jest bezrobotny

            DigitalDB.Buildings.Add(new Building("City Hall", "1 Main St", 10, 5000000.00m));
            DigitalDB.Buildings.Add(new Building("The Corner Store", "15 Oak Ave", 1, 150000.00m));
        }

        // 3.4. Metody sterujące timerem
        public void StartSimulation()
        {
            _simulationTimer.Start();
            OnCityEvent("SimulationStarted", $"Witaj w {CityName} w roku {Year}.");
        }

        public void StopSimulation()
        {
            _simulationTimer.Stop();
            OnCityEvent("SimulationStopped", "Symulacja wstrzymana.");
        }

        // 3.5. Handler zdarzenia Timera (główna pętla symulacji)
        private void OnSimulationTick(object sender, ElapsedEventArgs e)
        {
            Year++; // Symulacja mija jeden rok

            // Wywołanie asynchronicznej metody w tle
            Task.Run(() => RunAnnualCycleAsync());
        }

        // 3.6. Metoda asynchroniczna symulująca długotrwałe operacje
        private async Task RunAnnualCycleAsync()
        {
            OnCityEvent("AnnualCycleStarted", $"Rok {Year} się rozpoczął.");

            // Symulacja aktywności wszystkich jednostek
            foreach (var entity in DigitalDB.Citizens.Cast<CityEntity>().Concat(DigitalDB.Buildings))
            {
                entity.SimulateActivity(SimulationSpeedHours * 365);
            }

            // Symulacja długiego procesu (np. obliczanie podatków)
            await Task.Delay(50); // Symulacja 50ms opóźnienia

            // Obliczenie i zastosowanie podatków
            CalculateTaxes();

            // Losowe zdarzenie
            if (new Random().Next(1, 10) > 8)
            {
                OnCityEvent("RandomEvent", "Wielkie Odkrycie Technologiczne! Wszyscy mieszkańcy zarobili bonus.");
                await Task.Run(() => ApplyBonusSavings());
            }

            OnCityEvent("AnnualCycleCompleted", $"Rok {Year} zakończony. Stan ludności: {DigitalDB.Citizens.Count}");
        }

        // 3.7. Metody LINQ i operacje na kolekcjach
        private void CalculateTaxes()
        {
            // LINQ do pobrania całkowitego długu podatkowego z budynków
            decimal totalTaxDue = DigitalDB.Buildings.Sum(b => b.YearlyTax);

            // Pobranie najbogatszych mieszkańców z wykorzystaniem LINQ
            var wealthiestCitizens = DigitalDB.Citizens
                .Where(c => c.Savings > 5000m)
                .OrderByDescending(c => c.Savings)
                .Take(3)
                .ToList();

            // Klasyczna pętla foreach
            foreach (var citizen in wealthiestCitizens)
            {
                // Obciążenie podatkiem (prosta symulacja)
                decimal tax = citizen.Savings * 0.05m;
                citizen.Savings -= tax;
                OnCityEvent("TaxCollected", $"Pobrano ${tax:N2} podatku od {citizen.Name}.");
            }
            OnCityEvent("TaxesSummary", $"Całkowity podatek z budynków: ${totalTaxDue:N0}. Podatek od mieszkańców zebrany.");
        }

        private void ApplyBonusSavings()
        {
            // LINQ w metodzie
            DigitalDB.Citizens.AsParallel().ForAll(c => c.Savings += 500m);
        }

        // 3.8. Metoda wywołująca zdarzenie
        protected virtual void OnCityEvent(string eventName, object data)
        {
            // Użycie operatora ?. (null-conditional operator) dla bezpieczeństwa wątkowego/null
            CityEventOccurred?.Invoke(eventName, data);
        }

        // 3.9. Metoda generująca raporty ze wszystkich jednostek (polimorfizm)
        public string GetFullCityReport()
        {
            var reportList = new List<string>();

            // Użycie polimorfizmu do wywołania metody GenerateReport na wszystkich jednostkach
            foreach (var entity in DigitalDB.Citizens.Cast<IReportable>().Concat(DigitalDB.Buildings))
            {
                reportList.Add(entity.GenerateReport(2));
            }

            // Konwersja całej struktury na JSON (dla długości i złożoności)
            var jsonOutput = JsonConvert.SerializeObject(new
            {
                City = CityName,
                CurrentYear = Year,
                CitizenCount = DigitalDB.Citizens.Count,
                ReportLines = reportList
            }, Formatting.Indented);

            return jsonOutput;
        }
    }

    // -------------------------------------------------------------------------
    // 4. Klasa główna (Program)
    // -------------------------------------------------------------------------

    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("=== Digital City Simulator (C# Complex Example) ===");

            // Inicjalizacja Managera
            var manager = new DigitalCityManager("NeoTech-Alpha");

            // Subskrypcja zdarzenia miejskiego
            manager.CityEventOccurred += HandleCityEvent;

            // Użycie metody DisplayInfo z nadpisaniem (polimorfizm)
            Console.WriteLine("\n--- Initial State ---");
            DigitalDB.Citizens.First().DisplayInfo();
            DigitalDB.Buildings.First().DisplayInfo();

            // Uruchomienie symulacji asynchronicznej
            manager.StartSimulation();

            Console.WriteLine("\n--- Running Simulation for 5 seconds ---");
            Task.Delay(5000).Wait(); // Czekaj 5 sekund

            manager.StopSimulation();

            // Wygenerowanie i wyświetlenie pełnego raportu
            Console.WriteLine("\n--- Final Report (JSON) ---");
            string finalReport = manager.GetFullCityReport();
            Console.WriteLine(finalReport);

            // Demonstracja operacji LINQ
            DemonstrateLinq(manager);

            Console.WriteLine("\n=== Simulation Finished. Press any key to exit. ===");
            Console.ReadKey();
        }

        // Handler zdarzeń (funkcja wywoływana przez delegata)
        private static void HandleCityEvent(string eventName, object data)
        {
            Console.ForegroundColor = eventName.Contains("Completed") ? ConsoleColor.Green :
                                      eventName.Contains("Started") ? ConsoleColor.Yellow :
                                      eventName.Contains("Event") ? ConsoleColor.Magenta :
                                      ConsoleColor.White;

            Console.WriteLine($"[EVENT] {DateTime.Now:HH:mm:ss} | {eventName}: {data}");
            Console.ResetColor();
        }

        // Dodatkowa statyczna metoda do demonstracji LINQ
        private static void DemonstrateLinq(DigitalCityManager manager)
        {
            Console.WriteLine("\n--- LINQ Demonstration ---");

            // Złożone zapytanie LINQ
            var highAchievers = from citizen in DigitalDB.Citizens
                                where citizen.Age >= 25 && citizen.IsEmployed
                                select new
                                {
                                    citizen.Name,
                                    citizen.JobTitle,
                                    NetWorth = citizen.Savings
                                };

            Console.WriteLine($"Top Achievers ({highAchievers.Count()}):");
            foreach (var a in highAchievers)
            {
                Console.WriteLine($"- {a.Name}, Job: {a.JobTitle}, Worth: ${a.NetWorth:N2}");
            }
        }
    }
}