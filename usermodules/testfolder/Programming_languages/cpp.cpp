#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <memory> // Dla std::shared_ptr
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <stdexcept>

// Ustawienia symulacji
const int MAX_ITERATIONS = 50;
const int INITIAL_FISH = 30;
const int INITIAL_SHARKS = 5;
const int WORLD_SIZE = 100;

// Klasa bazowa (interfejs)
class IOrganism {
public:
    virtual ~IOrganism() = default;
    virtual void live(std::vector<std::shared_ptr<IOrganism>>& world) = 0;
    virtual std::string getType() const = 0;
    virtual bool isAlive() const = 0;
    virtual void setPosition(int x, int y) = 0;
    virtual int getEnergy() const = 0;
    virtual void printStatus() const = 0;
    virtual bool isPrey() const = 0;
    virtual int getX() const = 0;
    virtual int getY() const = 0;
};

// Klasa bazowa implementująca wspólne cechy
class Organism : public IOrganism {
protected:
    int energy;
    int age;
    bool alive;
    int x, y;
    std::string type;

public:
    Organism(int initialEnergy, std::string t) :
        energy(initialEnergy), age(0), alive(true), type(t) {
        // Losowe pozycjonowanie w świecie
        x = rand() % WORLD_SIZE;
        y = rand() % WORLD_SIZE;
    }

    // Wirtualne implementacje
    bool isAlive() const override { return alive; }
    std::string getType() const override { return type; }
    int getEnergy() const override { return energy; }
    void setPosition(int newX, int newY) override {
        x = newX;
        y = newY;
    }
    int getX() const override { return x; }
    int getY() const override { return y; }

    void printStatus() const override {
        std::cout << type << " (Age: " << age << ", Energy: " << energy
                  << ", Pos: " << x << "," << y << ") "
                  << (alive ? "Alive" : "Dead") << std::endl;
    }

    // Wirtualne metody do zaimplementowania w klasach pochodnych
    virtual bool isPrey() const override = 0;
};

// Klasa Ryba (Dziedziczy z Organism)
class Fish : public Organism {
private:
    static int fishCount;
    const int reproduction_cost = 5;
    const int max_energy = 20;
    const int movement_cost = 1;

public:
    Fish() : Organism(10, "Fish") { fishCount++; }
    ~Fish() { if (alive) fishCount--; }

    bool isPrey() const override { return true; }

    void live(std::vector<std::shared_ptr<IOrganism>>& world) override {
        if (!alive) return;

        age++;
        energy -= movement_cost;

        // Warunki śmierci
        if (age > 100 || energy <= 0) {
            alive = false;
            return;
        }

        // Ruch (losowy)
        int dx = (rand() % 3) - 1; // -1, 0, 1
        int dy = (rand() % 3) - 1;
        x = (x + dx + WORLD_SIZE) % WORLD_SIZE; // Utrzymanie w granicach świata
        y = (y + dy + WORLD_SIZE) % WORLD_SIZE;

        // Rozmnażanie
        if (energy >= max_energy / 2 && rand() % 10 == 0) {
            reproduce(world);
        }

        // Odzyskiwanie energii (jedzenie alg)
        if (energy < max_energy) {
            energy += 1;
        }
    }

    void reproduce(std::vector<std::shared_ptr<IOrganism>>& world) {
        if (energy >= reproduction_cost) {
            energy -= reproduction_cost;
            auto newFish = std::make_shared<Fish>();
            newFish->setPosition(x, y);
            world.push_back(newFish);
        }
    }

    static int getFishCount() { return fishCount; }
};

int Fish::fishCount = 0;

// Klasa Rekin (Dziedziczy z Organism)
class Shark : public Organism {
private:
    static int sharkCount;
    const int hunt_cost = 2;
    const int max_energy = 50;

public:
    Shark() : Organism(25, "Shark") { sharkCount++; }
    ~Shark() { if (alive) sharkCount--; }

    bool isPrey() const override { return false; }

    void live(std::vector<std::shared_ptr<IOrganism>>& world) override {
        if (!alive) return;

        age++;
        energy -= hunt_cost;

        // Warunki śmierci
        if (age > 200 || energy <= 0) {
            alive = false;
            return;
        }

        // Polowanie
        if (energy < max_energy) {
            hunt(world);
        }

        // Ruch (losowy, ale mniej niż ryby)
        int dx = (rand() % 2) - 1; // -1, 0
        int dy = (rand() % 2) - 1;
        x = (x + dx + WORLD_SIZE) % WORLD_SIZE;
        y = (y + dy + WORLD_SIZE) % WORLD_SIZE;

        // Rozmnażanie (dużo rzadsze)
        if (energy >= max_energy - 5 && rand() % 20 == 0) {
            reproduce(world);
        }
    }

    void hunt(std::vector<std::shared_ptr<IOrganism>>& world) {
        for (const auto& other : world) {
            if (other->isAlive() && other->isPrey() &&
                other->getX() == x && other->getY() == y) {

                // Zjedzenie
                energy += other->getEnergy();
                // Oznaczanie jako martwe bez usuwania natychmiast,
                // by nie psuć iteracji pętli
                // W rzeczywistym kodzie należałoby to obsłużyć inaczej, np.
                // tworząc listę do usunięcia.
                // Na potrzeby tego przykładu, użyjemy dynamicznego rzutowania:
                if (auto fish = std::dynamic_pointer_cast<Fish>(other)) {
                    fish->alive = false; // "Zjedzone"
                    energy = std::min(energy, max_energy);
                    return; // Zjedz tylko jedną rybę na cykl
                }
            }
        }
    }

    void reproduce(std::vector<std::shared_ptr<IOrganism>>& world) {
        if (energy >= max_energy / 2) {
            energy -= max_energy / 2;
            auto newShark = std::make_shared<Shark>();
            newShark->setPosition(x, y);
            world.push_back(newShark);
        }
    }

    static int getSharkCount() { return sharkCount; }
};

int Shark::sharkCount = 0;

// Szablon funkcji do filtrowania wektorów
template<typename T>
std::vector<std::shared_ptr<T>> filterByType(const std::vector<std::shared_ptr<IOrganism>>& world) {
    std::vector<std::shared_ptr<T>> result;
    for (const auto& organism : world) {
        if (auto specific_type = std::dynamic_pointer_cast<T>(organism)) {
            result.push_back(specific_type);
        }
    }
    return result;
}

// Funkcja zapisująca status do pliku (z obsługą wyjątków)
void saveStatusToFile(const std::vector<std::shared_ptr<IOrganism>>& world, int iteration) {
    std::string filename = "ecosystem_log.txt";
    std::ofstream file(filename, std::ios_base::app);

    if (!file.is_open()) {
        throw std::runtime_error("Nie można otworzyć pliku do zapisu: " + filename);
    }

    file << "--- Iteracja " << iteration << " ---\n";
    file << "Ryby: " << Fish::getFishCount() << ", Rekiny: " << Shark::getSharkCount() << "\n";

    // Opcjonalne zapisywanie statusu każdego organizmu
    for (const auto& org : world) {
        if (org->isAlive()) {
            file << " - " << org->getType() << " | E: " << org->getEnergy()
                 << " | Pos: " << org->getX() << "," << org->getY() << "\n";
        }
    }
    file << "\n";
    file.close();
}

// Główna funkcja symulacji
void runSimulation() {
    std::srand(std::time(0));
    std::vector<std::shared_ptr<IOrganism>> world;

    std::cout << "Inicjalizacja Ekosystemu..." << std::endl;

    // Utwórz początkowe populacje
    for (int i = 0; i < INITIAL_FISH; ++i) {
        world.push_back(std::make_shared<Fish>());
    }
    for (int i = 0; i < INITIAL_SHARKS; ++i) {
        world.push_back(std::make_shared<Shark>());
    }

    std::cout << "Rozpoczęcie symulacji. Początkowa populacja: Ryby: "
              << Fish::getFishCount() << ", Rekiny: " << Shark::getSharkCount() << std::endl;

    for (int iter = 1; iter <= MAX_ITERATIONS; ++iter) {
        std::cout << "\n=== ITERACJA " << iter << " ===\n";

        // Krok 1: Organizmy żyją
        for (const auto& organism : world) {
            organism->live(world);
        }

        // Krok 2: Usuwanie martwych organizmów (garbage collection)
        auto it = std::remove_if(world.begin(), world.end(),
                                 [](const std::shared_ptr<IOrganism>& org){
                                     return !org->isAlive();
                                 });
        world.erase(it, world.end());

        // Krok 3: Wyświetlenie statusu i zapis do pliku
        std::cout << "Aktualna populacja: Ryby: " << Fish::getFishCount()
                  << ", Rekiny: " << Shark::getSharkCount() << std::endl;

        if (Fish::getFishCount() <= 0) {
            std::cout << "Wszystkie ryby wyginęły! Symulacja zakończona." << std::endl;
            break;
        }
        if (Shark::getSharkCount() <= 0 && Fish::getFishCount() > 0) {
            std::cout << "Rekiny wyginęły. Ryby są bezpieczne." << std::endl;
        }

        try {
            saveStatusToFile(world, iter);
        } catch (const std::runtime_error& e) {
            std::cerr << "Błąd zapisu pliku: " << e.what() << std::endl;
            // Kontynuujemy symulację, ale bez logowania
        }

        // Zbyt duża populacja spowalnia symulację (tylko dla demonstrowania limitu)
        if (world.size() > 500) {
            std::cout << "Zbyt duża populacja, stabilizowanie systemu..." << std::endl;
        }

        // Krótka pauza, by zobaczyć postęp
        // std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\n*** SYMULACJA ZAKOŃCZONA ***" << std::endl;
}

// Główna funkcja programu
int main() {
    // Prosta obsługa wyjątków na najwyższym poziomie
    try {
        runSimulation();
    } catch (const std::exception& e) {
        std::cerr << "Wystąpił nieoczekiwany błąd krytyczny: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Wystąpił nieznany błąd." << std::endl;
        return 1;
    }

    // Demonstracja użycia szablonu
    std::cout << "\n--- DEMO UŻYCIA SZABLONU ---\n";
    std::vector<std::shared_ptr<IOrganism>> final_world;
    final_world.push_back(std::make_shared<Fish>());
    final_world.push_back(std::make_shared<Shark>());

    auto fish_only = filterByType<Fish>(final_world);
    std::cout << "Wyfiltrowano ryb: " << fish_only.size() << std::endl; // Powinno być 1

    return 0;
}