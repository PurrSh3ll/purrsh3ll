# shelter_manager.rb - Złożony przykład kodu Ruby

# -------------------------------------------------------------------------
# 1. Klasy, Dziedziczenie i Metody
# -------------------------------------------------------------------------

# Klasa bazowa (Rodzic)
class Animal
  # Właściwości dostępu (gettery i settery)
  attr_accessor :name, :age
  # Właściwości tylko do odczytu (getter)
  attr_reader :species, :id

  # Zmienna klasowa do generowania ID
  @@next_id = 1

  # Konstruktor
  def initialize(name, age, species)
    @id = @@next_id
    @@next_id += 1
    @name = name
    @age = age
    @species = species
    @adopted = false
  end

  # Metoda instancji
  def speak
    # Interpolacja ciągów znaków
    puts "Cześć, jestem #{@name} i jestem #{get_age_description}!"
  end

  # Metoda prywatna
  private

  def get_age_description
    @age > 5 ? 'doświadczony' : 'młody'
  end
end

# Klasa pochodna (Dziecko)
class Dog < Animal
  # Stała
  BREED_INFO = "Pies domowy - najlepszy przyjaciel człowieka"

  # Nadpisanie metody speak
  def speak
    puts "#{@name} szczeka: Hau hau!"
  end

  # Metoda unikalna dla Dog
  def bark_at(target)
    # Wyrażenia warunkowe
    if target.nil?
      puts "Nikogo nie ma, żeby szczekać."
    else
      puts "#{@name} szczeka na #{target}!"
    end
  end
end

# -------------------------------------------------------------------------
# 2. Główny Menedżer (Bloki Kodu i Iteratory)
# -------------------------------------------------------------------------

class ShelterManager
  # Inicjalizacja Hasza i Tablicy
  def initialize
    # Tablica do przechowywania obiektów Animal
    @animals = []
    # Hash do śledzenia statusu adopcji (ID zwierzęcia => Data adopcji)
    @adoption_records = {}
  end

  # Dodanie zwierzęcia do tablicy
  def add_animal(animal)
    @animals << animal
    puts "[INFO] Dodano: #{animal.name} (ID: #{animal.id})"
  end

  # Metoda wykorzystująca blok kodu (yield)
  def process_all_animals
    puts "\n--- Przetwarzanie wszystkich zwierząt ---"
    # Iterator each
    @animals.each do |animal|
      # yield przekazuje sterowanie do bloku wywołującego
      yield animal if block_given?
    end
    puts "----------------------------------------"
  end

  # Metoda używająca iteratorów i metod Tablic
  def adopt_animal(id, adopter_name)
    # Użycie find do wyszukania w tablicy
    animal = @animals.find { |a| a.id == id }

    # Wyrażenie warunkowe
    unless animal.nil?
      if @adoption_records.key?(id)
        puts "[BŁĄD] #{animal.name} został już adoptowany."
        return false
      end

      # Dodanie rekordu adopcji
      @adoption_records[id] = Time.now.strftime("%Y-%m-%d")
      puts "[SUKCES] #{animal.name} adoptowany przez #{adopter_name} w dniu #{@adoption_records[id]}!"
      return true
    else
      puts "[BŁĄD] Nie znaleziono zwierzęcia o ID: #{id}."
      return false
    end
  end

  # Metoda wyświetlająca rekordy adopcji (Iteracja po Hashu)
  def display_adoption_records
    puts "\n--- Rekordy Adopcji ---"
    if @adoption_records.empty?
      puts "Brak dotychczasowych adopcji."
      return
    end

    # Iteracja po Hashu
    @adoption_records.each do |id, date|
      # Użycie find ponownie do znalezienia imienia po ID
      name = @animals.find { |a| a.id == id }&.name || "Nieznane"
      puts "ID: #{id}, Imię: #{name}, Data: #{date}"
    end
  end
end

# -------------------------------------------------------------------------
# 3. Uruchomienie i demonstracja
# -------------------------------------------------------------------------

# Inicjalizacja menedżera
manager = ShelterManager.new

# Tworzenie obiektów
dog1 = Dog.new("Max", 3, "Pies")
cat1 = Animal.new("Puszek", 5, "Kot")
dog2 = Dog.new("Rocky", 8, "Pies")

# Dodanie do systemu
manager.add_animal(dog1)
manager.add_animal(cat1)
manager.add_animal(dog2)

# Demonstracja polimorfizmu i metod
puts "\n--- Demonstracja Klas ---"
dog1.speak         # Wywołuje metodę Dog#speak
cat1.speak         # Wywołuje metodę Animal#speak
dog2.bark_at("listonosza") # Metoda unikalna dla Dog

# Demonstracja metody z blokiem (yield)
manager.process_all_animals do |animal|
  puts "  - Przetwarzanie #{animal.name} (Wiek: #{animal.age})"
end

# Demonstracja adopcji i Hasha
manager.adopt_animal(dog1.id, "Katarzyna W.")
manager.adopt_animal(cat1.id, "Marek Z.")
manager.adopt_animal(99, "Anonim") # Błąd

# Wyświetlenie końcowych rekordów
manager.display_adoption_records