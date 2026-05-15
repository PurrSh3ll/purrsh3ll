import random
import time
from typing import Dict, List, Any, Optional

# --- 1. DEFINICJE KLAS PRZEDMIOTÓW I ZARZĄDZANIA ---

class Item:
    """Klasa bazowa dla wszystkich przedmiotów."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str]):
        self.item_id = item_id
        self.name = name
        self.rarity = rarity
        self.value = value
        self.weight = weight
        self.tags = tags

    def get_info(self) -> str:
        return f"[{self.rarity}] {self.name} (ID: {self.item_id}, Wartość: {self.value}, Waga: {self.weight})"

class Weapon(Item):
    """Przedmiot typu broń."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], damage: int, type: str):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.damage = damage
        self.type = type

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Obrażenia: {self.damage} ({self.type})"

class Consumable(Item):
    """Przedmiot typu zużywalny (np. mikstura)."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], effect: str, duration: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.effect = effect
        self.duration = duration

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Efekt: {self.effect} przez {self.duration}s"

class Currency(Item):
    """Przedmiot typu waluta."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], amount: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.amount = amount

    def get_info(self) -> str:
        return f"WALUTA: {self.name} ({self.amount} szt.)"

# --- 2. ZARZĄDZANIE TABELAMI ŁUPU (LOOT TABLE MANAGER) ---

class LootTableManager:
    """Zarządza i losuje przedmioty z zdefiniowanych tabel łupu."""
    
    def __init__(self):
        # Słownik przechowujący obiekty Item po ich ID
        self.all_items: Dict[str, Item] = {}
        # Słownik przechowujący definicje tabel łupu
        self.loot_tables: Dict[str, List[Dict[str, Any]]] = {}

    def register_item(self, item: Item):
        """Rejestruje pojedynczy przedmiot w menedżerze."""
        self.all_items[item.item_id] = item

    def register_loot_table(self, table_id: str, table_data: List[Dict[str, Any]]):
        """Rejestruje całą tabelę łupu."""
        self.loot_tables[table_id] = table_data

    def get_item_by_id(self, item_id: str) -> Optional[Item]:
        """Pobiera obiekt przedmiotu na podstawie ID."""
        return self.all_items.get(item_id)

    def draw_from_table(self, table_id: str, count: int = 1) -> List[Optional[Item]]:
        """Losuje 'count' przedmiotów z danej tabeli."""
        if table_id not in self.loot_tables:
            print(f"Błąd: Tabela łupu '{table_id}' nie istnieje.")
            return []

        table = self.loot_tables[table_id]
        
        # 1. Przygotowanie danych do ważonego losowania
        item_ids = [entry['item_id'] for entry in table]
        weights = [entry['weight'] for entry in table]

        if not item_ids:
            return []
            
        # 2. Losowanie z wagami (z możliwością powtórzeń)
        try:
            drawn_ids = random.choices(item_ids, weights=weights, k=count)
        except ValueError as e:
            print(f"Błąd losowania w tabeli {table_id}: {e}. Sprawdź wagi.")
            return []

        # 3. Zwracanie obiektów Item
        return [self.get_item_by_id(item_id) for item_id in drawn_ids]

# --- 3. KLASA SKRZYNI ŁUPU (CHEST) ---

class LootChest:
    """Reprezentuje skrzynię łupu w grze."""
    def __init__(self, chest_id: str, name: str, main_loot_table: str, min_items: int, max_items: int):
        self.chest_id = chest_id
        self.name = name
        self.main_loot_table = main_loot_table
        self.min_items = min_items
        self.max_items = max_items

    def open_chest(self, manager: LootTableManager) -> List[Optional[Item]]:
        """Otwiera skrzynię i losuje łup."""
        num_items_to_draw = random.randint(self.min_items, self.max_items)
        
        print(f"\n--- Otwieranie Skrzyni: {self.name} ---")
        print(f"Losowanie {num_items_to_draw} przedmiotów z tabeli: {self.main_loot_table}...")

        loot = manager.draw_from_table(self.main_loot_table, num_items_to_draw)
        
        print("Zawartość skrzyni:")
        for item in loot:
            if item:
                print(f" - ZNALEZIONO: {item.get_info()}")
            else:
                print(" - ZNALEZIONO: Nieznany przedmiot (błąd rejestracji)")
        
        return loot

# --- 4. PRZYKŁADOWE DANE (DŁUGA LISTA DANYCH) ---

# Długie listy przedmiotów dla rozbudowania kodu:
ITEM_DATA_LIST = [
    # Broń
    Weapon("swd_001", "Zardzewiały Miecz", "Common", 10, 0.5, ["Melee", "Sword"], 5, "Slashing"),
    Weapon("swd_002", "Miecz Weterana", "Uncommon", 50, 0.4, ["Melee", "Sword"], 15, "Slashing"),
    Weapon("swd_003", "Klinga Burzy", "Rare", 500, 0.2, ["Melee", "Sword", "Magic"], 30, "Slashing"),
    Weapon("ax_001", "Topór Drwala", "Common", 15, 0.6, ["Melee", "Axe"], 8, "Chopping"),
    Weapon("bow_001", "Krótki Łuk", "Common", 20, 0.3, ["Ranged", "Bow"], 10, "Piercing"),
    Weapon("bow_002", "Łuk Myśliwego", "Uncommon", 100, 0.25, ["Ranged", "Bow"], 25, "Piercing"),
    Weapon("stf_001", "Laska Nowicjusza", "Common", 5, 0.1, ["Magic", "Staff"], 3, "Blunt"),
    Weapon("stf_002", "Kostur Żywiołów", "Epic", 5000, 0.05, ["Magic", "Staff"], 50, "Elemental"),

    # Zużywalne
    Consumable("pot_hp_s", "Mała Mikstura HP", "Common", 5, 0.8, ["Potion", "Heal"], "Restore 50 HP", 0),
    Consumable("pot_hp_m", "Średnia Mikstura HP", "Uncommon", 20, 0.5, ["Potion", "Heal"], "Restore 150 HP", 0),
    Consumable("pot_mp_s", "Mała Mikstura Many", "Common", 7, 0.7, ["Potion", "Mana"], "Restore 40 Mana", 0),
    Consumable("bomb_s", "Mała Bomba", "Uncommon", 30, 0.2, ["Bomb", "Damage"], "Area Damage 50", 0),

    # Waluta/Skarby
    Currency("coin_g", "Złota Moneta", "Common", 1, 1.0, ["Currency"], 1),
    Currency("coin_s", "Srebrna Moneta", "Common", 0, 2.0, ["Currency"], 1),
    Item("gem_ruby", "Rubin", "Rare", 250, 0.1, ["Gem", "Treasure"]),
    Item("gem_dia", "Diament", "Epic", 5000, 0.01, ["Gem", "Treasure"]),
    Item("map_01", "Stara Mapa", "Uncommon", 50, 0.3, ["Map", "Quest"]),
    Item("relic_01", "Amulet Czasu", "Legendary", 20000, 0.001, ["Artifact", "Relic"]),
    
    # Więcej Zwykłych Przedmiotów dla Długości
    Item("mat_wood", "Drewno Dębowe", "Common", 2, 5.0, ["Material"]),
    Item("mat_iron", "Ruda Żelaza", "Uncommon", 10, 3.0, ["Material"]),
    Item("mat_silk", "Jedwab", "Rare", 50, 1.0, ["Material"]),
    Item("armor_c", "Skórzana Zbroja", "Common", 30, 0.4, ["Armor", "Light"]),
    Item("armor_r", "Płytowa Zbroja", "Rare", 700, 0.1, ["Armor", "Heavy"]),
    Item("scroll_fire", "Zwój Kuli Ognia", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("scroll_ice", "Zwój Lodowej Strzały", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("key_c", "Klucz do Krypty", "Epic", 0, 0.005, ["Key", "Quest"]),
    Item("trap_s", "Pułapka na Niedźwiedzie", "Common", 10, 0.9, ["Trap"]),
    Item("torch_f", "Pochodnia", "Common", 2, 1.5, ["Utility"]),
]


# Długa definicja tabel łupu:

# Tabela dla zwykłego potwora (Common Mob)
LOOT_TABLE_MOB = [
    {"item_id": "coin_s", "weight": 40.0},
    {"item_id": "mat_wood", "weight": 10.0},
    {"item_id": "trap_s", "weight": 8.0},
    {"item_id": "pot_hp_s", "weight": 5.0},
    {"item_id": "pot_mp_s", "weight": 4.0},
    {"item_id": "swd_001", "weight": 3.0},
    {"item_id": "ax_001", "weight": 3.0},
    {"item_id": "bow_001", "weight": 2.0},
    {"item_id": "armor_c", "weight": 1.0},
]

# Tabela dla skrzyni w lesie (Forest Chest)
LOOT_TABLE_FOREST_CHEST = [
    {"item_id": "coin_g", "weight": 15.0},
    {"item_id": "pot_hp_m", "weight": 10.0},
    {"item_id": "gem_ruby", "weight": 5.0},
    {"item_id": "swd_002", "weight": 3.0},
    {"item_id": "bow_002", "weight": 2.0},
    {"item_id": "map_01", "weight": 1.0},
    {"item_id": "stf_001", "weight": 4.0},
    {"item_id": "mat_iron", "weight": 8.0},
    {"item_id": "scroll_fire", "weight": 0.5},
]

# Tabela dla legendarnego łupu (Legendary Cache)
LOOT_TABLE_LEGENDARY = [
    {"item_id": "coin_g", "weight": 5.0},
    {"item_id": "pot_hp_m", "weight": 1.0},
    {"item_id": "gem_dia", "weight": 15.0},
    {"item_id": "stf_002", "weight": 5.0},
    {"item_id": "armor_r", "weight": 10.0},
    {"item_id": "swd_003", "weight": 10.0},
    {"item_id": "key_c", "weight": 0.1},
    {"item_id": "relic_01", "weight": 0.05},
    {"item_id": "mat_silk", "weight": 20.0},
]

# Definicja różnych skrzyń:
CHEST_DATA_LIST = [
    LootChest("chest_wood", "Drewniana Skrzynia", "MOB_LOOT", 2, 4),
    LootChest("chest_iron", "Żelazna Skrzynia", "FOREST_CHEST_LOOT", 3, 5),
    LootChest("chest_legend", "Legendarna Krypta", "LEGENDARY_LOOT", 1, 2),
    LootChest("chest_boss", "Skrzynia Bossa", "LEGENDARY_LOOT", 4, 6),
    LootChest("chest_daily", "Skrzynia Dzienna", "FOREST_CHEST_LOOT", 1, 3),
    LootChest("chest_small", "Mały Worek", "MOB_LOOT", 1, 2),
    LootChest("chest_test", "Skrzynia Testowa", "LEGENDARY_LOOT", 10, 10),
]


# --- 5. GŁÓWNA FUNKCJA URUCHAMIAJĄCA SYSTEM ---

def initialize_and_run_loot_system():
    """Główna funkcja inicjalizująca i demonstrująca system."""
    
    start_time = time.time()
    print("Inicjalizacja systemu zarządzania łupem...")
    
    manager = LootTableManager()
    
    # 5.1 Rejestracja wszystkich przedmiotów
    for item in ITEM_DATA_LIST:
        manager.register_item(item)
    
    print(f"Zarejestrowano {len(manager.all_items)} unikalnych przedmiotów.")
    
    # 5.2 Rejestracja tabel łupu
    manager.register_loot_table("MOB_LOOT", LOOT_TABLE_MOB)
    manager.register_loot_table("FOREST_CHEST_LOOT", LOOT_TABLE_FOREST_CHEST)
    manager.register_loot_table("LEGENDARY_LOOT", LOOT_TABLE_LEGENDARY)
    
    print(f"Zarejestrowano {len(manager.loot_tables)} tabel łupu.")
    
    # 5.3 Symulacja otwierania skrzyń

    print("\n" + "="*50)
    print("ROZPOCZĘCIE SYMULACJI OTWIERANIA SKRZYŃ")
    print("="*50)
    
    for chest in CHEST_DATA_LIST:
        # Losowanie z niewielkim opóźnieniem dla symulacji
        time.sleep(0.1) 
        
        # Otwarcie skrzyni
        _ = chest.open_chest(manager)
        
        print("-" * 40)
        
    # 5.4 Pokazanie losowania bezpośrednio z tabeli
    print("\n" + "="*50)
    print("LOSOWANIE BEZPOŚREDNIO Z TABELI MOB_LOOT (50 losowań)")
    print("="*50)

    # 50 losowań z jednej tabeli
    test_loot = manager.draw_from_table("MOB_LOOT", 50)
    
    # Podsumowanie wyników testu
    result_counts: Dict[str, int] = {}
    for item in test_loot:
        if item:
            result_counts[item.name] = result_counts.get(item.name, 0) + 1
    
    for name, count in sorted(result_counts.items(), key=lambda item: item[1], reverse=True):
        print(f" - {name}: {count} razy")
        
    end_time = time.time()
    print(f"\nOperacja zakończona w: {end_time - start_time:.4f} sekundy.")

# --- 6. URUCHOMIENIE PROGRAMU ---

if __name__ == "__main__":
    initialize_and_run_loot_system()
    
import random
import time
from typing import Dict, List, Any, Optional

# --- 1. DEFINICJE KLAS PRZEDMIOTÓW I ZARZĄDZANIA ---

class Item:
    """Klasa bazowa dla wszystkich przedmiotów."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str]):
        self.item_id = item_id
        self.name = name
        self.rarity = rarity
        self.value = value
        self.weight = weight
        self.tags = tags

    def get_info(self) -> str:
        return f"[{self.rarity}] {self.name} (ID: {self.item_id}, Wartość: {self.value}, Waga: {self.weight})"

class Weapon(Item):
    """Przedmiot typu broń."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], damage: int, type: str):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.damage = damage
        self.type = type

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Obrażenia: {self.damage} ({self.type})"

class Consumable(Item):
    """Przedmiot typu zużywalny (np. mikstura)."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], effect: str, duration: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.effect = effect
        self.duration = duration

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Efekt: {self.effect} przez {self.duration}s"

class Currency(Item):
    """Przedmiot typu waluta."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], amount: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.amount = amount

    def get_info(self) -> str:
        return f"WALUTA: {self.name} ({self.amount} szt.)"

# --- 2. ZARZĄDZANIE TABELAMI ŁUPU (LOOT TABLE MANAGER) ---

class LootTableManager:
    """Zarządza i losuje przedmioty z zdefiniowanych tabel łupu."""
    
    def __init__(self):
        # Słownik przechowujący obiekty Item po ich ID
        self.all_items: Dict[str, Item] = {}
        # Słownik przechowujący definicje tabel łupu
        self.loot_tables: Dict[str, List[Dict[str, Any]]] = {}

    def register_item(self, item: Item):
        """Rejestruje pojedynczy przedmiot w menedżerze."""
        self.all_items[item.item_id] = item

    def register_loot_table(self, table_id: str, table_data: List[Dict[str, Any]]):
        """Rejestruje całą tabelę łupu."""
        self.loot_tables[table_id] = table_data

    def get_item_by_id(self, item_id: str) -> Optional[Item]:
        """Pobiera obiekt przedmiotu na podstawie ID."""
        return self.all_items.get(item_id)

    def draw_from_table(self, table_id: str, count: int = 1) -> List[Optional[Item]]:
        """Losuje 'count' przedmiotów z danej tabeli."""
        if table_id not in self.loot_tables:
            print(f"Błąd: Tabela łupu '{table_id}' nie istnieje.")
            return []

        table = self.loot_tables[table_id]
        
        # 1. Przygotowanie danych do ważonego losowania
        item_ids = [entry['item_id'] for entry in table]
        weights = [entry['weight'] for entry in table]

        if not item_ids:
            return []
            
        # 2. Losowanie z wagami (z możliwością powtórzeń)
        try:
            drawn_ids = random.choices(item_ids, weights=weights, k=count)
        except ValueError as e:
            print(f"Błąd losowania w tabeli {table_id}: {e}. Sprawdź wagi.")
            return []

        # 3. Zwracanie obiektów Item
        return [self.get_item_by_id(item_id) for item_id in drawn_ids]

# --- 3. KLASA SKRZYNI ŁUPU (CHEST) ---

class LootChest:
    """Reprezentuje skrzynię łupu w grze."""
    def __init__(self, chest_id: str, name: str, main_loot_table: str, min_items: int, max_items: int):
        self.chest_id = chest_id
        self.name = name
        self.main_loot_table = main_loot_table
        self.min_items = min_items
        self.max_items = max_items

    def open_chest(self, manager: LootTableManager) -> List[Optional[Item]]:
        """Otwiera skrzynię i losuje łup."""
        num_items_to_draw = random.randint(self.min_items, self.max_items)
        
        print(f"\n--- Otwieranie Skrzyni: {self.name} ---")
        print(f"Losowanie {num_items_to_draw} przedmiotów z tabeli: {self.main_loot_table}...")

        loot = manager.draw_from_table(self.main_loot_table, num_items_to_draw)
        
        print("Zawartość skrzyni:")
        for item in loot:
            if item:
                print(f" - ZNALEZIONO: {item.get_info()}")
            else:
                print(" - ZNALEZIONO: Nieznany przedmiot (błąd rejestracji)")
        
        return loot

# --- 4. PRZYKŁADOWE DANE (DŁUGA LISTA DANYCH) ---

# Długie listy przedmiotów dla rozbudowania kodu:
ITEM_DATA_LIST = [
    # Broń
    Weapon("swd_001", "Zardzewiały Miecz", "Common", 10, 0.5, ["Melee", "Sword"], 5, "Slashing"),
    Weapon("swd_002", "Miecz Weterana", "Uncommon", 50, 0.4, ["Melee", "Sword"], 15, "Slashing"),
    Weapon("swd_003", "Klinga Burzy", "Rare", 500, 0.2, ["Melee", "Sword", "Magic"], 30, "Slashing"),
    Weapon("ax_001", "Topór Drwala", "Common", 15, 0.6, ["Melee", "Axe"], 8, "Chopping"),
    Weapon("bow_001", "Krótki Łuk", "Common", 20, 0.3, ["Ranged", "Bow"], 10, "Piercing"),
    Weapon("bow_002", "Łuk Myśliwego", "Uncommon", 100, 0.25, ["Ranged", "Bow"], 25, "Piercing"),
    Weapon("stf_001", "Laska Nowicjusza", "Common", 5, 0.1, ["Magic", "Staff"], 3, "Blunt"),
    Weapon("stf_002", "Kostur Żywiołów", "Epic", 5000, 0.05, ["Magic", "Staff"], 50, "Elemental"),

    # Zużywalne
    Consumable("pot_hp_s", "Mała Mikstura HP", "Common", 5, 0.8, ["Potion", "Heal"], "Restore 50 HP", 0),
    Consumable("pot_hp_m", "Średnia Mikstura HP", "Uncommon", 20, 0.5, ["Potion", "Heal"], "Restore 150 HP", 0),
    Consumable("pot_mp_s", "Mała Mikstura Many", "Common", 7, 0.7, ["Potion", "Mana"], "Restore 40 Mana", 0),
    Consumable("bomb_s", "Mała Bomba", "Uncommon", 30, 0.2, ["Bomb", "Damage"], "Area Damage 50", 0),

    # Waluta/Skarby
    Currency("coin_g", "Złota Moneta", "Common", 1, 1.0, ["Currency"], 1),
    Currency("coin_s", "Srebrna Moneta", "Common", 0, 2.0, ["Currency"], 1),
    Item("gem_ruby", "Rubin", "Rare", 250, 0.1, ["Gem", "Treasure"]),
    Item("gem_dia", "Diament", "Epic", 5000, 0.01, ["Gem", "Treasure"]),
    Item("map_01", "Stara Mapa", "Uncommon", 50, 0.3, ["Map", "Quest"]),
    Item("relic_01", "Amulet Czasu", "Legendary", 20000, 0.001, ["Artifact", "Relic"]),
    
    # Więcej Zwykłych Przedmiotów dla Długości
    Item("mat_wood", "Drewno Dębowe", "Common", 2, 5.0, ["Material"]),
    Item("mat_iron", "Ruda Żelaza", "Uncommon", 10, 3.0, ["Material"]),
    Item("mat_silk", "Jedwab", "Rare", 50, 1.0, ["Material"]),
    Item("armor_c", "Skórzana Zbroja", "Common", 30, 0.4, ["Armor", "Light"]),
    Item("armor_r", "Płytowa Zbroja", "Rare", 700, 0.1, ["Armor", "Heavy"]),
    Item("scroll_fire", "Zwój Kuli Ognia", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("scroll_ice", "Zwój Lodowej Strzały", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("key_c", "Klucz do Krypty", "Epic", 0, 0.005, ["Key", "Quest"]),
    Item("trap_s", "Pułapka na Niedźwiedzie", "Common", 10, 0.9, ["Trap"]),
    Item("torch_f", "Pochodnia", "Common", 2, 1.5, ["Utility"]),
]


# Długa definicja tabel łupu:

# Tabela dla zwykłego potwora (Common Mob)
LOOT_TABLE_MOB = [
    {"item_id": "coin_s", "weight": 40.0},
    {"item_id": "mat_wood", "weight": 10.0},
    {"item_id": "trap_s", "weight": 8.0},
    {"item_id": "pot_hp_s", "weight": 5.0},
    {"item_id": "pot_mp_s", "weight": 4.0},
    {"item_id": "swd_001", "weight": 3.0},
    {"item_id": "ax_001", "weight": 3.0},
    {"item_id": "bow_001", "weight": 2.0},
    {"item_id": "armor_c", "weight": 1.0},
]

# Tabela dla skrzyni w lesie (Forest Chest)
LOOT_TABLE_FOREST_CHEST = [
    {"item_id": "coin_g", "weight": 15.0},
    {"item_id": "pot_hp_m", "weight": 10.0},
    {"item_id": "gem_ruby", "weight": 5.0},
    {"item_id": "swd_002", "weight": 3.0},
    {"item_id": "bow_002", "weight": 2.0},
    {"item_id": "map_01", "weight": 1.0},
    {"item_id": "stf_001", "weight": 4.0},
    {"item_id": "mat_iron", "weight": 8.0},
    {"item_id": "scroll_fire", "weight": 0.5},
]

# Tabela dla legendarnego łupu (Legendary Cache)
LOOT_TABLE_LEGENDARY = [
    {"item_id": "coin_g", "weight": 5.0},
    {"item_id": "pot_hp_m", "weight": 1.0},
    {"item_id": "gem_dia", "weight": 15.0},
    {"item_id": "stf_002", "weight": 5.0},
    {"item_id": "armor_r", "weight": 10.0},
    {"item_id": "swd_003", "weight": 10.0},
    {"item_id": "key_c", "weight": 0.1},
    {"item_id": "relic_01", "weight": 0.05},
    {"item_id": "mat_silk", "weight": 20.0},
]

# Definicja różnych skrzyń:
CHEST_DATA_LIST = [
    LootChest("chest_wood", "Drewniana Skrzynia", "MOB_LOOT", 2, 4),
    LootChest("chest_iron", "Żelazna Skrzynia", "FOREST_CHEST_LOOT", 3, 5),
    LootChest("chest_legend", "Legendarna Krypta", "LEGENDARY_LOOT", 1, 2),
    LootChest("chest_boss", "Skrzynia Bossa", "LEGENDARY_LOOT", 4, 6),
    LootChest("chest_daily", "Skrzynia Dzienna", "FOREST_CHEST_LOOT", 1, 3),
    LootChest("chest_small", "Mały Worek", "MOB_LOOT", 1, 2),
    LootChest("chest_test", "Skrzynia Testowa", "LEGENDARY_LOOT", 10, 10),
]


# --- 5. GŁÓWNA FUNKCJA URUCHAMIAJĄCA SYSTEM ---

def initialize_and_run_loot_system():
    """Główna funkcja inicjalizująca i demonstrująca system."""
    
    start_time = time.time()
    print("Inicjalizacja systemu zarządzania łupem...")
    
    manager = LootTableManager()
    
    # 5.1 Rejestracja wszystkich przedmiotów
    for item in ITEM_DATA_LIST:
        manager.register_item(item)
    
    print(f"Zarejestrowano {len(manager.all_items)} unikalnych przedmiotów.")
    
    # 5.2 Rejestracja tabel łupu
    manager.register_loot_table("MOB_LOOT", LOOT_TABLE_MOB)
    manager.register_loot_table("FOREST_CHEST_LOOT", LOOT_TABLE_FOREST_CHEST)
    manager.register_loot_table("LEGENDARY_LOOT", LOOT_TABLE_LEGENDARY)
    
    print(f"Zarejestrowano {len(manager.loot_tables)} tabel łupu.")
    
    # 5.3 Symulacja otwierania skrzyń

    print("\n" + "="*50)
    print("ROZPOCZĘCIE SYMULACJI OTWIERANIA SKRZYŃ")
    print("="*50)
    
    for chest in CHEST_DATA_LIST:
        # Losowanie z niewielkim opóźnieniem dla symulacji
        time.sleep(0.1) 
        
        # Otwarcie skrzyni
        _ = chest.open_chest(manager)
        
        print("-" * 40)
        
    # 5.4 Pokazanie losowania bezpośrednio z tabeli
    print("\n" + "="*50)
    print("LOSOWANIE BEZPOŚREDNIO Z TABELI MOB_LOOT (50 losowań)")
    print("="*50)

    # 50 losowań z jednej tabeli
    test_loot = manager.draw_from_table("MOB_LOOT", 50)
    
    # Podsumowanie wyników testu
    result_counts: Dict[str, int] = {}
    for item in test_loot:
        if item:
            result_counts[item.name] = result_counts.get(item.name, 0) + 1
    
    for name, count in sorted(result_counts.items(), key=lambda item: item[1], reverse=True):
        print(f" - {name}: {count} razy")
        
    end_time = time.time()
    print(f"\nOperacja zakończona w: {end_time - start_time:.4f} sekundy.")

# --- 6. URUCHOMIENIE PROGRAMU ---

if __name__ == "__main__":
    initialize_and_run_loot_system()
    
import random
import time
from typing import Dict, List, Any, Optional

# --- 1. DEFINICJE KLAS PRZEDMIOTÓW I ZARZĄDZANIA ---

class Item:
    """Klasa bazowa dla wszystkich przedmiotów."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str]):
        self.item_id = item_id
        self.name = name
        self.rarity = rarity
        self.value = value
        self.weight = weight
        self.tags = tags

    def get_info(self) -> str:
        return f"[{self.rarity}] {self.name} (ID: {self.item_id}, Wartość: {self.value}, Waga: {self.weight})"

class Weapon(Item):
    """Przedmiot typu broń."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], damage: int, type: str):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.damage = damage
        self.type = type

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Obrażenia: {self.damage} ({self.type})"

class Consumable(Item):
    """Przedmiot typu zużywalny (np. mikstura)."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], effect: str, duration: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.effect = effect
        self.duration = duration

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Efekt: {self.effect} przez {self.duration}s"

class Currency(Item):
    """Przedmiot typu waluta."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], amount: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.amount = amount

    def get_info(self) -> str:
        return f"WALUTA: {self.name} ({self.amount} szt.)"

# --- 2. ZARZĄDZANIE TABELAMI ŁUPU (LOOT TABLE MANAGER) ---

class LootTableManager:
    """Zarządza i losuje przedmioty z zdefiniowanych tabel łupu."""
    
    def __init__(self):
        # Słownik przechowujący obiekty Item po ich ID
        self.all_items: Dict[str, Item] = {}
        # Słownik przechowujący definicje tabel łupu
        self.loot_tables: Dict[str, List[Dict[str, Any]]] = {}

    def register_item(self, item: Item):
        """Rejestruje pojedynczy przedmiot w menedżerze."""
        self.all_items[item.item_id] = item

    def register_loot_table(self, table_id: str, table_data: List[Dict[str, Any]]):
        """Rejestruje całą tabelę łupu."""
        self.loot_tables[table_id] = table_data

    def get_item_by_id(self, item_id: str) -> Optional[Item]:
        """Pobiera obiekt przedmiotu na podstawie ID."""
        return self.all_items.get(item_id)

    def draw_from_table(self, table_id: str, count: int = 1) -> List[Optional[Item]]:
        """Losuje 'count' przedmiotów z danej tabeli."""
        if table_id not in self.loot_tables:
            print(f"Błąd: Tabela łupu '{table_id}' nie istnieje.")
            return []

        table = self.loot_tables[table_id]
        
        # 1. Przygotowanie danych do ważonego losowania
        item_ids = [entry['item_id'] for entry in table]
        weights = [entry['weight'] for entry in table]

        if not item_ids:
            return []
            
        # 2. Losowanie z wagami (z możliwością powtórzeń)
        try:
            drawn_ids = random.choices(item_ids, weights=weights, k=count)
        except ValueError as e:
            print(f"Błąd losowania w tabeli {table_id}: {e}. Sprawdź wagi.")
            return []

        # 3. Zwracanie obiektów Item
        return [self.get_item_by_id(item_id) for item_id in drawn_ids]

# --- 3. KLASA SKRZYNI ŁUPU (CHEST) ---

class LootChest:
    """Reprezentuje skrzynię łupu w grze."""
    def __init__(self, chest_id: str, name: str, main_loot_table: str, min_items: int, max_items: int):
        self.chest_id = chest_id
        self.name = name
        self.main_loot_table = main_loot_table
        self.min_items = min_items
        self.max_items = max_items

    def open_chest(self, manager: LootTableManager) -> List[Optional[Item]]:
        """Otwiera skrzynię i losuje łup."""
        num_items_to_draw = random.randint(self.min_items, self.max_items)
        
        print(f"\n--- Otwieranie Skrzyni: {self.name} ---")
        print(f"Losowanie {num_items_to_draw} przedmiotów z tabeli: {self.main_loot_table}...")

        loot = manager.draw_from_table(self.main_loot_table, num_items_to_draw)
        
        print("Zawartość skrzyni:")
        for item in loot:
            if item:
                print(f" - ZNALEZIONO: {item.get_info()}")
            else:
                print(" - ZNALEZIONO: Nieznany przedmiot (błąd rejestracji)")
        
        return loot

# --- 4. PRZYKŁADOWE DANE (DŁUGA LISTA DANYCH) ---

# Długie listy przedmiotów dla rozbudowania kodu:
ITEM_DATA_LIST = [
    # Broń
    Weapon("swd_001", "Zardzewiały Miecz", "Common", 10, 0.5, ["Melee", "Sword"], 5, "Slashing"),
    Weapon("swd_002", "Miecz Weterana", "Uncommon", 50, 0.4, ["Melee", "Sword"], 15, "Slashing"),
    Weapon("swd_003", "Klinga Burzy", "Rare", 500, 0.2, ["Melee", "Sword", "Magic"], 30, "Slashing"),
    Weapon("ax_001", "Topór Drwala", "Common", 15, 0.6, ["Melee", "Axe"], 8, "Chopping"),
    Weapon("bow_001", "Krótki Łuk", "Common", 20, 0.3, ["Ranged", "Bow"], 10, "Piercing"),
    Weapon("bow_002", "Łuk Myśliwego", "Uncommon", 100, 0.25, ["Ranged", "Bow"], 25, "Piercing"),
    Weapon("stf_001", "Laska Nowicjusza", "Common", 5, 0.1, ["Magic", "Staff"], 3, "Blunt"),
    Weapon("stf_002", "Kostur Żywiołów", "Epic", 5000, 0.05, ["Magic", "Staff"], 50, "Elemental"),

    # Zużywalne
    Consumable("pot_hp_s", "Mała Mikstura HP", "Common", 5, 0.8, ["Potion", "Heal"], "Restore 50 HP", 0),
    Consumable("pot_hp_m", "Średnia Mikstura HP", "Uncommon", 20, 0.5, ["Potion", "Heal"], "Restore 150 HP", 0),
    Consumable("pot_mp_s", "Mała Mikstura Many", "Common", 7, 0.7, ["Potion", "Mana"], "Restore 40 Mana", 0),
    Consumable("bomb_s", "Mała Bomba", "Uncommon", 30, 0.2, ["Bomb", "Damage"], "Area Damage 50", 0),

    # Waluta/Skarby
    Currency("coin_g", "Złota Moneta", "Common", 1, 1.0, ["Currency"], 1),
    Currency("coin_s", "Srebrna Moneta", "Common", 0, 2.0, ["Currency"], 1),
    Item("gem_ruby", "Rubin", "Rare", 250, 0.1, ["Gem", "Treasure"]),
    Item("gem_dia", "Diament", "Epic", 5000, 0.01, ["Gem", "Treasure"]),
    Item("map_01", "Stara Mapa", "Uncommon", 50, 0.3, ["Map", "Quest"]),
    Item("relic_01", "Amulet Czasu", "Legendary", 20000, 0.001, ["Artifact", "Relic"]),
    
    # Więcej Zwykłych Przedmiotów dla Długości
    Item("mat_wood", "Drewno Dębowe", "Common", 2, 5.0, ["Material"]),
    Item("mat_iron", "Ruda Żelaza", "Uncommon", 10, 3.0, ["Material"]),
    Item("mat_silk", "Jedwab", "Rare", 50, 1.0, ["Material"]),
    Item("armor_c", "Skórzana Zbroja", "Common", 30, 0.4, ["Armor", "Light"]),
    Item("armor_r", "Płytowa Zbroja", "Rare", 700, 0.1, ["Armor", "Heavy"]),
    Item("scroll_fire", "Zwój Kuli Ognia", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("scroll_ice", "Zwój Lodowej Strzały", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("key_c", "Klucz do Krypty", "Epic", 0, 0.005, ["Key", "Quest"]),
    Item("trap_s", "Pułapka na Niedźwiedzie", "Common", 10, 0.9, ["Trap"]),
    Item("torch_f", "Pochodnia", "Common", 2, 1.5, ["Utility"]),
]


# Długa definicja tabel łupu:

# Tabela dla zwykłego potwora (Common Mob)
LOOT_TABLE_MOB = [
    {"item_id": "coin_s", "weight": 40.0},
    {"item_id": "mat_wood", "weight": 10.0},
    {"item_id": "trap_s", "weight": 8.0},
    {"item_id": "pot_hp_s", "weight": 5.0},
    {"item_id": "pot_mp_s", "weight": 4.0},
    {"item_id": "swd_001", "weight": 3.0},
    {"item_id": "ax_001", "weight": 3.0},
    {"item_id": "bow_001", "weight": 2.0},
    {"item_id": "armor_c", "weight": 1.0},
]

# Tabela dla skrzyni w lesie (Forest Chest)
LOOT_TABLE_FOREST_CHEST = [
    {"item_id": "coin_g", "weight": 15.0},
    {"item_id": "pot_hp_m", "weight": 10.0},
    {"item_id": "gem_ruby", "weight": 5.0},
    {"item_id": "swd_002", "weight": 3.0},
    {"item_id": "bow_002", "weight": 2.0},
    {"item_id": "map_01", "weight": 1.0},
    {"item_id": "stf_001", "weight": 4.0},
    {"item_id": "mat_iron", "weight": 8.0},
    {"item_id": "scroll_fire", "weight": 0.5},
]

# Tabela dla legendarnego łupu (Legendary Cache)
LOOT_TABLE_LEGENDARY = [
    {"item_id": "coin_g", "weight": 5.0},
    {"item_id": "pot_hp_m", "weight": 1.0},
    {"item_id": "gem_dia", "weight": 15.0},
    {"item_id": "stf_002", "weight": 5.0},
    {"item_id": "armor_r", "weight": 10.0},
    {"item_id": "swd_003", "weight": 10.0},
    {"item_id": "key_c", "weight": 0.1},
    {"item_id": "relic_01", "weight": 0.05},
    {"item_id": "mat_silk", "weight": 20.0},
]

# Definicja różnych skrzyń:
CHEST_DATA_LIST = [
    LootChest("chest_wood", "Drewniana Skrzynia", "MOB_LOOT", 2, 4),
    LootChest("chest_iron", "Żelazna Skrzynia", "FOREST_CHEST_LOOT", 3, 5),
    LootChest("chest_legend", "Legendarna Krypta", "LEGENDARY_LOOT", 1, 2),
    LootChest("chest_boss", "Skrzynia Bossa", "LEGENDARY_LOOT", 4, 6),
    LootChest("chest_daily", "Skrzynia Dzienna", "FOREST_CHEST_LOOT", 1, 3),
    LootChest("chest_small", "Mały Worek", "MOB_LOOT", 1, 2),
    LootChest("chest_test", "Skrzynia Testowa", "LEGENDARY_LOOT", 10, 10),
]


# --- 5. GŁÓWNA FUNKCJA URUCHAMIAJĄCA SYSTEM ---

def initialize_and_run_loot_system():
    """Główna funkcja inicjalizująca i demonstrująca system."""
    
    start_time = time.time()
    print("Inicjalizacja systemu zarządzania łupem...")
    
    manager = LootTableManager()
    
    # 5.1 Rejestracja wszystkich przedmiotów
    for item in ITEM_DATA_LIST:
        manager.register_item(item)
    
    print(f"Zarejestrowano {len(manager.all_items)} unikalnych przedmiotów.")
    
    # 5.2 Rejestracja tabel łupu
    manager.register_loot_table("MOB_LOOT", LOOT_TABLE_MOB)
    manager.register_loot_table("FOREST_CHEST_LOOT", LOOT_TABLE_FOREST_CHEST)
    manager.register_loot_table("LEGENDARY_LOOT", LOOT_TABLE_LEGENDARY)
    
    print(f"Zarejestrowano {len(manager.loot_tables)} tabel łupu.")
    
    # 5.3 Symulacja otwierania skrzyń

    print("\n" + "="*50)
    print("ROZPOCZĘCIE SYMULACJI OTWIERANIA SKRZYŃ")
    print("="*50)
    
    for chest in CHEST_DATA_LIST:
        # Losowanie z niewielkim opóźnieniem dla symulacji
        time.sleep(0.1) 
        
        # Otwarcie skrzyni
        _ = chest.open_chest(manager)
        
        print("-" * 40)
        
    # 5.4 Pokazanie losowania bezpośrednio z tabeli
    print("\n" + "="*50)
    print("LOSOWANIE BEZPOŚREDNIO Z TABELI MOB_LOOT (50 losowań)")
    print("="*50)

    # 50 losowań z jednej tabeli
    test_loot = manager.draw_from_table("MOB_LOOT", 50)
    
    # Podsumowanie wyników testu
    result_counts: Dict[str, int] = {}
    for item in test_loot:
        if item:
            result_counts[item.name] = result_counts.get(item.name, 0) + 1
    
    for name, count in sorted(result_counts.items(), key=lambda item: item[1], reverse=True):
        print(f" - {name}: {count} razy")
        
    end_time = time.time()
    print(f"\nOperacja zakończona w: {end_time - start_time:.4f} sekundy.")

# --- 6. URUCHOMIENIE PROGRAMU ---

if __name__ == "__main__":
    initialize_and_run_loot_system()
    
import random
import time
from typing import Dict, List, Any, Optional

# --- 1. DEFINICJE KLAS PRZEDMIOTÓW I ZARZĄDZANIA ---

class Item:
    """Klasa bazowa dla wszystkich przedmiotów."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str]):
        self.item_id = item_id
        self.name = name
        self.rarity = rarity
        self.value = value
        self.weight = weight
        self.tags = tags

    def get_info(self) -> str:
        return f"[{self.rarity}] {self.name} (ID: {self.item_id}, Wartość: {self.value}, Waga: {self.weight})"

class Weapon(Item):
    """Przedmiot typu broń."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], damage: int, type: str):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.damage = damage
        self.type = type

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Obrażenia: {self.damage} ({self.type})"

class Consumable(Item):
    """Przedmiot typu zużywalny (np. mikstura)."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], effect: str, duration: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.effect = effect
        self.duration = duration

    def get_info(self) -> str:
        base_info = super().get_info()
        return f"{base_info} | Efekt: {self.effect} przez {self.duration}s"

class Currency(Item):
    """Przedmiot typu waluta."""
    def __init__(self, item_id: str, name: str, rarity: str, value: int, weight: float, tags: List[str], amount: int):
        super().__init__(item_id, name, rarity, value, weight, tags)
        self.amount = amount

    def get_info(self) -> str:
        return f"WALUTA: {self.name} ({self.amount} szt.)"

# --- 2. ZARZĄDZANIE TABELAMI ŁUPU (LOOT TABLE MANAGER) ---

class LootTableManager:
    """Zarządza i losuje przedmioty z zdefiniowanych tabel łupu."""
    
    def __init__(self):
        # Słownik przechowujący obiekty Item po ich ID
        self.all_items: Dict[str, Item] = {}
        # Słownik przechowujący definicje tabel łupu
        self.loot_tables: Dict[str, List[Dict[str, Any]]] = {}

    def register_item(self, item: Item):
        """Rejestruje pojedynczy przedmiot w menedżerze."""
        self.all_items[item.item_id] = item

    def register_loot_table(self, table_id: str, table_data: List[Dict[str, Any]]):
        """Rejestruje całą tabelę łupu."""
        self.loot_tables[table_id] = table_data

    def get_item_by_id(self, item_id: str) -> Optional[Item]:
        """Pobiera obiekt przedmiotu na podstawie ID."""
        return self.all_items.get(item_id)

    def draw_from_table(self, table_id: str, count: int = 1) -> List[Optional[Item]]:
        """Losuje 'count' przedmiotów z danej tabeli."""
        if table_id not in self.loot_tables:
            print(f"Błąd: Tabela łupu '{table_id}' nie istnieje.")
            return []

        table = self.loot_tables[table_id]
        
        # 1. Przygotowanie danych do ważonego losowania
        item_ids = [entry['item_id'] for entry in table]
        weights = [entry['weight'] for entry in table]

        if not item_ids:
            return []
            
        # 2. Losowanie z wagami (z możliwością powtórzeń)
        try:
            drawn_ids = random.choices(item_ids, weights=weights, k=count)
        except ValueError as e:
            print(f"Błąd losowania w tabeli {table_id}: {e}. Sprawdź wagi.")
            return []

        # 3. Zwracanie obiektów Item
        return [self.get_item_by_id(item_id) for item_id in drawn_ids]

# --- 3. KLASA SKRZYNI ŁUPU (CHEST) ---

class LootChest:
    """Reprezentuje skrzynię łupu w grze."""
    def __init__(self, chest_id: str, name: str, main_loot_table: str, min_items: int, max_items: int):
        self.chest_id = chest_id
        self.name = name
        self.main_loot_table = main_loot_table
        self.min_items = min_items
        self.max_items = max_items

    def open_chest(self, manager: LootTableManager) -> List[Optional[Item]]:
        """Otwiera skrzynię i losuje łup."""
        num_items_to_draw = random.randint(self.min_items, self.max_items)
        
        print(f"\n--- Otwieranie Skrzyni: {self.name} ---")
        print(f"Losowanie {num_items_to_draw} przedmiotów z tabeli: {self.main_loot_table}...")

        loot = manager.draw_from_table(self.main_loot_table, num_items_to_draw)
        
        print("Zawartość skrzyni:")
        for item in loot:
            if item:
                print(f" - ZNALEZIONO: {item.get_info()}")
            else:
                print(" - ZNALEZIONO: Nieznany przedmiot (błąd rejestracji)")
        
        return loot

# --- 4. PRZYKŁADOWE DANE (DŁUGA LISTA DANYCH) ---

# Długie listy przedmiotów dla rozbudowania kodu:
ITEM_DATA_LIST = [
    # Broń
    Weapon("swd_001", "Zardzewiały Miecz", "Common", 10, 0.5, ["Melee", "Sword"], 5, "Slashing"),
    Weapon("swd_002", "Miecz Weterana", "Uncommon", 50, 0.4, ["Melee", "Sword"], 15, "Slashing"),
    Weapon("swd_003", "Klinga Burzy", "Rare", 500, 0.2, ["Melee", "Sword", "Magic"], 30, "Slashing"),
    Weapon("ax_001", "Topór Drwala", "Common", 15, 0.6, ["Melee", "Axe"], 8, "Chopping"),
    Weapon("bow_001", "Krótki Łuk", "Common", 20, 0.3, ["Ranged", "Bow"], 10, "Piercing"),
    Weapon("bow_002", "Łuk Myśliwego", "Uncommon", 100, 0.25, ["Ranged", "Bow"], 25, "Piercing"),
    Weapon("stf_001", "Laska Nowicjusza", "Common", 5, 0.1, ["Magic", "Staff"], 3, "Blunt"),
    Weapon("stf_002", "Kostur Żywiołów", "Epic", 5000, 0.05, ["Magic", "Staff"], 50, "Elemental"),

    # Zużywalne
    Consumable("pot_hp_s", "Mała Mikstura HP", "Common", 5, 0.8, ["Potion", "Heal"], "Restore 50 HP", 0),
    Consumable("pot_hp_m", "Średnia Mikstura HP", "Uncommon", 20, 0.5, ["Potion", "Heal"], "Restore 150 HP", 0),
    Consumable("pot_mp_s", "Mała Mikstura Many", "Common", 7, 0.7, ["Potion", "Mana"], "Restore 40 Mana", 0),
    Consumable("bomb_s", "Mała Bomba", "Uncommon", 30, 0.2, ["Bomb", "Damage"], "Area Damage 50", 0),

    # Waluta/Skarby
    Currency("coin_g", "Złota Moneta", "Common", 1, 1.0, ["Currency"], 1),
    Currency("coin_s", "Srebrna Moneta", "Common", 0, 2.0, ["Currency"], 1),
    Item("gem_ruby", "Rubin", "Rare", 250, 0.1, ["Gem", "Treasure"]),
    Item("gem_dia", "Diament", "Epic", 5000, 0.01, ["Gem", "Treasure"]),
    Item("map_01", "Stara Mapa", "Uncommon", 50, 0.3, ["Map", "Quest"]),
    Item("relic_01", "Amulet Czasu", "Legendary", 20000, 0.001, ["Artifact", "Relic"]),
    
    # Więcej Zwykłych Przedmiotów dla Długości
    Item("mat_wood", "Drewno Dębowe", "Common", 2, 5.0, ["Material"]),
    Item("mat_iron", "Ruda Żelaza", "Uncommon", 10, 3.0, ["Material"]),
    Item("mat_silk", "Jedwab", "Rare", 50, 1.0, ["Material"]),
    Item("armor_c", "Skórzana Zbroja", "Common", 30, 0.4, ["Armor", "Light"]),
    Item("armor_r", "Płytowa Zbroja", "Rare", 700, 0.1, ["Armor", "Heavy"]),
    Item("scroll_fire", "Zwój Kuli Ognia", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("scroll_ice", "Zwój Lodowej Strzały", "Uncommon", 100, 0.2, ["Scroll", "Magic"]),
    Item("key_c", "Klucz do Krypty", "Epic", 0, 0.005, ["Key", "Quest"]),
    Item("trap_s", "Pułapka na Niedźwiedzie", "Common", 10, 0.9, ["Trap"]),
    Item("torch_f", "Pochodnia", "Common", 2, 1.5, ["Utility"]),
]


# Długa definicja tabel łupu:

# Tabela dla zwykłego potwora (Common Mob)
LOOT_TABLE_MOB = [
    {"item_id": "coin_s", "weight": 40.0},
    {"item_id": "mat_wood", "weight": 10.0},
    {"item_id": "trap_s", "weight": 8.0},
    {"item_id": "pot_hp_s", "weight": 5.0},
    {"item_id": "pot_mp_s", "weight": 4.0},
    {"item_id": "swd_001", "weight": 3.0},
    {"item_id": "ax_001", "weight": 3.0},
    {"item_id": "bow_001", "weight": 2.0},
    {"item_id": "armor_c", "weight": 1.0},
]

# Tabela dla skrzyni w lesie (Forest Chest)
LOOT_TABLE_FOREST_CHEST = [
    {"item_id": "coin_g", "weight": 15.0},
    {"item_id": "pot_hp_m", "weight": 10.0},
    {"item_id": "gem_ruby", "weight": 5.0},
    {"item_id": "swd_002", "weight": 3.0},
    {"item_id": "bow_002", "weight": 2.0},
    {"item_id": "map_01", "weight": 1.0},
    {"item_id": "stf_001", "weight": 4.0},
    {"item_id": "mat_iron", "weight": 8.0},
    {"item_id": "scroll_fire", "weight": 0.5},
]

# Tabela dla legendarnego łupu (Legendary Cache)
LOOT_TABLE_LEGENDARY = [
    {"item_id": "coin_g", "weight": 5.0},
    {"item_id": "pot_hp_m", "weight": 1.0},
    {"item_id": "gem_dia", "weight": 15.0},
    {"item_id": "stf_002", "weight": 5.0},
    {"item_id": "armor_r", "weight": 10.0},
    {"item_id": "swd_003", "weight": 10.0},
    {"item_id": "key_c", "weight": 0.1},
    {"item_id": "relic_01", "weight": 0.05},
    {"item_id": "mat_silk", "weight": 20.0},
]

# Definicja różnych skrzyń:
CHEST_DATA_LIST = [
    LootChest("chest_wood", "Drewniana Skrzynia", "MOB_LOOT", 2, 4),
    LootChest("chest_iron", "Żelazna Skrzynia", "FOREST_CHEST_LOOT", 3, 5),
    LootChest("chest_legend", "Legendarna Krypta", "LEGENDARY_LOOT", 1, 2),
    LootChest("chest_boss", "Skrzynia Bossa", "LEGENDARY_LOOT", 4, 6),
    LootChest("chest_daily", "Skrzynia Dzienna", "FOREST_CHEST_LOOT", 1, 3),
    LootChest("chest_small", "Mały Worek", "MOB_LOOT", 1, 2),
    LootChest("chest_test", "Skrzynia Testowa", "LEGENDARY_LOOT", 10, 10),
]


# --- 5. GŁÓWNA FUNKCJA URUCHAMIAJĄCA SYSTEM ---

def initialize_and_run_loot_system():
    """Główna funkcja inicjalizująca i demonstrująca system."""
    
    start_time = time.time()
    print("Inicjalizacja systemu zarządzania łupem...")
    
    manager = LootTableManager()
    
    # 5.1 Rejestracja wszystkich przedmiotów
    for item in ITEM_DATA_LIST:
        manager.register_item(item)
    
    print(f"Zarejestrowano {len(manager.all_items)} unikalnych przedmiotów.")
    
    # 5.2 Rejestracja tabel łupu
    manager.register_loot_table("MOB_LOOT", LOOT_TABLE_MOB)
    manager.register_loot_table("FOREST_CHEST_LOOT", LOOT_TABLE_FOREST_CHEST)
    manager.register_loot_table("LEGENDARY_LOOT", LOOT_TABLE_LEGENDARY)
    
    print(f"Zarejestrowano {len(manager.loot_tables)} tabel łupu.")
    
    # 5.3 Symulacja otwierania skrzyń

    print("\n" + "="*50)
    print("ROZPOCZĘCIE SYMULACJI OTWIERANIA SKRZYŃ")
    print("="*50)
    
    for chest in CHEST_DATA_LIST:
        # Losowanie z niewielkim opóźnieniem dla symulacji
        time.sleep(0.1) 
        
        # Otwarcie skrzyni
        _ = chest.open_chest(manager)
        
        print("-" * 40)
        
    # 5.4 Pokazanie losowania bezpośrednio z tabeli
    print("\n" + "="*50)
    print("LOSOWANIE BEZPOŚREDNIO Z TABELI MOB_LOOT (50 losowań)")
    print("="*50)

    # 50 losowań z jednej tabeli
    test_loot = manager.draw_from_table("MOB_LOOT", 50)
    
    # Podsumowanie wyników testu
    result_counts: Dict[str, int] = {}
    for item in test_loot:
        if item:
            result_counts[item.name] = result_counts.get(item.name, 0) + 1
    
    for name, count in sorted(result_counts.items(), key=lambda item: item[1], reverse=True):
        print(f" - {name}: {count} razy")
        
    end_time = time.time()
    print(f"\nOperacja zakończona w: {end_time - start_time:.4f} sekundy.")

# --- 6. URUCHOMIENIE PROGRAMU ---

if __name__ == "__main__":
    initialize_and_run_loot_system()
    
    
