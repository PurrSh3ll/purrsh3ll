import sys

# sys.argv to lista argumentów wiersza poleceń
# sys.argv[0] to zawsze nazwa skryptu
# sys.argv[1] to pierwszy argument podany przez użytkownika
# sys.argv[2] to drugi argument
# sys.argv[3] to trzeci argument

def process_arguments():
    # Sprawdź, czy podano dokładnie 3 argumenty użytkownika (czyli 4 elementy łącznie z nazwą skryptu)
    if len(sys.argv) != 4:
        print("Błąd: Ten skrypt wymaga podania dokładnie 3 argumentów.")
        print("Użycie: python args_example.py <argument1> <argument2> <argument3>")
        sys.exit(1) # Zakończ skrypt z kodem błędu

    arg1 = sys.argv[1]
    arg2 = sys.argv[2]
    arg3 = sys.argv[3]

    print("--- Wyniki ---")
    print(f"Nazwa skryptu: {sys.argv[0]}")
    print(f"Argument 1: {arg1}")
    print(f"Argument 2: {arg2}")
    print(f"Argument 3: {arg3}")
    print(f"Suma liczby znaków w argumentach: {len(arg1) + len(arg2) + len(arg3)}")

if __name__ == "__main__":
    process_arguments()