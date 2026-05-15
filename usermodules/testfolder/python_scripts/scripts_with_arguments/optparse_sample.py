import optparse


def main():
    """
    Program demonstracyjny używający przestarzałego modułu optparse.

    Program akceptuje opcjonalny argument --nazwa oraz flagę --wielkie-litery.
    """

    # 1. Utwórz parser i zdefiniuj jego użycie
    parser = optparse.OptionParser(
        usage="usage: %prog [options] [argument_pozycyjny]",
        version="%prog 1.0"
    )

    # 2. Dodaj opcje (argumenty z flagami)

    # Opcja dla nazwy (wymaga wartości)
    parser.add_option(
        '-n', '--nazwa',
        dest='user_name',
        default='Gościu',
        help="Określa nazwę użytkownika. Domyślnie: Gościu."
    )

    # Opcja flagi (nie wymaga wartości, przechowuje True/False)
    parser.add_option(
        '-u', '--uppercase',
        action='store_true',  # Ustawia na True, jeśli flaga jest obecna
        dest='upper_case',
        default=False,
        help="Jeśli ustawiono, nazwa zostanie wyświetlona wielkimi literami."
    )

    # 3. Sparsuj argumenty
    # 'options' to słownik zawierający wartości opcji (--nazwa, --uppercase)
    # 'args' to lista argumentów pozycyjnych (nieużywanych w tym przykładzie, ale mogłyby być)
    (options, args) = parser.parse_args()

    # 4. Użyj sparsowanych argumentów

    powitanie = f"Witaj, {options.user_name}!"

    if options.upper_case:
        powitanie = powitanie.upper()

    print(powitanie)

    if args:
        print(f"\nIgnorowane argumenty pozycyjne: {args}")


if __name__ == "__main__":
    main()