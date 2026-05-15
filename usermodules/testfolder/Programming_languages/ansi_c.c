#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Definicja stałych
#define MAX_NAME_LEN 50
#define MAX_COURSE_LEN 30
#define DB_FILENAME "student_database.dat"

// Definicja struktury studenta
typedef struct Student {
    int id;
    char name[MAX_NAME_LEN];
    char course[MAX_COURSE_LEN];
    float gpa;
    struct Student *prev; // Wskaźnik do poprzedniego elementu
    struct Student *next; // Wskaźnik do następnego elementu
} Student;

// Globalny wskaźnik na początek i koniec listy
Student *head = NULL;
Student *tail = NULL;
int next_id = 1;

// --- PROTOTYPY FUNKCJI ---
void load_database();
void save_database();
void free_list();

void add_student(const char *name, const char *course, float gpa);
void display_students(Student *start);
void search_student_by_id(int id);
void delete_student_by_id(int id);
void sort_students_by_gpa();
void run_menu();

// --- POMOCNICZE FUNKCJE LISTY ---

// Funkcja dodająca element do końca listy
void add_to_list(Student *new_student) {
    if (head == NULL) {
        head = new_student;
        tail = new_student;
    } else {
        tail->next = new_student;
        new_student->prev = tail;
        tail = new_student;
    }
}

// Funkcja zwalniająca całą pamięć listy
void free_list() {
    Student *current = head;
    Student *next_node;
    while (current != NULL) {
        next_node = current->next;
        free(current);
        current = next_node;
    }
    head = NULL;
    tail = NULL;
}

// --- ZARZĄDZANIE PLIKAMI ---

// Wczytywanie bazy danych z pliku
void load_database() {
    FILE *file = fopen(DB_FILENAME, "rb");
    if (file == NULL) {
        printf("Baza danych nie znaleziona. Rozpoczynanie z pustą listą.\n");
        return;
    }

    free_list(); // Wyczyść listę przed wczytaniem
    next_id = 1;

    Student temp_student;
    while (fread(&temp_student, sizeof(Student), 1, file) == 1) {
        Student *new_student = (Student *)malloc(sizeof(Student));
        if (new_student == NULL) {
            perror("Błąd alokacji pamięci podczas wczytywania");
            free_list();
            exit(EXIT_FAILURE);
        }

        // Kopiowanie danych (bez wskaźników)
        new_student->id = temp_student.id;
        strncpy(new_student->name, temp_student.name, MAX_NAME_LEN);
        strncpy(new_student->course, temp_student.course, MAX_COURSE_LEN);
        new_student->gpa = temp_student.gpa;

        new_student->prev = NULL;
        new_student->next = NULL;

        add_to_list(new_student);

        if (new_student->id >= next_id) {
            next_id = new_student->id + 1;
        }
    }

    printf("Pomyślnie wczytano bazę danych z pliku '%s'. Liczba studentów: %d\n", DB_FILENAME, next_id - 1);
    fclose(file);
}

// Zapis bazy danych do pliku
void save_database() {
    FILE *file = fopen(DB_FILENAME, "wb");
    if (file == NULL) {
        perror("Błąd otwarcia pliku do zapisu");
        return;
    }

    Student *current = head;
    Student temp_student;

    while (current != NULL) {
        // Kopiowanie danych do tymczasowej struktury (bez wskaźników)
        temp_student.id = current->id;
        strncpy(temp_student.name, current->name, MAX_NAME_LEN);
        strncpy(temp_student.course, current->course, MAX_COURSE_LEN);
        temp_student.gpa = current->gpa;
        temp_student.prev = NULL; // Zerowanie wskaźników przed zapisem
        temp_student.next = NULL; // Zerowanie wskaźników przed zapisem

        if (fwrite(&temp_student, sizeof(Student), 1, file) != 1) {
            perror("Błąd zapisu do pliku");
            fclose(file);
            return;
        }
        current = current->next;
    }

    printf("Pomyślnie zapisano bazę danych do pliku '%s'.\n", DB_FILENAME);
    fclose(file);
}

// --- GŁÓWNE FUNKCJE APLIKACJI ---

// Dodawanie nowego studenta
void add_student(const char *name, const char *course, float gpa) {
    Student *new_student = (Student *)malloc(sizeof(Student));
    if (new_student == NULL) {
        perror("Błąd alokacji pamięci");
        return;
    }

    new_student->id = next_id++;
    strncpy(new_student->name, name, MAX_NAME_LEN - 1);
    new_student->name[MAX_NAME_LEN - 1] = '\0';
    strncpy(new_student->course, course, MAX_COURSE_LEN - 1);
    new_student->course[MAX_COURSE_LEN - 1] = '\0';
    new_student->gpa = gpa;
    new_student->prev = NULL;
    new_student->next = NULL;

    add_to_list(new_student);
    printf("Dodano studenta ID: %d (%s).\n", new_student->id, new_student->name);
}

// Wyświetlanie wszystkich studentów
void display_students(Student *start) {
    if (start == NULL) {
        printf("\nLista studentów jest pusta.\n");
        return;
    }

    printf("\n--- LISTA STUDENTÓW ---\n");
    printf("| %-4s | %-40s | %-25s | %-4s |\n", "ID", "IMIĘ I NAZWISKO", "KIERUNEK", "ŚR.");
    printf("|------|------------------------------------------|---------------------------|------|\n");

    Student *current = start;
    while (current != NULL) {
        printf("| %-4d | %-40s | %-25s | %-4.2f |\n",
               current->id,
               current->name,
               current->course,
               current->gpa);
        current = current->next;
    }
    printf("---------------------------------------------------------------------------------\n");
}

// Szukanie studenta po ID
void search_student_by_id(int id) {
    Student *current = head;
    while (current != NULL) {
        if (current->id == id) {
            printf("\n--- ZNALEZIONO STUDENTA ---\n");
            printf("ID: %d\n", current->id);
            printf("Imię i Nazwisko: %s\n", current->name);
            printf("Kierunek: %s\n", current->course);
            printf("Średnia (GPA): %.2f\n", current->gpa);
            printf("---------------------------\n");
            return;
        }
        current = current->next;
    }
    printf("Błąd: Nie znaleziono studenta o ID %d.\n", id);
}

// Usuwanie studenta po ID
void delete_student_by_id(int id) {
    Student *current = head;
    while (current != NULL) {
        if (current->id == id) {
            // Przypadek 1: Usuwanie głowy
            if (current == head) {
                head = current->next;
                if (head != NULL) {
                    head->prev = NULL;
                } else {
                    tail = NULL; // Lista stała się pusta
                }
            }
            // Przypadek 2: Usuwanie ogona
            else if (current == tail) {
                tail = current->prev;
                if (tail != NULL) {
                    tail->next = NULL;
                }
            }
            // Przypadek 3: Usuwanie środkowego elementu
            else {
                current->prev->next = current->next;
                current->next->prev = current->prev;
            }

            printf("Pomyślnie usunięto studenta: %s (ID: %d).\n", current->name, current->id);
            free(current);
            return;
        }
        current = current->next;
    }
    printf("Błąd: Nie znaleziono studenta o ID %d do usunięcia.\n", id);
}

// Sortowanie listy dwukierunkowej (za pomocą prostego sortowania bąbelkowego na danych)
void sort_students_by_gpa() {
    if (head == NULL || head->next == NULL) {
        return; // Pusta lub pojedyncza lista
    }

    int swapped;
    Student *ptr1;
    Student *lptr = NULL; // Ostatni element posortowany

    do {
        swapped = 0;
        ptr1 = head;

        while (ptr1->next != lptr) {
            if (ptr1->gpa < ptr1->next->gpa) { // Porównanie GPA (malejąco)
                // --- Zamiana danych w węzłach (unikamy skomplikowanej zamiany wskaźników) ---

                // Kopiowanie danych studenta 1 do tymczasowej struktury
                Student temp;
                temp.id = ptr1->id;
                temp.gpa = ptr1->gpa;
                strncpy(temp.name, ptr1->name, MAX_NAME_LEN);
                strncpy(temp.course, ptr1->course, MAX_COURSE_LEN);

                // Kopiowanie danych studenta 2 do studenta 1
                ptr1->id = ptr1->next->id;
                ptr1->gpa = ptr1->next->gpa;
                strncpy(ptr1->name, ptr1->next->name, MAX_NAME_LEN);
                strncpy(ptr1->course, ptr1->next->course, MAX_COURSE_LEN);

                // Kopiowanie danych tymczasowych (student 1) do studenta 2
                ptr1->next->id = temp.id;
                ptr1->next->gpa = temp.gpa;
                strncpy(ptr1->next->name, temp.name, MAX_NAME_LEN);
                strncpy(ptr1->next->course, temp.course, MAX_COURSE_LEN);

                swapped = 1;
            }
            ptr1 = ptr1->next;
        }
        lptr = ptr1; // Ostatni element jest na właściwym miejscu
    } while (swapped);

    printf("Pomyślnie posortowano studentów według średniej (GPA) - malejąco.\n");
}


// --- GŁÓWNA PĘTLA PROGRAMU I MENU ---

void run_menu() {
    int choice;
    int id;
    char name[MAX_NAME_LEN];
    char course[MAX_COURSE_LEN];
    float gpa;

    do {
        printf("\n\n=============== MENU GŁÓWNE ==============\n");
        printf("1. Dodaj nowego studenta\n");
        printf("2. Wyświetl wszystkich studentów\n");
        printf("3. Wyszukaj studenta po ID\n");
        printf("4. Usuń studenta po ID\n");
        printf("5. Sortuj według średniej (GPA)\n");
        printf("6. Zapisz i Wyjdź\n");
        printf("7. Wyjdź bez zapisu\n");
        printf("==========================================\n");
        printf("Wybierz opcję: ");

        if (scanf("%d", &choice) != 1) {
            // Obsługa błędów wejścia
            printf("Błąd: Nieprawidłowy wybór. Proszę podać liczbę.\n");
            while (getchar() != '\n'); // Oczyść bufor
            continue;
        }

        // Oczyść bufor po wczytaniu liczby
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                printf("\n--- DODAJ STUDENTA ---\n");
                printf("Imię i Nazwisko: ");
                fgets(name, MAX_NAME_LEN, stdin);
                name[strcspn(name, "\n")] = 0; // Usuń znak nowej linii

                printf("Kierunek: ");
                fgets(course, MAX_COURSE_LEN, stdin);
                course[strcspn(course, "\n")] = 0;

                printf("Średnia (GPA - format 0.00): ");
                if (scanf("%f", &gpa) != 1 || gpa < 0.0 || gpa > 5.0) {
                    printf("Błąd: Nieprawidłowy format lub zakres GPA (0.0 - 5.0).\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n'); // Oczyść bufor
                add_student(name, course, gpa);
                break;

            case 2:
                display_students(head);
                break;

            case 3:
                printf("Podaj ID studenta do wyszukania: ");
                if (scanf("%d", &id) != 1) {
                    printf("Błąd: Proszę podać liczbę.\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n');
                search_student_by_id(id);
                break;

            case 4:
                printf("Podaj ID studenta do usunięcia: ");
                if (scanf("%d", &id) != 1) {
                    printf("Błąd: Proszę podać liczbę.\n");
                    while (getchar() != '\n');
                    break;
                }
                while (getchar() != '\n');
                delete_student_by_id(id);
                break;

            case 5:
                sort_students_by_gpa();
                display_students(head);
                break;

            case 6:
                save_database();
                free_list();
                printf("Baza danych zapisana. Program zakończony.\n");
                return; // Wyjście z funkcji

            case 7:
                free_list();
                printf("Program zakończony bez zapisu.\n");
                return; // Wyjście z funkcji

            default:
                printf("Błąd: Nieznana opcja. Spróbuj ponownie.\n");
                break;
        }
    } while (choice != 6 && choice != 7);
}


// --- MAIN ---
int main() {
    load_database();
    run_menu();
    return 0;
}