// VirtualCampus.java - Rozbudowany przykład kodu Java

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

// -------------------------------------------------------------------------
// 1. Definicje interfejsów funkcyjnych i klas
// -------------------------------------------------------------------------

/**
 * Interfejs funkcyjny (SAM interface) do logowania zdarzeń.
 */
@FunctionalInterface
interface CampusLogger {
    void log(String message);
}

/**
 * Interfejs dla jednostek, które mogą być oceniane.
 */
interface IAssessable {
    double calculateFinalGrade();
    void provideFeedback(String feedback);
}

/**
 * Klasa wyjątku niestandardowego.
 */
class EnrollmentException extends Exception {
    public EnrollmentException(String message) {
        super(message);
    }
}

// -------------------------------------------------------------------------
// 2. Klasy bazowe i dziedziczenie (OOP)
// -------------------------------------------------------------------------

/**
 * Abstrakcyjna klasa bazowa dla wszystkich osób na kampusie.
 */
abstract class Person {
    private final int id;
    private String name;

    // Użycie stałej enum
    public enum Role { STUDENT, PROFESSOR }
    protected Role role;

    public Person(int id, String name, Role role) {
        this.id = id;
        this.name = name;
        this.role = role;
    }

    public abstract void introduce();

    // Metoda finalna (nie można jej nadpisać)
    public final int getId() {
        return id;
    }

    // Getter i Setter
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
}

/**
 * Klasa reprezentująca studenta.
 */
class Student extends Person implements IAssessable {
    private final List<Double> grades; // Lista ocen
    private final Map<String, Boolean> courseStatus; // Czy kurs zaliczony?

    public Student(int id, String name) {
        super(id, name, Role.STUDENT);
        this.grades = new ArrayList<>();
        this.courseStatus = new ConcurrentHashMap<>();
    }

    @Override
    public void introduce() {
        System.out.println("Jestem studentem: " + getName() + " (ID: " + getId() + ")");
    }

    public void addGrade(double grade) {
        if (grade < 2.0) {
            System.err.println("Otrzymano ocenę niezaliczającą! " + getName());
        }
        this.grades.add(grade);
    }

    @Override
    public double calculateFinalGrade() {
        if (grades.isEmpty()) {
            return 0.0;
        }
        // Strumień (Stream) do obliczenia średniej
        return grades.stream()
                     .mapToDouble(d -> d)
                     .average()
                     .orElse(0.0);
    }

    @Override
    public void provideFeedback(String feedback) {
        System.out.println("Feedback dla " + getName() + ": " + feedback);
    }

    public void setCourseCompleted(String courseName, boolean completed) {
        this.courseStatus.put(courseName, completed);
    }

    // Użycie Optional
    public Optional<Boolean> getCourseCompletionStatus(String courseName) {
        return Optional.ofNullable(courseStatus.get(courseName));
    }
}

/**
 * Klasa reprezentująca profesora.
 */
class Professor extends Person {
    private String department;

    public Professor(int id, String name, String department) {
        super(id, name, Role.PROFESSOR);
        this.department = department;
    }

    @Override
    public void introduce() {
        System.out.println("Jestem profesorem: " + getName() + " z wydziału " + department);
    }

    // Metoda z rzucaniem wyjątku
    public void assignGrade(Student student, double grade) throws IllegalArgumentException {
        if (grade < 1.0 || grade > 5.0) {
            throw new IllegalArgumentException("Ocena musi być w zakresie 1.0 - 5.0");
        }
        student.addGrade(grade);
    }
}

// -------------------------------------------------------------------------
// 3. Klasa zarządzająca i logiką biznesową
// -------------------------------------------------------------------------

/**
 * Klasa zarządzająca kursem i procesem nauczania.
 */
class Course {
    private final String courseName;
    private Professor professor;
    private final List<Student> enrolledStudents;
    private static final int MAX_STUDENTS = 10;

    // Lambda do logowania
    private final CampusLogger logger = (msg) ->
        System.out.println("[LOG-" + courseName + "] " + msg);

    public Course(String name, Professor prof) {
        this.courseName = name;
        this.professor = prof;
        this.enrolledStudents = new ArrayList<>();
        logger.log("Kurs utworzony przez " + prof.getName());
    }

    // Metoda z wyjątkiem niestandardowym
    public void enrollStudent(Student student) throws EnrollmentException {
        if (enrolledStudents.size() >= MAX_STUDENTS) {
            throw new EnrollmentException("Kurs jest pełny: " + courseName);
        }
        if (enrolledStudents.contains(student)) {
            logger.log(student.getName() + " jest już zapisany.");
            return;
        }
        enrolledStudents.add(student);
        logger.log(student.getName() + " zapisany pomyślnie.");
    }

    // Metoda wykorzystująca Consumer i Predicate
    public void processStudents(Consumer<Student> action, Predicate<Student> condition) {
        enrolledStudents.stream()
                        .filter(condition) // Aplikacja predykatu
                        .forEach(action); // Aplikacja konsumenta
    }

    // Metoda statyczna do sprawdzania warunku (użycie w strumieniach)
    public static boolean isPassing(Student student) {
        return student.calculateFinalGrade() >= 3.0;
    }

    public List<Student> getEnrolledStudents() {
        return enrolledStudents;
    }

    public String getCourseName() {
        return courseName;
    }
}

/**
 * Centralna klasa zarządzająca całym kampusem.
 */
class VirtualCampusManager {
    private final Map<String, Course> availableCourses;
    private final List<Person> allPeople;
    private final ExecutorService executorService;
    private final CampusLogger logger = (msg) -> System.out.println("[MANAGER] " + msg);

    public VirtualCampusManager() {
        this.availableCourses = new ConcurrentHashMap<>();
        this.allPeople = new ArrayList<>();
        // Użycie puli wątków
        this.executorService = Executors.newFixedThreadPool(4);
    }

    public void addPerson(Person person) {
        allPeople.add(person);
        logger.log(person.getName() + " dodany do listy osób. Rola: " + person.role);
    }

    public void addCourse(Course course) {
        availableCourses.put(course.getCourseName(), course);
        logger.log("Kurs " + course.getCourseName() + " dodany.");
    }

    // 4. Wielowątkowość i asynchroniczność

    /**
     * Symuluje asynchroniczne sprawdzanie testu i zwraca ocenę.
     */
    public Future<Double> submitTestAsync(Student student, String courseName) {
        return executorService.submit(() -> {
            logger.log("Sprawdzanie testu dla " + student.getName() + " w tle...");
            Thread.sleep(new Random().nextInt(1000) + 500); // Symulacja opóźnienia 0.5 - 1.5 sekundy
            double grade = 1.0 + new Random().nextDouble() * 4.0; // Ocena od 1.0 do 5.0
            return Math.round(grade * 10.0) / 10.0; // Zaokrąglenie do 1 miejsca po przecinku
        });
    }

    /**
     * Główna metoda przetwarzania wyników testu.
     */
    public void processTestResults(Student student, String courseName, Future<Double> gradeFuture) {
        executorService.submit(() -> {
            try {
                double grade = gradeFuture.get(); // Blokuje do momentu ukończenia Future

                // Użycie instancji profesora do wystawienia oceny
                Professor prof = getProfessorForCourse(courseName);
                if (prof != null) {
                    prof.assignGrade(student, grade);
                    logger.log("Oceniono test dla " + student.getName() + ": " + grade);

                    if (grade >= 3.0) {
                        student.setCourseCompleted(courseName, true);
                    }
                }
            } catch (Exception e) {
                logger.log("Błąd przetwarzania wyników: " + e.getMessage());
            }
        });
    }

    // 5. Złożone operacje na kolekcjach (Streams)

    /**
     * Zwraca listę wszystkich studentów z danym statusem zaliczenia.
     */
    public List<String> getStudentsByPassStatus(String courseName, boolean passed) {
        return allPeople.stream()
                        .filter(p -> p.role == Person.Role.STUDENT)
                        .map(p -> (Student)p)
                        .filter(s -> s.getCourseCompletionStatus(courseName).isPresent() &&
                                     s.getCourseCompletionStatus(courseName).get() == passed)
                        .map(Person::getName) // Metoda referencyjna
                        .collect(Collectors.toList());
    }

    /**
     * Oblicza średnią ocen studentów, używając strumieni.
     */
    public double calculateAverageStudentGrade() {
        return allPeople.stream()
                        .filter(p -> p.role == Person.Role.STUDENT)
                        .map(p -> (Student)p)
                        .mapToDouble(Student::calculateFinalGrade)
                        .average()
                        .orElse(0.0);
    }

    private Professor getProfessorForCourse(String courseName) {
        // Prosta logika: zakładamy, że profesor jest pierwszą osobą o roli PROFESSOR,
        // (W prawdziwym systemie byłoby to mapowanie)
        return (Professor) allPeople.stream()
                                    .filter(p -> p.role == Person.Role.PROFESSOR)
                                    .findFirst()
                                    .orElse(null);
    }

    // 6. Obsługa plików (I/O)

    /**
     * Zapisuje status kursów do pliku.
     */
    public void saveCourseStatusToFile(String filename) {
        try (FileWriter writer = new FileWriter(filename)) {
            // Złożona operacja I/O i strumień
            String status = availableCourses.values().stream()
                .flatMap(course -> course.getEnrolledStudents().stream()
                    .map(s -> s.getName() + " (" + s.getId() + ") - Średnia: " + s.calculateFinalGrade()))
                .collect(Collectors.joining("\n"));

            writer.write("--- RAPORT KOŃCOWY KAMPUSU ---\n");
            writer.write(status);
            logger.log("Zapisano status kursów do pliku: " + filename);
        } catch (IOException e) {
            logger.log("Błąd zapisu pliku: " + e.getMessage());
        }
    }

    /**
     * Wczytuje i wyświetla zawartość pliku.
     */
    public void readAndDisplayFile(String filename) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(filename));
            logger.log("--- Zawartość pliku " + filename + " ---");
            lines.forEach(System.out::println);
        } catch (IOException e) {
            logger.log("Błąd odczytu pliku: " + e.getMessage());
        }
    }

    public void shutdown() {
        executorService.shutdown();
        logger.log("Pula wątków zamknięta.");
    }
}

// -------------------------------------------------------------------------
// 7. Klasa główna (Program)
// -------------------------------------------------------------------------

public class VirtualCampus {

    public static void main(String[] args) {
        System.out.println("=== Wirtualny Kampus: Demonstracja Javy ===");

        VirtualCampusManager manager = new VirtualCampusManager();

        // 1. Inicjalizacja Danych
        Professor prof1 = new Professor(101, "Dr. Anna Kowalska", "Informatyka");
        Student stud1 = new Student(1, "Ewa Nowak");
        Student stud2 = new Student(2, "Piotr Zając");
        Student stud3 = new Student(3, "Karolina Wróbel");

        manager.addPerson(prof1);
        manager.addPerson(stud1);
        manager.addPerson(stud2);
        manager.addPerson(stud3);

        Course javaCourse = new Course("Zaawansowana Java", prof1);
        Course mathCourse = new Course("Matematyka Dyskretna", prof1);

        manager.addCourse(javaCourse);
        manager.addCourse(mathCourse);

        // 2. Obsługa Wyjątków (try-catch)
        try {
            javaCourse.enrollStudent(stud1);
            javaCourse.enrollStudent(stud2);
            mathCourse.enrollStudent(stud2);
            mathCourse.enrollStudent(stud3);

            // Próba zapisu więcej niż max (aby wywołać wyjątek)
            for (int i = 0; i < 10; i++) {
                javaCourse.enrollStudent(new Student(10 + i, "Anonim " + i));
            }

        } catch (EnrollmentException e) {
            System.err.println("[EXCEPTION] Błąd zapisu: " + e.getMessage());
        }

        System.out.println("\n--- Symulacja Oceniania (Asynchroniczność) ---");

        // 3. Wielowątkowość (Asynchroniczne sprawdzanie testów)
        Future<Double> gradeFuture1 = manager.submitTestAsync(stud1, javaCourse.getCourseName());
        Future<Double> gradeFuture2 = manager.submitTestAsync(stud2, javaCourse.getCourseName());

        manager.processTestResults(stud1, javaCourse.getCourseName(), gradeFuture1);
        manager.processTestResults(stud2, javaCourse.getCourseName(), gradeFuture2);

        // Czekaj na zakończenie wszystkich wątków (symulacja)
        try {
            Thread.sleep(3000);
        } catch (InterruptedException ignored) {}

        // 4. Demonstracja lambd, Consumer i Predicate
        System.out.println("\n--- Przetwarzanie studentów (Lambdy) ---");

        // Consumer: Wypisz imię i średnią ocenę
        Consumer<Student> displayGrade = s ->
            System.out.printf("Student: %s, Średnia: %.2f%n", s.getName(), s.calculateFinalGrade());

        // Predicate: Wybierz tylko studentów z ID > 1
        Predicate<Student> isExperienced = s -> s.getId() > 1;

        javaCourse.processStudents(displayGrade, isExperienced);

        // 5. Finalny raport (Streams i Kolekcje)
        System.out.println("\n--- Raport Kampusu (Streams) ---");
        System.out.printf("Średnia ocen na kampusie: %.2f%n", manager.calculateAverageStudentGrade());

        List<String> passedStudents = manager.getStudentsByPassStatus(javaCourse.getCourseName(), true);
        System.out.println("Zaliczyli kurs Java: " + passedStudents);

        // 6. I/O - Zapis i odczyt
        final String fileName = "campus_report.txt";
        manager.saveCourseStatusToFile(fileName);
        manager.readAndDisplayFile(fileName);

        manager.shutdown();
        System.out.println("\n=== Symulacja zakończona. ===");
    }
}