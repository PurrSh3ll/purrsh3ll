// app.js - Złożony przykład kodu JavaScript (ES6+)

// -------------------------------------------------------------------------
// 1. Definicja Klasy (OOP)
// -------------------------------------------------------------------------

/**
 * Klasa reprezentująca pojedyncze zadanie.
 */
class Task {
    // Statyczne pole do śledzenia ID
    static nextId = 1;

    // Prywatne pola (użycie # dla enkapsulacji)
    #id;
    #isCompleted;

    constructor(title, priority = 'Medium') {
        this.#id = Task.nextId++;
        this.title = title;
        this.priority = priority; // High, Medium, Lowddd
        this.#isCompleted = false;
    }

    // Metoda do ustawiania statusu
    toggleCompletion() {
        this.#isCompleted = !this.#isCompleted;
        console.log(`Task ${this.#id} status changed to ${this.#isCompleted ? 'Done' : 'Pending'}`);
    }

    // Getter (tylko do odczytu)
    get id() {
        return this.#id;
    }

    get status() {
        return this.#isCompleted ? 'Completed' : 'Pending';
    }

    // Metoda do serializacji obiektu
    toJSON() {
        return {
            id: this.#id,
            title: this.title,
            priority: this.priority,
            status: this.status
        };
    }
}

// -------------------------------------------------------------------------
// 2. Moduł API (Asynchroniczność z Promise i async/await)
// -------------------------------------------------------------------------

/**
 * Moduł do symulacji operacji na API.
 */
const APIService = (() => {
    const virtualData = [
        new Task("Napisz kod JS", "High"),
        new Task("Zaimplementuj asynchroniczność", "High"),
        new Task("Zrób kawę", "Low")
    ];

    /**
     * Symuluje asynchroniczne pobieranie danych.
     * Używa Promise i losowego opóźnienia.
     * @returns {Promise<Task[]>}
     */
    const fetchTasks = () => {
        return new Promise((resolve) => {
            const delay = Math.random() * 1000 + 500; // 500ms do 1500ms
            setTimeout(() => {
                console.log(`[API] Symulacja zakończona po ${delay.toFixed(0)}ms.`);
                resolve(virtualData);
            }, delay);
        });
    };

    /**
     * Symuluje asynchroniczne dodawanie nowego zadania.
     * @param {Task} task
     */
    const addTask = (task) => {
        return new Promise((resolve) => {
            setTimeout(() => {
                virtualData.push(task);
                resolve(task);
            }, 300);
        });
    };

    return { fetchTasks, addTask };
})();


// -------------------------------------------------------------------------
// 3. Główna Aplikacja (Funkcje wyższego rzędu, DOM Manipulation)
// -------------------------------------------------------------------------

/**
 * Główny obiekt aplikacji zarządzającej DOM i logiką.
 */
const TodoApp = {
    taskList: [],

    // Pobranie elementu DOM (zakładając, że istnieje <ul id="task-list">)
    listElement: document.getElementById('task-list') || document.createElement('ul'),

    // Funkcja wyższego rzędu: zwraca funkcję do filtrowania
    getFilterFunction(priority) {
        // Funkcja zwracająca predykat
        return (task) => task.priority === priority;
    },

    // Metoda renderująca listę
    renderList() {
        this.listElement.innerHTML = ''; // Czyści listę

        // Strumień (Array methods) do sortowania i mapowania
        this.taskList
            .sort((a, b) => b.priority.localeCompare(a.priority)) // Sortowanie według priorytetu
            .map(task => this.createTaskListItem(task))
            .forEach(li => this.listElement.appendChild(li));
    },

    // Tworzenie elementu DOM (Template Literals)
    createTaskListItem(task) {
        const li = document.createElement('li');
        li.className = `task-item task-${task.priority.toLowerCase()}`;
        li.dataset.id = task.id;

        li.innerHTML = `
            <span class="task-title" style="text-decoration: ${task.status === 'Completed' ? 'line-through' : 'none'};">
                [${task.priority}] ${task.title}
            </span>
            <button class="toggle-btn">${task.status === 'Completed' ? 'Undo' : 'Complete'}</button>
            <button class="delete-btn">Delete</button>
        `;

        // Przypisanie handlerów zdarzeń do przycisków
        li.querySelector('.toggle-btn').addEventListener('click', () => this.handleToggle(task.id));
        li.querySelector('.delete-btn').addEventListener('click', () => this.handleDelete(task.id));

        return li;
    },

    // Logika przełączania statusu zadania
    handleToggle(id) {
        const task = this.taskList.find(t => t.id === id);
        if (task) {
            task.toggleCompletion();
            this.renderList();
        }
    },

    // Logika usuwania zadania (użycie filter)
    handleDelete(id) {
        this.taskList = this.taskList.filter(task => task.id !== id);
        console.log(`Task ${id} deleted.`);
        this.renderList();
    },

    // Asynchroniczna metoda inicjalizująca
    async init() {
        console.log("Inicjalizacja aplikacji ToDo...");
        try {
            // Użycie async/await do oczekiwania na Promise z API
            const rawTasks = await APIService.fetchTasks();

            // Mapowanie surowych danych na instancje klasy Task
            this.taskList = rawTasks.map(t =>
                 new Task(t.title, t.priority)
            );

            this.renderList();

            // Przykład użycia funkcji wyższego rzędu
            const highPriorityTasks = this.taskList.filter(this.getFilterFunction('High'));
            console.log("Liczba zadań o wysokim priorytecie: ", highPriorityTasks.length);

        } catch (error) {
            console.error("Wystąpił błąd podczas pobierania zadań:", error);
        }
    },

    // Metoda do dodawania zadania (pokazuje, jak użyć API)
    async addNewTask(title, priority) {
        const newTask = new Task(title, priority);
        await APIService.addTask(newTask);
        this.taskList.push(newTask);
        this.renderList();
    }
};

// -------------------------------------------------------------------------
// 4. Uruchomienie Aplikacji i Zdarzenia Globalne
// -------------------------------------------------------------------------

// Sprawdzenie, czy DOM jest załadowany przed uruchomieniem
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Podłączenie list elementu do DOM (dla celów testowych)
        document.body.appendChild(TodoApp.listElement);
        TodoApp.init();
    });
} else {
    // Podłączenie list elementu do DOM (dla celów testowych)
    document.body.appendChild(TodoApp.listElement);
    TodoApp.init();
}

// Przykładowe asynchroniczne dodanie zadania po 4 sekundach
setTimeout(() => {
    TodoApp.addNewTask("Zrób kompleksowy raport", "High");
}, 4000);

// Przykładowe manipulacje konsolą
console.log(JSON.stringify(TodoApp.taskList.map(t => t.toJSON()), null, 2));

// Dodanie globalnego listenera do demonstrowania event delegation
document.addEventListener('click', (e) => {
    if (e.target.tagName === 'BUTTON') {
        // Demonstracja event delegation
        console.log(`[CLICK] Kliknięto przycisk: ${e.target.className}`);
    }
});