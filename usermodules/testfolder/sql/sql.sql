-- example_database.sql
-- Plik testowy dla highlightera SQL
-- Zawiera: CREATE, DROP, INSERT, SELECT, JOIN, CTE, funkcje, typy, komentarze /* */ i '--'

/* ---------------------------
   Setup: usuń stare obiekty
   --------------------------- */
DROP VIEW IF EXISTS demo.v_user_stats;
DROP TABLE IF EXISTS demo.users;
DROP TABLE IF EXISTS demo.orders;
DROP TABLE IF EXISTS demo.products;
DROP SCHEMA IF EXISTS demo CASCADE;
CREATE SCHEMA demo;

-- Tworzenie tabel z typami
CREATE TABLE demo.users (
    id          bigserial PRIMARY KEY,
    username    varchar(50) NOT NULL,
    email       varchar(255) UNIQUE NOT NULL,
    created_at  timestamp without time zone DEFAULT now(),
    active      boolean DEFAULT true,
    login_count integer DEFAULT 0
);

CREATE TABLE demo.products (
    product_id  serial PRIMARY KEY,
    sku         varchar(32) NOT NULL,
    name        text NOT NULL,
    price       numeric(10,2) NOT NULL,
    stock       integer DEFAULT 0
);

CREATE TABLE demo.orders (
    order_id    bigserial PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES demo.users(id),
    created     timestamp DEFAULT now(),
    total_cents integer NOT NULL,
    status      varchar(20) DEFAULT 'pending'
);

-- indeksy i constraints
CREATE INDEX idx_orders_user ON demo.orders (user_id);
ALTER TABLE demo.products ADD CONSTRAINT price_positive CHECK (price >= 0);

-- Wstawianie danych (różne typy, liczby, stringi)
INSERT INTO demo.users (username, email, created_at, active, login_count) VALUES
('alice', 'alice@example.com', '2023-01-10 09:12:00', true, 12),
('bob', 'bob@example.com', now(), false, 0),
('carol', 'carol@example.com', '2024-07-01 15:30:20', true, 42);

INSERT INTO demo.products (sku, name, price, stock) VALUES
('SKU-001', 'Small Widget', 9.99, 100),
('SKU-002', 'Large Widget', 19.95, 50),
('SKU-003', 'Gadget Pro', 199.99, 5);

INSERT INTO demo.orders (user_id, created, total_cents, status) VALUES
(1, '2025-02-01 12:00:00', 1999, 'paid'),
(1, '2025-02-02 12:10:00', 999, 'shipped'),
(3, now(), 19999, 'processing');

-- Prosty SELECT z aliasami i funkcjami
SELECT u.id, u.username, u.email,
       COALESCE(u.login_count, 0) AS logins,
       to_char(u.created_at, 'YYYY-MM-DD') AS created_date
FROM demo.users u
WHERE u.active = true
ORDER BY u.created_at DESC
LIMIT 10 OFFSET 0;

-- JOIN, agregacja i GROUP BY
SELECT u.username,
       COUNT(o.order_id) AS orders_count,
       SUM(o.total_cents) / 100.0 AS orders_total_eur
FROM demo.users u
LEFT JOIN demo.orders o ON o.user_id = u.id
GROUP BY u.username
HAVING COUNT(o.order_id) > 0
ORDER BY orders_total_eur DESC;

-- Subquery i aliasy z kropką w identyfikatorze (schema.table)
SELECT p.product_id, p.name, p.price
FROM demo.products p
WHERE p.price > (SELECT AVG(price) FROM demo.products);

-- CTE (WITH) i okna
WITH recent_orders AS (
    SELECT order_id, user_id, created, total_cents,
           ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created DESC) rn
    FROM demo.orders
)
SELECT r.user_id, r.order_id, r.total_cents
FROM recent_orders r
WHERE r.rn = 1;

-- Aktualizacja i usuwanie
UPDATE demo.users SET login_count = login_count + 1 WHERE username = 'alice';
DELETE FROM demo.orders WHERE status = 'cancelled' AND created < '2020-01-01';

-- Widok oraz prosta procedura (dialekt DEMO)
CREATE VIEW demo.v_user_stats AS
SELECT u.id, u.username, COUNT(o.order_id) AS total_orders, SUM(o.total_cents) AS sum_cents
FROM demo.users u
LEFT JOIN demo.orders o ON o.user_id = u.id
GROUP BY u.id, u.username;

-- Przykład użycia funkcji i wbudowanych
SELECT COUNT(*) AS total_products, MIN(price) AS min_price, MAX(price) AS max_price
FROM demo.products;

-- Złożony przykład: regexp, LIKE, oraz wartości liczbowe
SELECT *
FROM demo.products
WHERE name ~* 'widget' OR sku LIKE 'SKU-%'
AND price BETWEEN 5.00 AND 200.00;

-- Przykładowe komentarze inline and block:
-- linia komentarza: -- to jest komentarz
/*
   blok komentarza:
   używany do dłuższych opisów i tymczasowego wyłączenia kodu
*/

-- Quoted identifiers and special characters
CREATE TABLE "Demo"."Strange-Table" (
    "Id.Value" serial PRIMARY KEY,
    "Weird Name" text
);

INSERT INTO "Demo"."Strange-Table" ("Weird Name") VALUES ('Some "quoted" text'), ('Another value');

-- Transakcje
BEGIN;
UPDATE demo.products SET stock = stock - 1 WHERE product_id = 1;
INSERT INTO demo.orders (user_id, total_cents, status) VALUES (2, 999, 'paid');
COMMIT;

-- Przykłady funkcji z nawiasami — powinny być wykryte jako function
SELECT now(), lower(username), upper(username), concat(username, '@', 'domain.com') FROM demo.users;

-- Typy w CREATE TABLE: sprawdź podświetlenie typu
CREATE TABLE demo.metrics (
    metric_id serial PRIMARY KEY,
    created_at timestamp DEFAULT now(),
    value numeric(12,4),
    host_ip inet DEFAULT '127.0.0.1'
);

-- INSERT z liczbami całkowitymi i floatami
INSERT INTO demo.metrics (value, host_ip) VALUES (123.4567, '192.168.0.1');

-- Pętla proceduralna (przykład PL/pgSQL-like, test for function keyword detection)
CREATE OR REPLACE FUNCTION demo.increment_login(uid bigint) RETURNS void AS $$
BEGIN
    UPDATE demo.users SET login_count = login_count + 1 WHERE id = uid;
END;
$$ LANGUAGE plpgsql;

-- GRANT / REVOKE
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA demo TO public;
REVOKE DELETE ON demo.orders FROM public;

-- Końcowy SELECT z aliasami i złożonym wyrażeniem
SELECT u.username AS user_name,
       (SELECT COUNT(*) FROM demo.orders o WHERE o.user_id = u.id) AS orders_count,
       CASE WHEN u.login_count > 10 THEN 'power-user' ELSE 'regular' END AS tier
FROM demo.users u
ORDER BY orders_count DESC, u.username;
