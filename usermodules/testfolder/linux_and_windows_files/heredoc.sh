#!/bin/bash
# === Test heredoc i here-string ===

USER="Alice"
DAY=$(date +%A)

echo "=== HEREDOC – podstawowy przykład ==="
cat <<EOF
Witaj, $USER!
Dzisiaj jest $DAY.
To jest przykładowy tekst z heredoca.
EOF

echo
echo "=== HEREDOC – brak ekspansji zmiennych (cytowany znacznik) ==="
cat <<'NO_EXPAND'
Zmienna $USER nie zostanie rozwinięta.
Polecenia $(date) również nie zostaną wykonane.
NO_EXPAND

echo
echo "=== HEREDOC – z podwójnym cudzysłowem (ekspansja działa) ==="
cat <<"DOUBLE_EXPAND"
Hej, $USER! To jest heredoc z ekspansją w cudzysłowie.
Dzisiaj: $(date)
DOUBLE_EXPAND

echo
echo "=== HEREDOC – z usuwaniem tabulatorów (<<-) ==="
cat <<-TRIMMED
	To jest linia z tabulatorem.
	Bash przytnie początkowe tabulatory przy użyciu <<-.
TRIMMED

echo
echo "=== HEREDOC – w połączeniu z poleceniem awk ==="
awk '{ print "Linia:", $0 }' <<AWKCODE
To jest linia pierwsza.
To jest linia druga, $USER!
AWKCODE

echo
echo "=== HERE-STRING (<<<) ==="
grep "Alice" <<< "Hello Alice, how are you?"

echo
echo "=== Zagnieżdżony heredoc (rzadki przypadek) ==="
cat <<OUTER
To jest heredoc z wewnętrznym heredoc (symulowanym):
$(cat <<INNER
To jest wewnętrzny heredoc.
Zmienna: $USER
INNER
)
OUTER

echo "=== Koniec testu ==="
