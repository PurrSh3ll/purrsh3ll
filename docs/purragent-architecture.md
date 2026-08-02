# purragent — architektura (szkielet)

> Status: **koncepcja/szkielet** do dalszego rozwoju i testów.
> Nazwa narzędzia: `purragent` (marka *purr* + *agent*).
> Rdzeń: **LangGraph**. Wykonanie narzędzi: **MCP**. Wybór narzędzi: **RAG + rerank**.
> Powiązane: `core/rag` (ChromaDB + embeddingi + chunker + watchdog).

Konsolowy agent pentestowy: LangGraph steruje maszyną stanów prowadzącą LLM przez
engagement, warstwa narzędzi serwowana przez MCP, narzędzia wybierane przez RAG+rerank,
sesje dla narzędzi stanowych (ssh/msf), sub-cally do zarządzania kontekstem.
**LLM nigdy nie dotyka surowych sekretów ani surowych wielkich outputów.**

## Decyzje (locked)

| Wymiar | Wybór | Konsekwencje |
|---|---|---|
| LLM/provider | **Lokalny 7–14B (Ollama)** | twardy structured-output (Outlines/grammar + Instructor), shortlist k=3–5, agresywny context mgmt, opcjonalnie 2 modele (router+main) |
| Autonomia | **Semi-auto** | HITL tylko dla `risk ∈ {high, destructive}`, out-of-scope, lub eskalacji loop-guarda; `low/med` w scope → auto |
| Zakres | **Jeden host** | jeden wątek LangGraph, liniowe fazy; `findings` keyowane po `host` (multi-host = przyszły dodatek) |
| Persistencja | **SQLite** | `core/memory/store.py` + `SqliteSaver` (checkpointer, wznawialne engagementy) |

## 1. Widok z lotu ptaka

```
┌──────────────────────────── purragent (CLI) ────────────────────────────┐
│  core/cli  ──▶  core/graph (LangGraph = rdzeń, maszyna stanów)           │
│                     │                                                    │
│     ┌───────────────┼─────────────────────────────────────────┐         │
│     ▼               ▼                     ▼                     ▼         │
│  core/llm      core/rag+rerank      core/tools (MCP client)  core/context│
│  (klient LLM)  (retrieval tooli)    │        │        │      (budżet,     │
│     │                               ▼        ▼        ▼       summaryzer) │
│  core/auth                     MCP server  sessions  registry            │
│  (keyring /                    (exec)      (ssh/msf) (tool cards)         │
│   api_key_helper)                                                        │
│  core/memory (findings + history + engagement state, SQLite)            │
└──────────────────────────────────────────────────────────────────────────┘
```

Zasada: **LangGraph orkiestruje, MCP wykonuje, RAG wybiera, reszta to usługi.**

## 2. Układ modułów (pod `core/`)

```
core/
  auth/           endpoint+provider (persist) + klucz (keyring / api_key_helper / env)
  llm/            klient LLM (Ollama; opc. 2 modele) + structured output (Instructor/Outlines)
  rag/            [istnieje] chroma + embeddings + chunker + watchdog
    toolindex.py  indeks LONG-opisów narzędzi
    rerank.py     cross-encoder (bge-reranker-v2-m3, wielojęzyczny)
  tools/
    cards.py      model ToolCard + loader (ekstrakcja z pshuntera)
    mcp_server.py serwer MCP: rejestruje narzędzia (SHORT desc = schema MCP)
    executor.py   walidacja args → wykonanie → capture output
    sessions.py   SessionManager: ssh/msf/shell (stan poza checkpointem grafu)
  graph/
    state.py      AgentState (TypedDict, serializowalny)
    nodes.py      5 węzłów-LLM + węzły agenta
    guards.py     loop-detection, walidacje, budżet, scope, safety_gate
    phases.py     definicje faz + cele + kryteria wejścia/wyjścia
    build.py      montaż grafu, krawędzie, SqliteSaver checkpointer
  context/
    budget.py     licznik tokenów, progi
    summarizer.py oddzielny, izolowany call do LLM (tylko output)
    # future: llmlingua.py, nli.py, running_summary.py  (puste sloty)
  memory/
    store.py      SQLite: engagements, findings, history, sessions_meta, blobs
    models.py     Finding, Step, Engagement
  cli/
    __main__.py   `purragent` entrypoint + REPL/HITL
```

## 3. Modele danych

**ToolCard** (jeden rekord per komenda; dwa opisy):
```python
id: str                     # np. "smb.enum.nxc_shares"
name: str
phases: list[str]           # w których fazach ma sens
short_desc: str             # → do LLM (token-lean)
long_desc: str              # → do RAG+rerank (co robi, KIEDY użyć, czym różni się od podobnych)
params: PydanticModel       # schema argumentów (walidacja + structured fill)
command_template: str       # z placeholderami <RHOST> itd.
requires_session: {type, key} | None   # ssh|msf|shell
os: str; requires_creds: bool; risk: "low|med|high|destructive"
tags: list[str]
```
`long_desc` żyje w indeksie RAG (metadana po `id`); `short_desc` = schemat narzędzia w MCP.
Retrieval liczy się na LONG, wywołanie idzie po realnym schemacie MCP.

**AgentState** (stan grafu — serializowalny; trzyma *referencje* sesji, nie żywe sockety):
```python
engagement: {targets, scope, stop_condition, started_at}
phase: str
goal: str                       # cel bieżącej fazy (wysyłany do LLM co call)
findings: list[Finding]         # ustrukturyzowane, keyowane po host
history: list[Step]             # kompaktowe (tool, args, summary, ts, status)
tool_intent: str | None         # wynik kroku 1 (zapytanie do RAG)
candidates: list[ToolCardRef]   # po retrieval+rerank (SHORT)
chosen_tool: str | None
filled_args: dict | None
last_output_ref: str | None     # duży output leży poza stanem (blob store)
sessions: dict[key, session_id] # referencje, rozwiązuje SessionManager
loop: {fingerprints: deque, findings_delta: int, phase_steps: int}
budget: {tokens_used, steps, deadline}
decision: Literal["continue","switch_tool","next_phase","back_phase","finish"]
```

## 4. Pętla 5 kroków → węzły LangGraph

Każdy krok LLM ma **wymuszony format wyjścia** (pod słabszy lokalny model — mniej swobody = mniej halucynacji).

| # | Węzeł | Typ | Wejście (minimalne) | Wyjście (constrained) |
|---|---|---|---|---|
| 1 | `need_tool` | **LLM** | host/cel/deadline + `phase` + `goal` + kompakt findings/history | `tool_intent` (zapytanie zdolności) |
| — | `retrieve_rerank` | agent | `tool_intent` | top-k `candidates` (SHORT) |
| 2 | `select_tool` | **LLM** | `candidates` (SHORT) + `goal` | `chosen_tool` = **enum(id ∈ shortlist)** |
| 3 | `fill_args` | **LLM** | schemat `params` + `phase`+`goal`+kontekst hosta | `filled_args` = JSON walidowany schematem |
| — | `validate`+`safety_gate` | agent | `filled_args`, `risk` | ok / HITL / odrzucenie |
| — | `execute` | agent | `chosen_tool`+`args`+sesje | `last_output_ref` (raw) |
| — | `summarize_if_large` | ctx | raw output | streszczenie (jeśli > próg) |
| 4 | `observe_memory` | **LLM** | streszczenie/output (bez history!) | `findings[]` + `memory_writes[]` |
| — | `loop_check` | agent | fingerprinty + delta findings | flaga pętli |
| 5 | `route` | **LLM** | findings+history+goal+phase+deadline | `decision` = **enum** (+ opc. target) |

- **Faza+cel wstrzykiwane w krokach 1/3/5** → maksymalizuje trafność argumentów (krok 3).
- **Memory writes jawne** (krok 4) → `core/memory/store.py`.

## 5. Przepływ sterowania (krawędzie + guardy)

```
START → need_tool → retrieve_rerank → select_tool → fill_args
      → validate ─(fail)→ fill_args / operator
      → safety_gate ─(risk high|destructive | out-of-scope | loop-escalation)→ [interrupt HITL]
      → execute → summarize_if_large → observe_memory → loop_check → route

route ── continue    → need_tool
     ├── switch_tool  → retrieve_rerank        (maska na powtórzone narzędzie)
     ├── next_phase   → advance_phase → need_tool
     ├── back_phase   → rewind_phase  → need_tool
     └── finish       → report → END
```

**Guardy (`graph/guards.py`):**
- **Loop-detection:** deque fingerprintów `(tool_id + znormalizowane args)`; wyzwalacze: ten sam fingerprint ≥K, brak nowego findingu przez M kroków, oscylacja tool-A↔tool-B, powtarzający się błąd. Reakcje eskalujące: (1) wymuś inne narzędzie (maskuj), (2) `back_phase`, (3) nowe zapytanie RAG z negatywnym constraintem, (4) eskalacja do operatora, (5) abort + raport.
- **Walidacje:** scope/autoryzacja (cel w zakresie, brak self/localhost), safety-gate (`risk=destructive`→operator), schemat args, legalność przejścia faz, budżet/deadline.
- **safety_gate (semi-auto):** interrupt tylko gdy `risk ∈ {high,destructive}` lub out-of-scope lub eskalacja loop-guarda; `low/med` w scope → auto.

## 6. MCP + dwa opisy

- **Serwer MCP** = granica wykonania; graf jest **klientem MCP**. Zysk: izolacja, standard, reużywalność toolboxa.
- **SHORT desc** = schema narzędzia w MCP → do LLM (krok 2).
- **LONG desc** = bogaty opis w indeksie RAG (co robi, kiedy użyć, **czym różni się od podobnych** — poprawia rerank) → tylko do wyszukiwania, nie do LLM.
- Transport: `stdio`/local (narzędzia lokalne na Kali). Executor respektuje `requires_session`.

## 7. Sesje (stateful tools)

- `SessionManager` (singleton, **poza** checkpointem grafu — żywe sockety nieserializowalne). Stan grafu trzyma tylko `session_id`.
- Backendy: SSH (`paramiko`/`pexpect`), Metasploit (`msfrpc`), interaktywny shell (`pexpect`).
- Cykl: open-if-needed → run → capture → health-check → timeout/close → cleanup na koniec engagementu.

## 8. Duży output → izolowany call (context safety)

- `context/budget.py` liczy tokeny; gdy `sizeof(output) > próg` (lokalny model → **niski próg, ~800 tok**) → `summarize_if_large` robi **oddzielny call do LLM z jedynym wejściem = surowy output** + instrukcja streszczenia (**bez** history/findings/celu). Wynik wpływa do kroku 4. Surowy output → blob-store (`last_output_ref`), nie do stanu.

## 9. Punkty rozszerzeń (przyszłe wstawki — gotowe sloty)

- **LLMLingua** → `context/llmlingua.py`: kompresja promptu (kroki 1/3/5).
- **NLI encoder** → `context/nli.py`: dedup/spójność findings (krok 4), sprzeczności w historii.
- **Running summary** → `context/running_summary.py`: rolling-summary historii zamiast pełnej `history`.
- Wpinają się jako węzły/edge-hooki — bez ruszania 5-krokowej pętli.

## 10. Auth (`core/auth`)

- Persist (non-secret): provider (`anthropic|openai-compat|ollama`), `base_url`, `model`, typ endpointu.
- Sekret — kolejność ładowania: **`--api-key`/env → `api_key_helper` (komenda) → keyring** (Secret Service).
- `purragent auth login|status|logout`, maskowanie w logach, nigdy plaintext w repo.
- Wzorzec `api_key_helper` = jak `apiKeyHelper` w Claude Code (config trzyma *komendę jak zdobyć sekret*, nie sekret).

## 11. Structured output pod lokalny 7–14B

- krok 2 `select_tool` → **grammar/enum** ID z shortlisty (Outlines lub Ollama `format`=JSON-schema z `enum`).
- krok 3 `fill_args` → JSON-schema Pydantic + **Instructor** (auto-retry naprawy JSON).
- krok 5 `route` → enum `decision`.
- Shortlist **k=3–5** (retrieve N≈25 → rerank). Mierzyć `recall@k` na eval-secie.
- Prompt lean: `phase`+`goal`+ostatnie N findings (reszta = running-summary).
- Dwa modele: mały (routing/streszczenia: kroki 2/4/5) + główny (fill/analiza). `keep_alive` w Ollama, `temp≈0–0.2`.

## 12. CLI

```
purragent run --target <ip> --scope <cidr/file> --until "<warunek/deadline>"
purragent auth login|status|logout
purragent tools reindex            # przebuduj indeks LONG-descs
purragent sessions ls|kill
purragent engagement resume <id>   # SqliteSaver → wznawialne
```
Engagement = wątek LangGraph z checkpointerem (wznawialny). REPL do HITL.

## 13. Kolejność budowy

1. **`tools/cards.py` + ekstraktor** z `_STEP_COMMANDS`/`_EXPLOIT_STEPS`/`_PRIVESC_STEPS` → JSONL ToolCard (SHORT+LONG, `risk`, `requires_session`). Czysta funkcja, testowalna, zero AI — fundament.
2. **`rag/toolindex.py` + `rag/rerank.py`** → `search_tools(query,k)`.
3. **`core/llm`** (Ollama, 2 modele, Instructor/Outlines) + **`core/auth`** (keyring/api_key_helper).
4. **`graph/`**: `state.py` → 5 węzłów → `guards.py` (loop/validate/safety_gate) → `build.py` z `SqliteSaver`.
5. **`tools/mcp_server.py` + `executor.py` + `sessions.py`** (ssh/msf).
6. **`context/summarizer.py`** + puste sloty (`llmlingua`, `nli`, `running_summary`).
