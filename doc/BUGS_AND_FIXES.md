# Баги и исправления  DarkSword Jailbreak

> Полная хронология всех 436 задокументированных багов
> Обновлено: 2026-04-04 (build 82+) Bug #440-455

---

## Bug #455  exact 21D61 всё ещё не находит validated self-proc через socket/TRO, а wide page-seed phase 4 (`64MB`) провоцирует zone-bound panic; phase 4 отключена по умолчанию, fast path расширен только до nearby offsets (2026-04-04)

**Symptom:** свежие логи `log/syslog_2026-04-04_18-35-47.txt` и panic bundle `log/panics_2026-04-04_18-37-25/` показали новую картину после Bug #454:
- `Bug #451` стабильно принимает `kbase+0x3213680` как triage `kernproc`,
- `socket/tro fast path` на exact `21D61` видит usable socket и non-zero thread path, но не возвращает validated `self proc`,
- `ourproc()` затем уходит в `Bug #325/#332` page-seed fallback,
- на phase 4 (`window=0x4000000`) появляется panic `zone bound checks: buffer 0xffffffdf08be8060 of length 4 overflows object ... size 0`, что совпадает с шаблоном probe `page_base + 0x60`.

**Root cause:**
- строгий 21D61 socket/TRO набор `bg=0x2a8/0x298/0x2b0`, `tro=0x368/0x358/0x370` оказался недостаточным: fast path остаётся слишком узким и не даёт validated self-proc на свежем boot;
- при этом поздний fallback phase 4 в page-seed scan расширяется до `64MB` и снова начинает читать PID-поле на страницах, которые уже не являются безопасными proc-object кандидатами для этого build.

**Fix** (`darksword/utils.m`):
1. Для exact `21D61` fast path расширен не до старого broad scan, а только до **nearby** диапазонов:
  - `socket_bg_thread_offs`: локальный sweep `0x288..0x2c0 step 0x8`
  - `thread_tro_offs`: локальный sweep `0x340..0x380 step 0x8`
  Это оставляет path таргетированным под 21D61 и не возвращает старую широкую unsafe surface.
2. В `Bug #325/#332` для exact `21D61` phase 4 (`64MB`) теперь **отключена по умолчанию**.
  - override сохранён через `DS_ENABLE_WIDE_SEED_SCAN=1`
  - phases 0..3 (`0x4000`, `0x40000`, `0x100000`, `0x400000`) остаются активными.

**Current status after fix:**
- panic-class от wide phase должен уйти,
- но functional success ещё не гарантирован: главный незакрытый blocker — stable `ourproc()` / `self proc` recovery на exact `21D61`.

---

## Bug #448  disc_pl Phase 2 пропускал list_off=0x00 (начинал с 0x08); выбирал list_off=0xb0 (чужой список) → allproc chain 227 проц max_pid=320 < ourpid=466 → Bug #336 (2026-04-04)

**Symptom (build 81†):** disc_pl нашёл allproc=`0xfffffff020dcc480` (SUCCESS). disc_pl выбрал layout: `list_off=0xb0, pid_off=0xd8, score=50`. ourproc() прошёл 227 процессов (pid=320 → 319 → ... → ~94), цепочка закончилась `raw_next=0x0` (NULL). max_pid=320 < ourpid=466. `Bug #336: allproc chain exhausted (227 procs, max_pid=320 < ourpid=466) and no alt-list hit`.

**Root cause:**
- disc_pl Phase 2: `for (list_off = 0x08; ...)` — пропускал `list_off=0x00`
- Диагностика подтверждала: `*(kernproc+0x00)=0xffffffe26b5c7430` (след. proc IRL), `*(kernproc+0x08)=allproc` (le_prev указывает на allproc = le_front iOS 17 TAILQ `p_list`)
- `list_off=0xb0` == какой-то структурный список (p_pglist? p_siblings?). Цепочка в нём: pid=320→319→318...→~94 (227 процессов с монотонно убывающим pid). SCORE=50 — выше list_off=0x00 (#0x00 не тестировался вовсе)
- Реальная `allproc p_list` iOS 17 TAILQ на list_off=0x00: kernproc→launchd→...→DarkSword(466). Охватывает ВСЕ процессы
- Bug #337 ходил proc0[+0x00] только 10 шагов (недостаточно) и не восстанавливал PROC_LIST_OFFSET

**Fix** (`darksword/utils.m`):
1. **Phase 2 disc_pl**: `list_off = 0x08` → `list_off = 0x00`. Теперь Phase 2 пробует list_off=0x00 первым. score_proc_chain_ex с list_off=0x00 наберёт ~50 unique pid (0,1,2,...,50) за 50 шагов → score≥40 → early exit → PROC_LIST_OFFSET=0x00
2. **Bug #337+448 recovery**: 10 шагов → 500 шагов, при нахождении ourpid — устанавливает `PROC_LIST_OFFSET=0x00` и возвращает proc (как fallback если Phase 2 не сработал)

**Build:** 82 (2026-04-04)

---

## Bug #447  proc-scope kread anchor window (±12GB) блокировал proc-адреса >12GB выше rw_socket_pcb; disc_pl накапливал 32 blocked → PANIC GUARD → abort (2026-04-04)

**Symptom:** build 80†: allproc SUCCESS нашёл head=`0xfffffff010d40400` (kernproc, offset 0x321c400). `disc_pl` запускался с entry `0xffffffe4668b3000`. Но procs из kernproc chain находились на `0xffffffe71936xxxx` (~14.3GB выше rw_socket_pcb=`0xffffffe380bb4400`). Каждое такое чтение через `set_target_kaddr` проверялось по anchor window `[rw-12GB, rw+12GB]=[0xffffffe2ccb98000, 0xffffffe680bb4400)`. Адреса >14GB выше rw падали в BLOCKED → `++g_proc_scope_block_count`. После 32 блокировок → `g_proc_scope_block_latched=true` → PANIC GUARD трипнулся. Затем `disc_pl` вернул `NO MATCH`. `[ourproc] walk` при step=0 уже видел PANIC GUARD → abort.

**File:** `darksword/darksword_core.m`, `set_target_kaddr()`, блок anchor window

**Root cause:**
- Bug #426 установил proc-scope anchor span=12GB (`0x300000000`). На большинстве устройств procs укладываются в ±12GB от rw_socket_pcb.
- На 21D61 A12Z зона map = 24GB. rw_socket_pcb = `0xffffffe380bb4400` (~4.5GB выше zone_min). Procs из kernproc chain могут быть в конце zone_map (~19GB выше zone_min = ~14.5GB выше rw) → выходят за верхний предел anchor window.
- По сути anchor_max должен быть zone_guard_max (верхняя граница zone_map), а не rw+12GB.

**Fix** (`darksword/darksword_core.m`):
- В proc-scope (`g_proc_read_scope_depth > 0`): `anchor_max = zone_guard_max` (без ограничения спаном).
- Вне proc-scope: поведение прежнее (`anchor_max = rw + span`, клампинг к zone_guard_max).
- Нижний bound (anchor_min = rw - 12GB) не изменяется — прокси от низких false-ptrs сохраняется.

**Build:** 81 (2026-04-04)

---

## Bug #446  `validate_allproc` Bug #398 отклонял allproc head `0xffffffe465391000` (kernproc) как «слишком далеко» от rw_pcb (diff=7.2GB), хотя он находится в zone_map (2026-04-05)

**Symptom:** build 79†: allproc candidate из XPF offset 0x3213680 → head=`0xffffffe465391000` (kernproc, pid=0). После успешной val_ap-pass проверка Bug #398 «far head» с порогом 3GB от rw_pcb отклоняла его: `diff=0x1ca468c00 > PROC_NEAR_PCB_MAX_DIFF=0xC0000000` → `return false`. Кандидат помечался как failed.

**File:** `darksword/utils.m`, `validate_allproc()`, константа `PROC_NEAR_PCB_MAX_DIFF`

**Root cause:**
- Bug #398 намеренно ввёл 3GB порог чтобы отсечь GEN3-false heads с Per-CPU pages, которые паниковали при chain-walk.
- НО: реальный proc0/kernproc (`0xffffffe465391000`) находится в zone_map [0xffffffe165948000, 0xffffffe765948000] (~7.2GB от rw_pcb). Это допустимо — proc structs размещаются по всей 24GB зоне.
- Проверка по расстоянию от rw_pcb — неправильный критерий для allproc head; правильный критерий — нахождение в zone_map.

**Fix** (`darksword/utils.m`, `validate_allproc()`):
- После вычисления `allow_far_bsd_backlink`, добавить: `bool allow_zone_map_head = is_in_zone_map(head_stripped);`
- Условие отклонения: `if (!allow_far_bsd_backlink && !allow_zone_map_head)` вместо `if (!allow_far_bsd_backlink)`
- Добавлен лог `Bug #446: allowing zone-map head despite rw_pcb dist`

---

## Bug #445  allproc head и proc chain entries ниже `zone_safe_min` отклонялись как «не heap» во всех путях валидации allproc; реальный allproc head `0xffffffe299239000` из XPF offset 0x3213678 был первой жертвой (2026-04-05)

**Symptom:** build 79†: offset 0x3213678 → allproc candidate `0xfffffff010003678` → `*(candidate)=0xffffffe299239000`. Это НАСТОЯЩИЙ allproc head (первый user-процесс в SMRQ списке). Но `is_heap_ptr_relaxed(0xffffffe299239000)` = false (addr ниже `zone_safe_min=0xffffffe2e5948000` на ~0.9GB). Результат: `direct shortlist → "not even relaxed-heap" → continue` во всех проходах; `validate_direct_allproc_v2` никогда не пытался этот адрес; `validate_allproc` тоже сразу возвращал false на первом heap-check.

**Context:**
- `rw_pcb = 0xffffffe29af28400` (ниже safe_min на ~1.6GB)
- `zone_safe_min = zone_min + zone_span/4 = 0xffffffe165948000 + 0x180000000 = 0xffffffe2e5948000`
- Весь relevant heap-регион (rw_pcb, allproc head, первые user-procs) находится в zone_map но НИЖЕ safe_min — они выделены в GEN1-регионе ~21-33% от zone_min
- Bug #397 ввёл safe_min чтобы избежать sparse GEN0 pages (<<20% от zone_min). Наши адреса — это GEN1+, а не GEN0 sprase. Безопасны для kread.

**Affected code** (`darksword/utils.m`):
1. `direct shortlist`: `bool relaxed_heap = is_heap_ptr_relaxed(stripped)` → добавлено `|| is_in_zone_map(stripped)`
2. `validate_allproc` head-check: `if (!is_heap_ptr_relaxed(head))` → добавлено `&& !is_in_zone_map(head)`
3. `validate_direct_allproc_v2_with_layout` — 5 мест: entry_ptr check, first_proc check, chain-loop condition, next_entry check, next_proc check — во все добавлено `&& !is_in_zone_map(...)` / `|| is_in_zone_map(...)`

**Expected result:** `0xffffffe299239000` допускается как allproc head; `validate_direct_allproc_v2` с list_off=0xb0, pid_off=0x60 обходит SMRQ список начиная с `proc=0xffffffe299238f50` (первый user-proc, PID = plausible), находит pid=479 → allproc SUCCESS.

---

## Bug #444  `find_self_proc_via_socket_tro` использовал неправильные `tro_proc_off=0x18`/`tro_task_off=0x28` для iOS 17.0-17.3; fast path был отключён (2026-04-05)

**Symptom:** сборки 40-78 на iOS 17.3.1 (21D61): Bug #433 явно отключал socket/tro fast path (`enable_socket_tro_fastpath = false` для 21D61), потому что fast path возвращал 0 (все proc-кандидаты отклонялись как `!proc_ok`). Проверка PID тоже никогда не срабатывала.

**File:** `darksword/utils.m`, функция `find_self_proc_via_socket_tro()`

**Root cause:**
- В функции были жёстко зашиты `tro_proc_off = 0x18` (= `offsetof(thread_ro, tro_proc)`) и `tro_task_off = 0x28` — это значения для **iOS 17.4+** и iOS 18.x.
- Для **iOS 17.0-17.3** правильные значения: `tro_proc=0x10`, `tro_task=0x20` (подтверждено `off_thread_ro_tro_proc = 0x10 //17.0-17.3` из референс-репозитория wh1te4ever/darksword-kexploit-fun).
- При чтении `tro + 0x18` на iOS 17.3.1 мы читали `tro_task` (kptr), а не `tro_proc` (zone ptr) → `proc_ok = false` → `proc_ptr_rejects++` → fast path всегда возвращал 0 → был явно отключён в Bug #433.

**Fix:**
- `tro_proc_off = 0x18` и `tro_task_off = 0x28` заменены на массивы кандидатов `{0x10, 0x18}` и `{0x20, 0x28}` соответственно.
- Добавлен внутренний цикл `for (pc...)` внутри цикла по TRO-офсетам, который перебирает пары `(tro_proc_off, tro_task_off)` пока не найдёт совпадение по PID.
- Снята блокировка Bug #433: `else if (ds_build_is_21D61()) { enable_socket_tro_fastpath = false; }` удалено.
- В лог SUCCESS добавлено поле `tro_proc_off=0x%x` для диагностики.

**Expected result:** на iOS 17.3.1 fast path попытает `tro_proc_off=0x10` первым, прочитает правильный proc ptr из heap, проверит PID совпадение → `ourproc()` вернёт адрес selfproc напрямую, минуя весь allproc-scan.

---

## Bug #443  `validate_kernproc_forward_chain` / `validate_kernproc_backward_chain` использовали `is_heap_ptr_relaxed` для chain-walk ptrs — ранние kernel-thread procs ниже `zone_safe_min` резались, ограничивая chain≤11 (2026-04-05)

**Symptom:** при сборке 77 оба кандидата 0x3213678 и 0x3213680 проходят `detect_kernproc_variable`, но `validate_kernproc_forward_chain` возвращает `chain_len=11, unique_nonzero=2, found_ourpid=0` → не достигает порога `≥20 & ≥8`. Оба кандидата отбрасываются, allproc → 0.

**File:** `darksword/utils.m`

**Root cause:**
- в обоих chain-walk валидаторах проверка допустимости указателя: `is_heap_ptr_relaxed(cur)` / `is_heap_ptr_relaxed(next)` — использовала `zone_safe_min` как нижнюю границу,
- ранние kernel-thread proc-объекты живут в GEN0-регионе зоны (`zone_map_min..zone_safe_min` ≈ `0xffffffe1736d4000..0xffffffe2f36d4000`),
- при проходе цепочки proc 12+ адрес попадал ниже `zone_safe_min` и предикат возвращал `false` → `break` на i=11,
- `is_in_zone_map()` специально введена для подобных walks (см. комментарий Bug #403), но не использовалась.

**Fix:**
- в `validate_kernproc_forward_chain`: заменить `is_heap_ptr_relaxed(cur) || is_kernel_data_ptr(cur)` на `is_proc_chain_ptr(cur)` и аналогично для `next`,
- в `validate_kernproc_backward_chain`: то же самое,
- `is_proc_chain_ptr` = `is_heap_ptr_relaxed || is_in_zone_map || (direct_layout && is_kernel_data_ptr)` — охватывает весь zone_map без метаданных-панических region.

**Expected effect:** chain_len вырастет с 11 → 20+ (или до `found_ourpid=true`); `detect_kernproc_variable` вернёт true для валидных кандидатов.

---

## Bug #442  `g_failed_allproc_heads` не сбрасывался между pass-0 и pass-1 в `kernprocaddress()` — head, занесённый в blacklist в minimal-pass, блокировался в safe-pass (2026-04-05)

**Symptom:** при auto-safe-fallback (pass=1) кандидаты с теми же `allproc` адресами что и в pass=0 (например 0x3213678) немедленно отвергались из-за blacklist head `0xffffffe473704000` добавленного в pass-0.

**File:** `darksword/utils.m`

**Root cause:** `g_failed_allproc_head_count` и `g_failed_allproc_heads[]` — статические глобальные переменные, которые не очищались при переходе к safe shortlist pass.

**Fix:** при `pass > 0` сбросить `g_failed_allproc_head_count = 0` перед обходом safe shortlist.

**Expected effect:** safe-pass видит чистый blacklist → fresh попытка для всех safe-кандидатов.

---

## Bug #440  `PROC_BSD_BACKLINK_MAX_DIFF` (8 GB) слишком мал для zone_map 24 GB — head на 10.9 GB от rw_socket_pcb отбрасывался в `validate_allproc` (2026-04-05)

**Symptom:** кандидат `kbase+0x3213680` → head=`0xffffffe55aa5f000`, diff от `rw_socket_pcb=0xffffffe2a8940400` = 10.9 GB. `PROC_NEAR_PCB_MAX_DIFF` (3 GB) не проходит, BSD-backlink bypass проверяет `diff ≤ PROC_BSD_BACKLINK_MAX_DIFF` — но 10.9 GB > 8 GB → head отвергается без disc_pl.

**File:** `darksword/utils.m`

**Root cause:** `PROC_BSD_BACKLINK_MAX_DIFF = 0x200000000ULL` (8 GB) задан безотносительно фактического размера zone_map. На этом boot zone_map = 24 GB, а proc-объекты распределены по всему её диапазону.

**Fix:** поднять константу до `0x500000000ULL` (20 GB) — перекрывает весь возможный 24 GB zone_map span.

**Expected effect:** head на 10.9 GB пройдёт BSD-backlink check → попадёт в `discover_proc_list_layout` → allproc validation.

---

## Bug #429  `ourproc()` мог продолжать агрессивный speculative walk после шквала reject-ов в `set_target_kaddr`, что повышало риск metadata-class panic в proc-scope (2026-04-04)

**Symptom:** в runtime `syslog_2026-04-04_13-01-38.txt` после `about to call ourproc()` шёл длинный шторм `set_target_kaddr: BLOCKED ...`, затем сессия заканчивалась `panic 210` (`panic-full-2026-04-04-130206.0002.ips`) с `FAR` в `Zone info -> Metadata`.

**File:** `darksword/darksword_core.m`

**Root cause:**
- даже при множественных BLOCKED-кандидатах proc-scope traversal продолжал спекулятивные попытки,
- при деградировавшем chain-walk это увеличивало шанс дойти до опасного адресного паттерна и словить kernel data abort.

**Fix:**
- добавлен fail-fast PANIC GUARD для proc-scope в `set_target_kaddr()`:
  - считается число blocked-кандидатов в активном proc-scope,
  - после порога guard latch-ится и отклоняет дальнейшие speculative target-адреса до выхода из scope,
- latch/counter сбрасываются на входе/выходе `ds_enter_proc_read_scope()`/`ds_leave_proc_read_scope()`.

**Expected effect:** при плохом `allproc/ourproc` chain run должен безопасно оборваться (вернуть `ourproc=0` и ранний abort), а не эскалировать в metadata-class kernel panic.

---

## Bug #428  Pre-zone-discovery `set_target_kaddr()` использовал слишком широкий primed range (rw_socket_pcb ±24GB), что допускало speculative reads в zone metadata/bitmaps и приводило к `Kernel data abort` (2026-04-04)

**Symptom:** в новом runtime (`syslog_2026-04-04_12-55-06.txt`) перед стабильной late-stage зоне-дискавери наблюдались ранние шумные deref, после чего сессия завершилась `panic 210` (`panic-full-2026-04-04-125536.0002.ips`) с `FAR=0xffffffdc011810b0` (metadata region).

**File:** `darksword/darksword_core.m`

**Root cause:**
- в fallback ветке до подтверждённых `zone_info` bounds выполнялся `prime_zone_bounds_from_rw_pcb()` с очень широким полу-окном (`±24GB`),
- такой primed диапазон численно захватывал области zone metadata/bitmaps,
- одиночный мусорный target мог пройти pre-discovery gate и вызвать data-abort в copyout path.

**Fix:**
- в pre-zone-discovery path добавлен отдельный `rw_socket_pcb` anchor-window `±12GB`,
- если адрес вне этого окна — `set_target_kaddr()` делает ранний reject с новым telemetry:
  `BLOCKED pre-discovery addr outside rw_socket_pcb anchor window ...`,
- post-discovery guarded/anchor logic (Bug #426/#427) не изменялась.

**Expected effect:** меньше шансов получить metadata-class panic до/во время раннего pointer probing, при сохранении совместимости с валидными pre-discovery deref около live `rw_socket_pcb`.

---

## Bug #427  В `set_target_kaddr` lower guarded bound (`g_zone_safe_min`) оказался слишком высоким для scoped proc/allproc traversal и резал валидные low-zone chain links (2026-04-04)

**Symptom:** после Bug #426 исчезли `anchor window` блоки, но run всё ещё завершался `allproc not found`; в DATA/Mach-O scan оставались массовые блоки вида `BLOCKED zone addr outside guarded window [safe_min, zone_max-4MB)` на адресах `0xffffffe3...`.

**Files:** `darksword/darksword_core.m`

**Fix:**
- в scoped proc/allproc path (`g_proc_read_scope_depth > 0`) нижняя граница guarded-window опускается на 4GB:
  - было: `zone_guard_min = g_zone_safe_min`
  - стало: `zone_guard_min = max(g_zone_map_min, g_zone_safe_min - 4GB)`
- вне scope поведение не меняется,
- верхний top-tail guard (`zone_map_max - 4MB`) сохранён.

**Expected effect:** меньше ложных low-bound reject в proc/allproc chain traversal без снятия глобальных safety guards.

---

## Bug #426  Scoped `rw_socket_pcb` anchor-window ±8GB оказался слишком узким для части валидных far-head кандидатов на 21D61, что ломало allproc validation даже в panic-free run (2026-04-04)

**Symptom:** в свежем runtime (12:46:59) run остаётся panic-free, но allproc resolve снова уходит в safe-abort:
- `Bug #297` корректно пробует обновлённый builtin XPF-lite shortlist,
- при проверке сильных head-кандидатов появляются массовые блокировки `set_target_kaddr: BLOCKED zone addr outside rw_socket_pcb anchor window ...`,
- затем `XPF-lite exhausted` → scan fallback → `ERROR: all strategies exhausted, allproc not found`.

**Files:** `darksword/darksword_core.m`

**Root cause:**
- после Bug #423 scoped widen был ограничен `±8GB` (только при `g_proc_read_scope_depth > 0`),
- на этом boot наблюдаются валидные zone-адреса кандидатов с дельтой от `rw_socket_pcb` около `0x2b5...` (больше 8GB),
- из-за этого low-level target gate отрезал чтения до структурной валидации chain/layout.

**Fix:**
- в `set_target_kaddr()` scoped anchor-window расширен с `±8GB` до `±12GB` **только** внутри proc/allproc scoped path,
- default окно вне scope оставлено прежним (`±4GB`),
- `zone_guard_min/max`, top-tail guard и остальные safety checks сохранены без ослабления.

**Expected effect:**
- меньше ложных `anchor window` блоков при `validate_allproc()` / `try_xpf_lite_offsets()`,
- больше кандидатов доживают до реальной chain/layout проверки вместо раннего low-level reject.

---

## Bug #424  `reject_mixed_bsd_head_candidate()` ложно отвергала корректный `allproc` кандидат на iOS 17.3.1 из-за SMRQ-структуры и совпадения adjacent-sublist pointer (2026-04-04)

**Symptom:** Build 49, первый run после Bug #423:
- `disc_pl` Phase 2 успешно находит правильную раскладку: `list_off=0xb0, pid_off=0xd8, score=50, nextpid=357 → FOUND!`
- `[[val_ap] Bug #390: rejecting mixed head 0xfffffff022e0c480 — disc_pl chose list_off=0xb0, but proc0 has BSD head signature (p_list prev=head next=0xffffffe55bc540b0) while chosen entry prev=0x10 is non-kptr`
- После этого XPF-lite, DATA scan, Mach-O scan — все итерации заблокированы (allproc не найден).

**Files:** `darksword/utils.m`

**Root cause:**
- `reject_mixed_bsd_head_candidate()` проверяет `*(firstproc + PROC_LIST_OFFSET + 0x08)` как «chosen chain le_prev», полагая что `firstproc = proc0 + PROC_LIST_OFFSET`.
- На самом деле в Phase 2: `best_base = raw` (т.е. `firstproc = proc0_base`), а `PROC_LIST_OFFSET` уже хранится отдельно. Поэтому `firstproc + PROC_LIST_OFFSET + 0x08 = proc0 + 0xb0 + 0xb8 = proc0 + 0x168` — читается мусор `0x10`.
- BSD head shape (bsd_prev == allproc_addr) на `proc0[+0x00/+0x08]` — случайное совпадение: iOS 17.3.1 там хранит `le_next/le_prev` соседнего 11-элементного подсписка, le_prev которого равен allproc_addr.
- iOS 17.3.1 xnu-10002 использует **SMRQ** (SMR queue) для allproc — `proc0.p_list` по `+0xb0` не имеет классического `le_prev` backlink (вместо него SMR epoch tag `0x10`).
- Итог: функция ошибочно возвращает `true` (отвергнуть), хотя `disc_pl` нашёл правильный список.

**Fix:**
- Перед итоговым `return true` в ветке `!bsd_chain_ok` добавлена проверка:
  ```objc
  if (validate_proc_chain_with_pid_off(firstproc, PROC_LIST_OFFSET, PROC_PID_OFFSET, 200)) {
      return false;  // disc_pl был прав — BSD shape случайный
  }
  ```
- Если chosen `list_off` chain проходит 200-шаговую walk → BSD head shape считается случайным совпадением, candidate принимается.
- Если chosen chain тоже не проходит — старое отвержение по Bug #390 остаётся.

**Expected effect:**
- `[val_ap] Bug #424: chosen list_off=0xb0 validates full chain (BSD shape at proc0=... coincidental sublist) — accepting`
- `allproc` принят, `ourproc` находит PID 483 → jailbreak продолжается

> Doc-sync policy: после каждого code-fix в этой ветке обновлять минимум `doc/BUGS_AND_FIXES.md` + `doc/CURRENT_STATUS.md` в том же рабочем цикле.

---

## Bug #423  После Bug #422 run стал panic-free, но validated proc-chain traversal всё ещё срывался на `set_target_kaddr()` из-за слишком узкого `rw_socket_pcb` anchor-window, поэтому сильный `allproc` candidate не доживал до acceptance (2026-04-04)

**Symptom:** свежий panic-free run ([log/syslog_2026-04-04_12-04-00.txt](log/syslog_2026-04-04_12-04-00.txt)) показал:
- `Bug #422` корректно выключает direct `kernproc` path на `21D61`,
- `XPF-lite`, inner `__DATA` scan и `Mach-O parse scan` реально запускаются,
- но внутри `validate_allproc()` / `ourproc()` candidate traversal массово режется логами `set_target_kaddr: BLOCKED zone addr outside rw_socket_pcb anchor window ...`,
- в итоге run завершается panic-free, но функционально бесполезным abort: `all strategies exhausted, allproc not found`.

**Files:** `darksword/darksword_core.m`, `darksword/utils.m`, `darksword/darksword_core.h`

**Root cause:**
- guard из Bug #419 держал единый жёсткий anchor-window `±4GB` вокруг `rw_socket_pcb` для всех zone deref,
- этого хватало для crash-hardening, но уже не хватало для реального proc-chain traversal: часть правдоподобных `proc`/`allproc` links лежала дальше `4GB`, хотя всё ещё внутри допустимого zone-map и не в per-cpu tail,
- из-за этого валидный или почти-валидный candidate отвергался не по структуре chain, а по слишком раннему low-level read gate.

**Fix:**
- в low-level KRW path добавлен scoped режим `ds_enter_proc_read_scope()` / `ds_leave_proc_read_scope()`,
- внутри этого scope `set_target_kaddr()` временно расширяет `rw_socket_pcb` anchor-window с `±4GB` до `±8GB`,
- расширение включается только на validated proc/allproc traversal path (`validate_allproc()` и `ourproc()`),
- все остальные safety-границы остаются прежними: `zone_map`, `zone_safe_min`, top-tail guard и text/data gate не ослабляются.

**Expected effect:**
- `validate_allproc()` больше не должен терять сильные proc-chain candidates только из-за `anchor window` reject,
- следующий run должен показать, что `XPF-lite` / `DATA` / `Mach-O` path проходит глубже, чем раньше,
- при неуспехе ожидается всё тот же controlled abort без возврата к kernel panic.

---

## Bug #422  На build `21D61` direct `kernproc`-ветка оставалась включённой в auto-run, хотя именно она привела к новому panic `zone bound checks: ... is a per-cpu allocation` во время `baseline-auto` (2026-04-04)

**Symptom:** свежий auto-run ([log/syslog_2026-04-04_11-51-51.txt](log/syslog_2026-04-04_11-51-51.txt), [log/panics_2026-04-04_11-53-31/panic-full-2026-04-04-115222.0002.ips](log/panics_2026-04-04_11-53-31/panic-full-2026-04-04-115222.0002.ips)) показал:
- стартовал только `baseline-auto`, до `safe-direct`/`full-direct` выполнение не дошло,
- после неудачи `socket/tro fast path` код вошёл в direct shortlist,
- кандидат `0x3213680` активировал `detect_kernproc_variable()` и далее спровоцировал новый kernel panic:
  - `panicString`: `zone bound checks: address 0xffffffe0d4024ac0 is a per-cpu allocation`,
  - panicked task: `DarkSword` (pid 462),
  - bug_type 210.

**File:** `darksword/utils.m`

**Root cause:**
- несмотря на ранние hardening-фиксы, `detect_kernproc_variable()` по-прежнему допускал direct `kernproc` path на target build `21D61`,
- на этом build kernel-only / tail-`kernproc` ветка уже ранее проявляла себя как unsafe,
- новый auto-orchestration запускал её в первом же профиле, из-за чего приложение падало до более безопасных scan/Mach-O fallback стадий.

**Fix:**
- добавлен build-gated guard: direct `kernproc` path теперь по умолчанию выключен на `21D61`,
- ручной opt-in сохранён через `DS_ENABLE_KERNPROC_DIRECT=1`,
- при skip логируется telemetry `Bug #422: kernproc direct path disabled by default on 21D61`.

**Expected effect:**
- `baseline-auto` больше не должен паниковать на `detect_kernproc_variable()` для кандидата `0x3213680`,
- run сможет продолжить к более безопасным путям (`DATA scan`, `Mach-O scan`, последующие auto-profiles),
- если `allproc` всё ещё не будет найден, ожидается controlled abort без reboot/panic.

---

## Bug #421  Standalone `jailbreak_full()` использовал один статичный runtime path и не автоматизировал профильные allproc-стратегии, из-за чего требовались ручные env-переключения для повторных прогонов (2026-04-04)

**Symptom:** после Bug #420 код уже имел сильные fallback-пути (`DATA scan`, `Mach-O scan`, direct shortlist modes), но standalone app всё ещё запускала `ds_run()` линейно:
- без автоматического перебора `DS_DIRECT_MODE=minimal/safe/full`,
- без включённой в UI индикации активного auto-mode,
- при functional failure требовались ручные правки env/config вместо self-healing sequence.

**Files:** `darksword/darksword_exploit.m`, `app/main.m`

**Root cause:**
- orchestration логика жила фрагментарно внутри отдельных fallback-блоков,
- верхний standalone pipeline не управлял runtime-профилями как единым автоматическим сценарием,
- приложение не сообщало пользователю, что exploit теперь использует авто-перебор стратегий.

**Fix:**
- в `jailbreak_full()` добавлен automatic multi-profile launch sequence:
  - `baseline-auto`
  - `safe-direct`
  - `full-direct`
- каждый профиль автоматически выставляет `DS_DIRECT_MODE` / `DS_ENABLE_DATA_DIRECT` / scan flags перед `ds_run()`,
- приложение обновлено: UI явно показывает auto-mode и запуск `baseline → safe → full`.

**Expected effect:**
- меньше ручных переключений при повторах exploit-run,
- автоматический переход к более агрессивным allproc-стратегиям при провале базового профиля,
- лучшее соответствие между фактической логикой exploit и UX standalone app.

---

## Bug #420  `kernprocaddress()` оставлял Mach-O parse scan opt-in, из-за чего run завершался `allproc not found` даже после снятия panic-класса (2026-04-04)

**Symptom:** свежий прогон ([log/syslog_2026-04-04_11-34-05.txt](log/syslog_2026-04-04_11-34-05.txt), [log/darksword_log.txt](log/darksword_log.txt)) после Bug #419 показал:
- kernel panic больше не воспроизводится,
- `set_target_kaddr` активно блокирует дальние/опасные адреса (`outside rw_socket_pcb anchor window`, `outside guarded window`),
- но сессия стабильно уходит в controlled abort: `all strategies exhausted, allproc not found` -> `ourproc() failed (0x0)` -> `PANIC GUARD`.

**File:** `darksword/utils.m`

**Root cause:**
- в `kernprocaddress()` финальный `scan_for_allproc()` оставался выключенным по умолчанию и запускался только при `DS_ENABLE_MACHO_SCAN=1`,
- на текущем boot direct/XPF-lite/inner DATA paths иногда не дают `allproc`, а до последнего резолвера код не доходил,
- в результате exploit завершался безопасно, но преждевременно — без попытки последнего fallback.

**Fix:**
- Mach-O parse fallback переведён в `enabled-by-default` режим,
- добавлен явный opt-out: `DS_ENABLE_MACHO_SCAN=0`,
- telemetry обновлена: `falling back to Mach-O parse scan (Bug #420: enabled by default)...`.

**Expected effect:**
- при провале direct/XPF-lite/inner DATA стратегий run автоматически пробует финальный Mach-O parse fallback,
- должна снизиться частота `allproc not found` abort-only сессий,
- при необходимости рисковый путь по-прежнему отключается через `DS_ENABLE_MACHO_SCAN=0`.

---

## Bug #419  В `set_target_kaddr()` оставалось слишком широкое zone-допущение без proximity-anchor к `rw_socket_pcb`, из-за чего в `ourproc()` ещё могли проходить дальние «псевдо-валидные» zone-адреса и вызывать `Kernel data abort` (2026-04-04)

**Symptom:** после Bug #418 новый прогон ([log/syslog_2026-04-04_11-22-37.txt](log/syslog_2026-04-04_11-22-37.txt)) показал:
- exploit стабильно доходит до `kernel r/w is ready` и входа в `ourproc`,
- в `ourproc` уже активно блокируются мусорные адреса (`BLOCKED misaligned`, `outside zone_map`, `outside kbase window`, `BLOCKED high non-kernel`),
- но panic всё равно воспроизводится; panic bundle ([log/panics_2026-04-04_11-24-37/panic-full-2026-04-04-112303.0002.ips](log/panics_2026-04-04_11-24-37/panic-full-2026-04-04-112303.0002.ips)) фиксирует `Kernel data abort`, bug_type 210, panicked task `DarkSword`, FAR `0xffffffe21d069fd0`.

**File:** `darksword/darksword_core.m`

**Root cause:**
- Bug #418 сузил общий zone-window (`safe_min .. zone_max-4MB`), но это окно всё ещё огромно для спекулятивного `ourproc` chain-walk,
- отдельные дальние zone-кандидаты могут оставаться «численно валидными» и проходить gate, хотя practically ведут в sparse/unbacked path,
- без дополнительной привязки к уже подтверждённому live-объекту (`rw_socket_pcb`) panic-risk сохраняется даже при рабочих блоках #417/#418.

**Fix:**
- в zone-ветке `set_target_kaddr()` добавлен второй guard — proximity-anchor window вокруг `rw_socket_pcb`:
  - если `rw_socket_pcb` в `zone_map`, разрешаются только адреса в широком окне `rw_socket_pcb ± 4GB`,
  - окно дополнительно clamp'ится к уже действующему guarded zone-window,
  - вне окна адрес блокируется с telemetry `outside rw_socket_pcb anchor window`.

**Expected effect:**
- `ourproc` и смежные chain-walk этапы больше не смогут дёргать дальние zone-адреса, которые формально лежат в `zone_map`, но нестабильны для copyout validation,
- должна исчезнуть текущая panic-сигнатура `Kernel data abort` (bug_type 210) на этапе сразу после входа в `ourproc`,
- при новых шумных указателях ожидается controlled reject через `BLOCKED ... anchor window`, а не reboot/panic.

---

## Bug #418  `set_target_kaddr()` принимал весь `[zone_map_min, zone_map_max)`, включая рискованные sparse/tail зоны, что оставляло окно для `Kernel data abort` с FAR в Zone Metadata (2026-04-04)

**Symptom:** после Bug #417 новый run ([log/syslog_2026-04-04_11-16-04.txt](log/syslog_2026-04-04_11-16-04.txt)) показал, что high-kaddr блоки работают (`BLOCKED high non-kernel text/data addr 0xfffffffd52800039`), но panic не исчез:
- panic bundle ([log/panics_2026-04-04_11-17-51/panic-full-2026-04-04-111655.0002.ips](log/panics_2026-04-04_11-17-51/panic-full-2026-04-04-111655.0002.ips)) фиксирует `Kernel data abort`, bug_type 210,
- `FAR: 0xffffffe2035d0240`, что попадает в `Zone info -> Metadata` диапазон,
- значит авария уже не от high text/data мусора, а от metadata-path при deref zone-адресов.

**File:** `darksword/darksword_core.m`

**Root cause:**
- в `set_target_kaddr()` zone-ветка после Bug #417 всё ещё разрешала почти весь `zone_map` (`[g_zone_map_min, g_zone_map_max)`),
- для ранних/спекулятивных kread это слишком широко: часть zone VA лежит в sparse/unallocated областях, где kernel-side metadata validation может попасть в неотмапленную metadata страницу и дать data-abort,
- в `utils.m` аналогичный риск уже давно смягчён через `zone_safe_min + top_guard`, но `set_target_kaddr()` оставался шире этого safety-window.

**Fix:**
- в zone-ветке `set_target_kaddr()` добавлен guarded-window gate:
  - lower bound: `g_zone_safe_min` (fallback на `g_zone_map_min`),
  - upper bound: `g_zone_map_max - 0x400000` (top 4MB guard),
  - вне окна адрес блокируется с telemetry: `outside guarded window`.

**Expected effect:**
- ранние kread/kwrite перестанут ходить в наиболее рискованные sparse/tail участки zone_map,
- должна исчезнуть текущая panic-сигнатура `Kernel data abort` с FAR в `Zone Metadata`,
- если функциональный blocker останется, run должен завершаться controlled reject/abort без kernel panic.

---

## Bug #417  `set_target_kaddr()` допускал слишком широкий high-kernel диапазон для non-zone адресов, что пропускало мусорные `0xfffffffd...` kaddr и приводило к panic `copy_validate: kaddr not in kernel` (2026-04-04)

**Symptom:** в свежем run ([log/syslog_2026-04-04_11-11-04.txt](log/syslog_2026-04-04_11-11-04.txt)) после Bug #416 exploit доходил до `kernel r/w is ready` и входа в `ourproc`, но затем устройство падало; panic bundle ([log/panics_2026-04-04_11-12-26/panic-full-2026-04-04-111133.0002.ips](log/panics_2026-04-04_11-12-26/panic-full-2026-04-04-111133.0002.ips)) зафиксировал:
- `panicString: copy_validate(..., 0xfffffffd52800039, 8) - kaddr not in kernel @copyio.c:194`,
- panicked task `DarkSword` (pid 439), bug_type 210,
- перед crash в syslog уже видны множественные `set_target_kaddr: BLOCKED misaligned/outside zone_map`, но проблемный high-kaddr не отсеивался.

**File:** `darksword/darksword_core.m`

**Root cause:**
- `set_target_kaddr()` для диапазона `where >= 0xfffffff000000000` применял слишком coarse допуск (до `0xffffffff...`) и не привязывал адрес к реальному `kernel_base`,
- из-за этого отдельные мусорные high-half значения (включая tagged/malformed) проходили guard как «text/data candidate»,
- downstream `copy_validate` в kernel корректно отвергал такой адрес и паниковал до пользовательского recover path.

**Fix:**
- в ветке kernel text/data добавлены дополнительные safety gates:
  - coarse upper bound: блок `where >= 0xfffffff800000000`,
  - если `kernel_base` уже известен — разрешается только bounded window вокруг него (`kbase-0x02000000 .. kbase+0x80000000`, с clamp до `0xffffffff00000000`),
  - при выходе за окно добавлен явный блок-лог `outside kbase window`.

**Expected effect:**
- мусорные high-kaddr вида `0xfffffffd...` будут блокироваться до `setsockopt/copyout` стадии,
- должен исчезнуть panic-сценарий `copy_validate ... kaddr not in kernel` в аналогичных прогонах,
- следующий run должен либо дойти до старого функционального blocker'а (`ourproc`/layout), либо дать новый контролируемый reject без kernel panic.

---

## Bug #416  `socket/tro` fast path ограничивал `thread->tro` scan окном до `0x3b0`, из-за чего на текущем boot все TRO-кандидаты отбрасывались и path не доходил до `proc/pid` proof (2026-04-04)

**Symptom:** в свежем runtime ([log/syslog_2026-04-04_11-07-03.txt](log/syslog_2026-04-04_11-07-03.txt)) после Bug #415:
- `socket/tro fast path stats ... tro_rejects=106`,
- detail-log: `rejected 106 tro pointers ... last tro_off=0x3b0 raw=0x121d0108b9424268 stripped=0x8b9424268`,
- fast-path снова завершился `no validated self proc found`, затем fallback ушёл в прежний `Bug #268` / `disc_layout FAILED` цикл.

**File:** `darksword/utils.m`

**Root cause:**
- текущий bounded `thread->tro` scan (`0x320..0x3b0`) оказался слишком узким для данного boot-layout,
- телеметрия показывает упор в верхнюю границу (`last tro_off=0x3b0`), что типично для ситуации «правильный field рядом, но вне окна»,
- в результате fast-path не находил валидный TRO pointer и не мог перейти к стабильной `proc/pid/task` проверке.

**Fix:**
- расширено окно `thread->tro` fallback scan:
  - `start: 0x320 -> 0x300`
  - `end:   0x3b0 -> 0x3f0`
  - шаг остаётся `0x8`, dedup сохранён.

**Expected effect:**
- fast-path должен покрыть дополнительные соседние layout-варианты `thread->tro` без ослабления ptr-gates,
- в следующем run ожидается либо переход к `proc/pid` стадиям (изменение `proc_rejects/pid_misses/task_proof_misses`), либо как минимум смена `last tro_off`/характера TRO reject telemetry,
- при успехе уменьшится частота fallback заходов в `kernprocaddress` и связанный `disc_layout` fail-loop.

---

## Bug #415  Спекулятивные kernproc chain-walk допускали raw zone-map указатели как next/prev, что повышало риск metadata data-abort в fallback валидации (2026-04-04)

**Symptom:** после Bug #414 новый runtime ([log/syslog_2026-04-04_10-58-47.txt](log/syslog_2026-04-04_10-58-47.txt)) сохранил функциональный blocker (`disc_layout FAILED`, повторяющийся `Bug #268`), а параллельно появился свежий panic bundle ([log/panics_2026-04-04_11-00-46/panic-full-2026-04-04-105954.0002.ips](log/panics_2026-04-04_11-00-46/panic-full-2026-04-04-105954.0002.ips)):
- `bug_type: 210`, `Kernel data abort`, panicked task `DarkSword` (pid 440),
- FAR указывает в low-zone metadata region (`0xffffffe0af33b410`),
- по времени совпадает с глубоким fallback chain traversal после неудачного fast-path.

**File:** `darksword/utils.m`

**Root cause:**
- в спекулятивных kernproc walkers (`validate_kernproc_forward_chain`, `validate_kernproc_backward_chain`, `probe_kernproc_backward_pid_offset_for_ourpid`) next/prev переходы принимали слишком широкий класс raw low-zone указателей через `is_in_zone_map`,
- при плохом candidate это позволяло traversal заходить в неустойчивые metadata/служебные области вместо строго proc/data-linked узлов,
- итог — повышенный риск abort при очередном `kread*_ptr` в fallback validation loop.

**Fix:**
- в трёх kernproc chain walkers удалён permissive допуск raw zone-map ptr как самостоятельного критерия next/prev traversal,
- переходы ужесточены до pointer gates на базе `is_heap_ptr_relaxed` и direct-layout data-pointer checks (с сохранением стартового first-node `is_kptr` допуска там, где это нужно),
- тем самым спекулятивные переходы больше не принимают «любой low-zone адрес» без признаков proc/data-chain структуры.

**Expected effect:**
- fallback chain validation должен стать существенно безопаснее на boot'ах с агрессивной zone-map разметкой,
- должен снизиться риск повторного `Kernel data abort` в metadata диапазоне при неуспешном allproc discovery,
- функциональный `disc_layout` blocker остаётся отдельной задачей следующего цикла, но без прежней степени panic-risk во время диагностики.

---

## Bug #414  `Bug #268` forward chain validation зависела от глобального `PROC_NEXT_OFFSET`, из-за чего kernproc-кандидат системно обрывался на `len=11` (2026-04-04)

**Symptom:** свежий runtime ([log/syslog_2026-04-04_10-54-11.txt](log/syslog_2026-04-04_10-54-11.txt)) после Bug #413 всё ещё завершался ранним abort:
- strong candidate `0xfffffff016b9b678` детектился и доходил до `validate_allproc()`,
- `disc_pl` включал weak-score путь (`Bug #400`), но `full chain validation failed`,
- ключевой upstream маркер оставался прежним: `Bug #268: kernproc chain validate: len=11 ... found_ourpid=0`,
- дальше `ERROR: all strategies exhausted` и `ourproc(): 0x0`.

**File:** `darksword/utils.m`

**Root cause:**
- `validate_kernproc_forward_chain()` читал next-link через `proc_list_next_checked_pid()`, который использует глобальный `PROC_NEXT_OFFSET`,
- в момент ранней kernproc-проверки этот global может быть stale/неподходящим для текущего candidate,
- из-за этого даже валидный candidate получал искусственно короткий forward-chain (`len≈11`) и отклонялся до финальной acceptance.

**Fix:**
- `validate_kernproc_forward_chain()` переписан на локальный dual-probe next field:
  - проверяются `next_ff=0x00` и `next_ff=0x08` независимо от глобального `PROC_NEXT_OFFSET`,
  - выбирается лучший результат по приоритету (`found_ourpid` → `chain_len` → `unique_nonzero`),
  - лог теперь показывает `next_ff` для каждого прогона.
- ptr-gates внутри этой валидации выровнены на `is_proc_chain_ptr()`.

**Expected effect:**
- kernproc forward validation больше не будет ложно зависеть от состояния глобального offset-декодера,
- candidate вида `0xfffffff016b9b678` должен либо пройти дальше (reach ourpid / stronger chain), либо дать уже честный downstream reject с корректным `next_ff` telemetry,
- целевой маркер следующего run: исчезновение стабильного `Bug #268 ... len=11` паттерна как финальной причины reject.

---

## Bug #413  `disc_pl` scoring и visible-chain walk всё ещё обрезали proc-chain по `zone_safe_min`, из-за чего реальный `allproc` кандидат застревал на score=9/len=11 (2026-04-04)

**Symptom:** новый runtime ([log/syslog_2026-04-04_10-49-53.txt](log/syslog_2026-04-04_10-49-53.txt)) после Bug #412 уже не ушёл в post-KRW panic, но снова рано остановился на `ourproc()`:
- `socket/tro fast path ... no validated self proc found`
- затем `kernprocaddress()` нашёл сильный кандидат `0xfffffff012dd3678`, который дошёл до `validate_allproc()` и `disc_pl`,
- однако layout discovery не был принят:
  - `Bug #402: allowing far head via BSD backlink ...`
  - `disc_pl ... best_score=9`
  - `disc_layout FAILED ...`
  - `ERROR: all strategies exhausted, allproc not found`
- run завершился `PANIC GUARD: ourproc() failed (0x0)`.

**File:** `darksword/utils.m`

**Root cause:**
- Bug #403/#404 уже перевели строгие proc-chain validators на `is_in_zone_map()` / `is_proc_chain_ptr()`,
- но вспомогательные pre-validation paths всё ещё использовали старый heap-only gate:
  - `score_proc_chain_ex()` — loop condition и `next` check через `is_heap_ptr_relaxed`,
  - `discover_proc_list_layout()` — candidate `next` gate через `is_heap_ptr_relaxed`,
  - `walk_proc_chain_for_pid()` — visible-chain walk для `ourpid` всё ещё мог обрываться на boot'ах, где ранние kernel-thread `proc` лежат ниже `zone_safe_min`.
- в результате реальная proc-chain снова обрезалась на раннем kernel-thread префиксе, candidate недобирал score и даже не доходил до полной validation-фазы.

**Fix:**
- `score_proc_chain_ex()` переведён на unified `is_proc_chain_ptr()` для `cur` и `next`.
- `discover_proc_list_layout()` теперь принимает `next` через `is_proc_chain_ptr()` в обеих scoring phases.
- `walk_proc_chain_for_pid()` переведён на `is_proc_chain_ptr()` для current/next proc pointers.

**Expected effect:**
- `disc_pl` больше не должен искусственно занижать score сильного BSD-backlink кандидата из-за low-zone-map kernel-thread proc entries,
- candidate уровня `0xfffffff012dd3678` должен либо набрать достаточно score для полной validation, либо дать уже downstream reject после настоящего полного chain walk,
- следующий run должен показать либо `proc list layout ... -> FOUND!`, либо более узкий residual blocker уже после принятия layout, а не ранний `allproc not found`.

---

## Bug #412  `kfs_init()` после успешного KRW повторно заходил в `procbyname()->kernprocaddress()->allproc` и снова трогал опасный proc-discovery path (2026-04-04)

**Symptom:** свежий runtime (`log/syslog_2026-04-04_10-39-48.txt`) доказал, что основной exploit уже проходит критическую точку:
- `returned from ourproc(): 0xffffffde2218f1f8`
- `returned from ourtask(): 0xffffffde2218f210`
- `Kernel R/W achieved!`
- сразу после этого, уже внутри `kfs_init`, syslog снова показывает `enter kernprocaddress`, а затем позднее возникают `getsockopt failed (early_kread)!` и kernel panic из `proc_task` zone (`buffer length 32`).

**File:** `darksword/kfs.m`

**Root cause:**
- `kfs_init()` вызывал `find_procs()`, а тот искал `launchd` через `procbyname("launchd")`,
- `procbyname()` всегда заходит в `kernprocaddress()` и может повторно запускать `allproc` discovery / proc walk, хотя к этому моменту `our_proc` уже подтверждён самим exploit'ом,
- на свежем runtime это создавало лишний post-KRW re-entry в нестабильный proc-discovery path и коррелировало с последующим `early_kread` degradation / `proc_task` zone panic.

**Fix:**
- в `find_procs()` поиск `launchd` переведён на безопасный приоритет:
  - сначала bounded PID-walk от уже известного `g_our_proc` к `pid=1`,
  - `procbyname("launchd")` оставлен только как last-resort fallback.
- в `kfs_init()` при валидных `proc/task` из exploit сразу кэшируется `g_our_proc`, чтобы downstream code reuse'ил уже подтверждённый self-proc.

**Expected effect:**
- после `Kernel R/W achieved!` `kfs_init` больше не должен без необходимости повторно заходить в `kernprocaddress()` на нормальном hot-path,
- уменьшается шанс post-success `early_kread` regression и повторного unsafe proc-discovery доступа перед `rootvnode`/`ncache` фазой,
- следующий runtime должен либо пройти дальше по `kfs_init`, либо показать уже более узкий residual blocker без повторного `enter kernprocaddress` сразу после старта `kfs`.

---

## Bug #411  `socket/tro` fast path дошёл до `thread`, но упирался в слишком узкий набор `thread->tro` offset'ов (2026-04-04)

**Symptom:** после Bug #410 свежий runtime (`log/darksword_log.txt`, Date `10:37:05`) показал явный прогресс:
- `socket_off=0x40`
- `bg_candidates=29`
- `thread_zero_reads=18`
- `thread_rejects=3`
- но новый blocker сместился на `tro`-стадию:
  - `tro_rejects=23`
  - `proc_rejects=0`, `pid_misses=0`, то есть fast-path не доходил до `proc/pid` proof.

**File:** `darksword/utils.m`

**Root cause:**
- bounded scan для `socket->thread` нашёл более правдоподобные thread-кандидаты,
- однако список `thread_tro_offs` оставался жёстко ограниченным (`0x360/0x368/0x370/0x378`),
- на текущем boot-layout реальные `tro`-ссылки, вероятно, смещены внутри соседнего окна и потому системно отбрасываются как non-pointer.

**Fix:**
- `thread->tro` discovery расширен bounded scan-окном:
  - known offsets сохранены,
  - добавлен fallback scan по `0x320..0x3b0` с шагом `0x8` и dedup.
- добавлена detail-telemetry для TRO стадии:
  - `tro_candidates`, `tro_read_failures`, `tro_zero_reads`,
  - лог последнего rejected `tro` (`tro_off/raw/stripped`).

**Expected effect:**
- если правильный `tro` offset лежит в соседнем bounded-окне, fast-path должен впервые дойти до `proc/pid` стадии или дать `SUCCESS`,
- если даже widened scan даёт только non-pointer/zero значения, следующий run уже даст точный `tro`-stage root-cause без двусмысленности.

---

## Bug #410  `socket/tro` fast path полагался на слишком узкий набор `so_bg_thread*` offset'ов и на этом boot видел только нули (2026-04-04)

**Symptom:** после Bug #409 новый runtime (`log/syslog_2026-04-04_10-29-33.txt`) уже подтвердил правильный `socket`-stage:
- `socket_off=0x38 socket_ptr_rejects=1 ...`
- паттерн `thread=0x300` исчез,
- но fast-path всё ещё не проходил дальше, так как все thread reads на известных offset'ах сводились к `0x0`:
  - `thread_rejects=5`, `last raw=0x0 stripped=0x0`.

**File:** `darksword/utils.m`

**Root cause:**
- Bug #409 устранил ложный `pcb->socket`, но текущий boot-layout всё ещё не совпадает с жёстким списком `so_bg_thread*` смещений (`0x2a0..0x2c0`),
- в результате fast-path смотрит в правильный `socket`, но в неправильные поля внутри него и получает нули вместо `thread` pointer.

**Fix:**
- набор `socket->thread` кандидатов расширен bounded-scan окном:
  - known offsets сохранены,
  - добавлен fallback scan по `0x240..0x320` с шагом `0x8` и dedup.
- thread-stage telemetry расширен:
  - `bg_candidates`, `thread_read_failures`, `thread_zero_reads`, `last bg=...`.
- thread gate слегка расширен до `is_kptr(thread)` в дополнение к `is_heap_ptr_relaxed/thread_in_zone_map`.

**Expected effect:**
- если реальный `so_bg_thread*` смещён внутри bounded-окна, fast-path дойдёт до `tro/proc/pid` и даст новый downstream root-cause или `SUCCESS`,
- если даже расширенный scan даёт только нули, следующий лог уже однозначно подтвердит, что `socket/tro` путь на этом boot требует не offset broadening, а альтернативный источник `thread`/`task`.

---

## Bug #409  `socket/tro` fast path читал `socket` только по одному `pcb+0x40`, что давало ложный `thread=0x300` и блокировало всю ветку (2026-04-04)

**Symptom:** после Bug #408 свежий runtime (`log/syslog_2026-04-04_10-23-19.txt`) показал:
- `[ourproc] socket/tro fast path stats: thread_rejects=5 ...`
- `rejected 5 thread pointers ... (last raw=0x300 stripped=0x300)`
- при этом `tro/proc/pid` стадии не запускались (`tro_rejects=0`, `pid_misses=0`).

**File:** `darksword/utils.m`

**Root cause:**
- fast-path брал `socket` только из одного смещения `pcb_socket_offset=0x40`,
- на текущем boot это смещение может указывать не на реальный `struct socket`, а на соседнее поле/невалидный view,
- в результате чтение `so_bg_thread*` возвращало tiny sentinel (`0x300`), и thread-gate детерминированно отбрасывал все кандидаты.

**Fix:**
- в `find_self_proc_via_socket_tro()` добавлен multi-offset выбор `socket` из `pcb`:
  - кандидаты смещений: `0x40, 0x38, 0x30, 0x48, 0x50, 0x28`.
- для каждого `socket_candidate` добавлен pre-probe `so_bg_thread*`:
  - если все ненулевые thread-read значения tiny (`< 4GB`) и ни один не pointer-like, кандидат отвергается как ложный.
- добавлена telemetry по socket-stage:
  - `socket_ptr_rejects`, `socket_read_failures`, `socket_off=...`,
  - отдельный лог `no usable socket candidate ... last raw/stripped ...`.
- success-log дополнен выбранным `pcb_soff`.

**Expected effect:**
- уйдёт ложный паттерн `thread=0x300` на неверном `pcb`-offset,
- fast-path дойдёт до `tro/proc/pid` стадий либо даст ранний диагностический `no usable socket candidate` с причинами,
- увеличится шанс раннего `socket/tro fast path SUCCESS` без перехода в unstable allproc path.

---

## Bug #408  socket/TRO fast path преждевременно отбрасывал `rw_socket_pcb` как unavailable на boot с low zone_map адресом (2026-04-04)

**Symptom:** в новом runtime (`log/syslog_2026-04-04_10-18-33.txt`) fast-path сразу завершался:
- `[ourproc] socket/tro fast path: rw_socket_pcb unavailable (0xffffffdec49dc400)`
- то есть path не доходил даже до чтения `socket`/`thread`.

**File:** `darksword/utils.m`

**Root cause:**
- pre-gate для `rw_pcb` использовал только `is_heap_ptr_relaxed(rw_pcb)`,
- адрес `0xffffffdec49dc400` лежит в валидном kernel/zone_map диапазоне, но ниже `zone_safe_min`, поэтому false-negative и мгновенный abort fast-path.

**Fix:**
- расширен `rw_pcb` gate в `find_self_proc_via_socket_tro()`:
  - `rw_pcb_ok = rw_pcb && (is_heap_ptr_relaxed(rw_pcb) || is_in_zone_map(rw_pcb) || is_kptr(rw_pcb))`

**Expected effect:**
- fast-path перестаёт отваливаться на входе,
- в следующем run должны появиться downstream маркеры (`thread/tro/proc/pid`) или `socket/tro fast path SUCCESS`.

---

## Bug #407  socket/TRO fast path застревал на `thread` gate (`thread_rejects=5`) и не доходил до TRO/PROC стадии (2026-04-04)

**Symptom:** свежий runtime (`log/syslog_2026-04-04_10-14-35.txt`) после Bug #406 дал:
- `[ourproc] socket/tro fast path stats: thread_rejects=5 tro_rejects=0 proc_rejects=0 pid_misses=0 task_proof_misses=0`
- это означает, что fast-path отбрасывал все `socket->so_bg_thread*` указатели на первой же проверке и ни разу не дошёл до `tro/proc/pid`.

**File:** `darksword/utils.m`

**Root cause:**
- thread pointer gate оставался на `is_heap_ptr_relaxed(thread)` (зависимость от `zone_safe_min`),
- как и ранее для proc-chain, часть валидных kernel объектов может быть ниже `zone_safe_min`, но внутри `zone_map`.

**Fix:**
- расширен thread gate в `find_self_proc_via_socket_tro()`:
  - `thread_ok = is_heap_ptr_relaxed(thread) || is_in_zone_map(thread)`
- добавлен detail-лог по thread reject:
  - count + `last raw/stripped` rejected thread pointer.

**Expected effect:**
- fast-path должен пройти минимум до TRO/PROC стадии (ненулевые `tro_rejects` или `pid_misses`),
- а при удаче дать `socket/tro fast path SUCCESS` и обойти unstable allproc path.

---

## Bug #406  socket/TRO fast path оставался «чёрным ящиком» и мог отсекать валидный `tro` pointer (2026-04-04)

**Symptom:** после Bug #405 свежий runtime (`log/syslog_2026-04-04_10-11-20.txt`) всё ещё показывал:
- `[ourproc] socket/tro fast path: no validated self proc found`
- далее повторный fail-path (`Bug #291 chain=11`, `Bug #303 reject`, `all strategies exhausted`, `PANIC GUARD`).

**File:** `darksword/utils.m`

**Root cause:**
- в `find_self_proc_via_socket_tro()` проверка `tro` была слишком узкой (`is_kptr(tro)`),
- при этом в логах не было stage-telemetry, поэтому невозможно было понять, на каком именно gate fast path «ломается» (thread/tro/proc/pid/task-proof).

**Fix:**
- расширен gate для `tro`:
  - `is_kptr(tro) || is_in_zone_map(tro) || is_heap_ptr_relaxed(tro)`
- добавлена подробная статистика fast-path на каждом run:
  - `thread_rejects`, `tro_rejects`, `proc_rejects`, `pid_misses`, `task_proof_misses`
- сохранён/дополнен лог `proc`-reject с последним `raw/stripped` адресом.

**Expected effect:**
- уменьшить ложные отбрасывания валидного `tro`/`proc` пути,
- получить детерминированный root-cause в следующем syslog даже если fast-path снова не даст selfproc.

---

## Bug #405  `ourproc` socket/TRO fast path отбрасывал валидный `proc` в нижней части zone_map (2026-04-04)

**Symptom:** в свежем runtime (`log/syslog_2026-04-04_10-06-35.txt`) перед вызовом `kernprocaddress()` fast path стабильно возвращал:
- `[ourproc] socket/tro fast path: no validated self proc found`
- дальше run уходил в старый fail-path: `Bug #291 chain=11`, `Bug #303 rejecting candidate`, `all strategies exhausted`, `PANIC GUARD`.

**File:** `darksword/utils.m`

**Root cause:**
- в `find_self_proc_via_socket_tro()` проверка `proc_ok` принимала только
  `is_heap_ptr_relaxed(proc) || is_kernel_data_ptr(proc)`
- как и в Bug #403/#404, часть реальных proc-объектов может лежать в валидной zone_map-области ниже `zone_safe_min`; такие указатели тихо отбрасывались, и fast path не доходил до PID-proof.

**Fix:**
- расширен ptr-gate в fast path:
  - `proc_ok = is_heap_ptr_relaxed(proc) || is_in_zone_map(proc) || is_kernel_data_ptr(proc)`
- добавлена лёгкая telemetry-диагностика для этой ветки:
  - счётчик отклонений `proc_ptr_rejects`
  - лог последнего rejected `proc_raw/stripped`.

**Expected effect:**
- `ourproc()` чаще будет резолвиться через socket/TRO fast path без полного allproc discovery,
- уменьшается вероятность повторного safe-abort цикла (`kernprocaddress()=0`) на бут-конфигурациях, где `proc` находится ниже `zone_safe_min`, но внутри zone_map.

---

## Bug #404  `direct_v2`/`Bug #291` всё ещё обрывались на `len=11` из-за `is_heap_ptr_relaxed` и лимита chain=64 (2026-04-04)

**Symptom:** после Bug #403 свежий runtime (`log/darksword_log.txt`, PID=506) продолжил показывать:
- `Bug #291: ... chain=11 ... found_ourpid=0`
- `Bug #268: kernproc chain validate: len=11 ... found_ourpid=0`
- `Bug #303: rejecting candidate 0xfffffff021683678 despite le_prev back-reference`

**File:** `darksword/utils.m`

**Root cause:**
- в `validate_proc_chain_with_pid_off()` цикл и next-check всё ещё использовали только `is_heap_ptr_relaxed` (zone_safe_min), поэтому walk рвался на ранних kthread-proc ниже safe_min
- в `Bug #291` probe цепочка была жёстко ограничена `64` узлами (`chain_procs[64]`, `probe_seen[64]`, `for i<64`) — недостаточно для достижения текущего user PID в длинной allproc

**Fix:**
- добавлен unified predicate `is_proc_chain_ptr()`:
  - `is_heap_ptr_relaxed(p)` **или** `is_in_zone_map(p)` **или** (`g_direct_layout_set && is_kernel_data_ptr(p)`)
- `validate_proc_chain_with_pid_off()` переведён на `is_proc_chain_ptr()` для `cur` и `next`
- `Bug #291` probe расширен:
  - `chain_procs[64] -> [512]`
  - `probe_seen[64] -> [512]`
  - loop depth `i < 64 -> i < 512`
  - ptr-check в probe также на `is_proc_chain_ptr()`

**Expected effect:**
- direct/probe chain больше не залипает на 11 шагах
- `Bug #291` получает шанс дойти до ourpid в длинной allproc
- снимается ложный reject по `Bug #303` для confirmed `proc0.le_prev == candidate`

---

## Bug #403  `validate_kernproc_forward_chain` использует `is_heap_ptr_relaxed` (zone_safe_min) — walk прерывается на 11 записях, не достигая ourpid (2026-04-04)

**Symptom:** во всех run после Bug #397 forward chain останавливается на `len=11`, `found_ourpid=0` — `Bug #268: kernproc chain validate: len=11 unique_nonzero=2 found_ourpid=0 pid_off=0xd8`. Даже при подтверждённом `proc0.le_prev == candidate 0xfffffff02378f678` кандидат отклоняется с `Bug #303: rejecting candidate ... chain remained non-user-visible`.

**File:** `darksword/utils.m`

**Root cause:**
- `is_heap_ptr_relaxed` проверяет `addr >= zone_safe_min = 0xffffffe1619bc000`
- ранние kernel-thread proc struct'ы (kthread #12+) созданы в нижнем GEN0-регионе zone_map, ниже `zone_safe_min`
- loop в `validate_kernproc_forward_chain` прерывается при первом kthread-proc ниже `zone_safe_min` → chain=11
- ourpid=440 находится в записи #100+ в allproc — далеко за пределами 11 шагов
- Bug #397 (поднял нижнюю границу до zone_safe_min) решил panic-проблему, но сломал chain-walk через ранние kthread

**Fix:**
- добавлена `is_in_zone_map()` — вариант без `zone_safe_min`: принимает `[zone_map_min, zone_map_max - 4MB)`, применяется ТОЛЬКО для подтверждённых chain-walk (не для спекулятивного сканирования)
- в `validate_kernproc_forward_chain` ptr_ok расширен: `is_in_zone_map(cur) || is_heap_ptr_relaxed(cur) || (i==0 && is_kptr(cur))`
- то же исправление в `validate_kernproc_backward_chain` (ptr_ok и prev-check) и в `probe_kernproc_backward_pid_offset_for_ourpid`
- в `normalize_proc_link_target_with_pid` добавлен `|| is_in_zone_map(cand)` к ptr_ok

**Safety:**
- все kreads внутри chain walk используют `kread*_checked_local`: нечитаемая страница безопасно завершает walk без паники
- `is_in_zone_map` сохраняет ZONE_TOP_GUARD (4MB) для исключения per-CPU-region, как в `is_heap_ptr`
- `is_in_zone_map` **не** применяется ни в каком спекулятивном пути — только для walk от confirmed proc0

**Expected effect:**
- walk идёт через kthread #12, #13 ... до entry ~100 и находит ourpid=440 → `found_ourpid=true` → chain_ok=true
- `Bug #303` принимает кандидат `0xfffffff02378f678` как allproc
- `Bug #372` перестаёт перехватывать кандидаты с confirmed le_prev backref (validation теперь проходит)
- следующий run должен показать `KERNPROC detected at 0xfffffff02378f678`

---

## Bug #402  `validate_allproc()` допускает ограниченный far-head только при подтверждённом BSD-backlink на `allproc_addr` (2026-04-04)

**Symptom:** в run `syslog_2026-04-04_09-30-28.txt` новые XPF-lite кандидаты системно отклонялись на раннем `Bug #398` distance-gate как far-head, и поиск завершался `allproc not found` без входа в глубокую layout-валидацию.

**File:** `darksword/utils.m`

**Root cause:** фиксированный лимит `3GB` в `Bug #398` оказался слишком жёстким для части boot-layout'ов: потенциально валидные head-кандидаты с корректной структурной сигнатурой могли отсеиваться до `discover_proc_list_layout()`.

**Fix:**
- добавлен `Bug #402` guarded-exception в `validate_allproc()`:
  - если `abs(head-rw_socket_pcb) > 3GB`, кандидат обычно reject,
  - **исключение** только когда `pac_strip(*(head+0x08)) == allproc_addr` (BSD `LIST_HEAD` backlink) и `diff <= 8GB`.
- при таком исключении кандидат продолжает стандартный safe-пайплайн (структурные guards + layout/chain валидации), иначе остаётся прежний reject.

**Expected effect:**
- вернуть в обработку часть потенциально валидных XPF-lite head-кандидатов, не ослабляя глобально anti-panic фильтрацию,
- сохранить panic-safe поведение за счёт строгого backlink-условия и прежних downstream валидаторов.

---

## Bug #401  `validate_allproc()` добавлен BSD-head recovery fallback после partial reject для interior `list_off` (2026-04-04)

**Symptom:** в свежем run (`syslog_2026-04-04_09-26-20.txt`) Bug #400 активировался, но `allproc` всё равно не принимался: сильный кандидат (`score=50`, `list_off=0xb0`) стабильно отбрасывался `Bug #394` как partial (`max_pid=219 < ourpid=460`).

**File:** `darksword/utils.m`

**Root cause:** часть кандидатов показывает mixed/interior list geometry (`list_off!=0`) и может пройти score/full-chain на этой геометрии, но visible-chain gate для `ourpid` там оказывается усечённым. При этом у такого `firstproc` может быть BSD `LIST_HEAD` сигнатура (`firstproc+0x08 == allproc_addr`), которую текущий путь не пытается использовать как recovery.

**Fix:**
- после miss в `Bug #394` добавлен `Bug #401` fallback:
  - если `PROC_LIST_OFFSET != 0` и `pac_strip(*(firstproc+0x08)) == allproc_addr`,
  - выполняется bounded walk на BSD-геометрии (`list_off=0x0`, `next_off=0x0`) для текущего и alternate `pid_off`,
  - acceptance только если найден `ourpid` **и** проходит `validate_proc_chain_with_pid_off(firstproc, 0x0, pid_off, 200)`.
- при success коммитятся `PROC_LIST_OFFSET=0`, `PROC_NEXT_OFFSET=0`, `PROC_PREV_OFFSET=8`, `PROC_PID_OFFSET=validated_pid_off`.

**Expected effect:**
- уменьшить ложные `partial allproc` reject для кандидатов с корректной BSD-head сигнатурой,
- сохранить safety, так как fallback принимает candidate только при явном reach до `ourpid` и полной chain-валидации.

---

## Bug #400  near-`rw_socket_pcb` weak-score gate в `discover_proc_list_layout()` расширен до score>=6 при обязательной full-chain валидации (2026-04-04)

**Symptom:** после Bug #399 run оставался panic-free, но в свежем syslog не появлялся telemetry-маркер weak-score path; `allproc` по-прежнему не находился и сессия завершалась через `PANIC GUARD`.

**File:** `darksword/utils.m`

**Root cause:** near-ветка с порогом `score>=9` оставалась слишком узкой для части реалистичных кандидатов около `rw_socket_pcb`; такие кандидаты не доходили до строгой `validate_proc_chain_with_pid_off()`.

**Fix:**
- в `discover_proc_list_layout()` добавлен `PROC_NEAR_PCB_MIN_SCORE = 6` (вместо фактического порога `9` для near-ветки),
- near-path включается при `best_score>=6` и `abs(best_base-rw_socket_pcb)<=3GB`,
- acceptance по-прежнему происходит **только** после успешной `validate_proc_chain_with_pid_off(...)` (safety gate сохранён),
- telemetry обновлён на явный маркер `Bug #400` с выводом `min`-порога.

**Expected effect:**
- снизить false-negative в `disc_pl` для близких кандидатов со score в диапазоне `6..8`,
- сохранить panic-safe профиль, так как weak-score путь не bypass'ит full-chain проверку.

---

## Bug #399  `discover_proc_list_layout()` не должен отбрасывать near-`rw_socket_pcb` кандидаты только из-за score<20 до full-chain проверки (2026-04-04)

**Symptom:** после Bug #398 run стал panic-free, но часть перспективных head-кандидатов около рабочей exploit-области завершалась на `disc_pl NO MATCH` при `best_score` ниже порога `20`, и `allproc` так и не находился.

**File:** `darksword/utils.m`

**Root cause:** в `discover_proc_list_layout()` жёсткий pre-threshold `best_score >= 20` применялся до `validate_proc_chain_with_pid_off()`. Это отбрасывало потенциально валидные кандидаты, даже если они были пространственно близки к `rw_socket_pcb` и могли пройти строгую chain-валидацию.

**Fix:**
- добавлен near-`rw_pcb` weak-score path (`Bug #399`):
  - если `best_base` в пределах `3GB` от `rw_socket_pcb` и `best_score >= 9`,
  - допускается переход к полной валидации (`validate_proc_chain_with_pid_off`) при lowered pre-threshold `9`.
- safety сохранён: acceptance всё равно происходит **только** при успешной full-chain проверке.

**Expected effect:**
- уменьшение false-negative в `disc_pl` на близких к реальной зоне кандидатах,
- без возврата к unsafe-acceptance, так как слабый score сам по себе не принимается без full-chain успеха.

---

## Bug #398  Жёсткий proximity-gate к `rw_socket_pcb` для allproc-head кандидатов, чтобы не заходить в ложные дальние цепочки (2026-04-04)

**Symptom:** после серии panic с `zone bound checks: ... per-cpu allocation` текущий runtime часто выходил на ложные `allproc`/`kernproc` head-кандидаты далеко от рабочей exploit-области (`rw_socket_pcb`), что повышало риск опасных deref в неверных регионах.

**File:** `darksword/utils.m`

**Root cause:** даже при `heap/relaxed` фильтрах часть кандидатов оставалась структурно правдоподобной, но находилась слишком далеко от подтверждённого `rw_socket_pcb`, из-за чего валидация могла уйти в токсичный путь.

**Fix:**
- введён proximity-limit `PROC_NEAR_PCB_MAX_DIFF = 0xC0000000` (3GB)
- в `validate_allproc()` добавлен ранний reject для head-кандидатов, у которых `abs(head - rw_socket_pcb) > 3GB`
- в pre-filter scan-пути порог ужесточён с `16GB` до `3GB`
- добавлена telemetry с маркером `Bug #398` для явной диагностики rejected дальних head-адресов

**Validation (runtime 2026-04-04 09:12:40):**
- panic-файлов после запуска не появилось
- в syslog есть многократные срабатывания `Bug #398: rejecting far head=...`
- run завершился безопасно через `PANIC GUARD` (`ourproc() failed`, `allproc not found`), без kernel panic

**Expected effect:**
- снижение риска возврата к panic-классу `per-cpu allocation`/опасным deref при allproc discovery
- перевод невалидных кандидатов в безопасный fail-path (`panic-guard abort`) вместо kernel panic

---

## Bug #397  `is_heap_ptr_relaxed()` допускал sparse lower-GEN0 адреса, что снова приводило к translation-fault panic через Zone Metadata (2026-04-04)

**Symptom:** после деплоя Build 49 появился новый panic другого класса:
- panicString: `Kernel data abort. ... esr: 0x96000007`
- `far: 0xffffffdc13b4a280`
- panicked task: `DarkSword` (pid 491)
- таймлайн: panic во время `Bug #372` forward-chain validation (allproc/kernproc path)

**File:** `darksword/utils.m`

**Root cause:**
- `is_heap_ptr_relaxed()` использовал диапазон `[zone_map_min, zone_map_max)`
- на этом boot candidate вроде `0xffffffde0b120000` формально проходил relaxed-check (aligned, в range)
- но страница была sparse/unallocated; при `copyout` kernel полез в Zone Metadata entry
- metadata address (`FAR`) попал в region `0xffffffdc13774000..0xffffffdc14f74000`, где страница не была замаплена
- итог: translation fault L3 (`ESR 0x96000007`) и panic

**Fix:**
- в `is_heap_ptr_relaxed()` нижняя граница переведена с `zone_map_min` на `zone_safe_min`
- теперь relaxed-path также пропускает только `[zone_safe_min, zone_map_max)`
- fallback на raw `zone_map_min` оставлен только для ранней фазы до вычисления safe bounds

**Expected effect:**
- chain validation больше не должна дёргать sparse lower-GEN0 страницы,
- должны исчезнуть panic класса `Kernel data abort` с `FAR` в Zone Metadata во время allproc walk.

---

## Bug #396  `is_heap_ptr()` должен отрезать верхний tail zone-map, чтобы не трогать per-cpu allocations (2026-04-04)

**Symptom:** после Bug #395 resolver снова дошёл до `__DATA.__bss_allproc` scan, но свежий runtime упал в kernel panic:
- panicString: `zone bound checks: address ... is a per-cpu allocation`
- panicked task: `DarkSword` (pid 473)
- по таймлайну panic совпал с фазой чтения scan chunks в `__bss_allproc`.

**File:** `darksword/utils.m`

**Root cause:** текущий heap-filter допускал адреса почти до самого `zone_map_max`. На этом boot верхняя часть zone-map может содержать per-cpu allocation region, и blind `kread` по таким "почти-валидным" адресам провоцирует zone-bound panic.

**Fix:**
- в `is_heap_ptr()` добавлен верхний guard `ZONE_TOP_GUARD = 0x400000` (4MB)
- верхняя граница acceptance теперь `zmax - 0x400000` вместо `zmax`
- guard применён и в safe-path (при валидных `zone_map_min/max`), и в fallback-path (когда используются эвристические bounds)

**Expected effect:** scanner перестанет принимать адреса из опасного верхнего tail zone-map, что должно снизить риск повторного panic класса `per-cpu allocation` во время allproc discovery.

---

## Bug #395  safe `__DATA.__bss` scan должен покрывать нижние boot-specific кандидаты около `0x3213678/0x3213680` (2026-04-04)

**Symptom:** после Bug #394 false partial `allproc` больше не принимался, но свежий runtime стал заканчиваться слишком рано:
- `kernprocaddress() returned 0x0`
- `ERROR: all strategies exhausted, allproc not found`

при этом XPF-lite перед fallback'ом уже видел heap-like кандидаты в нижней части `__DATA.__bss`:
- `kbase+0x3213678`
- `kbase+0x3213680`

но стандартный inner DATA scan начинался только с `kbase+0x3218000`, то есть эта зона вообще не попадала в scan window.

**File:** `darksword/utils.m`

**Root cause:** `scan_allproc_known_range()` использовал слишком узкое и слишком позднее окно для `__DATA.__bss_allproc` (`0x321c000..0x322c000`). Исторический boot с `0x321c4xx` оно покрывало, но новый boot показал смещение полезных кандидатов ниже примерно на `0x4a00`.

**Fix:**
- `__DATA.__bss_allproc` safe scan расширен вниз:
  - **было:** `start=0x321c000 size=0x10000`
  - **стало:** `start=0x3213000 size=0x18000`
- теперь default scan покрывает и историческую область `0x321c4xx`, и новые boot-specific offsets `0x3213678/0x3213680`
- Mach-O parse scan по-прежнему не включается и не требуется для этого расширения

**Expected effect:** resolver должен снова видеть реальные/почти-реальные `allproc` candidates из нижней части `__bss` без возврата к опасному broad scan.

---

## Bug #394  `validate_allproc()` не должен принимать partial `allproc`, если visible chain не достигает `ourpid` и обрывается ниже него (2026-04-04)

**Symptom:** после Bug #393 panic исчез, но новый runtime всё ещё принимал scan candidate `0xfffffff02381c500` как `allproc`:
- `DATA scan found allproc at 0xfffffff02381c500`
- `proc list layout ... list_off=0xb0 pid_off=0xd8 ... -> FOUND!`

затем `ourproc()` проходил только частичную user-visible цепочку и останавливался на:
- `NOT FOUND after 271 iterations (our pid=479, max_pid_seen=368)`

после чего candidate приходилось blacklist'ить уже постфактум в `ourproc()` (`Bug #377`).

**File:** `darksword/utils.m`

**Root cause:** `validate_allproc()` принимал candidate после `discover_proc_list_layout()` + `validate_proc_chain()`, но не проверял, достигает ли уже принятый layout реально текущего процесса. Из-за этого partial `allproc` с хорошим score/diversity, но усечённой цепочкой до `max_pid_seen < ourpid`, мог проходить в success-path и падать только позже.

**Fix:**
- после успешного `validate_proc_chain()` добавлен Bug #394 visible-chain gate
- validator теперь делает прямой walk через `walk_proc_chain_for_pid()` к `ourpid`
- если основной `pid_off` не даёт `ourpid`, дополнительно пробуется alternate `pid_off` (`0xd8 <-> 0x60`)
- candidate отклоняется, если обе проверки не находят `ourpid`, а видимая цепочка остаётся частичной (`max_pid_seen < ourpid`)
- если alternate `pid_off` действительно доходит до `ourpid`, он принимается и коммитится обратно в `PROC_PID_OFFSET`

**Expected effect:** partial `allproc` candidates типа `0x321c500`, которые видят только раннюю часть user chain и потом обрываются, будут отсеиваться ещё в resolver'е, без позднего blacklist/retry в `ourproc()`.

---

## Bug #393  `direct_v2` не должен принимать kernel-only PID=0 chain по shortcut (2026-04-04)

**Symptom:** в свежем runtime `direct_v2` давал ранний success:
- `direct_v2 SUCCESS: iOS 17 kernel chain detected (list=0x0 pid=0x60)`

после чего `ourproc()` шёл по `pid=0`/zombie-heavy path и сессия заканчивалась panic (`zone bound checks`, panicked task `DarkSword`).

**File:** `darksword/utils.m`

**Root cause:** в `validate_direct_allproc_v2_with_layout()` оставался shortcut acceptance для kernel-only цепочки (`first_pid=0`, `max_pid_seen=0`) при `list_off=0x00` и `pid_off=0x60`. На build `21D61` этот shortcut даёт ложный lock-in на не-user-visible chain.

**Fix:**
- shortcut acceptance для kernel-only chain отключён
- такие candidates теперь явно логируются как отклонённые (`Bug #393: kernel-only chain rejected`)
- принятие direct_v2 теперь требует только:
  - реальную PID-diversity в основном walk, **или**
  - явное подтверждение через PID-probe ветку (`Bug #291`)

**Expected effect:** `direct_v2` больше не будет prematurely lock-in на zero-only цепочке; resolver продолжит поиск более корректного head-кандидата и должен уменьшить риск повторного `ourproc` crash-path.

---

## Bug #392  `discover_proc_list_layout()` не должен коммитить `FOUND`/`PID offset switch` до полного chain-validate (2026-04-04)

**Symptom:** в свежем runtime лог появлялся как будто успешный layout:
- `proc list layout ... score=25 -> FOUND!`
- `switching PID offset 0xd8 -> 0x60`

но в конце той же попытки всё равно было:
- `ERROR: all strategies exhausted, allproc not found`
- `kernprocaddress() returned 0x0`

**File:** `darksword/utils.m`

**Root cause:** `discover_proc_list_layout()` принимал candidate только по score (`best_score >= 20`) и сразу коммитил глобальные `PROC_LIST_OFFSET/PROC_PID_OFFSET`, хотя полный критерий real allproc (длинная user-visible chain через `validate_proc_chain_with_pid_off`) мог не пройти. Это давало ложный промежуточный `FOUND` и потенциально отравляло последующие проверки сменой PID offset.

**Fix:**
- перед коммитом `FOUND` добавлен обязательный full-check:
  `validate_proc_chain_with_pid_off(best_base, best_off, best_pid_off, 200)`
- если full-check не проходит, candidate отклоняется (`[disc_pl] REJECT: ...`) и глобальные offsets **не** переключаются
- `FOUND` и `switching PID offset ...` теперь происходят только после полного chain-validate

**Expected effect:** больше не будет ложных `layout FOUND` без реального принятия `allproc`; scan-путь станет детерминированнее и не будет менять глобальный `PROC_PID_OFFSET` на неподтверждённом кандидате.

---

## Bug #391  `validate_direct_allproc_v2_with_layout()` не должен жёстко читать `p_pid` только по `+0x60` (2026-04-04)

**Symptom:** после Bug #390 ложный partial-legacy path исчез, но свежий runtime всё равно завершился на `kernprocaddress() == 0`:
- direct candidate `0x321C480` больше не lock-in'ится ошибочно
- однако `direct_v2` по нему не даёт success-path вообще
- при этом `detect_kernproc_variable()` на том же candidate видит `pid=0` по trusted `+0xD8`, а по `+0x60` там мусор

**File:** `darksword/utils.m`

**Root cause:** `validate_direct_allproc_v2_with_layout()` всё ещё был захардкожен на `p_pid @ +0x60` для первого proc и для всего chain walk. На текущем build `21D61` trusted runtime offset — `0xD8`, поэтому real candidate мог отбрасываться ещё до chain logging / acceptance.

**Fix:**
- `direct_v2` теперь выбирает `pid_off` через `build_pid_offset_candidates()`
- приоритет сохраняется у trusted `PROC_PID_OFFSET` (`0xD8` на `21D61`), затем пробуется alternate offset
- выбранный `pid_off` используется и для first-proc validation, и для всего chain walk, и при success-path записывается обратно в `PROC_PID_OFFSET`

**Expected effect:** реальный direct candidate типа `0x321C480` больше не должен теряться только потому, что на этом boot `+0x60` не является валидным `p_pid`; следующий runtime должен либо получить `direct_v2 SUCCESS`, либо как минимум дать честную chain telemetry уже под `pid_off=0xD8`.

---

## Bug #390  legacy `validate_allproc()` не должен принимать mixed-head candidate, где `disc_pl` выбирает interior `list_off`, а сам `proc0` уже выглядит как BSD `allproc` head (2026-04-04)

**Symptom:** после Bug #389 старый ложный `0x321C400` lock-in исчез, но свежий runtime всё ещё принимал `kbase+0x321C480` через legacy path:
- `disc_pl` выбирал `list_off=0xb0`, `score=50`
- затем `ourproc()` шёл по цепочке только до `max_pid_seen=215 < ourpid=483`
- у `proc0` одновременно были признаки BSD head на `+0x00/+0x08`, а выбранный `prev` для `+0xb0` был `0x10`

**File:** `darksword/utils.m`

**Root cause:** phase2 в `discover_proc_list_layout()` мог выиграть на внутреннем proc-sublist (`list_off=0xb0`), хотя тот же `proc0` уже показывал BSD-head signature (`p_list.le_prev == allproc`). Legacy validator после этого принимал candidate только по score/diversity, не проверяя, что выбранный interior-entry structurally совместим с самим head.

**Fix:**
- в `validate_allproc()` добавлен Bug #390 mixed-head guard
- если выбран `PROC_LIST_OFFSET != 0`, но `proc0` имеет BSD head signature на `+0x00/+0x08`, а `chosen prev` для interior-entry не является kernel pointer'ом, candidate отклоняется
- дополнительно делается короткая проверка BSD `p_list` chain; если она тоже не user-visible, candidate считается ложным и не принимается

**Expected effect:** `kbase+0x321C480` больше не должен проходить через legacy `disc_pl` как partial `allproc`; resolver должен быстрее перейти к следующему real candidate / retry path вместо 176-step dead-end walk с `max_pid_seen=215`.

---

## Bug #389  `detect_kernproc_variable()` не должен принимать PID-0-only chain как доказательство реального `kernproc` (2026-04-04)

**Symptom:** свежий runtime после Bug #388 больше не спорит с `p_pid=0xD8`, но `ourproc()` всё равно не находит self proc:
- candidate `kbase+0x321C400` принимается как `KERNPROC candidate SUCCESS`
- затем `ourproc()` стартует с `LIST_OFFSET=0x0`, `NEXT_OFFSET=0x0`
- весь walk идёт по heap-объектам с `pid=0`, а итог — `NOT FOUND ... max_pid_seen=0`

**File:** `darksword/utils.m`

**Root cause:** старое смягчение Bug #373 считало, что zero-only forward chain от `kernel_task` может быть нормальным подтверждением реального `allproc/kernproc`. На свежем syslog это оказалось ложным: `le_prev` backlink и структурная связность ещё не означают, что chain user-visible.

**Fix:**
- убрано acceptance-правило `unique_n == 0 && chain_len >= 2`
- теперь `validate_kernproc_forward_chain()` принимает candidate только если найден `ourpid` или есть достаточная nonzero PID-diversity
- в direct shortlist дополнительно поднят `0x321C480` как runtime-подтверждённый более сильный head-кандидат

**Expected effect:** ложный lock-in на `0x321C400` должен исчезнуть; resolver продолжит поиск реального `allproc/kernproc` вместо перехода в zero-only dead-end path.

---

## Bug #388  build-profile pin для 21D61 должен жёстко фиксировать `PROC_PID_OFFSET=0xD8` (2026-04-04)

**Symptom:** в долгих сериях правок offset-эвристик есть риск регрессии, когда общий iOS-version branch или будущий fallback снова смещает `PROC_PID_OFFSET` и ломает `ourproc` на целевом build.

**File:** `darksword/utils.m`

**Root cause:** offset выбирался только по major/minor iOS branch. Это корректно в среднем, но для целевого build `21D61` уже есть подтверждённая runtime/binary база (`p_pid=0xD8`), и её надо закрепить отдельным deterministic profile.

**Fix:**
- добавлен helper чтения `kern.osversion` (build string)
- для build `21D61` в `init_offsets` добавлен pin: `PROC_PID_OFFSET=0xD8`
- добавлен отдельный telemetry-лог `Bug #388` для явной проверки в runtime

**Expected effect:** на целевом устройстве `ourproc` всегда стартует с корректного `pid` offset, независимо от будущих изменений общих эвристик.

---

## Bug #387  seed-local scan всё ещё мог читать per-cpu/unsafe страницы из relaxed path и провоцировать zone panic (2026-04-04)

**Symptom:** even после перехода на seed-local стратегию fallback всё ещё оставался чувствителен к токсичным адресам в blind-probe фазах (`cand + pid_off`), особенно при расширенных seeds.

**File:** `darksword/utils.m`

**Root cause:** часть guard'ов в seed-local ветке использовала `is_heap_ptr_relaxed`, который годится для proc-chain нормализации, но недостаточно строг для blind `kread` в зоне, где kernel может вернуть per-cpu allocation fault.

**Fix:**
- blind seed/page probes в `bug296_zone_scan` переведены на строгий `is_heap_ptr`
- ужесточён `proc0_chain` seed harvesting: dereference только при strict heap-pass
- обновлён builtin shortlist для `21D61`: сначала runtime-подтверждённый `0x321C480`, затем `0x321C408` и fallback-кандидаты

**Expected effect:** снижение риска повторного per-cpu zone-bound panic в seed-local fallback и более детерминированный старт allproc discovery на 21D61.

---

## Validation note 2026-04-04  build/sign/install после Bug #387/#388

**Result:**
- полный `build_sign_install.sh` прошёл успешно
- IPA подписан (`ldid` + `zsign`) и установлен
- `ideviceinstaller -l` подтверждает `soft.ru.app` version 52

**Current limitation:** automated runtime launch через `idevicedebug` заблокирован отсутствием mounted DeveloperDiskImage (`com.apple.debugserver`), поэтому подтверждение runtime-телеметрии `ourproc` требует ручного запуска на устройстве + параллельного syslog capture.

---

## Bug #385  page-local seed scan должен использовать реальные observed intra-page proc slots, а не synthetic subslots (2026-04-03)

**Symptom:** после Bug #384 runtime дошёл до page-local seed scan, но новый panic остался:
- `Bug #383` уже реально срабатывает
- safe seed scan стартует на `seed_pages`
- затем panic: `zone bound checks: buffer ...00d8 of length 4 overflows object ... of size 0`

**File:** `darksword/utils.m`

**Root cause:** даже page-local fallback всё ещё предполагал фиксированные subslots `0x0/0x400/0x800/0xC00`. На этом устройстве реальные `proc` из `fwd_procs` сидят на других intra-page offsets, поэтому scan продолжал читать `pid` от synthetic slot/base и всё ещё попадал в zero-sized/non-proc objects.

**Fix:**
- synthetic slot geometry убрана как основная
- seed-local scan теперь собирает **реальные** intra-page offsets из observed `fwd_procs`
- эти observed offsets используются и в prepass, и в widened local page-seed scan
- дополнительно расширены seeds: используются не только `fwd_procs`, но и `proc0[+0x00]`-chain neighbors

**Expected effect:** следующий runtime должен либо впервые найти наш `proc` в safe seed-local path, либо по крайней мере перестать падать на synthetic `...+0xd8` slot, который не соответствует реальному layout текущего boot.

---

## Bug #384  non-page-aligned anchors всё ещё уводили fallback в legacy broad zone scan (2026-04-03)

**Symptom:** после Bug #383 alternate `pid_off` уже реально исполнялся, но затем runtime уходил в новый panic:
- `Bug #383: suspicious direct walk ... retrying with alt pid_off=0x60`
- `Bug #383: alt pid walk done ... found=0x0`
- после этого логировал `Bug #296/320: zone scan ... page_aligned=0`
- свежий panic уже был `Kernel data abort`, а не прежний zero-only chain abort

**File:** `darksword/utils.m`

**Root cause:** даже после перевода на safer fallback код всё ещё выбирал legacy broad-scan branch, если anchors оставались interior/non-page-aligned. То есть unsafe path не был полностью отрезан: он просто начал достигаться новым способом.

**Fix:**
- для non-aligned anchors добавлена принудительная нормализация к page base
- fallback всегда переводится в page-aligned seed-local scan
- legacy broad scan больше не должен выбираться только из-за interior proc pointers

**Expected effect:** следующий runtime должен уйти из legacy broad scan и концентрироваться только на local seed pages / safe windows вокруг них.

---

## Bug #383  alternate PID offset fallback был слишком узким и не запускался на partial/suspicious chains (2026-04-03)

**Symptom:** ранние runtime после интеграции `socket/tro` fast path уже перестали умирать на `kernprocaddress()==0`, но `ourproc()` всё равно не находил self proc:
- direct walk мог давать `max_pid_seen=103`, `361` или мусорный `65538`
- при этом alternate `pid_off=0x60` вообще не пробовался, потому что код запускал fallback только при `max_pid_seen == 0`

**File:** `darksword/utils.m`

**Root cause:** условие Bug #383 было слишком строгим и считало только zero-only chain признаком ложной раскладки PID. На практике current boot показывает и другие suspicious cases: короткий partial list, PID diversity меньше `ourpid`, или битые слишком большие PID.

**Fix:**
- alternate `pid_off` теперь запускается на любом suspicious direct walk:
  - `max_pid_seen < ourpid`
  - или аномально большой `max_pid_seen >= 0x10000`
- добавлены отдельные логи для partial/suspicious direct walk
- runtime теперь реально выполняет direct replay с alternate `pid_off=0x60`

**Expected effect:** следующий runtime должен либо найти self proc с alternate PID offset, либо подтвердить, что проблема уже не только в `p_pid` offset, а в самой proc-list geometry/coverage.

---

## Bug #382  post-discovery `validate_proc_chain()` переотклонял сильный DATA-scan candidate из-за loop-back/cycle (2026-04-03)

**Symptom:** после Bug #381 panic исчез, но свежий runtime всё равно завершался на раннем этапе:
- DATA scan в `__DATA.__common_target` логирует `proc list layout ... score=25 -> FOUND!`
- сразу после этого `kernprocaddress()` всё равно возвращает `0`
- `ourproc()` даже не доходит до fallback scan, а чисто abort'ится через `PANIC GUARD`

**File:** `darksword/utils.m`

**Root cause:** `discover_proc_list_layout()` уже принимает candidate по достаточной PID-diversity, но следующий `validate_proc_chain()` имел более жёсткое правило: любой revisit/cycle немедленно `return false`. На реальном DATA-scan head это оказывалось слишком строгим: candidate успевал показать сильную PID-diversity, но затем loop-back в рамках той же очереди/головы всё равно выбивал его до итоговой summary-проверки.

**Fix:**
- в `validate_proc_chain_with_pid_off()` revisit больше не делает немедленный reject
- вместо этого walk останавливается и проходит через итоговую summary-валидацию (`seen/unique/zero_pid_count`)
- acceptance по-прежнему требует сильную PID-diversity, так что слабые cyclic false-positive списки не принимаются

**Expected effect:** следующий runtime должен либо принять уже найденный DATA candidate как `allproc`, либо хотя бы показать новый лог `Bug #382: accepting cyclic/looped proc chain ...`, после чего `kernprocaddress()` перестанет возвращать `0` на этом candidate.

---

## Bug #381  `kernproc mode` всё ещё обходил Bug #380, потому что `kernel_task proc` не page-aligned (2026-04-03)

**Symptom:** следующий runtime после Bug #380 снова panic-нул почти в том же месте:
- `Bug #255: kernproc mode — using BSD LIST (list=0x00 prev=0x08)`
- `kernel_task=0xffffffe239d7d4b0`
- затем сразу `Bug #296/320: zone scan ... stride=0x400 page_aligned=0 anchors=[0xffffffe239d7d4b0..]`

**File:** `darksword/utils.m`

**Root cause:** Bug #380 правильно запрещал legacy broad scan при BSD `p_list`, но делал это только если `kernproc` сам уже page-aligned. На этом устройстве в `kernproc mode` реальный `kernel_task proc` — это валидный proc по адресу внутри своей 4KB page (`...d4b0`), поэтому условие не срабатывало и код снова падал в старый `0x400` fallback.

**Fix:**
- guard больше не требует page-aligned `kernproc`
- в подтверждённом BSD direct layout anchors всегда нормализуются к page base
- safe fallback принудительно идёт в page-aligned seed-local path даже если исходный `kernproc` — interior proc pointer

**Expected effect:** следующий runtime должен впервые показать лог `Bug #381: forcing page-aligned seed-local scan ...`, после чего перейти в `Bug #327` / `Bug #332`, а не в `Bug #296/320 stride=0x400 page_aligned=0`.

---

## Bug #380  safe fallback всё ещё мог скатиться в legacy `0x400` broad scan из-за непостраничных anchors (2026-04-03)

**Symptom:** после Bug #379 код впервые реально дошёл до fallback, но свежий runtime снова panic-нул:
- лог дошёл до `Bug #379: ... continuing into safe Bug #296/#332 seed-local scan`
- затем сразу пошёл `Bug #296/320: zone scan ... stride=0x400 page_aligned=0 anchors=[0x...c430..0x...c430]`
- свежий panic: `zone bound checks: buffer ... of length 4 overflows object ... of size 0`

**File:** `darksword/utils.m`

**Root cause:** сам переход в fallback уже починен, но выбор между safe page-local path и старым legacy broad scan всё ещё зависел от `anchor_min/anchor_max`. Если `scan_min_seen`/`scan_max_seen` сохраняли смещённый внутрь proc-page адрес (`...c430`), `page_aligned_scan` становился `false`, и код снова шёл в panic-prone `0x400` scan, несмотря на подтверждённую BSD `p_list` layout `0/0/8`.

**Fix:**
- введён Bug #380 guard для BSD direct layout (`PROC_LIST_OFFSET=0`, `PROC_NEXT_OFFSET=0`, `PROC_PREV_OFFSET=0x8`)
- при page-aligned `kernproc` любые непостраничные anchors теперь нормализуются к page base
- после нормализации fallback принудительно остаётся в page-aligned seed-local path; legacy `0x400` broad scan больше не выбирается из-за смещённого `scan_min_seen`

**Expected effect:** следующий runtime должен снова дойти до fallback, но уже без `page_aligned=0` / `stride=0x400`; ожидаемый путь — `Bug #327` subslot prepass + `Bug #325/#332` extended local seed scan без нового zone panic.

---

## Bug #334  partial allproc guard `Bug #336` всё ещё блокирует safe seed-local scan (2026-04-03)

**Symptom:** после Bug #333 ранний abort на kernel-only chain исчез, но свежий runtime всё ещё не доходит до `Bug #327` / `Bug #332` path:
- `Bug #338` подтверждает BSD `p_list` head и проходит часть цепочки
- затем `Bug #336: allproc chain exhausted (316 procs, max_pid=419 < ourpid=439)`
- после retry следует `Bug #336: skipping zone scan to prevent panic`
- снова `PANIC GUARD: ourproc() failed (0x0)`

**File:** `darksword/utils.m`

**Root cause:** guard Bug #336 был задуман как stop-gap до появления безопасного fallback. После Bug #325..#333 он всё ещё делал `return 0` при partial allproc chain, хотя ниже уже находится page-aligned seed-local scan, а не старый broad panic-prone scan.

**Fix:**
- сохранён blacklist+retry logic Bug #377
- после исчерпания retry guard Bug #336 теперь не abort'ит `ourproc()`, а делает переход в `bug296_zone_scan`
- добавлен отдельный лог `Bug #379: ... continuing into safe Bug #296/#332 seed-local scan`

**Expected effect:** следующий runtime должен впервые пройти дальше partial-allproc guard и реально выполнить seed-page subslot prepass + extended local seed scan.

---

## Bug #333  legacy fail-fast guards блокируют Bug #332 safe seed-local scan (2026-04-03)

**Symptom:** свежий runtime после safe rollback и Bug #332 остался panic-free, но `ourproc()` всё равно не дошёл до нового `64MB` scan:
- `kernel r/w is ready!`
- forward walk идёт по kernel-thread chain (`pid=0`)
- затем `Bug #300: kernel-only PID=0 chain with empty backward walk ...`
- сразу `PANIC GUARD: ourproc() failed (0x0)`
- в логах **нет** ни `Bug #327: seed-page subslot prepass`, ни `Bug #332: extended local seed scan ...`

**File:** `darksword/utils.m`

**Root cause:** старые защитные early-return guards (`Bug #300`, затем `Bug #299c/376`) были введены до появления page-aligned seed-local fallback. После Bug #325..#332 они стали контрпродуктивными: speculative alt-link probes действительно нужно пропускать, но возврат `0` до `bug296_zone_scan` полностью отрезает уже безопасный путь поиска `ourproc()`.

**Fix:**
- `Bug #300` guard теперь skip'ает alt-list/alt-next probes, но делает переход в `bug296_zone_scan`
- `Bug #299c/376` guard сохраняет telemetry-log, но больше не делает early return
- результат: kernel-only PID=0 chain больше не завершает `ourproc()` до запуска safe Bug #325..#332 seed-local scan

**Expected effect:** следующий runtime должен остаться panic-free, без возврата `early_kread` storm, и впервые реально выполнить `Bug #327`/`Bug #332` path на текущем safe коде.

---

## Bug #332  panic-free seed scan слишком узкий: user proc за пределами 4MB от kernel-thread seeds (2026-04-03)

**Symptom:** после Bug #331 runtime panic-free, но `ourproc()` всё ещё не найден:
- seeds = 11 (два кластера: `0xffffffdf0ca8x`  kernel threads, `0xffffffde25a9x`)
- phase 3 max_window=0x400000  12737 iters, DarkSword (PID=364) не найден

**File:** `darksword/utils.m`

**Root cause:** `kbase+0x3213678` даёт цепочку **kernel threads** (11 штук, все PID=0 при pid_off=0x60). Именно они становятся seeds для seed-local scan. DarkSword (PID=364) аллоцирован в GEN0/GEN1 heap значительно дальше  за пределами 4MB от любого kernel-proc seed.

**Fix:** добавлена 5-я фаза seed-local scan:
- `window = 0x4000000` (64 MB)
- `gap_limit = 512` (допускает до 512  0x1000 подряд пустых страниц до break)
- panic-safe: probe  4-byte PID read по `+pid_off < 0x1000` внутри 1024-byte proc element; scan остаётся в zone_map; forward-only (pre_window=0) per Bug #324

**Expected effect:** следующий runtime должен сохранить panic-free поведение и достать DarkSword proc из той части GEN0/GEN1, что находится >4MB от ближайшего kernel-thread seed.

---

## РЎРІРѕРґРєР°

| РўРёРї | РљРѕР»РёС‡РµСЃС‚РІРѕ | РРјРїР°РєС‚ |
|-----|-----------|--------|
| Kernel panics | 6 | РљСЂСЌС€ РїСЂРё РєР°Р¶РґРѕРј Р·Р°РїСѓСЃРєРµ |
| Proc offset bugs | 4 | PID/UID/GID/allproc РЅРµРІРµСЂРЅС‹Рµ |
| VFS offset bugs | 4 | rootvnode NEVER found, wrong ncache |
| KASLR slide bug | 1 | allproc scan РЅРµ РЅР°С…РѕРґРёР» РЅРёС‡РµРіРѕ |
| PAC pointer bugs (kfs) | 14 | ncache traversal, rootvnode, ubcinfo |
| PAC pointer bugs (core) | 5 | control_pcb, pcbinfo, ipi_zone, zv_name, inp_list |
| Postexploit logic | 7 | sandbox ret, csflags, AMFI, ucred verify, root check, bail |
| Trustcache critical | 3 | KASLR slide, SuperBlob parse, sorting |
| Trustcache medium | 20 | FAT arm64e, malloc check, flush warn, header buf, range typo, stale init, false success, deb child-exit handling, deb path validation, shell quoting, API path guards, deb temp-dir hygiene, deb file validation, cdhash API guards |
| Exploit chain logic | 11 | pe_errors, kbase, magic, retry, state reset, PCB cleanup, bootstrap error accounting, env hygiene, concurrent-call honesty |
| Kernel base search | 1 | Р‘РµСЃРєРѕРЅРµС‡РЅС‹Р№ С†РёРєР» в†’ bounded + guard |
| Bootstrap hardening | 10 | prereqs, mkdir, timeout, pipeline, PATH, config API guards, URL validation |
| Utils safety | 2 | sysctlbyname fail, ourtask garbage return |
| Bootstrap critical | 45 | zstdв†’xz, disk space, uicache, SSH, cleanup, retry state, child-exit handling, sshd false-success, honest partial-status accounting, Sileo install verification, stale partial download cleanup, prepare/extract/source honesty, apt OpenSSH verification, shared SSH launch validation, env setup/restore, concurrent-call honesty, directory-type validation, sources write/flush validation, partial trust honesty |
| Retry/state bugs | 5 | stale cached state across kfs/postexploit/tc/bootstrap |
| KFS API safety | 3 | overwrite path/offset/size validation |
| Utils proc walk safety | 1 | procbyname used broad kptr validation |
| Core allocation hardening | 21 | IOSurface / phys-map failure, empty spray indexing, retry cleanup, setup guards |
| App UI/safety | 6 | signal handler UB, bgTask, O(nВІ), strongify, dedup, live log bridge |
| Build system | 3 | entitlements merge, compile-order fix, helper declaration fix |
| AMFI KASLR slide | 6 | CRITICAL: all vmaddrs unslid в†’ panic |
| Bootstrap apt sources | 1 | apt URL double /2000 в†’ apt fail |
| Zone metadata panic | 1 | **РљР РРўРР§Р•РЎРљР Р’РђР–РќРћ**: fallback bounds РІРєР»СЋС‡Р°Р»Рё 0xffffffdd... в†’ kernel data abort |
| allproc NOT FOUND | 1 | allproc СЃРјРµС‰РµРЅРёРµ 0x93B348 РѕС€РёР±РѕС‡РЅРѕ РїРѕРјРµС‡РµРЅРѕ РєР°Рє В«РїР»РѕС…РѕРµВ» вЂ” РІРµСЃСЊ post-exploit С†РµРїРѕС‡РєР° РјРµСЂС‚РІР° |
| Log spam / app freeze | 1 | BLOCKED misaligned Р»РѕРіРёСЂРѕРІР°Р»СЃСЏ С‚С‹СЃСЏС‡Рё СЂР°Р· вЂ” С„Р°Р№Р» Р»РѕРіР° 829KB, РїСЂРёР»РѕР¶РµРЅРёРµ РІРёСЃР»Рѕ РјРёРЅСѓС‚С‹ |
| trustcache xref infinite loop | 1 | `find_tc_head_by_string_xref` СЃРєР°РЅРёСЂРѕРІР°Р» 4MB Р±РµР· Р»РёРјРёС‚Р° kr64 в†’ Р·Р°РІРёСЃР°РЅРёРµ РїРѕСЃР»Рµ log |
| Early PCB read abort | 1 | zone bounds РЅРµ РїСЂР°Р№РјРёР»РёСЃСЊ РґРѕ РїРµСЂРІРѕРіРѕ heap read в†’ abort РґРѕ kernel-base |
| so_count wrong offset | 1 | `0x228` (iOS 16) РїРµСЂРµР·Р°РїРёСЃС‹РІР°Р» С‡СѓР¶РѕРµ РїРѕР»Рµ socket struct в†’ kernel panic |
| set_target_kaddr alignment | 1 | `where & 7` Р±Р»РѕРєРёСЂРѕРІР°Р» 4-byte-aligned Р°РґСЂРµСЃР° (so_count 0x24c) в†’ refcount РЅРµ Р±Р°РјРїРёР»СЃСЏ |
| 32-bit socket field corruption | 1 | РїСЂСЏРјРѕР№ patch 32-bit РїРѕР»СЏ РјРѕРі РїРѕСЂС‚РёС‚СЊ СЃРѕСЃРµРґРЅРµРµ РїРѕР»Рµ `struct socket` |
| Zone name rejection / narrow bounds | 1 | `site.struct inpcb` РѕС‚РІРµСЂРіР°Р»СЃСЏ, fallback bounds РЅРµ РїРѕРєСЂС‹РІР°Р»Рё СЂРµР°Р»СЊРЅС‹Р№ СЂР°Р·Р»С‘С‚ zone_map |
| per-CPU zone panic | 1 | allproc scan РїСЂРёРЅРёРјР°Р» VM-submap Р°РґСЂРµСЃР° Р·Р° heap ptr Рё РїР°РЅРёРєРѕРІР°Р» РІ `zalloc.c` |
| allproc ADRP candidates wrong | 1 | РІСЃРµ 8 ADRP candidates в†’ PAC function pointers, РЅРµ proc ptrs |
| allproc scan range | 1 | Р·Р°РјРµРЅРµРЅРѕ РЅР° scan __DATA.__common + __DATA.__bss |
| allproc shortlist РЅРµРїРѕР»РЅС‹Р№ | 1 | РІСЃРµ С‚СЂРё shortlist РЅРµ СЃРѕРґРµСЂР¶Р°Р»Рё РїРѕРґС‚РІРµСЂР¶РґС‘РЅРЅС‹Р№ offset 0x31FFF30 в†’ VALUE=0 РЅР° РІСЃРµС… РєР°РЅРґРёРґР°С‚Р°С… |
| Mach-O scan Metadata panic | 1 | COMMON_START=0x27000 Р·Р°С…РІР°С‚С‹РІР°Р» Metadata zone pointers в†’ Translation fault level 3 |
| allproc le_prev proof ignored | 1 | proc0.le_prev==allproc_head РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ РёРіРЅРѕСЂРёСЂРѕРІР°Р»РѕСЃСЊ; chain validator РёСЃРїРѕР»СЊР·РѕРІР°Р» РЅРµРІРµСЂРЅС‹Р№ pid_off=0xd8 в†’ РєР°РЅРґРёРґР°С‚ 0x3213678 РѕС‚РєР»РѕРЅС‘РЅ |
| **Р’СЃРµРіРѕ Р±Р°РіРѕРІ** | **337** | вЂ” |
| РќРѕРІС‹Рµ features | 4 | AMFI bypass, TC scan, PPL-aware, CS_DEBUGGED |

---

## Bug #331: bounded `p_comm` helper для `ourproc()`; name-fallback в seed-slot prepass позже откатан из-за early_kread regression (2026-04-03)

**Symptom:** после Bug #330 panic отсутствует, но `ourproc()` по-прежнему может не находить наш `pid`, даже при dual-pid (`0xd8` + `0x60`) и расширенных локальных окнах.

**File:** `darksword/utils.m`

**Root cause:** текущий seed-slot prepass делал успех только по `pid==ourpid`. На «смешанных» коротких цепочках `pid` может быть шумным/ложным, и наш proc-кандидат пропускается, хотя рядом уже есть валидные heap/list признаки. Параллельно прежний name-read в subslot path был рискован из-за фиксированного 32-byte чтения на tail-slot.

**Fix:**
- добавлен bounded helper для чтения `p_comm` без пересечения границы 4KB объекта
- первоначально был добавлен name-based fallback в seed-slot prepass (`proc_name(getpid())`/`getprogname()`/`DarkSword`)
- после device-regression (`getsockopt failed (early_kread)!` storm сразу на старте subslot prepass) этот name-based fallback был откатан
- в текущем коде seed-slot prepass снова PID-only, а bounded helper retained для безопасного чтения имени только на уже подтверждённых путях

**Expected effect:** bounded helper остаётся полезным для безопасного логирования/подтверждения `p_comm`, но seed-slot prepass больше не делает name-based fallback до появления device-validated безопасного варианта.

---

## Bug #330: после Bug #329 локальный seed-scan всё ещё узкий — нужен дополнительный safe phase `0x400000` (2026-04-03)

**Symptom:** первый runtime после Bug #328/329 подтвердил стабильность без нового panic, но `ourproc()` всё ещё не найден:
- `kernel r/w is ready!`
- `Bug #325: local page-seed scan done (2889 iters, not found)`
- `PANIC GUARD: ourproc() failed (0x0)`

**File:** `darksword/utils.m`

**Root cause:** Bug #329 ослабил ранний break на short gaps, но максимальное локальное окно оставалось `0x100000`. Для этого boot диапазона недостаточно, чтобы достать следующий proc-cluster от seed pages даже при panic-free page-aligned probing.

**Fix:** local seed scan расширен ещё одной безопасной фазой:
- добавлено окно `0x400000`
- добавлен `gap_limit=128` для новой фазы
- число фаз теперь вычисляется динамически по размеру массива
- добавлен лог-маркер `Bug #330: extended local seed scan ...`

**Expected effect:** следующий runtime должен сохранить panic-free поведение Bug #328/329 и дать более глубокое покрытие seed-local зоны без возврата к опасному broad contiguous sweep.

---

## Bug #329: panic-free local seed scan нельзя обрывать после первых 4 пустых page-base probe (2026-04-03)

**Symptom:** первый post-`Bug #328` runtime подтвердил, что panic устранён, но `ourproc()` всё ещё не найден:
- `Bug #327: seed-page subslot prepass ...` проходит без нового panic
- `Bug #325: local page-seed scan done (190 iters, not found)`
- safe `PANIC GUARD` abort остаётся стабильным

Для `11` seed pages и окон `0x4000 / 0x40000 / 0x100000` такой маленький `190 iters` показал, что большинство local scans заканчивается слишком рано.

**File:** `darksword/utils.m`

**Root cause:** Bug #325 правильно убрал опасный broad contiguous sweep, но сохранил слишком жёсткий stop-condition: `cfails >= 4`. После первых нескольких подряд пустых page-base probe scan полностью бросает конкретный local window, хотя следующий proc-cluster может лежать чуть дальше внутри того же safe seed-local диапазона.

**Fix:** local seed scan получил phase-aware gap tolerance:
- phase 0: `4` consecutive miss
- phase 1: `16`
- phase 2: `64`

Дополнительно в лог добавлен `gap_limit=...`, чтобы следующий runtime показал фактическую глубину локального прохода.

**Expected effect:** следующий runtime должен сохранить panic-free поведение Bug #325/328, но заметно лучше проходить короткие дыры между соседними proc clusters без возврата к прежнему опасному global scan.

---

## Bug #328: subslot prepass нельзя валидировать 32-byte name-read на slot `+0xC00` (2026-04-03)

**Symptom:** первый runtime после Bug #327 снова panic-нул, но уже сразу на старте нового subslot prepass:
- syslog дошёл до `Bug #327: seed-page subslot prepass ...`
- затем посыпался `getsockopt failed (early_kread)!`
- fresh panic: `buffer 0xffffffdf0f239fe8 of length 32 overflows object 0xffffffdf0f239000 of size 4096 in zone [shared.kalloc.4096]`

Адрес точно совпал с чтением `32` байт из конца seed-page объекта: slot `+0xC00` + name offset `0x3E8`.

**File:** `darksword/utils.m`

**Root cause:** сам pid-only subslot prepass был безопасен, но добавленный name-guided fallback читал `32` байта по `cand + name_off` на любом subslot-кандидате. Для кандидата в последнем slot 4KB-объекта это пересекало границу zone object и вызывало `zone bound checks`.

**Fix:** name-guided fallback полностью убран из subslot prepass. В этой фазе остаётся только pid-based low-risk probing; длинные строковые reads по subslot-кандидатам больше не выполняются.

**Expected effect:** следующий runtime должен сохранить полезную coverage Bug #327 (`+0x000/+0x400/+0x800/+0xC00`), но без повторного panic на 32-byte read через конец 4KB proc-page объекта.

---

## Bug #327: после panic-free `Bug #325/326` нужно проверить intra-page proc slots на самих seed pages (2026-04-03)

**Symptom:** свежий runtime после Bug #326 подтвердил, что dual-pid fallback сам по себе недостаточен:
- panic по-прежнему отсутствует
- `Bug #325: local page-seed scan done (186 iters, not found)`
- `pid_offs=2/0xd8 +0x60`, но наш PID всё равно не найден

**File:** `darksword/utils.m`

**Root cause:** Bug #325/326 уже сделали scan безопасным и tolerant к `0xd8` vs `0x60`, но page-seed path всё ещё читает только page base. Для proc-zone страниц это может видеть лишь slot `+0x000`, тогда как реальные proc элементы на той же странице могут лежать и в `+0x400`, `+0x800`, `+0xC00`. То есть safe cluster-local geometry уже верна, а coverage внутри самой seed page всё ещё неполная.

**Fix:** перед расширением local windows добавлен low-risk prepass только по уже наблюдённым `seed_pages`:
- проверяются subslots `0x000/0x400/0x800/0xC00`
- используется dual-pid logic (`active pid_off` + `0x60`)
- добавлен name-guided fallback по `DarkSword` на кандидате с правдоподобным `p_list`

**Expected effect:** следующий runtime должен сохранить panic-free поведение Bug #325/326, но получить шанс найти наш proc прямо на already-observed seed pages без возврата к широкому опасному intra-page sweep.

---

## Bug #326: panic-free seed-local zone scan должен перепроверять `0x60`, даже если direct accept временно выбрал `0xd8` (2026-04-03)

**Symptom:** первый post-`Bug #325` runtime больше не panic-нул вообще, но `ourproc()` всё равно не нашёл наш PID:
- `Bug #325: local page-seed scan done (178 iters, not found)`
- затем safe `PANIC GUARD` abort без нового `panics_*`

При этом тот же runtime показал, что accepted short chain всё ещё остаётся mixed/ложным:
- `kernprocaddress()` вернул `0x...1f9b3678`
- direct layout продолжил идти с `pid=0xd8`
- forward walk дал только `pid=0`, `115`, `29542`

**File:** `darksword/utils.m`

**Root cause:** Bug #325 исправил именно геометрию scan и подтвердил, что cluster-local page scan безопасен. Но functional blocker остался другим: optimistic direct accept всё ещё может временно жить на ложном `PROC_PID_OFFSET=0xd8`, тогда как safe zone scan читает только этот offset и может пропустить наш реальный `proc`, если на живых heap pages корректный `p_pid` снова лежит на подтверждённом `0x60`.

**Fix:** safe zone/seed-local scan теперь проверяет два PID offsets на каждой уже-безопасной proc page:
- сначала текущий `PROC_PID_OFFSET`
- затем подтверждённый fallback `0x60`, если он отличается
- при нахождении нашего PID scan логирует переключение и переводит `PROC_PID_OFFSET` на реально сработавший offset

**Expected effect:** следующий runtime должен сохранить panic-free поведение Bug #325, но перестать слепо зависеть от временного ложного `0xd8` и получить шанс найти наш app `proc` в тех же безопасных seed-local neighborhoods.

---

## Bug #325: contiguous page-aligned proc scan нужно заменить на seed-local windows (2026-04-03)

**Symptom:** даже после Bug #324 panic не исчез. Свежий runtime снова panic-нул в `ourproc()` scan, но уже не на lower bound, а глубже внутри forward-only contiguous range:
- `buffer 0xffffffe7e0dc40d8 ... size 0`
- адрес лежит заметно выше известных safe proc clusters
- syslog успевает дойти только до `Bug #319`, а затем процесс умирает до финального scan-summary

**File:** `darksword/utils.m`

**Root cause:** сам contiguous page-by-page sweep оказался неверной моделью. Даже если не идти назад, длинный сплошной проход через многомегабайтный range всё равно попадает в огромные дыры между реальными proc clusters и читает zero-sized non-proc objects.

**Fix:** page-aligned fallback больше не сканирует один сплошной диапазон. Вместо этого он:
- собирает seed pages из реально увиденных `fwd_procs`
- дедуплицирует их
- сканирует только локальные forward windows вокруг каждого seed
- расширяет именно размер локального окна, а не глобальный contiguous span

**Expected effect:** следующий runtime должен остаться вблизи уже подтверждённых proc neighborhoods и прекратить panic на огромных межкластерных дырах.

---

## Bug #324: page-aligned `ourproc()` scan нельзя начинать ниже текущего anchor (2026-04-03)

**Symptom:** даже после Bug #323 новый runtime всё равно panic-нул сразу на первом lower-bound probe:
- `panic-full-2026-04-03-060125.0002.ips`
- `buffer 0xffffffe09c4fe0d8 of length 4 overflows object ... size 0`
- адрес совпал с `kernproc - 0x400000 + PROC_PID_OFFSET`

То есть проблема была не только в слишком большом backward expansion, а в самом факте любого page-aligned scan ниже текущего anchor neighborhood.

**File:** `darksword/utils.m`

**Root cause:** на этом boot lower zone neighborhood под текущим anchor остаётся toxic даже при `0x1000` stride и минимальном `4MB` backward slack. Свежий panic показал, что первый же lower-bound read снова упирается в zero-sized/non-proc object.

**Fix:** page-aligned `Bug #296` scan теперь полностью one-sided:
- `pre_window = 0` во всех фазах
- scan стартует ровно с `anchor_min`
- расширение происходит только вперёд (`post_window`)

**Expected effect:** следующий runtime должен вернуть panic-free поведение и продолжить безопасный поиск `ourproc()` только в forward direction.

---

## Bug #323: staged page scan нельзя расширять назад дальше proven-safe lower bound (2026-04-03)

**Symptom:** первый runtime после Bug #322 больше не был panic-free. Вместо позднего socket-teardown panic появился новый fresh `bug_type 210` прямо внутри расширенного `ourproc()` zone scan.

Panic показал точный новый probe-адрес:
- `x0 = 0xffffffde25ea60d8`
- это соответствует `phase 1` lower bound `0xffffffde25ea6000 + PROC_PID_OFFSET`
- то есть crash произошёл сразу после backward expansion от `anchor_min`, ещё до какой-либо полезной новой coverage

**File:** `darksword/utils.m`

**Root cause:** Bug #322 правильно сохранил `0x1000` stride, но ошибочно предположил, что page-aligned safety симметрична в обе стороны. На этом boot расширение вниз от `anchor_min` быстро уходит в unsafe lower zone neighborhood, где даже page-aligned 4-byte read по `proc + pid_off` снова вызывает kernel data abort.

**Fix:** staged expansion теперь остаётся односторонним по lower bound:
- backward slack зафиксирован на уже доказанном safe окне `4MB`
- phase 1 и phase 2 расширяют только forward/post coverage
- page-aligned policy и `0x1000` stride не меняются

**Expected effect:** следующий runtime должен вернуть panic-free поведение Bug #321, но всё ещё попробовать найти `ourproc()` дальше ВПЕРЁД по page-aligned neighborhood без возврата к unsafe backward widening.

---

## Bug #322: safe page-aligned `Bug #296` scan нужно расширять по фазам, если bounded window не содержит наш `proc` (2026-04-03)

**Symptom:** после Bug #321 свежий runtime наконец стал полностью безопасным:
- `Bug #296/320` выполняется без panic
- `PANIC GUARD` завершается без позднего terminate-time panic
- приложение штатно доходит до `UIApplication will terminate`

Но `ourproc()` всё ещё стабильно не находит наш PID внутри текущего bounded page-aligned окна, хотя kernel r/w остаётся рабочим и accepted proc anchors выглядят корректно.

**File:** `darksword/utils.m`

**Root cause:** panic-safe window из Bug #320 (`pre=4MB`, `post=8MB`) оказался слишком узким именно для этого boot. Он уже достаточен, чтобы не трогать toxic interior offsets и не panic-ить, но недостаточен, чтобы покрыть весь реальный page-aligned proc neighborhood, где лежит наш app proc.

**Fix:** page-aligned `Bug #296` scan теперь делает staged expansion вместо единственного bounded pass:
- phase 0: старое безопасное окно `4MB/8MB`
- phase 1: расширение до `64MB/128MB`
- phase 2: расширение до `256MB/512MB`

Во всех фазах сохраняется безопасный `0x1000` stride и та же validation policy; меняется только покрытие окна.

**Expected effect:** следующий runtime должен сохранить no-panic behavior Bug #321, но получить существенно больше шансов реально найти `ourproc()` без возврата к опасному `0x400` interior scan.

---

## Bug #321: pre-hardened `PANIC GUARD` больше не должен rollback-ить `icmp6filt` после fresh evidence на `rw_socket_pcb + 0x150` (2026-04-03)

**Symptom:** после Bug #320 свежий syslog уже показывал новый neutralize-path в pre-hardened abort:
- `abort-neutralize: parked corrupted filter target at self ... +0x148`
- затем `rollback: restoring icmp6filt qword0 ... forcing qword1=0`
- затем `abort-cleanup: quarantine sockets without close`

Но новый full panic всё равно срабатывал уже после controlled abort, и panic-адрес снова точно попал внутрь embedded filter-slot: `0xffffffdffa348550`, то есть `rw_socket_pcb + 0x150`.

**File:** `darksword/darksword_core.m`

**Root cause:** для pre-hardened failing session даже partial rollback (`qword0 <- snapshot`, `qword1 <- 0`) всё ещё оказывался слишком агрессивным. Fresh panic доказал, что terminate-time teardown остаётся чувствительным к любому post-abort write-back в `icmp6filt` slot, даже если stale `target_kaddr` уже был заранее neutralize-нут на self-slot.

**Fix:** `panic_guard_abort_cleanup()` в pre-hardened ветке больше не вызывает rollback `icmp6filt`. Теперь эта ветка делает только:
- park corrupted target back to self-slot;
- quarantine fd / pcb state without close;
- skip rollback entirely.

**Expected effect:** controlled abort после неудачного `ourproc()` должен перестать ловить поздний terminate-time panic на `rw_socket_pcb + 0x150` в сессиях без success-only leak-hardening.

---

## Bug #320: pre-hardened panic-guard abort тоже должен neutralize-ить последний `target_kaddr` перед rollback/quarantine (2026-04-03)

**Symptom:** свежий runtime после исправления `Bug #296/320` больше не падал внутри zone-scan и доходил до controlled abort:
- `Bug #296: scan done ... not found`
- `PANIC GUARD: ourproc() failed (0x0)`
- `rollback: restoring icmp6filt qword0 ... forcing qword1=0`
- `abort-cleanup: quarantine sockets without close`

Но свежий full panic всё равно появлялся уже после завершения приложения, причём panic-адрес точно совпадал с `rw_socket_pcb + 0x150`, а panic string показывал новую zone/type mismatch сигнатуру: expected `data.kalloc.32`, found `kalloc.type0.1024 / struct inpcb`.

**File:** `darksword/darksword_core.m`

**Root cause:** pre-hardened abort-path всё ещё делал только rollback `icmp6filt`, но не neutralize-ил последний speculative `target_kaddr`, который остался припаркован на embedded slot внутри `rw inpcb`. Из-за этого terminate-time teardown позже всё ещё мог интерпретировать `rw_socket_pcb + 0x150` как standalone small allocation и паниковать уже после controlled abort.

**Fix:** в `fail_after_corruption_cleanup()` добавлен ранний вызов `park_corrupted_socket_filter_target_to_self()` до rollback/quarantine. Теперь pre-hardened guard-abort использует ту же stale-target neutralization policy, что и leak-hardened ветка `Bug #313/301`.

**Expected effect:** controlled abort после неудачного `ourproc()` должен завершаться без позднего terminate-time panic на `rw_socket_pcb + 0x150`, даже если leak-hardening ещё не был включён.

---

## Bug #319: short mixed `kernproc` chain после Bug #318 должен идти сразу в безопасный zone scan, а не в speculative alt-list probes (2026-04-03)

**Symptom:** свежий runtime после Bug #318 наконец принял `0x3213678` как `kernproc`, дошёл внутрь `ourproc()`, выполнил реальный forward walk и показал короткую mixed chain (`pid=0`, `115`, `29542`), но не нашёл `pid=471`. Сразу после этого старые `Bug #243B` / `alt next_off` пробы завершались `getsockopt failed (early_kread)!` до запуска безопасного `Bug #296` fallback.

**File:** `darksword/utils.m`

**Root cause:** этот runtime уже не является старым `PID=0-only` false-chain сценарием. После успешного optimistic `kernproc` accept у нас есть ограниченная, но user-visible цепочка без нашего процесса. speculative alt-link detours в таком случае не открывают новый путь к `ourproc()`, а лишь дестабилизируют ранний KRW до safe zone scan.

**Fix:** добавлен новый guard для short mixed `kernproc` chain (`count >= 8`, `max_pid_seen > 0`, `bwalk_count == 0`). В этом режиме `ourproc()` теперь пропускает `alt-list`, `alt-next` и legacy intermediate scans и сразу прыгает в безопасный `Bug #296/299` zone-scan fallback от `kernproc`.

**Expected effect:** следующий runtime должен сохранить рабочий `early_kread()` после неудачного short-chain walk и впервые реально показать результат безопасного stride-based zone scan для поиска нашего `proc`.

---

## Bug #318: strong `proc0.le_prev == candidate` + найденный `pid_off` должны приводить к немедленному accept внутри `kernprocaddress()` (2026-04-03)

**Symptom:** свежий runtime 2026-04-03 показал, что даже после Bug #317 кандидат `0x3213678` всё ещё отклонялся: лог доходил до `Bug #315: forward chain failed...`, а затем снова завершался `rejecting candidate ... despite le_prev back-reference`.

**File:** `darksword/utils.m`

**Root cause:** optimistic-pass был вставлен слишком поздно в ветку валидации. Сильный backlink-сигнал (`proc0.le_prev == candidate`) и подтверждённый `pid_off=0xd8` уже достаточны для success-first triage, но код продолжал пускать кандидата через промежуточные жёсткие chain-guards и терял его до фактического accept.

**Fix:** при `proc0.le_prev == candidate` и найденном `discovered_pid_off` код теперь сразу принимает candidate как `g_kernproc_addr`, выставляет `PROC_PID_OFFSET` и direct layout offsets и возвращает success из `kernprocaddress()` без ожидания поздней chain-validation.

**Expected effect:** следующий runtime должен наконец пройти за пределы `kernprocaddress()` и показать дальнейшее поведение уже внутри `ourproc()`/`ourtask()` после реального принятия `0x3213678`.

---

## Bug #317: `proc0.le_prev == candidate` плюс подтверждённый `pid_off` должны проходить как optimistic success-path candidate, а не отбрасываться слишком рано (2026-04-02)

**Symptom:** после Bug #316 свежий runtime впервые полноценно вошёл в `ourproc()`, но `kernprocaddress()` всё ещё преждевременно отклонял candidate `0x3213678` даже при сильной комбинации признаков: `proc0.le_prev == candidate` и подтверждённый `pid_off=0xd8`.

**File:** `darksword/utils.m`

**Root cause:** для success-first стратегии guard в `detect_kernproc_variable()` оставался слишком консервативным. Он требовал завершённое chain-proof ещё до передачи кандидата в `ourproc()`, хотя именно `ourproc()` содержит более богатую runtime-валидацию: backward walk, alt-list probes и последующие fallback-path.

**Fix:** добавлен controlled optimistic accept для случая `le_prev back-reference + discovered pid_off`. Такой кандидат теперь не режется преждевременно внутри `kernprocaddress()`, а передаётся дальше в `ourproc()` для окончательной runtime-проверки.

**Expected effect:** candidate `0x3213678` должен пройти дальше раннего reject, что позволит либо реально найти `ourproc()`, либо получить следующий точный blocker уже после принятия сильного allproc/kernproc кандидата.

---

## Bug #316: `ourproc()` и bootstrap-helper path не должны блокироваться на `ds_is_ready()` до завершения самого bootstrap (2026-04-02)

**Symptom:** после Bug #315 свежий runtime всё ещё немедленно падал в `PANIC GUARD: ourproc() failed (0x0)`, но при этом полностью отсутствовали ожидаемые логи из тела `ourproc()` (`kread health check`, `calling kernprocaddress()`, `kernprocaddress() returned ...`).

**File:** `darksword/utils.m`

**Root cause:** `darksword_core.m` вызывает `ourproc()` сразу после готовности раннего KRW, а `g_ds_ready` выставляет только после успешных `ourproc()` и `ourtask()`. В `utils.m` же `ourproc()` первым делом требовал `ds_is_ready()`, создавая циклический self-block: helper, который должен завершить bootstrap, сам запрещал себе запуск до конца bootstrap.

**Fix:** снят жёсткий gate на `ds_is_ready()` для bootstrap-path. `ourproc()` и `procbyname()` теперь допускаются к работе в pre-ready состоянии, если ранний KRW уже установил валидный `kernel_base`.

**Expected effect:** новый runtime должен реально входить в основную логику `ourproc()` и доходить до настоящего `allproc/kernproc/ourtask` blocker-а, вместо мгновенного самоблокирующего abort-а.

---

## Bug #315: не откатывать обратно на `pid_off=0x60`, если в kernproc probe уже подтверждён `pid_off=0xd8` (2026-04-02)

**Symptom:** в свежем runtime `detect_kernproc_variable()` находил рабочий `pid_off=0xd8` (`Bug #267A: ... ACCEPTED`), но затем в ветке `Bug #303` этот offset принудительно отбрасывался (`discarding probed pid_off=0xd8, keeping confirmed default 0x60`). После этого chain validation шла по неверному `0x60`, кандидат `0x3213678` отклонялся, и `ourproc()` стабильно падал с `kernprocaddress() returned 0`.

**File:** `darksword/utils.m`

**Root cause:** защитный фикс Bug #303 был слишком жёстким: при `proc0.le_prev == candidate` код всегда сбрасывал корректно найденный `pid_off` и проверял цепочку только дефолтным оффсетом, что на этом девайсе давало false reject.

**Fix:** валидация теперь использует `discovered_pid_off` в приоритете (включая `le_prev` back-reference case). Если forward chain с найденным offset не проходит, добавлен контролируемый fallback: повторная проверка с дефолтным `0x60`.

**Expected effect:** кандидат `0x3213678` больше не должен отбрасываться исключительно из-за принудительного возврата к `pid_off=0x60`; шанс пройти `allproc -> kernproc -> ourproc` на реальном устройстве должен заметно вырасти.

---

## Bug #314: `krw_sockets_leak_forever()` must be deferred until `ourproc()` and `ourtask()` succeed (2026-04-02)

**Symptom:** even after Bug #313, manual app close still produced a kernel panic. The fresh panic moved to `rw_socket_pcb + 0x148` itself: [panic-full-2026-04-02-214225.0002.ips](log/panics_2026-04-02_21-43-26/panic-full-2026-04-02-214225.0002.ips#L8-L10) reported `0xffffffdfeada8548 not in the expected zone data.kalloc.32[41], but found in kalloc.type1.1024[293]`, i.e. inside `struct inpcb`.

**File:** `darksword/darksword_core.m`

**Root cause:** the session enabled `krw_sockets_leak_forever()` immediately after early KRW was ready, before `ourproc()` and `ourtask()` proved that the run could continue. When `ourproc()` later failed, the abort path inherited a leak-hardened corrupted socket state. On manual process termination, teardown still touched the embedded `icmp6filt` slot inside `struct inpcb`, which is never a valid `data.kalloc.32` object.

**Fix:** moved `krw_sockets_leak_forever()` to the success-only path after both `ourproc()` and `ourtask()` are valid. Failing sessions now abort while still in the pre-hardened state, where rollback/quarantine logic is safer than leak-hardened terminate-time teardown.

**Expected effect:** sessions that fail at `ourproc()`/`ourtask()` should stop entering the leak-hardened close-time panic path on manual app termination. Leak-hardening is now reserved only for runs that have already passed proc/task validation.

---

## Bug #313: panic-guard leak-hardening path must neutralize the last stale `target_kaddr` before app termination (2026-04-02)

**Symptom:** after Bug #312 removed the newest false `allproc` offsets, the user still observed a delayed device panic only when manually closing the app. Syslog showed `PANIC GUARD: leak-hardening already active — skipping icmp6filt rollback`, then `abort-cleanup: quarantine sockets without close`, and only later `UIApplication will terminate`. The panic happened after process teardown, not during the original probe.

**File:** `darksword/darksword_core.m`

**Root cause:** in the leak-hardened abort path the code intentionally skipped rollback and only quarantined the corrupted fds. That left `icmp6filt qword0` holding the last speculative `target_kaddr` touched by `set_target_kaddr()`. When the process was manually killed, kernel socket teardown could still observe that stale fake target and panic during late cleanup.

**Fix:** added explicit abort-time neutralization for the leak-hardened path. Before quarantining the fds, `panic_guard_abort_cleanup()` now parks the corrupted filter target back onto its self-slot (`rw_socket_pcb + 0x148`) via `set_target_kaddr()`, preserving the no-rollback policy while clearing the last stale probe target.

**Expected effect:** manual app close after a leak-hardened PANIC GUARD abort should stop inheriting the final fake `allproc`/probe target into process teardown, reducing the delayed terminate-time kernel panic risk.

---

## Bug #312: auto-curated direct/XPF lists for `21D61` must also skip known-bad offset `0x3214850` (2026-04-02)

**Symptom:** after Bug #311 removed `0x3213EC8` from builtin XPF-lite, the next full panic moved to `0xffffffe3f16d0fa0`. Syslog correlated it with automatic candidate `0x3214850`, first through the direct shortlist and then again through builtin XPF-lite.

**File:** `darksword/utils.m`

**Fix:** removed `0x3214850` from the builtin `21D61` XPF-lite list and removed both `0x3214850` and `0x3213EC8` from the automatic direct curated lists. These offsets remain available only for explicit manual probing.

**Expected effect:** the default runtime path should stop touching the repeatedly false/panic-prone candidates `0x3214850` and `0x3213EC8`, leaving only the still-informative curated candidates in automatic direct/XPF fallback.

---

## Bug #311: builtin XPF-lite list for `21D61` must skip known-bad offset `0x3213EC8` (2026-04-02)

**Symptom:** after Bug #310 removed the old `head + 0x8` path, the next full panic moved to the fake head itself: `0xffffffe0d71da090`. Syslog correlated it directly with builtin XPF-lite candidate `0x3213ec8` on build `21D61`.

**File:** `darksword/utils.m`

**Fix:** removed `0x3213EC8` from the curated builtin XPF-lite offsets for `21D61`. The offset remains manually testable through `DS_XPF_OFFSETS`, but it is no longer exercised automatically in the default runtime path.

**Expected effect:** the device should stop touching the repeatedly false/panic-prone `0x3213ec8` candidate during builtin XPF-lite fallback, removing the newest panic source while preserving the other builtin candidates.

---

## Bug #310: staged qword guards must not read `head + 0x8` when `head + 0x0` already proves a fake head (2026-04-02)

**Symptom:** after Bug #309 closed the old `head - 0x50` SMRQ pid-probe path, the next full panic moved back to `0xffffffe0cce15ae8`, which is exactly `head + 0x8` for fake head `0xffffffe0cce15ae0`.

**File:** `darksword/utils.m`

**Fix:** added staged head-link helpers for the early direct/SMRQ guards. The code now reads `head + 0x00` first and reads `head + 0x08` only when `q0 == 0` and a second chance is genuinely needed. This removes unconditional `+0x8` reads on already-rejectable fake heads in both `validate_allproc()` and `detect_kernproc_variable()`.

**Expected effect:** fake heads like `0xffffffe0cce15ae0` should be rejected from `q0` alone without touching `head + 0x8`, closing the new panic path at `0xffffffe0cce15ae8`.

---

## Bug #309: validate_allproc must check SMRQ link qwords before reading `(head - 0xb0) + pid_off` (2026-04-02)

**Symptom:** after Bug #308 blocked the new fake `kernproc detect` candidates earlier, the next full panic still occurred at `0xffffffe2003d8780`.

**File:** `darksword/utils.m`

**Fix:** reordered the SMRQ preflight in `validate_allproc()`. The code now validates the candidate head's first two qwords first, and only performs the `(head - 0xb0) + PROC_PID_OFFSET` PID read if the head already looks like a plausible SMRQ/list entry.

**Expected effect:** fake SMRQ heads like `0xffffffe2003d87d0` should be rejected before any read at `head - 0x50`, closing the new panic path at `0xffffffe2003d8780`.

---

## Bug #308: detect_kernproc_variable must not pid-probe a fake SMRQ/direct head (2026-04-02)

**Symptom:** after Bug #307, the old false direct-head path was blocked earlier, but a fresh full panic still occurred at `0xffffffe261341650`. Syslog correlated it with `detect_kernproc_variable()` on candidate `0x3213ec8`: `entry_ptr=0xffffffe2613416a0`, then `interp2` read `(entry_ptr - 0xb0) + 0x60`, which is exactly `0xffffffe261341650`.

**File:** `darksword/utils.m`

**Fix:** added an early structural guard inside `detect_kernproc_variable()` based on the first two qwords of `entry_ptr`. The direct `interp1` pid probe now runs only if the head already looks like a plausible direct proc head, and the SMRQ `interp2` pid probe now runs only if the entry already looks like a plausible SMRQ/list entry.

**Expected effect:** false kernproc-detect candidates like `entry_ptr=0xffffffe2613416a0` should be rejected before any read of `(entry_ptr - 0xb0) + 0x60`, closing the new panic path at `0xffffffe261341650`.

---

## Bug #307: direct `proc_base` preflight must require a real link qword, not only a small PID (2026-04-02)

**Symptom:** after Bug #306, one fake XPF-lite head was rejected earlier, but candidate `0xffffffe3fbe0b400` still reached `disc_layout FAILED`; the new full panic again matched the same object at `0xffffffe3fbe0b408 = head + 0x8`.

**File:** `darksword/utils.m`

**Fix:** hardened the direct `proc_base` interpretation inside `validate_allproc()`. A plausible PID at `head + 0x60` is no longer enough on its own; at least one of `head+0x00` or `head+0x08` must also be a non-zero heap pointer after PAC stripping.

**Expected effect:** false direct-head candidates with coincidental small PID values should be rejected before `discover_proc_list_layout()`, closing the new late panic path correlated with `head + 0x8`.

---

## Bug #297: XPF-lite env fallback for allproc offsets (2026-04-02)

**Symptom:** after direct shortlist exhaustion, there was no safe runtime path to try offline patchfinder offsets before deep scan fallbacks.

**File:** `darksword/utils.m`

**Fix:** added `DS_XPF_OFFSETS` parsing (comma/semicolon/space separated). Supports offsets and absolute kptr values (normalized by kbase), validates each candidate via existing `validate_allproc()`, and runs before scan fallback.

**Expected effect:** faster controlled validation of offline-derived allproc candidates without enabling risky broad scans.

---

## Bug #299: skip unsafe zone scan after PID=0-only kernproc chain (2026-04-02)

**Symptom:** fresh device run reached `ourproc()` with a confirmed `kernproc` candidate, but the walked chain contained only PID 0 entries; immediately after `Bug #296/299: zone scan ...` the device panicked with `zone bound checks`, panicked task `DarkSword`.

**File:** `darksword/utils.m`

**Fix:** added a fail-fast guard before zone scan fallbacks. If the resolved chain is long enough to be meaningful but still has `max_pid_seen == 0`, `ourproc()` now logs the kernel-only-chain condition and returns failure instead of entering blind zone scanning.

**Expected effect:** prevents the known panic path on iOS 17.3.1 when the accepted `kernproc` candidate never escapes PID 0 / kernel-thread territory.

---

## Bug #300: skip alt-list / alt-next probes after empty backward walk on PID-0-only chain (2026-04-02)

**Symptom:** a fresh device run no longer reached the old zone-scan fallback first. Instead, `ourproc()` stayed in a PID-0-only chain, `Bug #243A` backward walk found zero procs, then `Bug #243B` / `alt next_off` probes were attempted and the log immediately degraded into repeated `getsockopt failed (early_kread)!` spam before the next panic.

**File:** `darksword/utils.m`

**Fix:** added a new fail-fast guard before alternative list-offset and reversed-link probes. When the forward chain is already long enough, `max_pid_seen == 0`, and backward walk produced zero real procs, `ourproc()` now returns failure immediately instead of performing speculative alt-link reads.

**Expected effect:** avoids the newly observed primitive-destabilization path where `early_kread` collapses right after `Bug #243A: backward walk checked 0 procs...`.

---

## Р‘Р°Рі #283: СЃР»РёС€РєРѕРј Р°РіСЂРµСЃСЃРёРІРЅС‹Р№ socket spray + СѓСЂРµР·Р°РЅРЅС‹Р№ entitlement merge РїРѕРІС‹С€Р°Р»Рё СЂРёСЃРє close-time panic (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РґР°Р¶Рµ РїРѕСЃР»Рµ Bug #282 С‡Р°СЃС‚СЊ СЃРµСЃСЃРёР№ РѕСЃС‚Р°РІР°Р»Р°СЃСЊ РЅРµСЃС‚Р°Р±РёР»СЊРЅРѕР№: РїСЂРё С‚СЏР¶С‘Р»РѕРј spray Рё РїРѕСЃР»РµРґСѓСЋС‰РµРј teardown РЅР°Р±Р»СЋРґР°Р»РёСЃСЊ `bug_type 210`/`Kernel data abort`.

**Root cause:**
- РІ `pe_v1`/`pe_v2` РёСЃРїРѕР»СЊР·РѕРІР°Р»РёСЃСЊ РІС‹СЃРѕРєРёРµ default-Р»РёРјРёС‚С‹ spray (РґРѕ ~22528 СЃРѕРєРµС‚РѕРІ), С‡С‚Рѕ РїРѕРІС‹С€Р°Р»Рѕ РґР°РІР»РµРЅРёРµ РЅР° teardown path;
- РІ `build_sign_install.sh` merge entitlements РїРµСЂРµРЅРѕСЃРёР» С‚РѕР»СЊРєРѕ dev-РєР»СЋС‡Рё Рё РЅРµ РїРѕРґС‚СЏРіРёРІР°Р» РјРёРЅРёРјР°Р»СЊРЅС‹Рµ runtime-РєР»СЋС‡Рё, СЃРѕРІРїР°РґР°СЋС‰РёРµ СЃРѕ СЃС‚Р°Р±РёР»СЊРЅС‹Рј СЂРµС„РµСЂРµРЅСЃРѕРј (`platform-application`, `com.apple.private.security.no-container`).

**Р¤Р°Р№Р»С‹:** `darksword/darksword_core.m`, `build_sign_install.sh`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґР»СЏ `pe_v1` РІРІРµРґС‘РЅ conservative default cap: `V1_SOCKET_SPRAY_TARGET=12288`;
- РґР»СЏ `pe_v2` cap СЃРЅРёР¶РµРЅ РґРѕ `V2_SOCKET_SPRAY_TARGET=0x3800`;
- entitlement allowlist СЂР°СЃС€РёСЂРµРЅ РґРІСѓРјСЏ С‚РѕС‡РµС‡РЅС‹РјРё РєР»СЋС‡Р°РјРё: `platform-application`, `com.apple.private.security.no-container`.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РјРµРЅСЊС€Р°СЏ С‚СѓСЂР±СѓР»РµРЅС‚РЅРѕСЃС‚СЊ РІ exploit/teardown lifecycle Рё Р»СѓС‡С€Р°СЏ runtime-РїР°СЂРёС‚РµС‚РЅРѕСЃС‚СЊ СЃ РїСЂРёР»РѕР¶РµРЅРёРµРј-СЂРµС„РµСЂРµРЅСЃРѕРј Р±РµР· СЂР°СЃС€РёСЂРµРЅРёСЏ merge РґРѕ РїРѕР»РЅРѕРіРѕ РЅР°Р±РѕСЂР° private-keys.

---

## Bug #302: false-positive после `corruption stuck` оставлял повреждённый sprayed socket без rollback (2026-04-02, session 25f)

**Symptom:** после `Bug #301` panic больше не указывал на финальный `rw_socket_pcb + 0x150`, но свежий full panic всё ещё был `panicked task: DarkSword` с новой zone/type mismatch сигнатурой: expected `data.kalloc.32`, found `shared.kalloc.4096`. Это указывало, что teardown ломается уже на другом `inpcb`, а не на финальном KRW socket.

**Root cause:** в `find_and_corrupt_socket()` существовала false-positive ветка: corruption уже успевала записаться в candidate socket, но marker-проверка показывала, что это не настоящий control-socket. Код в этом случае просто делал `close(sock)` и продолжал поиск, не восстанавливая `icmp6filt` у уже испорченного sprayed socket. Затем `sockets_release()` освобождал такой socket, и kernel поздно падал в zone free path.

**File:** `darksword/darksword_core.m`

**Fix:**
- в false-positive ветке добавлен немедленный `restore_corrupted_socket_filter_best_effort()`;
- после rollback очищается snapshot/pcb state кандидата;
- временный fd закрывается только после rollback.

**Expected effect:** false-positive candidates больше не должны оставлять скрыто повреждённые sprayed sockets, которые позже падают уже вне финального `rw_socket_pcb` path.

---

## Bug #303: `proc0.le_prev == candidate` больше не auto-accept-ит ложный `kernproc` (2026-04-02, session 25f)

**Symptom:** после Bug #302 runtime стабильно доходил до `KERNPROC detected at ... offset 0x3213678`, но `ourproc()` видел только соседнюю `PID=0` chain и завершался fail-fast. Новый panic указывал на `0xffffffe304644008`, то есть почти `kernel_task + 0x8`, а не на прежний socket teardown path.

**Root cause:** логика Bug #295 считала `proc0.le_prev == candidate` окончательным доказательством real `allproc` и пропускала `Bug #268` chain validation. На текущем boot этого оказалось недостаточно: ложный кандидат тоже имел корректный LIST_HEAD back-reference, но дальше вёл только по kernel-only `PID=0` объектам вокруг `kernel_task`.

**File:** `darksword/utils.m`

**Fix:**
- `proc0.le_prev == candidate` теперь рассматривается только как structural hint;
- даже при таком back-reference кандидат обязан пройти chain validation;
- для такого validation принудительно сохраняется подтверждённый default `pid_off=0x60`, а tentative PID probe отбрасывается.

**Expected effect:** false-positive `kernproc` candidates с формально корректным `le_prev` back-reference, но без реального пользовательского proc list, больше не должны приниматься.

---

## Bug #304: automatic Mach-O parse scan disabled by default after shortlist/XPF-lite exhaustion (2026-04-02, session 25f)

**Symptom:** after Bug #303, runtime no longer accepted the false `0x3213678/0x3213680` `kernproc` path. However, once direct candidates and builtin XPF-lite were exhausted, the code automatically entered `falling back to Mach-O parse scan...`, logged `reading scan chunk at 0xfffffff022180000`, then the device disconnected/reconnected and produced a new `bug_type 210` with `Panicked task: DarkSword`.

**Root cause:** the narrowed Mach-O-based `allproc` scan is still too risky as an automatic fallback on unstable post-exploit runtime sessions. In the fresh 21D61 run it no longer contributes a successful resolve, but it can still escalate a recoverable `allproc not found` condition into a kernel data abort during speculative scan reads.

**File:** `darksword/utils.m`

**Fix:**
- changed Mach-O parse scan from default-on to explicit opt-in;
- it now runs only when `DS_ENABLE_MACHO_SCAN=1` is set;
- default path logs a safe disabled-by-default message and proceeds to controlled failure.

**Expected effect:** when direct shortlist and XPF-lite candidates fail, the app should now fail fast instead of entering the newly observed scan-time panic path.

---

## Bug #305: reject non-proc-looking `allproc` heads before `disc_pl` (2026-04-02, session 25f)

**Symptom:** after Bug #304 the fresh syslog already showed the desired clean abort (`ourproc()==0`), but the newest full panic still remained and pointed at `0xffffffe21ca1b748`. Earlier in the same session, `validate_allproc()` had accepted a heap-looking head `0xffffffe21ca1b740` far enough to enter `disc_layout FAILED`, and the panic address matched that same object at `+0x8`.

**Root cause:** `validate_allproc()` only rejected heads that were obviously non-heap. That still allowed some zone objects to pass the first gate and reach `discover_proc_list_layout()`, where deeper structural probing (`raw+0x00`, `raw+0x08`, chain/layout reads) was performed even though the head did not yet look like either a real `proc_base` or a `proc_base+0xb0` list entry.

**File:** `darksword/utils.m`

**Fix:**
- added an early plausibility preflight in `validate_allproc()`;
- before `disc_pl`, the head must now already look like either `proc_base` or `proc_base+0xb0` by having a plausible PID at `+0x60`;
- if neither interpretation yields a plausible PID, the candidate is rejected immediately with a new Bug #305 log.

**Expected effect:** false `allproc` heads like `0xffffffe21ca1b740` should now be filtered out before deep layout discovery, reducing the late panic path that correlates with probing `+0x8` of that object.

---

## Bug #306: require structurally plausible link qwords for `proc_base+0xb0` heads (2026-04-02, session 25f)

**Symptom:** after Bug #305, the old false head near `0xffffffe21ca1b740` disappeared from the fresh logs, but a new panic still occurred at `0xffffffe848901208`. The same run showed `xpf-lite offset 0x3213ec8 -> head 0xffffffe848901200`, immediately followed by `disc_pl diag: pid=0x6c707041 [raw+0x00]=0x800000fa22000000 [raw+0x08]=0x0` and then `disc_layout FAILED`.

**Root cause:** Bug #305 only checked PID plausibility for the two coarse interpretations (`proc_base` and `proc_base+0xb0`). In the `proc_base+0xb0` case, a random zone object can still expose a small value at `(head-0xb0)+0x60` by coincidence, even when the entry itself is obviously not a live linked-list node.

**File:** `darksword/utils.m`

**Fix:**
- kept the existing PID plausibility preflight;
- added an extra structural guard for the `proc_base+0xb0` interpretation;
- now at least one of `head+0x00` or `head+0x08` must be a non-zero kernel pointer after PAC stripping, otherwise the candidate is rejected before `disc_pl`.

**Expected effect:** fake SMRQ-like heads such as `0xffffffe848901200` should no longer reach deep layout probing, reducing the new late panic path that matched `head + 0x8`.

---

## Bug #301: panic-guard rollback после `krw_sockets_leak_forever()` снова трогал `icmp6filt` и оставлял late-teardown panic (2026-04-02, session 25f)

**Symptom:** несмотря на `Bug #300` и controlled abort, свежий panic log всё ещё показывал `panicked task: DarkSword`, а panic-адрес указывал на `rw_socket_pcb + 0x150` уже ПОСЛЕ guard-abort cleanup.

**Root cause:** после успешного `krw_sockets_leak_forever()` сокеты уже находятся в leak/hardened режиме. Дополнительный rollback `icmp6filt` в `panic_guard_abort_cleanup()` повторно модифицировал embedded filter-slot внутри `inpcb`, хотя teardown уже должен был идти только по quarantine/leak path.

**File:** `darksword/darksword_core.m`

**Fix:**
- добавлен флаг активированного leak-hardening;
- после успешного `krw_sockets_leak_forever()` panic-guard abort больше не вызывает rollback `icmp6filt`;
- abort-path оставляет только quarantine fd/pcb state.

**Expected effect:** late post-abort zone panic на `rw_socket_pcb + 0x150` должен исчезнуть в сессиях, где KRW уже успел включить leak-hardening.

---

## Р‘Р°Рі #284: rollback РІС‚РѕСЂРѕРіРѕ qword `icmp6filt` РїРѕСЃР»Рµ PANIC GUARD РІРѕР·РІСЂР°С‰Р°Р» РЅРµСЃС‚Р°Р±РёР»СЊРЅРѕРµ СЃРѕСЃС‚РѕСЏРЅРёРµ Рё РїСЂРѕРІРѕС†РёСЂРѕРІР°Р» zone panic (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ СЃСЂР°Р±Р°С‚С‹РІР°РЅРёСЏ Bug #282 (`-2`, stop-retry) РІ СЃРІРµР¶РµРј panic РѕСЃС‚Р°РІР°Р»СЃСЏ `bug_type 210`, РЅРѕ СѓР¶Рµ РІ `zalloc.c`:
- `not in the expected zone data.kalloc.32 ... found in kalloc.type0.1024`
- Р°РґСЂРµСЃ panic: `rw inpcb + 0x150` (РІС‚РѕСЂРѕР№ qword `icmp6filt`).

**Root cause:** abort cleanup РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°Р» РѕР±Р° snapshot-qword `icmp6filt`, РІРєР»СЋС‡Р°СЏ РІС‚РѕСЂРѕР№ qword, РєРѕС‚РѕСЂС‹Р№ РІ СЂСЏРґРµ СЃРµСЃСЃРёР№ РІРѕР·РІСЂР°С‰Р°Р» С‚РѕРєСЃРёС‡РЅРѕРµ teardown-СЃРѕСЃС‚РѕСЏРЅРёРµ РЅРµСЃРјРѕС‚СЂСЏ РЅР° stop-retry.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РІ `restore_corrupted_socket_filter_best_effort()` РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёРµ РїРµСЂРµРІРµРґРµРЅРѕ РІ conservative СЂРµР¶РёРј:
  - `qword0` РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ РёР· snapshot;
  - `qword1` РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕ Р·Р°РЅСѓР»СЏРµС‚СЃСЏ (`0`) РІРјРµСЃС‚Рѕ restore snapshot-Р·РЅР°С‡РµРЅРёСЏ.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** СЃРЅРёР¶РµРЅРёРµ СЂРёСЃРєР° post-abort zone panic РЅР° close/teardown path РїСЂРё СЃРѕС…СЂР°РЅРµРЅРёРё РєРѕСЂСЂРµРєС‚РЅРѕРіРѕ rollback РїРµСЂРІРёС‡РЅРѕРіРѕ corruption-СЃР»РѕС‚Р°.

---

## Р‘Р°Рі #285: fallback РЅР° inner `allproc` scan РїСЂРѕРІРѕС†РёСЂРѕРІР°Р» scan-time panic РїСЂРё РЅРµСЃС‚Р°Р±РёР»СЊРЅРѕРј KRW (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ РїСЂРѕРІР°Р»Р° direct-РєР°РЅРґРёРґР°С‚РѕРІ РїСЂРёР»РѕР¶РµРЅРёРµ СѓС…РѕРґРёР»Рѕ РІ:
- `direct candidates exhausted, falling back to scan`
- `starting inner-kernel DATA range scan...`
- Р·Р°С‚РµРј СЃРІРµР¶РёР№ `bug_type 210` / `Kernel data abort` (panicked task: `DarkSword`, pid 524).

**Root cause:** РІ РЅРµСЃС‚Р°Р±РёР»СЊРЅРѕР№ post-corruption СЃРµСЃСЃРёРё Р°РіСЂРµСЃСЃРёРІРЅС‹Р№ fallback-СЃРєР°РЅ (`scan_allproc_known_range`) Р·Р°РїСѓСЃРєР°Р»СЃСЏ РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ Рё РІС‹РїРѕР»РЅСЏР» РґР»РёРЅРЅСѓСЋ СЃРµСЂРёСЋ kernel reads РІ РјРѕРјРµРЅС‚, РєРѕРіРґР° KRW СѓР¶Рµ РґРµРіСЂР°РґРёСЂРѕРІР°Р».

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- inner `allproc` scan РїРµСЂРµРІРµРґС‘РЅ РІ explicit opt-in:
  - РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ **РІС‹РєР»СЋС‡РµРЅ**;
  - РІРєР»СЋС‡Р°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РїСЂРё `DS_ENABLE_ALLPROC_SCAN=1`.
- РїСЂРё РІС‹РєР»СЋС‡РµРЅРЅРѕРј scan РїСѓС‚СЊ РґРµР»Р°РµС‚ Р±РµР·РѕРїР°СЃРЅС‹Р№ fail-fast Р±РµР· deep scan.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РёСЃРєР»СЋС‡РµРЅРёРµ scan-time panic СЃС†РµРЅР°СЂРёСЏ Рё РїРµСЂРµРІРѕРґ РЅРµСѓСЃРїРµС€РЅС‹С… СЃРµСЃСЃРёР№ РІ РєРѕРЅС‚СЂРѕР»РёСЂСѓРµРјС‹Р№ abort Р±РµР· kernel panic.

---

## Р‘Р°Рі #286: СЃР»РёС€РєРѕРј С€РёСЂРѕРєРёР№ default direct-shortlist СѓРІРµР»РёС‡РёРІР°Р» СЂРёСЃРє РґРµРіСЂР°РґР°С†РёРё РїРµСЂРµРґ fail-fast (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РґР°Р¶Рµ РїРѕСЃР»Рµ РѕС‚РєР»СЋС‡РµРЅРёСЏ scan fallback С‡Р°СЃС‚СЊ СЃРµСЃСЃРёР№ РїСЂРѕС…РѕРґРёР»Р° С‡РµСЂРµР· Р»РёС€РЅРёРµ direct-РєР°РЅРґРёРґР°С‚С‹ РґРѕ controlled-abort, СЃРѕР·РґР°РІР°СЏ Р»РёС€РЅСЋСЋ РЅР°РіСЂСѓР·РєСѓ РЅР° РЅРµСЃС‚Р°Р±РёР»СЊРЅС‹Р№ KRW.

**Root cause:** default-СЂРµР¶РёРј direct shortlist Р±С‹Р» `safe` (5 РєР°РЅРґРёРґР°С‚РѕРІ). РќР° РЅРµСЃС‚Р°Р±РёР»СЊРЅРѕР№ С„Р°Р·Рµ РїСЂРµРґРїРѕС‡С‚РёС‚РµР»СЊРЅРµРµ РјРёРЅРёРјР°Р»СЊРЅС‹Р№ probe-budget.

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`, `ipsw_analysis/offline_test_v24.py`, `ipsw_analysis/run_custom_trainings.py`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅС‹ custom-training СЃРєСЂРёРїС‚С‹ v24 РґР»СЏ РїРµСЂРµСЃРєРѕСЂРёРЅРіР° shortlist РЅР° С‚РµРєСѓС‰РµРј `kernelcache`;
- РІРІРµРґС‘РЅ СЂРµР¶РёРј `DS_DIRECT_MODE={minimal|safe|full}`;
- default РїРµСЂРµРєР»СЋС‡С‘РЅ РЅР° `minimal` (С‚РѕР»СЊРєРѕ `0x3213678`, `0x3213680`);
- `full` РѕСЃС‚Р°С‘С‚СЃСЏ С‡РµСЂРµР· `DS_ENABLE_DATA_DIRECT=1` РёР»Рё `DS_DIRECT_MODE=full`.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РјРµРЅСЊС€Р°СЏ РЅР°РіСЂСѓР·РєР° РЅР° fragile KRW-path Рё Р±РѕР»РµРµ Р±С‹СЃС‚СЂС‹Р№ Р±РµР·РѕРїР°СЃРЅС‹Р№ РІС‹С…РѕРґ РїСЂРё РЅРµСѓРґР°С‡РЅРѕРј direct-resolve.

---

## Р‘Р°Рі #287: `PROC_PID_OFFSET` РєРѕРјРјРёС‚РёР»СЃСЏ РґРѕ С„РёРЅР°Р»СЊРЅРѕР№ РІР°Р»РёРґР°С†РёРё РєР°РЅРґРёРґР°С‚Р° Рё РѕС‚СЂР°РІР»СЏР» РїРѕСЃР»РµРґСѓСЋС‰РёРµ РїСЂРѕРІРµСЂРєРё (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ Р»РѕРіР°С… РїРѕСЏРІР»СЏР»РѕСЃСЊ `PID offset CHANGED 0x60 -> 0xd8`, Р·Р°С‚РµРј С‚РѕС‚ Р¶Рµ РєР°РЅРґРёРґР°С‚ РѕС‚РєР»РѕРЅСЏР»СЃСЏ РєР°Рє false, РЅРѕ РїРѕСЃР»РµРґСѓСЋС‰РёРµ direct/kernproc РїСЂРѕРІРµСЂРєРё СѓР¶Рµ СЂР°Р±РѕС‚Р°Р»Рё СЃ Р»РѕР¶РЅС‹Рј `pid_off=0xd8`, С‡С‚Рѕ СѓСЃРєРѕСЂСЏР»Рѕ `allproc not found`.

**Root cause:** РІ `detect_kernproc_variable()` РіР»РѕР±Р°Р»СЊРЅС‹Р№ `PROC_PID_OFFSET` РјРµРЅСЏР»СЃСЏ СЃСЂР°Р·Сѓ РїРѕСЃР»Рµ РїСЂРѕРјРµР¶СѓС‚РѕС‡РЅРѕРіРѕ PID-probe, РґРѕ `validate_kernproc_forward_chain()`. РџСЂРё reject РєР°РЅРґРёРґР°С‚Р° РёР·РјРµРЅРµРЅРёРµ РѕСЃС‚Р°РІР°Р»РѕСЃСЊ РіР»РѕР±Р°Р»СЊРЅРѕ Р°РєС‚РёРІРЅС‹Рј.

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РІРІРµРґС‘РЅ Р°С‚РѕРјР°СЂРЅС‹Р№ commit-СЃС†РµРЅР°СЂРёР№ РґР»СЏ PID offset:
  - СЃРЅР°С‡Р°Р»Р° РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ `tentative` offset С‚РѕР»СЊРєРѕ РґР»СЏ Р»РѕРєР°Р»СЊРЅРѕР№ РІР°Р»РёРґР°С†РёРё РєР°РЅРґРёРґР°С‚Р°;
  - РіР»РѕР±Р°Р»СЊРЅС‹Р№ `PROC_PID_OFFSET` РѕР±РЅРѕРІР»СЏРµС‚СЃСЏ С‚РѕР»СЊРєРѕ РїРѕСЃР»Рµ СѓСЃРїРµС€РЅРѕР№ validation;
  - РїСЂРё reject РєР°РЅРґРёРґР°С‚Р° offset СЃРѕС…СЂР°РЅСЏРµС‚СЃСЏ/РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ РЅР° РёСЃС…РѕРґРЅРѕРµ Р·РЅР°С‡РµРЅРёРµ.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** Р»РѕР¶РЅС‹Р№ `pid_off` Р±РѕР»СЊС€Рµ РЅРµ РїСЂРѕС‚РµРєР°РµС‚ РјРµР¶РґСѓ РєР°РЅРґРёРґР°С‚Р°РјРё, СѓРјРµРЅСЊС€Р°РµС‚СЃСЏ cascade-failure РІ direct/kernproc phase.

---

## Р‘Р°Рі #288: tail-`kernproc` РєР°РЅРґРёРґР°С‚ РѕС‚РєР»РѕРЅСЏР»СЃСЏ РёР·-Р·Р° РїСЂРѕРІРµСЂРєРё С‚РѕР»СЊРєРѕ forward-С†РµРїРѕС‡РєРё (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ СЃРІРµР¶РµРј runtime (`syslog_2026-04-02_06-29-43`) РєР°РЅРґРёРґР°С‚ `0x3213680` РїРѕРєР°Р·С‹РІР°Р» РІР°Р»РёРґРЅС‹Р№ `kernel_task pid=0`, РЅРѕ `validate_kernproc_forward_chain()` РґР°РІР°Р» `len=1`, РїРѕСЃР»Рµ С‡РµРіРѕ РєР°РЅРґРёРґР°С‚ РѕС‚РІРµСЂРіР°Р»СЃСЏ Рё СЃРµСЃСЃРёСЏ СѓС…РѕРґРёР»Р° РІ `allproc not found`.

**Root cause:** `detect_kernproc_variable()` РІР°Р»РёРґРёСЂРѕРІР°Р» С‚РѕР»СЊРєРѕ forward-РїСЂРѕС…РѕРґ РѕС‚ `kernel_task`. Р”Р»СЏ tail-РєРµР№СЃР° СЌС‚Рѕ РѕР¶РёРґР°РµРјРѕ РєРѕСЂРѕС‚РєР°СЏ С†РµРїРѕС‡РєР°; РІР°Р»РёРґРЅС‹Р№ СЃРёРіРЅР°Р» РЅР°С…РѕРґРёС‚СЃСЏ РІ backward-РЅР°РїСЂР°РІР»РµРЅРёРё РїРѕ `le_prev`.

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ `validate_kernproc_backward_chain()`;
- РµСЃР»Рё forward-РІР°Р»РёРґР°С†РёСЏ СЃР»Р°Р±Р°СЏ Рё `le_prev` СѓРєР°Р·С‹РІР°РµС‚ РІ heap, РІРєР»СЋС‡Р°РµС‚СЃСЏ fallback backward-walk РїРѕ `le_prev`;
- РєР°РЅРґРёРґР°С‚ РїСЂРёРЅРёРјР°РµС‚СЃСЏ РїСЂРё С‚РµС… Р¶Рµ РєСЂРёС‚РµСЂРёСЏС… РєР°С‡РµСЃС‚РІР° (РЅР°С€ PID РёР»Рё РґРѕСЃС‚Р°С‚РѕС‡РЅР°СЏ РґР»РёРЅР°+diversity).

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РєРѕСЂСЂРµРєС‚РЅС‹Рµ tail-`kernproc` РєР°РЅРґРёРґР°С‚С‹ РїРµСЂРµСЃС‚Р°СЋС‚ Р»РѕР¶РЅРѕ РѕС‚Р±СЂР°СЃС‹РІР°С‚СЊСЃСЏ РЅР° `len=1` forward-path, С‡С‚Рѕ РїРѕРІС‹С€Р°РµС‚ С€Р°РЅСЃ СѓСЃРїРµС€РЅРѕРіРѕ `ourproc()` Р±РµР· РІРєР»СЋС‡РµРЅРёСЏ РѕРїР°СЃРЅС‹С… scan fallback.

---

## Р‘Р°Рі #289: backward-РІР°Р»РёРґР°С†РёСЏ tail-РєР°РЅРґРёРґР°С‚Р° Р·Р°РІРёСЃРµР»Р° РѕС‚ С„РёРєСЃРёСЂРѕРІР°РЅРЅРѕРіРѕ `pid_off=0x60` Рё РїСЂРѕРїСѓСЃРєР°Р»Р° СЂРµР°Р»СЊРЅС‹Р№ ourpid-path (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ `syslog_2026-04-02_06-35-03` РїРѕСЃР»Рµ РІРєР»СЋС‡РµРЅРёСЏ Bug #288 РІС‹РїРѕР»РЅСЏР»СЃСЏ backward-walk (`len=11`), РЅРѕ `unique_nonzero=0` РїСЂРё `pid_off=0x60`; РєР°РЅРґРёРґР°С‚ РІСЃС‘ СЂР°РІРЅРѕ РѕС‚РєР»РѕРЅСЏР»СЃСЏ РєР°Рє false.

**Root cause:** fallback backward-РІР°Р»РёРґР°С†РёСЏ РёСЃРїРѕР»СЊР·РѕРІР°Р»Р° С‚РѕР»СЊРєРѕ РѕРґРёРЅ `pid_off` (С‚РµРєСѓС‰РёР№/tentative). Р”Р»СЏ tail-РєРµР№СЃР° СЌС‚Рѕ РјРѕРі Р±С‹С‚СЊ РЅРµРІРµСЂРЅС‹Р№ offset, РёР·-Р·Р° С‡РµРіРѕ РІР°Р»РёРґРЅР°СЏ С†РµРїРѕС‡РєР° РЅРµ РЅР°С…РѕРґРёР»Р° РЅР°С€ PID.

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ `probe_kernproc_backward_pid_offset_for_ourpid()`;
- РїСЂРё РїСЂРѕРІР°Р»Рµ СЃС‚Р°РЅРґР°СЂС‚РЅРѕР№ backward-РІР°Р»РёРґР°С†РёРё РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ СЃС‚СЂРѕРіРёР№ РїРµСЂРµР±РѕСЂ РЅР°Р±РѕСЂР° PID-offset (0x60/0xd8/0x90/вЂ¦);
- РєР°РЅРґРёРґР°С‚ РїСЂРёРЅРёРјР°РµС‚СЃСЏ **С‚РѕР»СЊРєРѕ** РµСЃР»Рё РІ backward-С†РµРїРѕС‡РєРµ РЅР°Р№РґРµРЅ `ourpid` (Р±РµР· РѕСЃР»Р°Р±Р»РµРЅРёСЏ РїРѕСЂРѕРіРѕРІ diversity);
- РїСЂРё СѓСЃРїРµС…Рµ РЅР°Р№РґРµРЅРЅС‹Р№ `pid_off` РєРѕРјРјРёС‚РёС‚СЃСЏ С‡РµСЂРµР· СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ Р±РµР·РѕРїР°СЃРЅС‹Р№ РїСѓС‚СЊ Bug #286A.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** СЃРЅРёР¶РµРЅРёРµ Р»РѕР¶РЅС‹С… reject РґР»СЏ tail-`kernproc` Р±РµР· СЂР°СЃС€РёСЂРµРЅРёСЏ scan-path Рё Р±РµР· РѕСЃР»Р°Р±Р»РµРЅРёСЏ safety-РєСЂРёС‚РµСЂРёРµРІ.

---

## Р‘Р°Рі #290: РїРѕСЃР»Рµ РїСЂРѕРІР°Р»Р° `minimal` direct-shortlist РїСѓС‚СЊ Р·Р°РІРµСЂС€Р°Р»СЃСЏ fail-fast Р±РµР· РїРѕРїС‹С‚РєРё `safe` РєР°РЅРґРёРґР°С‚РѕРІ (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ `syslog_2026-04-02_06-41-27` `Bug #289` РѕС‚СЂР°Р±Р°С‚С‹РІР°Р» РєРѕСЂСЂРµРєС‚РЅРѕ, РЅРѕ РѕР±Р° `minimal` РєР°РЅРґРёРґР°С‚Р° (`0x3213678`, `0x3213680`) РѕС‚РєР»РѕРЅСЏР»РёСЃСЊ, РїРѕСЃР»Рµ С‡РµРіРѕ РєРѕРґ СЃСЂР°Р·Сѓ СѓС…РѕРґРёР» РІ `direct candidates exhausted` Рё fail-fast (scan РѕС‚РєР»СЋС‡С‘РЅ).

**Root cause:** default mode `minimal` РЅРµ РёРјРµР» Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРѕРіРѕ РїРµСЂРµС…РѕРґР° Рє `safe` shortlist РїСЂРё РїРѕР»РЅРѕРј РїСЂРѕРІР°Р»Рµ, С…РѕС‚СЏ С‚Р°РєРѕР№ С€Р°Рі Р·Р°РјРµС‚РЅРѕ Р±РµР·РѕРїР°СЃРЅРµРµ scan fallback Рё РґР°С‘С‚ РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅС‹Р№ С€Р°РЅСЃ РЅР° РІР°Р»РёРґРЅС‹Р№ direct-hit.

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ Р°РІС‚Рѕ-РїРµСЂРµС…РѕРґ `minimal -> safe` РґР»СЏ default-РєРѕРЅС„РёРіСѓСЂР°С†РёРё (РєРѕРіРґР° env РЅРµ Р·Р°РґР°РЅ);
- РїРѕСЃР»Рµ РїСЂРѕРІР°Р»Р° minimal-РїСЂРѕС…РѕРґР° Р·Р°РїСѓСЃРєР°РµС‚СЃСЏ РІС‚РѕСЂРѕР№ pass РїРѕ `safe` РєР°РЅРґРёРґР°С‚Р°Рј;
- scan fallback РѕСЃС‚Р°С‘С‚СЃСЏ РІС‹РєР»СЋС‡РµРЅРЅС‹Рј РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ (РїРѕРІРµРґРµРЅРёРµ Bug #285 СЃРѕС…СЂР°РЅРµРЅРѕ).

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** СЂР°СЃС€РёСЂРµРЅРёРµ direct-resolve coverage Р±РµР· РІРєР»СЋС‡РµРЅРёСЏ СЂРёСЃРєРѕРІР°РЅРЅС‹С… scan-path; РІ РЅРµСѓСЃРїРµС€РЅС‹С… СЃРµСЃСЃРёСЏС… СЃРѕС…СЂР°РЅСЏРµС‚СЃСЏ controlled abort.

---

## Р‘Р°Рі #291: `direct_v2` РѕС‚РєР»РѕРЅСЏР» РєР°РЅРґРёРґР°С‚Р° СЃ РІР°Р»РёРґРЅРѕР№ С†РµРїРѕС‡РєРѕР№, РµСЃР»Рё `PID` offset РѕС‚Р»РёС‡Р°Р»СЃСЏ РѕС‚ default 0x60 (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ СЃРІРµР¶РµРј runtime (`syslog_2026-04-02_06-46-12`) РїРѕСЃР»Рµ Bug #290 safe-pass Р·Р°РїСѓСЃРєР°Р»СЃСЏ РєРѕСЂСЂРµРєС‚РЅРѕ, РЅРѕ РЅР° `0x3213678`/`0x3213680` РѕСЃС‚Р°РІР°Р»РёСЃСЊ `chain=11` Рё `unique_pids=1`, Р·Р°С‚РµРј candidate РѕС‚РєР»РѕРЅСЏР»СЃСЏ Рё СЃРµСЃСЃРёСЏ СѓС…РѕРґРёР»Р° РІ `allproc not found`.

**Root cause:** `validate_direct_allproc_v2_with_layout()` РёСЃРїРѕР»СЊР·РѕРІР°Р» Р¶С‘СЃС‚РєРёР№ `PID` decode С‡РµСЂРµР· С‚РµРєСѓС‰РёР№ offset (РѕР±С‹С‡РЅРѕ `0x60`). РџСЂРё СЃРјРµС‰С‘РЅРЅРѕРј `pid_off` С„РѕСЂРјР° С†РµРїРѕС‡РєРё Р±С‹Р»Р° РїСЂР°РІРґРѕРїРѕРґРѕР±РЅРѕР№, РЅРѕ PID-diversity РІС‹РіР»СЏРґРµР»Р° В«РЅСѓР»РµРІРѕР№В», Рё РІР°Р»РёРґРЅС‹Р№ РєР°РЅРґРёРґР°С‚ РѕС‚Р±СЂР°СЃС‹РІР°Р»СЃСЏ РґРѕ РїРѕРїС‹С‚РєРё СЂРµР°Р»СЊРЅРѕРіРѕ `ourpid`-РїРѕРёСЃРєР° РЅР° СЌС‚РѕР№ Р¶Рµ С†РµРїРѕС‡РєРµ.

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ fallback `Bug #291` РІРЅСѓС‚СЂРё direct_v2:
  - РґР»СЏ РєР°РЅРґРёРґР°С‚РѕРІ СЃ СѓСЃС‚РѕР№С‡РёРІРѕР№ С†РµРїРѕС‡РєРѕР№ (`chain_len >= 8`) СЃРѕР±РёСЂР°РµС‚СЃСЏ forward-chain Р°РґСЂРµСЃРѕРІ;
  - РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ probe РЅР°Р±РѕСЂР° `pid_off` (0x60/0xd8/0x10/0x88/0x90/0x98/0xa0/0xa8/0xb0/0x18);
  - РєР°РЅРґРёРґР°С‚ РїСЂРёРЅРёРјР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РїСЂРё СЃС‚СЂРѕРіРѕРј СЃРёРіРЅР°Р»Рµ: РЅР°Р№РґРµРЅ `ourpid` + РґРѕСЃС‚Р°С‚РѕС‡РЅР°СЏ plausibility/diversity (`plausible >= 8`, `unique_nonzero >= 4`);
  - РїСЂРё СѓСЃРїРµС…Рµ Р°С‚РѕРјР°СЂРЅРѕ РєРѕРјРјРёС‚СЏС‚СЃСЏ `PROC_PID_OFFSET` Рё direct layout.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** СЃРЅРёР¶РµРЅРёРµ Р»РѕР¶РЅС‹С… reject СЂРµР°Р»СЊРЅРѕРіРѕ allproc-РєР°РЅРґРёРґР°С‚Р° РїСЂРё РЅРµСЃС‚Р°РЅРґР°СЂС‚РЅРѕРј PID-offset Р±РµР· РІРєР»СЋС‡РµРЅРёСЏ scan fallback Рё Р±РµР· РѕСЃР»Р°Р±Р»РµРЅРёСЏ safety-РіРµР№С‚РѕРІ.

---

## Р‘Р°Рі #295: Bug #268 chain validator РёСЃРїРѕР»СЊР·РѕРІР°Р» РЅРµРІРµСЂРЅС‹Р№ `pid_off=0xd8` Рё РѕС‚РєР»РѕРЅСЏР» РґРѕРєР°Р·Р°РЅРЅС‹Р№ allproc `0x3213678` (2026-04-02, СЃРµСЃСЃРёСЏ 25e)

**РЎРёРјРїС‚РѕРј:** РІ `syslog_2026-04-02_15-42` direct candidate `0x3213678`:
- value = `0xffffffdd3b1b5000` (РІР°Р»РёРґРЅС‹Р№ heap proc, PID=0 = proc0) вњ“
- `proc0.le_prev[+0x08] = 0xfffffff01d337678` = candidate address вњ“ (РјР°С‚РµРјР°С‚РёС‡РµСЃРєРѕРµ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ С‡С‚Рѕ СЌС‚Рѕ allproc)
- РЅРѕ PID probe РґР»СЏ РІС‚РѕСЂРѕРіРѕ proc РІ С†РµРїРѕС‡РєРµ РЅР°С€С‘Р» `pid_off=0xd8` (РІС‚РѕСЂРѕР№ proc С‚РѕР¶Рµ PID=0 РЅР° +0x60 = kernel thread)
- Bug #268 chain validate СЃ `pid_off=0xd8`: `len=11 unique_nonzero=2 found_ourpid=0` в†’ REJECTED

**Root cause:** PID probe РїСЂРѕС…РѕРґРёР» С‚РѕР»СЊРєРѕ РѕРґРёРЅ С€Р°Рі РІРїРµСЂС‘Рґ РѕС‚ proc0. Р’С‚РѕСЂРѕР№ proc РІ allproc вЂ” С‚РѕР¶Рµ kernel thread СЃ PID=0 РЅР° +0x60, РїРѕСЌС‚РѕРјСѓ probe РЅРµ РЅР°С€С‘Р» +0x60 РєР°Рє РІР°Р»РёРґРЅС‹Р№ PID-offset. Р’С‹Р±СЂР°Р» `pd_off=0xd8` (РєР°РєРѕРµ-С‚Рѕ РґСЂСѓРіРѕРµ РїРѕР»Рµ). Р—Р°С‚РµРј chain validate СЃ РЅРµРІРµСЂРЅС‹Рј offset РґР°РІР°Р» РјСѓСЃРѕСЂРЅС‹Рµ PID в†’ `unique_nonzero=2, found_ourpid=0`.

РџСЂРё СЌС‚РѕРј `le_prev == candidate` (РЅРµ-heap kdata ptr) Р±С‹Р»Рѕ СѓР¶Рµ РёР·РІРµСЃС‚РЅРѕ РёР· Р»РѕРіР°, РЅРѕ РєРѕРґ РЅРµ РїСЂРѕРІРµСЂСЏР» СЌС‚Рѕ РґРѕ РІР°Р»РёРґР°С†РёРё С†РµРїРѕС‡РєРё.

**Р¤Р°Р№Р»:** `darksword/utils.m` вЂ” `detect_kernproc_variable()`

**РСЃРїСЂР°РІР»РµРЅРёРµ:** РґРѕР±Р°РІР»РµРЅ СЌСЂР»Рё-РїСЂСѓС„ `skip_chain_validate` РґРѕ Р±Р»РѕРєР° Bug #268:
```objc
// Р•СЃР»Рё proc0.le_prev == candidate (РЅРµ-heap kdata) вЂ” СЌС‚Рѕ TAILQ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ
if (!is_heap_ptr_relaxed(le_prev) && is_kptr(le_prev) && le_prev == candidate) {
    skip_chain_validate = true;  // РїСЂРѕРїСѓСЃРєР°РµРј Bug #268, СЃР±СЂР°СЃС‹РІР°РµРј РЅРµРІРµСЂРЅС‹Р№ discovered_pid_off
}
```

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** `0x3213678` РїСЂРёРЅРёРјР°РµС‚СЃСЏ РЅРµРјРµРґР»РµРЅРЅРѕ, `kernprocaddress()` РІРѕР·РІСЂР°С‰Р°РµС‚ allproc, `ourproc()` РЅР°С…РѕРґРёС‚ DarkSword PID.

---

## Р‘Р°Рі #294: Mach-O scan `COMMON_START=0x27000` Р·Р°С…РІР°С‚С‹РІР°Р» РѕРїР°СЃРЅСѓСЋ РѕР±Р»Р°СЃС‚СЊ early `__DATA.__common` СЃ Metadata zone pointers в†’ kernel panic (2026-04-02, СЃРµСЃСЃРёСЏ 25e)

**РЎРёРјРїС‚РѕРј:** РІ `syslog_2026-04-02_15-00` fallback scan `scan_for_allproc()` РЅР°С‡РёРЅР°Р» СЃ `outer_DATA+0x27000` Рё РїР°РЅРёРєРѕРІР°Р» С‡РµСЂРµР· ~21 СЃРµРєСѓРЅРґСѓ (chunk 2, `outer_DATA+0x2F000`). Panic-base `panic-2026-04-02-150048`:
- `esr: 0x96000007` вЂ” Translation fault level 3 (СЃС‚СЂР°РЅРёС†Р° РЅРµ РѕС‚РѕР±СЂР°Р¶РµРЅР°)
- `far: 0xffffffe39af8cdf0` вЂ” METADATA ZONE (Р·Р° `zone_map_max=0xffffffe39398c000`)
- Panicked task pid 486: DarkSword

Early `__DATA.__common` СЃРѕРґРµСЂР¶РёС‚ СѓРєР°Р·Р°С‚РµР»Рё РІ Metadata zone (РЅРµРїРѕСЃР»РµРґРѕРІР°С‚РµР»СЊРЅС‹Рµ С‚Р°Р±Р»РёС†С‹ zone descriptors). Р­С‚Рё СЃС‚СЂР°РЅРёС†С‹ РЅРµ РІСЃРµРіРґР° РѕС‚РѕР±СЂР°Р¶РµРЅС‹ Рё С‡С‚РµРЅРёРµ РёР· РЅРёС… РІС‹Р·С‹РІР°РµС‚ Translation fault.

**Root cause:** `COMMON_START=0x27000` РЅР°С‡РёРЅР°Р» scan СЃР»РёС€РєРѕРј СЂР°РЅРѕ. Р РµР°Р»СЊРЅС‹Р№ target (`allproc`) РЅР°С…РѕРґРёС‚СЃСЏ РІ `outer_DATA+0x67F30`. Scan РґРѕС…РѕРґРёР» РґРѕ Metadata pointer (-РіРѕ) РІ `outer_DATA+0x2F000` Рё РїР°РЅРёРєРѕРІР°Р» РґРѕ chunk 15, РіРґРµ Р±С‹Р» allproc.

**Р¤Р°Р№Р»:** `darksword/utils.m` вЂ” С„СѓРЅРєС†РёСЏ `scan_for_allproc()`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
```objc
// Р‘Р«Р›Рћ:
const uint64_t COMMON_START = 0x27000ULL;
const uint64_t COMMON_END   = 0x83000ULL;
// РЎРўРђР›Рћ:
const uint64_t COMMON_START = 0x63000ULL; /* Bug #294: bypass dangerous early __common; start near allproc at +0x67F30 */
const uint64_t COMMON_END   = 0x70000ULL; /* Bug #294: narrow 32KB window around allproc; avoids metadata zone reads */
```

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** Mach-O scan РЅР°С‡РёРЅР°РµС‚ РІ Р±РµР·РѕРїР°СЃРЅРѕРј СѓР·РєРѕРј РѕРєРЅРµ (`outer_DATA+0x63000..0x70000`) Рё РЅРµРјРµРґР»РµРЅРЅРѕ РЅР°С…РѕРґРёС‚ allproc РЅР° `+0x67F30` Р±РµР· СЂРёСЃРєР° Translation fault РІ Metadata zone.

---

## Р‘Р°Рі #293: РІСЃРµ С‚СЂРё direct-shortlist РЅРµ СЃРѕРґРµСЂР¶Р°Р»Рё РїРѕРґС‚РІРµСЂР¶РґС‘РЅРЅС‹Р№ oС„С„СЃРµС‚ `0x31FFF30` (allproc РґР»СЏ iOS 17.3.1 21D61 A12Z) (2026-04-02, СЃРµСЃСЃРёСЏ 25e)

**РЎРёРјРїС‚РѕРј:** РІ `syslog_2026-04-02_15-00` shortlist-pass:
- `0x3213678` в†’ `VALUE=0` (РїСѓСЃС‚РѕР№ СЃР»РѕС‚),
- `0x3213680` в†’ `value=0xffffffe0939c9000` (proc0, PID=0, chain=1 вЂ” С‚РѕР»СЊРєРѕ РѕРґРёРЅ proc в†’ РЅРµ full allproc),
- РІСЃРµ РѕСЃС‚Р°Р»СЊРЅС‹Рµ РєР°РЅРґРёРґР°С‚С‹ вЂ” Р°РЅР°Р»РѕРіРёС‡РЅРѕ;
- `direct candidates exhausted, falling back to scan`.

РџСЂРё СЌС‚РѕРј РІ РєРѕРґРµ СѓР¶Рµ Р±С‹Р» РєРѕРјРјРµРЅС‚Р°СЂРёР№:
```
* allproc at outer __DATA + 0x67F30 = kbase + 0x31FFF30
* Scanning from the START panics at chunk 2 before reaching chunk 15.
* FIX: scan a NARROW WINDOW (32KB) around the known offset FIRST.
```
РћС„С„СЃРµС‚ `0x31FFF30` Р±С‹Р» РёР·РІРµСЃС‚РµРЅ РёР· offline-Р°РЅР°Р»РёР·Р° СЏРґСЂР° 21D61, РЅРѕ РќР• Р±С‹Р» РґРѕР±Р°РІР»РµРЅ РІ shortlist.

**Root cause:** offline-Р°РЅР°Р»РёР· `ipsw_analysis/analyze_sections.py` РїРѕРєР°Р·Р°Р» allproc РІ `__DATA.__common` РЅР° `kbase+0x31FFF30` (`outer_DATA+0x67F30`). РћРґРЅР°РєРѕ РІ code-fix С‚РѕР№ РёС‚РµСЂР°С†РёРё РґРѕР±Р°РІРёР»Рё С‚РѕР»СЊРєРѕ micro-window РІРѕРєСЂСѓРі `0x3213678/0x3213680` (Bug #292), РЅРµ РґРѕР±Р°РІРёРІ РїРѕРґС‚РІРµСЂР¶РґС‘РЅРЅС‹Р№ offset РЅР°РїСЂСЏРјСѓСЋ.

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:** РґРѕР±Р°РІР»РµРЅ `0x31FFF30ULL` РєР°Рє РџР•Р Р’Р«Р™ СЌР»РµРјРµРЅС‚ РІРѕ РІСЃРµ С‚СЂРё shortlist-РјР°СЃСЃРёРІР°:
```objc
static const uint64_t direct_offs_minimal[] = {
    0x31FFF30ULL,   /* Bug #293: allproc LIST_HEAD for iOS 17.3.1 (21D61) A12Z вЂ” outer __DATA+0x67F30 */
    0x3213678ULL,
    0x3213680ULL,
};
// РђРЅР°Р»РѕРіРёС‡РЅРѕ РІ direct_offs_safe[] Рё direct_offs_full[]
```

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** `kernprocaddress()` РїСЂРѕРІРµСЂРёС‚ `kbase+0x31FFF30` РІ РїРµСЂРІСѓСЋ РѕС‡РµСЂРµРґСЊ. РџСЂРё РїСЂР°РІРёР»СЊРЅРѕРј offset VALUE = heap pointer РЅР° newest proc в†’ `validate_direct_allproc_v2` РїСЂРѕР№РґС‘С‚ СЃ РІС‹СЃРѕРєРёРј score в†’ allproc found РґРѕ Р»СЋР±РѕРіРѕ scan.

---

## Р‘Р°Рі #292: direct-shortlist РЅРµ РїРѕРєСЂС‹РІР°Р» СЃРѕСЃРµРґРЅРёРµ 8-byte СЃРґРІРёРіРё РІРѕРєСЂСѓРі runtime-РєР»Р°СЃС‚РµСЂР° 0x3213678/0x3213680 (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ `syslog_2026-04-02_06-55-28` `minimal -> safe` РїСЂРѕС…РѕРґРёР» С€С‚Р°С‚РЅРѕ (Bug #290), РЅРѕ РІСЃРµ direct-РєР°РЅРґРёРґР°С‚С‹ РёСЃС‡РµСЂРїС‹РІР°Р»РёСЃСЊ; РїСЂРё СЌС‚РѕРј С„Р°Р»СЊС€РёРІС‹Рµ/СЃРјРµС‰С‘РЅРЅС‹Рµ РєР°РЅРґРёРґР°С‚С‹ РѕРєРѕР»Рѕ `0x3213678/0x3213680` РїСЂРѕРґРѕР»Р¶Р°Р»Рё РґР°РІР°С‚СЊ РїСЂР°РІРґРѕРїРѕРґРѕР±РЅС‹Рµ С†РµРїРѕС‡РєРё (`chainв‰€11`) Р±РµР· СѓСЃРїРµС€РЅРѕРіРѕ resolve.

**Root cause:** shortlist РїСЂРѕР±РѕРІР°Р» С‚РѕР»СЊРєРѕ РґРІРµ С†РµРЅС‚СЂР°Р»СЊРЅС‹Рµ С‚РѕС‡РєРё (`0x3213678`, `0x3213680`) Рё Р±РѕР»РµРµ РґР°Р»СЊРЅРёРµ fallback-offsets, РЅРѕ РЅРµ РІРєР»СЋС‡Р°Р» СѓР·РєРѕРµ СЃРѕСЃРµРґРЅРµРµ РѕРєРЅРѕ СЃ С€Р°РіРѕРј `0x8`. РџСЂРё РЅРµР±РѕР»СЊС€РѕРј runtime-РґСЂРµР№С„Рµ Р°РґСЂРµСЃР° РіРѕР»РѕРІС‹ СЃРїРёСЃРєР° СЌС‚Рѕ РїСЂРёРІРѕРґРёР»Рѕ Рє РїСЂРµР¶РґРµРІСЂРµРјРµРЅРЅРѕРјСѓ `all strategies exhausted`.

**Р¤Р°Р№Р»:** `darksword/utils.m`

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- safe/full direct-shortlist СЂР°СЃС€РёСЂРµРЅ micro-window СЃРѕСЃРµРґРЅРёС… РѕС„С„СЃРµС‚РѕРІ:
  - `0x3213660`, `0x3213668`, `0x3213670`, `0x3213678`, `0x3213680`, `0x3213688`, `0x3213690`;
- РјРѕРґРµР»СЊ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё СЃРѕС…СЂР°РЅРµРЅР°: РЅРёРєР°РєРёС… С€РёСЂРѕРєРёС… scan fallback РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ, С‚РѕР»СЊРєРѕ РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅС‹Рµ С‚РѕС‡РµС‡РЅС‹Рµ single-read direct probes.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РїРѕРІС‹С€РµРЅРёРµ coverage direct-resolve РїСЂРё РјРёРЅРёРјР°Р»СЊРЅРѕРј СЂРѕСЃС‚Рµ read-budget Рё Р±РµР· РІРѕР·РІСЂР°С‚Р° Рє СЂРёСЃРєРѕРІР°РЅРЅС‹Рј DATA/Mach-O scan-path.

---

## Р‘Р°Рі #268: `detect_kernproc_variable()` РїСЂРёРЅРёРјР°Р» РєРѕСЂРѕС‚РєРёРµ Р»РѕР¶РЅС‹Рµ PID-С†РµРїРѕС‡РєРё РєР°Рє РІР°Р»РёРґРЅС‹Р№ allproc/kernproc (2026-04-01, СЃРµСЃСЃРёСЏ 25)

**РЎРёРјРїС‚РѕРј:** `kernprocaddress()` СѓСЃРїРµС€РЅРѕ РґРµС‚РµРєС‚РёР» `pid_off=0xd8`, РЅРѕ `ourproc()` РїСЂРѕС…РѕРґРёР» С‚РѕР»СЊРєРѕ РєРѕСЂРѕС‚РєСѓСЋ С†РµРїРѕС‡РєСѓ (~10-11 СѓР·Р»РѕРІ), РЅРµ РЅР°С…РѕРґРёР» С‚РµРєСѓС‰РёР№ PID Рё РїР°РґР°Р» РІ fallback/zone scan. Р’ Р»РѕРіР°С…:
- `KERNPROC detected ... pid_off=0xd8`
- Р·Р°С‚РµРј `NOT FOUND after 10 iterations`
- Рё `brute-force on forward procs did not find pid=...`

**Root cause:** РїСЂРѕРІРµСЂРєР° РІ `detect_kernproc_variable()` Р±С‹Р»Р° СЃР»РёС€РєРѕРј РјСЏРіРєРѕР№: РґРѕСЃС‚Р°С‚РѕС‡РЅРѕ Р±С‹Р»Рѕ СѓРІРёРґРµС‚СЊ `kernel_task (pid=0)` Рё С„РѕСЂРјР°Р»СЊРЅРѕ РІР°Р»РёРґРЅС‹Р№ `le_prev`. Р­С‚РѕРіРѕ РЅРµРґРѕСЃС‚Р°С‚РѕС‡РЅРѕ вЂ” Р»РѕР¶РЅС‹Р№ СЃРїРёСЃРѕРє С‚РѕР¶Рµ РјРѕР¶РµС‚ РґР°С‚СЊ С‚Р°РєРёРµ РїСЂРёР·РЅР°РєРё.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” РІС‹Р±РёСЂР°Р»СЃСЏ РЅРµРІРµСЂРЅС‹Р№ РєР°РЅРґРёРґР°С‚ РіРѕР»РѕРІС‹ СЃРїРёСЃРєР°, РїРѕСЃР»Рµ С‡РµРіРѕ `ourproc()` Рё downstream post-exploit Р»РѕРјР°Р»РёСЃСЊ.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅР° `validate_kernproc_forward_chain()` (Bug #268)
- РґРѕ РїСЂРёРЅСЏС‚РёСЏ РєР°РЅРґРёРґР°С‚Р° РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ forward-walk РѕС‚ `kernel_task` СЃ РЅР°Р№РґРµРЅРЅС‹Рј `pid_off`
- РєР°РЅРґРёРґР°С‚ С‚РµРїРµСЂСЊ РїСЂРёРЅРёРјР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РµСЃР»Рё:
  - РЅР°Р№РґРµРЅ РЅР°С€ `pid`, **РёР»Рё**
  - С†РµРїРѕС‡РєР° РґРѕСЃС‚Р°С‚РѕС‡РЅРѕ РґР»РёРЅРЅР°СЏ Рё СЃ РґРѕСЃС‚Р°С‚РѕС‡РЅРѕР№ PID-diversity (`len >= 20`, `unique_nonzero >= 8`)
- РїСЂРё РїСЂРѕРІР°Р»Рµ РІР°Р»РёРґР°С†РёРё РєР°РЅРґРёРґР°С‚ РѕС‚РІРµСЂРіР°РµС‚СЃСЏ Рё РїРѕРёСЃРє РїСЂРѕРґРѕР»Р¶Р°РµС‚СЃСЏ

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** `kernprocaddress()` РїРµСЂРµСЃС‚Р°РЅРµС‚ РєСЌС€РёСЂРѕРІР°С‚СЊ Р»РѕР¶РЅС‹Рµ head-РєР°РЅРґРёРґР°С‚С‹ СЃ Р±РµРґРЅРѕР№ PID-С†РµРїРѕС‡РєРѕР№, С‡С‚Рѕ СѓРІРµР»РёС‡РёС‚ С€Р°РЅСЃ РІС‹С…РѕРґР° РЅР° СЂРµР°Р»СЊРЅС‹Р№ allproc Рё СѓСЃРїРµС€РЅС‹Р№ `ourproc()`.

---

## Р‘Р°Рі #269: `ourproc()` РЅРµ РёРЅРІР°Р»РёРґРёСЂРѕРІР°Р» Р»РѕР¶РЅС‹Р№ DATA-allproc РїСЂРё РєРѕСЂРѕС‚РєРѕР№ PID=0 С†РµРїРѕС‡РєРµ Рё РЅРµ РґРµР»Р°Р» СЂР°РЅРЅРёР№ PID fallback (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ `DATA-proc0 SMRQ allproc SUCCESS` РєСЌС€РёСЂРѕРІР°Р»СЃСЏ candidate РІ `kernel DATA`, РЅРѕ forward walk РІ `ourproc()` РІРёРґРµР» С‚РѕР»СЊРєРѕ `pid=0` Рё РѕР±СЂС‹РІР°Р»СЃСЏ Р±РµР· `our pid`. РџРѕРІС‚РѕСЂРЅС‹Рµ РІС‹Р·РѕРІС‹ РёСЃРїРѕР»СЊР·РѕРІР°Р»Рё С‚РѕС‚ Р¶Рµ Р»РѕР¶РЅС‹Р№ cache.

**Root cause:**
- `Bug #263F` СЃСЂР°Р±Р°С‚С‹РІР°Р» С‚РѕР»СЊРєРѕ РїСЂРё `count > 10`, РїРѕСЌС‚РѕРјСѓ РєРѕСЂРѕС‚РєРёРµ Р»РѕР¶РЅС‹Рµ DATA-С†РµРїРѕС‡РєРё (2вЂ“3 С€Р°РіР°, РІСЃРµ `pid=0`) РЅРµ РёРЅРІР°Р»РёРґРёСЂРѕРІР°Р»РёСЃСЊ.
- РЅР° РїРµСЂРІРѕРј DATA-С€Р°РіРµ РїСЂРё РЅРµРІРµСЂРЅРѕРј `PROC_PID_OFFSET` РЅРµ Р±С‹Р»Рѕ СЂР°РЅРЅРµРіРѕ fallback РЅР° canonical `0x60`.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” Р»РѕР¶РЅС‹Р№ `allproc` РѕСЃС‚Р°РІР°Р»СЃСЏ РІ runtime cache Рё Р»РѕРјР°Р» `ourproc()`/post-exploit.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ СѓС‡С‘С‚ `max_pid_seen` РІ forward walk `ourproc()`.
- СѓСЃР»РѕРІРёРµ `Bug #263F` СѓР¶РµСЃС‚РѕС‡РµРЅРѕ: С‚РµРїРµСЂСЊ invalidation СЃСЂР°Р±Р°С‚С‹РІР°РµС‚ РґР»СЏ DATA-head РїСЂРё РєРѕСЂРѕС‚РєРѕР№ С†РµРїРѕС‡РєРµ СЃ `count >= 2 && max_pid_seen == 0`.
- РґРѕР±Р°РІР»РµРЅ `Bug #269` fallback: РµСЃР»Рё РЅР° С€Р°РіРµ 0 DATA-head РґР°С‘С‚ РЅРµРІР°Р»РёРґРЅС‹Р№ pid РїСЂРё С‚РµРєСѓС‰РµРј offset, РїСЂРѕР±СѓРµС‚СЃСЏ `0x60`; РїСЂРё `pid=0` offset РїРµСЂРµРєР»СЋС‡Р°РµС‚СЃСЏ РЅР° `0x60`.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** Р»РѕР¶РЅС‹Рµ DATA-РєР°РЅРґРёРґР°С‚С‹ СЃ РѕРґРЅРёРјРё `pid=0` РЅРµ Р±СѓРґСѓС‚ РєСЌС€РёСЂРѕРІР°С‚СЊСЃСЏ РЅР°РґРѕР»РіРѕ; `kernprocaddress()` Р±СѓРґРµС‚ РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕ СЂРµС‚СЂР°РёС‚СЊСЃСЏ РЅР° СЃР»РµРґСѓСЋС‰РёР№ РєР°РЅРґРёРґР°С‚.

---

## Р‘Р°Рі #270: `kernprocaddress()` РїСЂРёРЅРёРјР°Р» DATA-proc0 РєР°РЅРґРёРґР°С‚РѕРІ РїСЂРё `next_pid=0` РёР·-Р·Р° СЃР»РёС€РєРѕРј РјСЏРіРєРѕРіРѕ `is_plausible_pid()`-РіРµР№С‚Р° (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ `DATA-proc0 SMRQ allproc SUCCESS` РІ Р»РѕРіР°С… РїРѕРІС‚РѕСЂСЏР»РёСЃСЊ РєРѕСЂРѕС‚РєРёРµ DATA-С†РµРїРѕС‡РєРё СЃ `pid=0`, РєР°РЅРґРёРґР°С‚ РїРµСЂРµРёСЃРїРѕР»СЊР·РѕРІР°Р»СЃСЏ РёР· cache Рё `ourproc()` СЃРЅРѕРІР° РїР°РґР°Р» РІ `NOT FOUND` + invalidate/retry loop.

**Root cause:** РІ РґРІСѓС… РјРµСЃС‚Р°С… РїСЂРѕРІРµСЂРєР° РІС‚РѕСЂРѕРіРѕ PID РёСЃРїРѕР»СЊР·РѕРІР°Р»Р° С‚РѕР»СЊРєРѕ `is_plausible_pid(np)`; Р·РЅР°С‡РµРЅРёРµ `0` СЃС‡РёС‚Р°РµС‚СЃСЏ plausible Рё РїСЂРѕС…РѕРґРёР»Рѕ РІР°Р»РёРґР°С†РёСЋ.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” Р»РѕР¶РЅС‹Р№ DATA-allproc РїСЂРѕРґРѕР»Р¶Р°Р» РїСЂРёРЅРёРјР°С‚СЊСЃСЏ/РєСЌС€РёСЂРѕРІР°С‚СЊСЃСЏ, РїРѕРІС‹С€Р°СЏ СЂРёСЃРє РїРѕРІС‚РѕСЂРЅС‹С… РЅРµРІРµСЂРЅС‹С… kernel deref.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РІ cache revalidate (`Bug #263E`) РґРѕР±Р°РІР»РµРЅРѕ С‚СЂРµР±РѕРІР°РЅРёРµ `np > 0` РґР»СЏ РІС‚РѕСЂРѕРіРѕ DATA-entry.
- РІ РІРµС‚РєРµ `DATA-proc0 allproc SUCCESS` РґРѕР±Р°РІР»РµРЅР° СЏРІРЅР°СЏ РїСЂРѕРІРµСЂРєР° `le_next` PID: С‚РѕР»СЊРєРѕ `pid > 0 && plausible`.
- РІ РІРµС‚РєРµ `DATA-proc0 SMRQ` СѓР¶РµСЃС‚РѕС‡РµРЅРѕ СѓСЃР»РѕРІРёРµ acceptance: `next_proc pid` РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ **non-zero** Рё plausible.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** DATA-РєР°РЅРґРёРґР°С‚С‹ СЃ С†РµРїРѕС‡РєРѕР№ `pid=0` РЅРµ Р±СѓРґСѓС‚ РїСЂРёРЅРёРјР°С‚СЊСЃСЏ РєР°Рє РІР°Р»РёРґРЅС‹Р№ `allproc`, С‡С‚Рѕ СѓРјРµРЅСЊС€РёС‚ loop Рё СЂРёСЃРє РїР°РЅРёРєРё РґРѕ РІС…РѕРґР° РІ `ourproc()`.

---

## Р‘Р°Рі #271: `scan_range_for_allproc()` РјРѕРі С‚СЂРёРіРіРµСЂРёС‚СЊ kernel data abort РЅР° 16KB bulk-read РґР°Р¶Рµ РїСЂРё checked-РїСѓС‚Рё (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ СЃС‚СЂРѕРєРё `starting inner-kernel DATA range scan` Рё РїРµСЂРІРѕРіРѕ `reading scan chunk at ...` РїСЂРёР»РѕР¶РµРЅРёРµ С‚РµСЂСЏР»Рѕ СЃРѕРµРґРёРЅРµРЅРёРµ, Р° РІ panic С„РёРєСЃРёСЂРѕРІР°Р»СЃСЏ `Kernel data abort` СЃ `Panicked task ... DarkSword`.

**Root cause:** РІ СЃРєР°РЅРµСЂРµ РёСЃРїРѕР»СЊР·РѕРІР°Р»РѕСЃСЊ bulk-С‡С‚РµРЅРёРµ С‡Р°РЅРєР° `0x4000` С‡РµСЂРµР· `ds_kread_checked()`. РќР° РЅРµСЃС‚Р°Р±РёР»СЊРЅС‹С… СЃРµСЃСЃРёСЏС… СЌС‚Рѕ С‡С‚РµРЅРёРµ РёРЅРѕРіРґР° РїСЂРѕРІРѕС†РёСЂРѕРІР°Р»Рѕ abort РґРѕ С‚РѕРіРѕ, РєР°Рє checked-РїСѓС‚СЊ СѓСЃРїРµРІР°Р» РІРµСЂРЅСѓС‚СЊ `false`.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” panic РїСЂРѕРёСЃС…РѕРґРёР» СѓР¶Рµ РЅР° СЃС‚Р°РґРёРё СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ `__DATA`, РґРѕ РЅРѕСЂРјР°Р»СЊРЅРѕР№ РІР°Р»РёРґР°С†РёРё РєР°РЅРґРёРґР°С‚РѕРІ.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- bulk-С‡С‚РµРЅРёРµ 16KB Р·Р°РјРµРЅРµРЅРѕ РЅР° slot-by-slot С‡С‚РµРЅРёРµ РїРѕ `8` Р±Р°Р№С‚ (`ds_kread64_checked(candidate, &val)`).
- РґРѕР±Р°РІР»РµРЅ РѕС‚РґРµР»СЊРЅС‹Р№ guard РїРѕ СЃРµСЂРёРё consecutive slot-read failures (`>=64` в†’ abort range).
- Р±С‹СЃС‚СЂС‹Р№ pre-filter С‚РµРїРµСЂСЊ РёСЃРїРѕР»СЊР·СѓРµС‚ СѓР¶Рµ СЃС‡РёС‚Р°РЅРЅРѕРµ `val` РєР°Рє `head_q` (СѓР±СЂР°РЅ Р»РёС€РЅРёР№ РїРѕРІС‚РѕСЂРЅС‹Р№ read РїРѕ `candidate`).

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** СЃРЅРёР¶Р°РµС‚СЃСЏ РІРµСЂРѕСЏС‚РЅРѕСЃС‚СЊ panic РїСЂРё РІС…РѕРґРµ РІ `DATA range scan`; РїСЂРё РґРµРіСЂР°РґР°С†РёРё РїСЂРёРјРёС‚РёРІР° СЃРєР°РЅ РґРѕР»Р¶РµРЅ Р·Р°РІРµСЂС€Р°С‚СЊСЃСЏ РѕС‚РєР°Р·РѕРј РґРёР°РїР°Р·РѕРЅР°, Р° РЅРµ kernel abort.

---

## Р‘Р°Рі #272: РїРѕР·РґРЅРёР№ fallback `scan_for_allproc()` (Mach-O parse __DATA.__common) РїСЂРѕРґРѕР»Р¶Р°Р» РїСЂРёРІРѕРґРёС‚СЊ Рє panic РїРѕСЃР»Рµ СѓСЃРїРµС€РЅС‹С… СЂР°РЅРЅРёС… guard-РѕРІ (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ РїСЂРѕС…РѕР¶РґРµРЅРёСЏ direct-РєР°РЅРґРёРґР°С‚РѕРІ Рё С‡Р°СЃС‚Рё Р±РµР·РѕРїР°СЃРЅРѕРіРѕ range-scan РїСЂРёР»РѕР¶РµРЅРёРµ РґРѕС…РѕРґРёР»Рѕ РґРѕ `falling back to Mach-O parse scan...`, РїРѕСЃР»Рµ С‡РµРіРѕ СЃР»РµРґРѕРІР°Р» `Kernel data abort` (`bug_type 210`, `Panicked task ... DarkSword`).

**Root cause:** fallback-РїСѓС‚СЊ `scan_for_allproc()` Р·Р°РїСѓСЃРєР°РµС‚СЃСЏ РЅР° Р±РѕР»РµРµ С€РёСЂРѕРєРѕРј СѓС‡Р°СЃС‚РєРµ `__DATA.__common` Рё РІ РЅРµСЃС‚Р°Р±РёР»СЊРЅС‹С… СЃРµСЃСЃРёСЏС… РѕСЃС‚Р°С‘С‚СЃСЏ high-risk РёСЃС‚РѕС‡РЅРёРєРѕРј panic.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** fallback `scan_for_allproc()` РїРµСЂРµРІРµРґС‘РЅ РІ opt-in С‡РµСЂРµР· `DS_ENABLE_MACHO_SCAN` (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ off).

---

## Р‘Р°Рі #273: pipeline РїСЂРѕРґРѕР»Р¶Р°Р» СЂР°Р±РѕС‚Сѓ РїСЂРё `ourproc()/ourtask == 0`, РѕСЃС‚Р°РІР»СЏСЏ РїСѓС‚СЊ Рє risky РѕРїРµСЂР°С†РёСЏРј (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ syslog Р±С‹Р»Рѕ `kernprocaddress() returned 0` / `ourproc ERROR`, РЅРѕ РґР°Р»РµРµ СЃРµСЃСЃРёСЏ РјРѕРіР»Р° РґРѕР№С‚Рё РґРѕ panic.

**Root cause:** `g_ds_ready` РІС‹СЃС‚Р°РІР»СЏР»СЃСЏ РґРѕ РІРµСЂРёС„РёРєР°С†РёРё `ourproc()/ourtask`, Рё РІРµСЂС…РЅРёР№ pipeline РЅРµ Р·Р°РІРµСЂС€Р°Р» Р·Р°РїСѓСЃРє Р¶С‘СЃС‚РєРѕ.

**Р¤Р°Р№Р»С‹:** `darksword/darksword_core.m`, `darksword/darksword_exploit.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** РґРѕР±Р°РІР»РµРЅС‹ panic-guard abort РїСЂРё `ourproc==0` Рё `ourtask==0`, СЃ РЅРµРјРµРґР»РµРЅРЅС‹Рј РІС‹С…РѕРґРѕРј РёР· exploit-РїР°Р№РїР»Р°Р№РЅР°.

---

## Р‘Р°Рі #274: retry-С†РёРєР» РїРѕРІС‚РѕСЂСЏР» `ds_run()` РґР°Р¶Рµ РїРѕСЃР»Рµ panic-guard abort (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ СЃС‚СЂРѕРєРё `PANIC GUARD: ourproc() failed` РІ С‚РѕР№ Р¶Рµ СЃРµСЃСЃРёРё РїСЂРѕРґРѕР»Р¶Р°Р»РёСЃСЊ РїРѕРІС‚РѕСЂРЅС‹Рµ retry.

**Root cause:** retry-Р»РѕРіРёРєР° РЅРµ СЂР°Р·Р»РёС‡Р°Р»Р° РѕР±С‹С‡РЅС‹Р№ fail Рё panic-guard fail.

**Р¤Р°Р№Р»С‹:** `darksword/darksword_core.m`, `darksword/darksword_exploit.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** РІРІРµРґС‘РЅ РѕС‚РґРµР»СЊРЅС‹Р№ РєРѕРґ guard-abort Рё РїСЂРµРєСЂР°С‰РµРЅРёРµ retry-С†РёРєР»Р° РІ СЌС‚РѕР№ СЃРµСЃСЃРёРё.

---

## Р‘Р°Рі #275: direct DATA-РєР°РЅРґРёРґР°С‚С‹ allproc РІ shortlist РѕСЃС‚Р°РІР°Р»РёСЃСЊ СЂР°РЅРЅРёРј crash-РїСѓС‚С‘Рј (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** panic РїСЂРѕРёСЃС…РѕРґРёР» РЅР° direct-РІРµС‚РєРµ РґРѕ СѓСЃС‚РѕР№С‡РёРІРѕРіРѕ РїРµСЂРµС…РѕРґР° Рє safer scan path.

**Root cause:** mixed shortlist СЃ DATA-heavy РєР°РЅРґРёРґР°С‚Р°РјРё РїСЂРѕРІРѕС†РёСЂРѕРІР°Р» РЅРµСЃС‚Р°Р±РёР»СЊРЅС‹Рµ deref РІ СЂР°РЅРЅРµР№ С„Р°Р·Рµ.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** `DS_ENABLE_DATA_DIRECT` (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ off), direct shortlist РѕРіСЂР°РЅРёС‡РµРЅ Р±РѕР»РµРµ Р±РµР·РѕРїР°СЃРЅС‹РјРё heap-РѕСЂРёРµРЅС‚РёСЂРѕРІР°РЅРЅС‹РјРё РєР°РЅРґРёРґР°С‚Р°РјРё.

---

## Р‘Р°Рі #276: РїРѕСЃР»Рµ panic-guard lifecycle path РЅРµ РїРµСЂРµРІРѕРґРёР»СЃСЏ РІ Р¶С‘СЃС‚РєРёР№ shutdown-safe СЂРµР¶РёРј (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ guard-abort РѕР±С‹С‡РЅС‹Р№ lifecycle (`resign/background/terminate`) РїСЂРѕРґРѕР»Р¶Р°Р» РІС‹РїРѕР»РЅСЏС‚СЊ Р»РёС€РЅРёРµ shutdown-РґРµР№СЃС‚РІРёСЏ.

**Root cause:** РЅРµ Р±С‹Р»Рѕ РѕС‚РґРµР»СЊРЅРѕРіРѕ fatal-state latch РЅР° СѓСЂРѕРІРЅРµ UI/lifecycle.

**Р¤Р°Р№Р»С‹:** `darksword/darksword_exploit.m`, `app/main.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** РІРІРµРґС‘РЅ fatal-state latch Рё shutdown-safe short-circuit РІ lifecycle callbacks.

---

## Р‘Р°Рі #277: leak-РїР°С‚С‡ РґРµСЂР¶Р°Р»СЃСЏ РЅР° РѕРґРЅРѕРј РѕС„С„СЃРµС‚Рµ `struct socket`, С‡С‚Рѕ РѕСЃС‚Р°РІР»СЏР»Рѕ panic РЅР° С‡Р°СЃС‚Рё СЃРµСЃСЃРёР№ (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ `krw_sockets_leak_forever()` panic РїСЂРё СЂСѓС‡РЅРѕРј Р·Р°РєСЂС‹С‚РёРё РѕСЃС‚Р°РІР°Р»СЃСЏ РЅР° С‡Р°СЃС‚Рё Р·Р°РїСѓСЃРєРѕРІ.

**Root cause:** Р¶С‘СЃС‚РєР°СЏ РїСЂРёРІСЏР·РєР° Рє РѕРґРЅРѕРјСѓ СЃРјРµС‰РµРЅРёСЋ `so_usecount/so_retaincnt`.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** dual-offset probe (`0x24c/0x228`) СЃРѕ СЃС‚СЂРѕРіРѕР№ sanity-РїСЂРѕРІРµСЂРєРѕР№ РїРµСЂРµРґ write.

---

## Р‘Р°Рі #278: РїСЂРё guard-abort РїРѕРІСЂРµР¶РґС‘РЅРЅС‹Р№ `icmp6filt` РјРѕРі РѕСЃС‚Р°РІР°С‚СЊСЃСЏ РІ rw-СЃРѕРєРµС‚Рµ РґРѕ terminate (2026-04-01, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РґР°Р¶Рµ РїРѕСЃР»Рµ guard-abort + shutdown-safe lifecycle РІРѕСЃРїСЂРѕРёР·РІРѕРґРёР»СЃСЏ `bug_type 210` РїСЂРё СЂСѓС‡РЅРѕРј Р·Р°РєСЂС‹С‚РёРё.

**Root cause:** РїРѕСЃР»Рµ `find_and_corrupt_socket()` РЅРµ РІС‹РїРѕР»РЅСЏР»СЃСЏ best-effort rollback С„РёР»СЊС‚СЂР° РІ abort-РїСѓС‚СЏС….

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** snapshot РёСЃС…РѕРґРЅРѕРіРѕ `icmp6filt` + `restore_corrupted_socket_filter_best_effort()` РІ guard-abort РІРµС‚РєР°С….

---

## Р‘Р°Рі #279: РїРѕСЃР»Рµ rollback СЃРѕРєРµС‚С‹ РѕСЃС‚Р°РІР°Р»РёСЃСЊ РѕС‚РєСЂС‹С‚С‹РјРё РґРѕ terminate, Рё teardown РІСЃС‘ РµС‰С‘ РјРѕРі РїР°РЅРёРєРѕРІР°С‚СЊ (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ post-fix С‚РµСЃС‚Рµ rollback РјРѕРі РѕС‚СЂР°Р±РѕС‚Р°С‚СЊ, РЅРѕ `bug_type 210` РїСЂРё СЂСѓС‡РЅРѕРј Р·Р°РєСЂС‹С‚РёРё СЃРѕС…СЂР°РЅСЏР»СЃСЏ.

**Root cause:** rollback С„РёР»СЊС‚СЂР° Р±РµР· РґРµР°РєС‚РёРІР°С†РёРё/Р·Р°РєСЂС‹С‚РёСЏ fd РѕСЃС‚Р°РІР»СЏР» Р¶РёРІС‹Рµ exploit-СЃРѕРєРµС‚С‹ РґРѕ СЃРёСЃС‚РµРјРЅРѕРіРѕ terminate-path.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РСЃРїСЂР°РІР»РµРЅРёРµ:** РґРѕР±Р°РІР»РµРЅ `abort_cleanup_corrupted_sockets_best_effort()` (`shutdown+close` РѕР±РѕРёС… СЃРѕРєРµС‚РѕРІ + СЃР±СЂРѕСЃ state) Рё РІС‹Р·РѕРІ РїРѕСЃР»Рµ rollback РІ guard-abort РїСѓС‚СЏС….

---

## Р‘Р°Рі #280: СЂР°РЅРЅРёРµ abort-path РїРѕСЃР»Рµ socket corruption РЅРµ РІРµР·РґРµ РїСЂРѕС…РѕРґРёР»Рё С‡РµСЂРµР· РµРґРёРЅС‹Р№ rollback+cleanup (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** С‡Р°СЃС‚СЊ СЂР°РЅРЅРёС… `return -1` РїРѕСЃР»Рµ СѓСЃРїРµС€РЅРѕРіРѕ `find_and_corrupt_socket()` РѕР±С…РѕРґРёР»Р° СѓРЅРёС„РёС†РёСЂРѕРІР°РЅРЅС‹Р№ teardown, РёР·-Р·Р° С‡РµРіРѕ rollback/cleanup РІС‹РїРѕР»РЅСЏР»РёСЃСЊ РЅРµРїРѕСЃР»РµРґРѕРІР°С‚РµР»СЊРЅРѕ РјРµР¶РґСѓ РІРµС‚РєР°РјРё.

**Root cause:** cleanup-Р»РѕРіРёРєР° Р±С‹Р»Р° СЂР°Р·РјР°Р·Р°РЅР° РїРѕ РЅРµСЃРєРѕР»СЊРєРёРј `if`-РІРµС‚РєР°Рј (`pe()`/socket setup), Рё РЅРµ РІСЃРµ guard-abort С‚РѕС‡РєРё РёСЃРїРѕР»СЊР·РѕРІР°Р»Рё РѕРґРёРЅ Рё С‚РѕС‚ Р¶Рµ РїСѓС‚СЊ Р·Р°РІРµСЂС€РµРЅРёСЏ.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™ вЂ” РїРѕРІС‹С€РµРЅРЅС‹Р№ СЂРёСЃРє РѕСЃС‚Р°РІРёС‚СЊ РїРѕРІСЂРµР¶РґС‘РЅРЅРѕРµ СЃРѕСЃС‚РѕСЏРЅРёРµ СЃРѕРєРµС‚РѕРІ РІ РѕС‚РґРµР»СЊРЅС‹С… fail-СЃС†РµРЅР°СЂРёСЏС….

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ РµРґРёРЅС‹Р№ helper `fail_after_corruption_cleanup()`;
- РєР»СЋС‡РµРІС‹Рµ СЂР°РЅРЅРёРµ abort-path РІ `find_and_corrupt_socket` Рё PANIC GUARD РІРµС‚РєР°С… `pe()` РїРµСЂРµРІРµРґРµРЅС‹ РЅР° РµРґРёРЅС‹Р№ РјР°СЂС€СЂСѓС‚: rollback `icmp6filt` + `abort_cleanup_corrupted_sockets_best_effort()` + `return -1`.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РґРµС‚РµСЂРјРёРЅРёСЂРѕРІР°РЅРЅС‹Р№ Рё РѕРґРёРЅР°РєРѕРІС‹Р№ teardown РїРѕСЃР»Рµ corruption-fail, СЃРЅРёР¶РµРЅРёРµ С€Р°РЅСЃР° close-time panic РІ СЂРµРґРєРёС… СЂР°РЅРЅРёС… РѕС‚РєР°Р·Р°С….

---

## Р‘Р°Рі #281: forced `shutdown/close` РІ abort-cleanup РІСЃС‘ РµС‰С‘ С‚СЂРёРіРіРµСЂРёР» close-time panic РЅР° С‡Р°СЃС‚Рё СЃРµСЃСЃРёР№ (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ `PANIC GUARD: ourproc() failed` Рё Р»РѕРіРѕРІ rollback (`pcb=...`), СѓСЃС‚СЂРѕР№СЃС‚РІРѕ РІСЃС‘ СЂР°РІРЅРѕ Р»РѕРІРёР»Рѕ `bug_type 210`; panic-Р°РґСЂРµСЃ СЃРѕРѕС‚РІРµС‚СЃС‚РІРѕРІР°Р» `rw_socket_pcb + 0x148` (icmp6filt field zone).

**Root cause:** РІ abort-path РІС‹РїРѕР»РЅСЏР»СЃСЏ РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅС‹Р№ `shutdown/close` corrupted exploit-СЃРѕРєРµС‚РѕРІ. Р”Р°Р¶Рµ РїСЂРё rollback-Р»РѕРіР°С… teardown СЌС‚РѕР№ РїР°СЂС‹ СЃРѕРєРµС‚РѕРІ РѕСЃС‚Р°РІР°Р»СЃСЏ РЅРµСЃС‚Р°Р±РёР»СЊРЅС‹Рј Рё РЅР° С‡Р°СЃС‚Рё Р·Р°РїСѓСЃРєРѕРІ РїСЂРёРІРѕРґРёР» Рє panic РІ kernel allocator path.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” panic РїРѕСЃР»Рµ guard-abort, РєРѕРіРґР° РїРѕСЃС‚-СЌРєСЃРїР»РѕР№С‚ СѓР¶Рµ РєРѕСЂСЂРµРєС‚РЅРѕ РѕСЃС‚Р°РЅРѕРІР»РµРЅ.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- `abort_cleanup_corrupted_sockets_best_effort()` РїРµСЂРµРІРµРґС‘РЅ РЅР° quarantine policy;
- СѓРґР°Р»С‘РЅ forced `shutdown/close` РґР»СЏ corrupted exploit fd;
- С‚РµРїРµСЂСЊ abort-path РґРµС‚Р°С‡РёС‚ РіР»РѕР±Р°Р»СЊРЅС‹Рµ fd/pcb state Рё РЅР°РјРµСЂРµРЅРЅРѕ leak-РёС‚ СЃРѕРєРµС‚С‹ РЅР° lifetime РїСЂРѕС†РµСЃСЃР°.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** СѓР±СЂР°РЅ РіР»Р°РІРЅС‹Р№ close-time trigger РїРѕСЃР»Рµ guard-abort; Р°РІР°СЂРёР№РЅС‹Р№ РІС‹С…РѕРґ СЃС‚Р°РЅРѕРІРёС‚СЃСЏ safer Р·Р° СЃС‡С‘С‚ РѕС‚РєР°Р·Р° РѕС‚ РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕРіРѕ teardown corrupted sockets.

---

## Р‘Р°Рі #282: retry-loop РїСЂРѕРґРѕР»Р¶Р°Р» `ds_run()` РїРѕСЃР»Рµ PANIC GUARD Рё РЅР°РєР°РїР»РёРІР°Р» corruption-СЃРµСЃСЃРёРё РІ РѕРґРЅРѕРј РїСЂРѕС†РµСЃСЃРµ (2026-04-02, СЃРµСЃСЃРёСЏ 25d)

**РЎРёРјРїС‚РѕРј:** РІ РѕРґРЅРѕРј PID С€Р»Р° СЃРµСЂРёСЏ `PANIC GUARD: ourproc() failed`, rollback/abort-cleanup РІС‹РїРѕР»РЅСЏР»РёСЃСЊ РјРЅРѕРіРѕРєСЂР°С‚РЅРѕ, РїРѕСЃР»Рµ С‡РµРіРѕ РїСЂРё `UIApplication will terminate` СЃРѕС…СЂР°РЅСЏР»СЃСЏ `bug_type 210`.

**Root cause:** panic-guard abort РІРѕР·РІСЂР°С‰Р°Р» РѕР±С‹С‡РЅС‹Р№ `-1`, РЅРµРѕС‚Р»РёС‡РёРјС‹Р№ РѕС‚ В«РѕР±С‹С‡РЅРѕРіРѕВ» fail VFS race, РїРѕСЌС‚РѕРјСѓ РІРЅРµС€РЅРёР№ retry-С†РёРєР» РїСЂРѕРґРѕР»Р¶Р°Р» РЅРѕРІС‹Рµ РїРѕРїС‹С‚РєРё РІ С‚РѕРј Р¶Рµ РїСЂРѕС†РµСЃСЃРµ.

**Р¤Р°Р№Р»С‹:** `darksword/darksword_core.m`, `darksword/darksword_exploit.m`
**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™ вЂ” РїРѕРІС‹С€РµРЅРЅС‹Р№ СЂРёСЃРє close-time panic РёР·-Р·Р° РЅР°РєРѕРїР»РµРЅРёСЏ repeated corruption/recovery С†РёРєР»РѕРІ Р·Р° РѕРґРЅСѓ СЃРµСЃСЃРёСЋ.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ latch `g_panic_guard_abort_latched` РІ core;
- PANIC GUARD РїСѓС‚Рё РїРµСЂРµРІРѕРґСЏС‚СЃСЏ С‡РµСЂРµР· `panic_guard_abort_cleanup()`;
- `ds_run()` РІРѕР·РІСЂР°С‰Р°РµС‚ СЃРїРµС†РёР°Р»СЊРЅС‹Р№ РєРѕРґ `-2` РїСЂРё guard-abort;
- РІ `jailbreak_full()` retry-loop РѕСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ РїСЂРё `-2` (Р±РµР· РґР°Р»СЊРЅРµР№С€РёС… РїРѕРІС‚РѕСЂРѕРІ РІ С‚РµРєСѓС‰РµР№ СЃРµСЃСЃРёРё).

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РїРѕСЃР»Рµ PANIC GUARD С‚РµРєСѓС‰Р°СЏ СЃРµСЃСЃРёСЏ Р·Р°РІРµСЂС€Р°РµС‚ РїРѕРїС‹С‚РєРё СЃСЂР°Р·Сѓ, С‡С‚Рѕ СѓРјРµРЅСЊС€Р°РµС‚ РЅР°РєРѕРїР»РµРЅРёРµ corrupted state Рё СЃРЅРёР¶Р°РµС‚ РІРµСЂРѕСЏС‚РЅРѕСЃС‚СЊ РїРѕСЃР»РµРґСѓСЋС‰РµРіРѕ terminate-time panic.

---

## Р‘Р°Рі #237: legacy curated `DATA_0x31FFF30/0x31FFB50/0x31FFC68` РІСЃС‘ РµС‰С‘ РїСЂРѕР±РѕРІР°Р»РёСЃСЊ РґРѕ scan Рё СЃСЂС‹РІР°Р»Рё session 24 (2026-04-01, СЃРµСЃСЃРёСЏ 24)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ С„РёРєСЃР° Bug #236 РїСЂРёР»РѕР¶РµРЅРёРµ РІРїРµСЂРІС‹Рµ РґРѕС€Р»Рѕ РґРѕ:
- `kernel r/w is ready!`
- `about to call ourproc()`
- `ourproc -> kernprocaddress()`

РќРѕ Р·Р°С‚РµРј session 24 СЃРЅРѕРІР° РѕР±РѕСЂРІР°Р»Р°СЃСЊ РµС‰С‘ РґРѕ РЅРѕРІРѕРіРѕ aligned `__DATA.__bss_nearby` scan. РџРѕСЃР»РµРґРЅРёРµ СЂРµР»РµРІР°РЅС‚РЅС‹Рµ СЃС‚СЂРѕРєРё:
- `[allproc] trying DATA_0x31FFF30 offset 0x31fff30 -> addr 0x...`
- `[val_ap] addr=0x... raw_head=0xfffffff0240d2bd4 stripped=0xfffffff0240d2bd4 heap=0`
- `[disc_pl] entry: raw=0xfffffff0240d2bd4 ... heap=0 relaxed=0`
- Р·Р°С‚РµРј `[disconnected]`

**Root cause:** С…РѕС‚СЏ Bug #236 СѓР¶Рµ РёСЃРїСЂР°РІРёР» РЅРµР±РµР·РѕРїР°СЃРЅС‹Р№ align-down РІ scan helper, РґРѕ СЃР°РјРѕРіРѕ scan РєРѕРґ РІСЃС‘ РµС‰С‘ РЅРµ РґРѕС…РѕРґРёР». `kernprocaddress()` РїРѕ-РїСЂРµР¶РЅРµРјСѓ РїРµСЂРµР±РёСЂР°Р» СЃС‚Р°СЂС‹Рµ curated `__DATA` offsets (`0x31FFF30`, `0x31FFB50`, `0x31FFC68`), РєРѕС‚РѕСЂС‹Рµ:
- РЅР° С‡Р°СЃС‚Рё boot'РѕРІ СѓРєР°Р·С‹РІР°СЋС‚ РЅРµ РЅР° heap `proc` pointers,
- Р° РЅР° РЅРµ-heap globals / Р»РѕР¶РЅС‹Рµ РґР°РЅРЅС‹Рµ,
- Рё С‚РµРј СЃР°РјС‹Рј РјРµС€Р°СЋС‚ РїРµСЂРµР№С‚Рё Рє РЅРѕРІС‹Рј Р±РµР·РѕРїР°СЃРЅС‹Рј aligned scan windows.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” РґР°Р¶Рµ РїРѕСЃР»Рµ С„РёРєСЃР° scan helper post-exploit РІСЃС‘ РµС‰С‘ РЅРµ РґРѕСЃС‚РёРіР°РµС‚ СЂРµР°Р»СЊРЅРѕРіРѕ runtime scan РІРѕРєСЂСѓРі `kbase+0x321c260`.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- `validate_allproc()` С‚РµРїРµСЂСЊ РЅРµРјРµРґР»РµРЅРЅРѕ РѕС‚РІРµСЂРіР°РµС‚ candidate, РµСЃР»Рё `*(allproc)` РЅРµ РЅР°С…РѕРґРёС‚СЃСЏ РІ heap / zone map
- legacy curated candidates `DATA_0x31FFF30`, `DATA_0x31FFB50`, `DATA_0x31FFC68` РѕС‚РєР»СЋС‡РµРЅС‹ РїРѕР»РЅРѕСЃС‚СЊСЋ
- РїРѕСЃР»Рµ GOT/PPLDATA РєРѕРґ СЃСЂР°Р·Сѓ РїРµСЂРµС…РѕРґРёС‚ Рє aligned scan windows (`__DATA.allproc_target`, `__DATA.__bss_nearby`)

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** session 25 РґРѕР»Р¶РЅР° РІРїРµСЂРІС‹Рµ СЂРµР°Р»СЊРЅРѕ РїСЂРѕР№С‚Рё Рє РЅРѕРІРѕРјСѓ aligned runtime scan РІРјРµСЃС‚Рѕ РїРѕРІС‚РѕСЂРЅРѕРіРѕ СЃСЂС‹РІР° РЅР° СѓСЃС‚Р°СЂРµРІС€РёС… curated `__DATA` offsets.

---

## Р‘Р°Рі #236: `scan_range_for_allproc()` С‡РёС‚Р°Р» СЃС‚СЂР°РЅРёС†Сѓ Р”Рћ С†РµР»РµРІРѕРіРѕ РѕРєРЅР° Рё СЂРѕРЅСЏР» session 23 РЅР° СЃС‚Р°СЂС‚Рµ `__DATA.__bss` scan (2026-04-01, СЃРµСЃСЃРёСЏ 23)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ С„РёРєСЃР° Bug #235 СЃС‚Р°СЂС‹Рµ curated false positives РїРµСЂРµСЃС‚Р°Р»Рё РїСЂРѕС…РѕРґРёС‚СЊ validation, РЅРѕ session 23 РІСЃС‘ СЂР°РІРЅРѕ РЅРµ РґРѕС€Р»Р° РЅРё РґРѕ РЅРѕРІРѕРіРѕ `allproc FOUND`, РЅРё РґРѕ `ourproc()` walk. РџРѕСЃР»РµРґРЅРёРµ СЂРµР»РµРІР°РЅС‚РЅС‹Рµ СЃС‚СЂРѕРєРё:
- `scan __DATA.__bss: 0xfffffff02ca6f000..0xfffffff02ca9f000`
- `reading scan chunk at 0xfffffff02ca6c000`
- Р·Р°С‚РµРј РЅРµРјРµРґР»РµРЅРЅС‹Р№ `[disconnected]`

**Root cause:** helper `scan_range_for_allproc()` РІС‹СЂР°РІРЅРёРІР°Р» `range_start` РІРЅРёР· РґРѕ 16KB boundary:
- requested start: `0x...6f000`
- С„Р°РєС‚РёС‡РµСЃРєРѕРµ РїРµСЂРІРѕРµ С‡С‚РµРЅРёРµ: `0x...6c000`

РўРѕ РµСЃС‚СЊ scan Р·Р°С…РѕРґРёР» РЅР° `0x3000` СЂР°РЅСЊС€Рµ С†РµР»РµРІРѕРіРѕ РѕРєРЅР°. Р”Р»СЏ СѓР·РєРёС… kernel windows СЌС‚Рѕ РєСЂРёС‚РёС‡РЅРѕ: pre-range page РјРѕР¶РµС‚ РїСЂРёРЅР°РґР»РµР¶Р°С‚СЊ СЃРѕСЃРµРґРЅРµРјСѓ, РјРµРЅРµРµ Р±РµР·РѕРїР°СЃРЅРѕРјСѓ СѓС‡Р°СЃС‚РєСѓ `__DATA` Рё РІС‹Р·С‹РІР°С‚СЊ disconnect / panic РµС‰С‘ РґРѕ С‚РѕРіРѕ, РєР°Рє РІР°Р»РёРґР°С‚РѕСЂ СѓРІРёРґРёС‚ С…РѕС‚СЏ Р±С‹ РѕРґРёРЅ РєР°РЅРґРёРґР°С‚.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” Р»РѕР¶РЅС‹Рµ `allproc` СѓР¶Рµ РѕС‚С„РёР»СЊС‚СЂРѕРІР°РЅС‹, РЅРѕ РЅРѕРІС‹Р№ Р±РµР·РѕРїР°СЃРЅС‹Р№ scan РІСЃС‘ СЂР°РІРЅРѕ РЅРµ СѓСЃРїРµРІР°РµС‚ РґРѕР±СЂР°С‚СЊСЃСЏ РґРѕ РїРѕР»РµР·РЅРѕР№ РѕР±Р»Р°СЃС‚Рё `__bss`.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- `scan_range_for_allproc()` РїРµСЂРµРІРµРґС‘РЅ РЅР° align-up СЃС‚Р°СЂС‚, С‡С‚РѕР±С‹ РЅРёРєРѕРіРґР° РЅРµ С‡РёС‚Р°С‚СЊ РїР°РјСЏС‚СЊ РґРѕ `range_start`
- narrow scan windows РїРµСЂРµРІРµРґРµРЅС‹ РЅР° 16KB-aligned offsets
- broad `__DATA.__bss` fallback Р·Р°РјРµРЅС‘РЅ РЅР° СѓР·РєРѕРµ aligned-РѕРєРЅРѕ СЂСЏРґРѕРј СЃ РїСЂРѕС€Р»С‹Рј runtime hit `kbase+0x321C260`

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** session 24 РґРѕР»Р¶РЅР° Р±РµР·РѕРїР°СЃРЅРѕ РїСЂРѕР№С‚Рё СѓР·РєРёР№ `__bss` probe Р±РµР· РїСЂРµР¶РЅРµРіРѕ pre-range read РІ `0x...6c000`, РїРѕСЃР»Рµ С‡РµРіРѕ СЃС‚Р°РЅРµС‚ РІРёРґРЅРѕ вЂ” РµСЃС‚СЊ Р»Рё СЂСЏРґРѕРј СЂРµР°Р»СЊРЅС‹Р№ `allproc`, Р»РёР±Рѕ РЅСѓР¶РµРЅ РµС‰С‘ РѕРґРёРЅ refinement validator/scoring.

---

## Р‘Р°Рі #235: `validate_allproc()` РїСЂРёРЅРёРјР°Р» Р»РѕР¶РЅС‹Рµ proc-like СЃРїРёСЃРєРё СЃ Р±РµРґРЅРѕР№ PID-diversity (2026-04-01, СЃРµСЃСЃРёСЏ 22)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ РІСЂРµРјРµРЅРЅРѕРіРѕ bypass Bug #234 `ourproc()` СЃРЅРѕРІР° РЅР°С‡Р°Р» РёСЃРїРѕР»РЅСЏС‚СЊСЃСЏ, РЅРѕ С‚Р°Рє Рё РЅРµ РЅР°С…РѕРґРёР» СЃРѕР±СЃС‚РІРµРЅРЅС‹Р№ `pid`:
- `kernprocaddress()` С‡РµСЂРµР· runtime scan РЅР°С…РѕРґРёР» candidate `kbase + 0x321c260`
- `discover_proc_list_layout()` РІС‹Р±РёСЂР°Р» layout РІСЂРѕРґРµ `list_off=0x0`, `next_ff=0x8`, `pid_off=0x60`
- walk С€С‘Р» РїРѕ Р°РґСЂРµСЃР°Рј СЃ PID-РїР°С‚С‚РµСЂРЅРѕРј `0, 5, 5, 5, 0, 0, 9, ...`
- С‡РµСЂРµР· 20 С€Р°РіРѕРІ loop Р·Р°РєР°РЅС‡РёРІР°Р»СЃСЏ `NOT FOUND after 20 iterations (our pid=397)`

**Root cause:** РїСЂРµРґС‹РґСѓС‰Р°СЏ РІР°Р»РёРґР°С†РёСЏ СЃС‡РёС‚Р°Р»Р° С‚РѕР»СЊРєРѕ РґР»РёРЅСѓ С†РµРїРѕС‡РєРё Рё Р±Р°Р·РѕРІСѓСЋ plausibility PID. Р­С‚РѕРіРѕ РѕРєР°Р·Р°Р»РѕСЃСЊ РЅРµРґРѕСЃС‚Р°С‚РѕС‡РЅРѕ: РЅРµРєРѕС‚РѕСЂС‹Рµ РЅРµРІРµСЂРЅС‹Рµ kernel lists СЃРѕРґРµСЂР¶Р°С‚ 20+ proc-like СѓР·Р»РѕРІ, РЅРѕ РїСЂРё СЌС‚РѕРј РїРѕС‡С‚Рё РІСЃРµ PID РїРѕРІС‚РѕСЂСЏСЋС‚ РјР°Р»РµРЅСЊРєРёР№ РЅР°Р±РѕСЂ (`0`, `5`, `9`). РўР°РєРёРµ СЃРїРёСЃРєРё РЅРµ СЏРІР»СЏСЋС‚СЃСЏ `allproc`, РЅРѕ РїСЂРѕС…РѕРґРёР»Рё `validate_allproc()`.

**Р¤Р°Р№Р»:** `darksword/utils.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” exploit РґРѕС…РѕРґРёС‚ РґРѕ `ourproc()`, РЅРѕ РІСЃС‘ РµС‰С‘ РЅРµ РјРѕР¶РµС‚ РЅР°Р№С‚Рё С‚РµРєСѓС‰РёР№ `proc`, РёР·-Р·Р° С‡РµРіРѕ РІРµСЃСЊ post-exploit РѕСЃС‚Р°С‘С‚СЃСЏ РЅРµСЂР°Р±РѕС‡РёРј.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- `score_proc_chain_ex()` Р±РѕР»СЊС€Рµ РЅРµ РёСЃРїРѕР»СЊР·СѓРµС‚ bonus Р·Р° `pid 1`
- score С‚РµРїРµСЂСЊ РѕСЃРЅРѕРІР°РЅ РЅР° **РєРѕР»РёС‡РµСЃС‚РІРµ СѓРЅРёРєР°Р»СЊРЅС‹С… PID**, Р° РЅРµ РЅР° СЃС‹СЂС‹С… hop'Р°С…
- `validate_proc_chain_with_pid_off()` С‚РµРїРµСЂСЊ С‚СЂРµР±СѓРµС‚:
  - РјРёРЅРёРјСѓРј 20 С€Р°РіРѕРІ
  - РјРёРЅРёРјСѓРј 8 СѓРЅРёРєР°Р»СЊРЅС‹С… PID
  - РЅРµ Р±РѕР»РµРµ 2 СѓР·Р»РѕРІ СЃ `pid=0`
- persisted `kernproc` cache РІСЂРµРјРµРЅРЅРѕ РѕС‚РєР»СЋС‡С‘РЅ, С‡С‚РѕР±С‹ false positive РЅРµ СЃРѕС…СЂР°РЅСЏР»СЃСЏ РјРµР¶РґСѓ Р·Р°РїСѓСЃРєР°РјРё

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** Р»РѕР¶РЅС‹Рµ СЃРїРёСЃРєРё СЃ PID-РїР°С‚С‚РµСЂРЅРѕРј `0/5/9` Р±СѓРґСѓС‚ РѕС‚РєР»РѕРЅСЏС‚СЊСЃСЏ РµС‰С‘ РІ `validate_allproc()`, Рё runtime scan РїСЂРѕРґРѕР»Р¶РёС‚ РїРѕРёСЃРє РґРѕ СЂРµР°Р»СЊРЅРѕРіРѕ `allproc`.

---

## Р‘Р°Рі #234: kernel panic РїСЂРѕРёСЃС…РѕРґРёР» РІ `krw_sockets_leak_forever()`, Р° РЅРµ РІ `ourproc()` (2026-04-01, СЃРµСЃСЃРёСЏ 21)

**РЎРёРјРїС‚РѕРј:** session 21 Р·Р°РІРµСЂС€Р°Р»Р°СЃСЊ СЂРµР°Р»СЊРЅС‹Рј reboot/panic, РЅРѕ РІ Р»РѕРіРµ РЅРµ Р±С‹Р»Рѕ РЅРё РѕРґРЅРѕР№ СЃС‚СЂРѕРєРё `ourproc()` / `allproc()` РїРµСЂРµРґ Р°РІР°СЂРёРµР№.

**Р§С‚Рѕ РїРѕРєР°Р·Р°Р» syslog:**
- РїРѕСЃР»РµРґРЅСЏСЏ СЃС‚СЂРѕРєР° РїСЂРёР»РѕР¶РµРЅРёСЏ РїРµСЂРµРґ panic:
  - `krw leak: refcount patch applied successfully`
- СЃС‚СЂРѕРєР°
  - `returned from krw_sockets_leak_forever()`
  С‚Р°Рє Рё РЅРµ РїРѕСЏРІР»СЏР»Р°СЃСЊ
- Р·РЅР°С‡РёС‚ РєРѕРґ РЅРµ РґРѕС…РѕРґРёР» РґРѕ `ourproc()` РІРѕРѕР±С‰Рµ

**Root cause:** kernel panic РІС‹Р·С‹РІР°Р»Р° С‚РµРєСѓС‰Р°СЏ СЂРµР°Р»РёР·Р°С†РёСЏ refcount/socket-leak СЃС‚Р°РґРёРё, Р° РЅРµ proc-list traversal. РџСЂРµРґС‹РґСѓС‰Р°СЏ РѕС‚Р»Р°РґРєР° `ourproc()` РЅР° session 21 Р±С‹Р»Р° Р»РѕР¶РЅРѕР№ РєРѕСЂСЂРµР»СЏС†РёРµР№.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” panic РїСЂРѕРёСЃС…РѕРґРёР» СЂР°РЅСЊС€Рµ, С‡РµРј РЅР°С‡РёРЅР°Р»Р°СЃСЊ СЂРµР°Р»СЊРЅР°СЏ post-exploit РґРёР°РіРЅРѕСЃС‚РёРєР° `ourproc()`.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- `krw_sockets_leak_forever()` РІСЂРµРјРµРЅРЅРѕ bypass'РЅСѓС‚
- РїРѕСЃР»Рµ СЌС‚РѕРіРѕ session 22 РґРѕС€Р»Р° РґРѕ `ourproc()`, С‡С‚Рѕ РїРѕР·РІРѕР»РёР»Рѕ РёР·РѕР»РёСЂРѕРІР°С‚СЊ СѓР¶Рµ СЃР»РµРґСѓСЋС‰РёР№ blocker (#235)

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РїСЂРёР»РѕР¶РµРЅРёРµ Р±РѕР»СЊС€Рµ РЅРµ СЂРµР±СѓС‚Р°РµС‚ СѓСЃС‚СЂРѕР№СЃС‚РІРѕ РґРѕ РЅР°С‡Р°Р»Р° РґРёР°РіРЅРѕСЃС‚РёРєРё proc-list Рё РїРѕР·РІРѕР»СЏРµС‚ РїСЂРѕРґРѕР»Р¶РёС‚СЊ РѕС‚Р»Р°РґРєСѓ `allproc`/`ourproc`.

---

## Р‘Р°Рі #230: `ourproc()` РїСЂРёРЅРёРјР°Р» РјСѓСЃРѕСЂРЅС‹Р№ `pid` РєР°Рє РІР°Р»РёРґРЅС‹Р№ next hop (2026-03-31, СЃРµСЃСЃРёСЏ 18)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ С„РёРєСЃР° Bug #229 `allproc` СѓР¶Рµ СЃС‚Р°Р±РёР»СЊРЅРѕ РЅР°С…РѕРґРёР»СЃСЏ, РЅРѕ `ourproc()` РІСЃС‘ РµС‰С‘ РЅРµ РґРѕС…РѕРґРёР» РґРѕ `pid=407`:
- `kernprocaddress()` РЅР°С€С‘Р» runtime candidate `kbase + 0x31FFC68`
- `discover_proc_list_layout()` РїРѕРґС‚РІРµСЂРґРёР» РЅРѕРІС‹Р№ layout `list_off=0x158`, `pid_off=0x60`
- РѕР±С…РѕРґ С€С‘Р» С‚Р°Рє: `pid 0 -> pid 6 -> pid 2869045281 -> raw_next=0`
- Р·Р°С‚РµРј `ourproc()` Р·Р°РІРµСЂС€Р°Р»СЃСЏ `NOT FOUND`

**Root cause:** even after normalizing `next` as base `proc`, traversal loop itself РІСЃС‘ РµС‰С‘ РЅРµРґРѕСЃС‚Р°С‚РѕС‡РЅРѕ Р¶С‘СЃС‚РєРѕ С„РёР»СЊС‚СЂРѕРІР°Р» РїСЂРѕРјРµР¶СѓС‚РѕС‡РЅС‹Рµ hop'С‹. РџСЂРё С‡С‚РµРЅРёРё РѕС‡РµСЂРµРґРЅРѕРіРѕ РєР°РЅРґРёРґР°С‚Р° РєРѕРґ РїСЂРѕСЃС‚Рѕ Р»РѕРіРёСЂРѕРІР°Р» `pid`, РґР°Р¶Рµ РµСЃР»Рё СЌС‚Рѕ Р±С‹Р» СЏРІРЅРѕ РјСѓСЃРѕСЂРЅС‹Р№ 32-bit value. РР·-Р·Р° СЌС‚РѕРіРѕ loop РјРѕРі РїСЂРёРЅСЏС‚СЊ Р»РѕР¶РЅС‹Р№ next node Рё СЃР»РѕРјР°С‚СЊ С†РµРїРѕС‡РєСѓ СЂР°РЅСЊС€Рµ РІСЂРµРјРµРЅРё.

**Р¤Р°Р№Р»:** `darksword/utils.m`  
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” `allproc` РЅР°Р№РґРµРЅ, РЅРѕ СЃРѕР±СЃС‚РІРµРЅРЅС‹Р№ `proc` РІСЃС‘ РµС‰С‘ РЅРµ РѕР±РЅР°СЂСѓР¶РёРІР°РµС‚СЃСЏ, СЃР»РµРґРѕРІР°С‚РµР»СЊРЅРѕ credential patch/post-exploit РѕСЃС‚Р°СЋС‚СЃСЏ РЅРµСЂР°Р±РѕС‡РёРјРё.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РІ `ourproc()` Рё РІ reverse-walk РґРѕР±Р°РІР»РµРЅ `read_proc_pid_checked(...)`
- РµСЃР»Рё `pid` РЅРµ РїСЂРѕС…РѕРґРёС‚ `is_plausible_pid()`, traversal РЅРµРјРµРґР»РµРЅРЅРѕ РѕСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ РєР°Рє invalid hop
- С‡С‚РµРЅРёРµ `next` РІ РѕСЃРЅРѕРІРЅРѕРј РѕР±С…РѕРґРµ РїРµСЂРµРІРµРґРµРЅРѕ РЅР° `proc_list_next_checked_pid(...)`
- direct `pac_strip(raw_next)` Р±РѕР»СЊС€Рµ РЅРµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ РєР°Рє РёСЃС‚РѕС‡РЅРёРє СЃР»РµРґСѓСЋС‰РµРіРѕ `proc`

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** loop РїРµСЂРµСЃС‚Р°РЅРµС‚ Р·Р°С…РѕРґРёС‚СЊ РІ РѕС‡РµРІРёРґРЅРѕ Р»РѕР¶РЅС‹Р№ `proc` СЃ РјСѓСЃРѕСЂРЅС‹Рј `pid` Рё Р»РёР±Рѕ РґРѕР№РґС‘С‚ РґРѕ СЂРµР°Р»СЊРЅРѕРіРѕ `pid=<our pid>`, Р»РёР±Рѕ РґР°СЃС‚ Р±РѕР»РµРµ С‚РѕС‡РЅСѓСЋ СЃР»РµРґСѓСЋС‰СѓСЋ РґРёР°РіРЅРѕСЃС‚РёРєСѓ РїРѕ СЃС‚СЂСѓРєС‚СѓСЂРµ СЃРїРёСЃРєР°.

---

## Р‘Р°Рі #229: `ourproc()` РѕР±С…РѕРґРёР» `LIST_ENTRY`, Р° РЅРµ base `proc` (2026-03-31, СЃРµСЃСЃРёСЏ 17)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ СѓСЃРїРµС€РЅРѕРіРѕ `kernel r/w` Рё СѓР¶Рµ РЅР°Р№РґРµРЅРЅРѕРіРѕ `allproc` post-exploit РІСЃС‘ СЂР°РІРЅРѕ Р»РѕРјР°Р»СЃСЏ РЅР° `ourproc()`:
- `kernprocaddress()` РІРѕР·РІСЂР°С‰Р°Р» РІР°Р»РёРґРЅС‹Р№ runtime offset `0x321b080`
- `discover_proc_list_layout()` РЅР°С…РѕРґРёР» РєРѕСЂСЂРµРєС‚РЅС‹Р№ layout РІ `__DATA.__bss`
- РЅРѕ `ourproc()` Р»РѕРіРёСЂРѕРІР°Р» С‚РѕР»СЊРєРѕ `pid=0 -> pid=0 -> pid=1`, РїРѕСЃР»Рµ С‡РµРіРѕ РїРѕР»СѓС‡Р°Р» `raw_next=0x0`
- РёС‚РѕРі: `returned from ourproc(): 0x0`

**Root cause:** РЅР° С‚РµРєСѓС‰РµРј boot/layout link РІ proc list РЅРµ РІСЃРµРіРґР° РјРѕР¶РЅРѕ С‚СЂР°РєС‚РѕРІР°С‚СЊ РєР°Рє РїСЂСЏРјРѕР№ base pointer РЅР° СЃР»РµРґСѓСЋС‰РёР№ `proc`. Р’ С‡Р°СЃС‚Рё СЃР»СѓС‡Р°РµРІ СЌС‚Рѕ pointer РІРЅСѓС‚СЂСЊ `LIST_ENTRY` СЃР»РµРґСѓСЋС‰РµРіРѕ `proc`. РЎС‚Р°СЂС‹Р№ РєРѕРґ РІ РѕР±С…РѕРґРµ Рё РІ helper'Р°С… РІРѕР·РІСЂР°С‰Р°Р» `pac_strip(raw)` Р±РµР· РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅРѕР№ РЅРѕСЂРјР°Р»РёР·Р°С†РёРё, РїРѕСЌС‚РѕРјСѓ traversal СѓС…РѕРґРёР» РІРЅСѓС‚СЂСЊ link-СѓР·Р»Р° Рё Р±С‹СЃС‚СЂРѕ Р·Р°РєР°РЅС‡РёРІР°Р»СЃСЏ.

**Р¤Р°Р№Р»:** `darksword/utils.m`  
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” `allproc` СѓР¶Рµ РЅР°Р№РґРµРЅ, РЅРѕ РїРѕРёСЃРє СЃРѕР±СЃС‚РІРµРЅРЅРѕРіРѕ `proc` РІСЃС‘ РµС‰С‘ РЅРµРІРѕР·РјРѕР¶РµРЅ, Р·РЅР°С‡РёС‚ root/post-exploit РЅРµ СЃС‚Р°СЂС‚СѓРµС‚.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ `normalize_proc_link_target_with_pid()`
- РґР»СЏ РєР°Р¶РґРѕРіРѕ raw link С‚РµРїРµСЂСЊ РїСЂРѕРІРµСЂСЏСЋС‚СЃСЏ 2 РІР°СЂРёР°РЅС‚Р°:
  1. raw РєР°Рє base `proc`
  2. `raw - list_off` РєР°Рє base `proc`
- РІС‹Р±РёСЂР°РµС‚СЃСЏ РІР°СЂРёР°РЅС‚, Сѓ РєРѕС‚РѕСЂРѕРіРѕ СѓСЃРїРµС€РЅРѕ С‡РёС‚Р°РµС‚СЃСЏ plausible `pid`
- `proc_list_next_checked()` / `proc_list_prev()` РїРµСЂРµРІРµРґРµРЅС‹ РЅР° СЌС‚Сѓ РЅРѕСЂРјР°Р»РёР·Р°С†РёСЋ
- `discover_proc_list_layout()` С‚РµРїРµСЂСЊ РёСЃРїРѕР»СЊР·СѓРµС‚ pid-aware normalizer РґР»СЏ `next` Рё `nextnext`

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** traversal РїРѕСЃР»Рµ РЅР°Р№РґРµРЅРЅРѕРіРѕ `allproc` РґРѕР»Р¶РµРЅ РїРѕР№С‚Рё РїРѕ СЂРµР°Р»СЊРЅС‹Рј base-Р°РґСЂРµСЃР°Рј `proc` Рё РІРїРµСЂРІС‹Рµ РґРѕР№С‚Рё РґРѕ `pid=<our pid>` РІРјРµСЃС‚Рѕ СЂР°РЅРЅРµР№ РѕСЃС‚Р°РЅРѕРІРєРё РЅР° `pid 1`.

---

## Р‘Р°Рі #223: 32-bit write corruption РІ `struct socket` (2026-03-31, СЃРµСЃСЃРёСЏ 12)

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ РїРµСЂРµС…РѕРґР° РЅР° iOS 17 offset `0x24c` refcount patch РІСЃС‘ РµС‰С‘ РјРѕРі РїСЂРёРІРѕРґРёС‚СЊ Рє panic РёР»Рё РјСѓСЃРѕСЂРЅС‹Рј Р·РЅР°С‡РµРЅРёСЏРј РІ СЃРѕСЃРµРґРЅРёС… РїРѕР»СЏС… socket struct.  
**Root cause:** 32-bit РїРѕР»СЏ `so_usecount` / `so_retaincnt` С‡РёС‚Р°Р»РёСЃСЊ Рё РїР°С‚С‡РёР»РёСЃСЊ С‡РµСЂРµР· РѕР±С‰РёР№ 8-byte primitive Р±РµР· Р°РєРєСѓСЂР°С‚РЅРѕРіРѕ РІС‹Р±РѕСЂР° РїРѕР»РѕРІРёРЅС‹ qword. РџСЂРё Р·Р°РїРёСЃРё РјРѕР¶РЅРѕ Р±С‹Р»Рѕ РёСЃРїРѕСЂС‚РёС‚СЊ СЃРѕСЃРµРґРЅРµРµ 32-bit РїРѕР»Рµ.  
**Р¤Р°Р№Р»С‹:** `darksword_core.m`  
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” РїРѕСЂС‡Р° `struct socket`, РЅРµСЃС‚Р°Р±РёР»СЊРЅС‹Р№ kernel r/w, panic РїРѕСЃР»Рµ refcount patch.

**РСЃРїСЂР°РІР»РµРЅРёРµ:** РґРѕР±Р°РІР»РµРЅС‹ `kread32_aligned()` Рё `kwrite32_aligned()`:
- Р°РґСЂРµСЃ РѕРєСЂСѓРіР»СЏРµС‚СЃСЏ РІРЅРёР· РґРѕ 8-byte boundary
- С‡РёС‚Р°РµС‚СЃСЏ РѕРґРёРЅ qword
- РїР°С‚С‡РёС‚СЃСЏ С‚РѕР»СЊРєРѕ РЅСѓР¶РЅР°СЏ 32-bit РїРѕР»РѕРІРёРЅР°
- Р·Р°С‚РµРј qword РїРёС€РµС‚СЃСЏ РѕР±СЂР°С‚РЅРѕ

Р­С‚Рѕ СѓСЃС‚СЂР°РЅРёР»Рѕ РїРѕСЂС‡Сѓ СЃРѕСЃРµРґРЅРµРіРѕ РїРѕР»СЏ РїСЂРё СЂР°Р±РѕС‚Рµ СЃ `so_usecount`/`so_retaincnt` РЅР° iOS 17.

---

## Р‘Р°Рі #224: `site.struct inpcb` РѕС‚РІРµСЂРіР°Р»СЃСЏ + bounds Р±С‹Р»Рё СЃР»РёС€РєРѕРј СѓР·РєРёРјРё (2026-03-31, СЃРµСЃСЃРёСЏ 12b)

**РЎРёРјРїС‚РѕРј:** exploit РґРѕС…РѕРґРёР» РґРѕ zone discovery, РЅРѕ:
- zone name `site.struct inpcb` РЅРµ СЃС‡РёС‚Р°Р»СЃСЏ РІР°Р»РёРґРЅС‹Рј
- fallback bounds Р±С‹Р»Рё СЃР»РёС€РєРѕРј СѓР·РєРёРјРё
- `struct socket` РѕРєР°Р·С‹РІР°Р»СЃСЏ РІРЅРµ emergency РѕРєРЅР° РѕС‚РЅРѕСЃРёС‚РµР»СЊРЅРѕ `struct inpcb`
- refcount bump СЃСЂС‹РІР°Р»СЃСЏ в†’ sockets РѕСЃРІРѕР±РѕР¶РґР°Р»РёСЃСЊ РІРѕ РІСЂРµРјСЏ allproc scan в†’ panic

**Root cause:**
1. `is_expected_ipi_zone_name()` РїСЂРёРЅРёРјР°Р» С‚РѕР»СЊРєРѕ РєРѕСЂРѕС‚РєРёРµ С‚РѕС‡РЅС‹Рµ РёРјРµРЅР° (`inpcb`, `raw6` Рё С‚.Рї.)
2. emergency / primed bounds РёСЃРїРѕР»СЊР·РѕРІР°Р»Рё С‚РѕР»СЊРєРѕ `ZONE_MAP_SPAN/3` (~8 GB), Р° РЅР° A12Z РґРёСЃС‚Р°РЅС†РёСЏ `inpcb в†” socket` РѕРєР°Р·Р°Р»Р°СЃСЊ ~11.5 GB

**Р¤Р°Р№Р»С‹:** `darksword_core.m`  
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” exploit РґРѕС…РѕРґРёР» РґРѕ kernel base, РЅРѕ Р»РѕРјР°Р»СЃСЏ РґРѕ СЃС‚Р°Р±РёР»СЊРЅРѕРіРѕ allproc scan.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- `is_expected_ipi_zone_name()` РїРµСЂРµРІРµРґС‘РЅ РЅР° substring match РїРѕ `inpcb`
- `prime_zone_bounds_from_rw_pcb()` в†’ РѕРєРЅРѕ СЂР°СЃС€РёСЂРµРЅРѕ РґРѕ РїРѕР»РЅРѕРіРѕ `ZONE_MAP_SPAN`
- `discover_zone_boundaries_raw()` emergency path в†’ С‚РѕР¶Рµ РїРѕР»РЅС‹Р№ `ZONE_MAP_SPAN`

**РџРѕРґС‚РІРµСЂР¶РґРµРЅРёРµ syslog-РѕРј:**
- `zone name: site.struct inpcb` в†’ accepted
- `zone_info FOUND ... zone_map [0xffffffdcc181c000 - 0xffffffe2c181c000]`
- `refcount bumped OK`

---

## Р‘Р°Рі #225: allproc scan С‡РёС‚Р°Р» per-CPU zone allocation в†’ panic РІ `zalloc.c` (2026-03-31, СЃРµСЃСЃРёСЏ 12b)

**РЎРёРјРїС‚РѕРј:** panic СѓР¶Рµ РїРѕСЃР»Рµ СѓСЃРїРµС€РЅС‹С…:
- zone discovery
- `kernel-base fallback`
- socket refcount/usecount patch
- kread health check

РџРѕСЃР»РµРґРЅРёРµ СЃС‚СЂРѕРєРё syslog:
```text
[allproc] scan __DATA.__common: 0xfffffff0254ef000..0xfffffff025547000
[val_ap] disc_layout FAILED ...
[allproc] reading scan chunk at 0xfffffff0254f0000
[disconnected]
```

**РџР°РЅРёРє-С„Р°Р№Р»:** `panic-full-2026-03-31-184806.000.ips`  
**Panic string:**
```text
panic(cpu 6 caller ...): zone bound checks: address 0xffffffdcc189e4e0 is a per-cpu allocation @zalloc.c:1267
```

**Zone info РёР· panic:**
- `zone_map = 0xffffffdcc181c000 - 0xffffffe2c181c000`
- panic address `0xffffffdcc189e4e0` Р»РµР¶РёС‚ РїРѕС‡С‚Рё Сѓ РЅР°С‡Р°Р»Р° `zone_map`
- СЌС‚Рѕ VM-submap, СЃРѕРґРµСЂР¶Р°С‰РёР№ per-CPU allocations

**Root cause:** `is_heap_ptr()` СЃС‡РёС‚Р°Р» РІР°Р»РёРґРЅС‹Рј Р»СЋР±РѕР№ PAC-stripped Р°РґСЂРµСЃ РІРЅСѓС‚СЂРё РїРѕР»РЅРѕРіРѕ `zone_map`.  
Р’Рѕ РІСЂРµРјСЏ `scan_range_for_allproc()` РЅРµРєРѕС‚РѕСЂС‹Рµ qword'С‹ РёР· `__DATA.__common` РІС‹РіР»СЏРґРµР»Рё РєР°Рє heap-РїРѕРёРЅС‚РµСЂС‹, РЅРѕ РЅР° РґРµР»Рµ СѓРєР°Р·С‹РІР°Р»Рё РІ VM-submap (`per-cpu allocation`). РЎР»РµРґСѓСЋС‰РёР№ `ds_kread32_checked(first_q + PROC_PID_OFFSET)` Р·Р°РїСѓСЃРєР°Р» copyout РёР· per-CPU Р°РґСЂРµСЃР°, Рё XNU РїР°РЅРёРєРѕРІР°Р» РІ `zone_bound_checks`.

**Р¤Р°Р№Р»С‹:** `utils.m`, `darksword_core.m`, `darksword_core.h`  
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” exploit РїСЂРѕС…РѕРґРёС‚ РІРµСЃСЊ СЂР°РЅРЅРёР№ chain, РЅРѕ РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕ РїР°РЅРёРєСѓРµС‚ РІ allproc scan.

**РСЃРїСЂР°РІР»РµРЅРёРµ:**
- РґРѕР±Р°РІР»РµРЅ `g_zone_safe_min`
- РїРѕСЃР»Рµ discovery/priming bounds РІС‹С‡РёСЃР»СЏРµС‚СЃСЏ `g_zone_safe_min = g_zone_map_min + ZONE_MAP_SPAN / 4`
- `is_heap_ptr()` С‚РµРїРµСЂСЊ РёСЃРїРѕР»СЊР·СѓРµС‚ `ds_get_zone_safe_min()` РєР°Рє РЅРёР¶РЅСЋСЋ РіСЂР°РЅРёС†Сѓ РґР»СЏ heap object pointers

**РџРѕС‡РµРјСѓ СЌС‚Рѕ Р±РµР·РѕРїР°СЃРЅРѕ:**
- VM + RO submaps Р·Р°РЅРёРјР°СЋС‚ РЅР°С‡Р°Р»СЊРЅСѓСЋ С‡Р°СЃС‚СЊ `zone_map`
- СЂРµР°Р»СЊРЅС‹Рµ zone objects (`proc`, `task`, `socket`, `inpcb`) Р¶РёРІСѓС‚ РІ GEN0/GEN1/GEN2/GEN3/DATA
- safe lower bound РѕС‚СЃРµРєР°РµС‚ per-CPU/VM zone addresses РґРѕ РїРµСЂРІРѕРіРѕ heap-read

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** allproc scan Р±СѓРґРµС‚ skip-Р°С‚СЊ С‚Р°РєРёРµ Р»РѕР¶РЅС‹Рµ РєР°РЅРґРёРґР°С‚С‹ РґРѕ `kread32(pid)` Рё РЅРµ РґРѕР»Р¶РµРЅ Р±РѕР»СЊС€Рµ РїР°РЅРёРєРѕРІР°С‚СЊ РЅР° `address X is a per-cpu allocation`.

---

## Р‘Р°Рі #201: Zone Metadata Kernel Data Abort (2026-03-31)

**РЎРёРјРїС‚РѕРј:** `panic(cpu 5 caller 0xfffffff012db6b00): Kernel data abort` РїСЂРё РєР°Р¶РґРѕРј Р·Р°РїСѓСЃРєРµ  
**ESR:** `0x96000007` (data abort, translation fault L3 вЂ” СЃС‚СЂР°РЅРёС†Р° РЅРµ РѕС‚РѕР±СЂР°Р¶РµРЅР°)  
**FAR:** `0xffffffdd8e93dec0` вЂ” Р°РґСЂРµСЃ РІ Zone Metadata (`0xffffffdd8d9fc000вЂ“0xffffffdd8f1fc000`)  
**РџР°РЅРёРє-С„Р°Р№Р»:** `panic-full-2026-03-31-064627.000.ips`, pid 1025 DarkSword  
**Root cause:** Fallback РІ `discover_zone_boundaries_raw()` РІС‹С‡РёСЃР»СЏР» РЅРёР¶РЅСЋСЋ РіСЂР°РЅРёС†Сѓ РєР°Рє  
  `g_zone_map_min = rw_socket_pcb - ZONE_MAP_SPAN/3` (~8 GB).  
  РџСЂРё `rw_socket_pcb в‰€ 0xffffffe5...` СЌС‚Рѕ РґР°РІР°Р»Рѕ `g_zone_map_min в‰€ 0xffffffdd...`,  
  С‡С‚Рѕ Р’РљР›Р®Р§РђР›Рћ Zone Metadata РІ СЏРєРѕР±С‹ В«Р±РµР·РѕРїР°СЃРЅС‹Р№В» РґРёР°РїР°Р·РѕРЅ.  
  `set_target_kaddr()` РїСЂРѕРїСѓСЃРєР°Р» Р°РґСЂРµСЃ `0xffffffdd8e93dec0`, СЏРґСЂРѕ РїС‹С‚Р°Р»РѕСЃСЊ РІС‹РїРѕР»РЅРёС‚СЊ  
  `copyout` РёР· СЌС‚РѕРіРѕ Р°РґСЂРµСЃР° в†’ translation fault в†’ kernel panic.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” kernel panic РїСЂРё РєР°Р¶РґРѕРј Р·Р°РїСѓСЃРєРµ РїРѕСЃР»Рµ РїРѕР»СѓС‡РµРЅРёСЏ kernel R/W

```c
// Р‘Р«Р›Рћ:
const uint64_t FALLBACK_SPAN = ZONE_MAP_SPAN / 3; /* ~8 GB */
g_zone_map_min = rw_socket_pcb - FALLBACK_SPAN;   // в†’ 0xffffffdd... в‰Ў Zone Metadata!
if (g_zone_map_min < 0xffffffd000000000ULL)        // СЃР»РёС€РєРѕРј РЅРёР·РєР°СЏ Р·Р°С‰РёС‚Р°
    g_zone_map_min = 0xffffffd000000000ULL;

// РЎРўРђР›Рћ:
g_zone_map_min = rw_socket_pcb - FALLBACK_SPAN;
if (g_zone_map_min < 0xffffffe000000000ULL)        // Zone Metadata РІСЃРµРіРґР° < 0xffffffe0
    g_zone_map_min = 0xffffffe000000000ULL;
```

**РСЃРїСЂР°РІР»РµРЅРѕ РІ 4 РјРµСЃС‚Р°С…:**
1. `set_target_kaddr()` fallback branch: РЅРёР¶РЅСЏСЏ РіСЂР°РЅРёС†Р° `0xffffffd...` в†’ `0xffffffe0...`
2. `discover_zone_boundaries_raw()` FALLBACK_SPAN clamp: `0xffffffd...` в†’ `0xffffffe0...`
3. `discover_zone_boundaries_raw()` EMERGENCY bounds: `0xffffffd...` в†’ `0xffffffe0...`
4. `discover_zone_boundaries_raw()` last resort static: `0xffffffd...` в†’ `0xffffffe0...`

**РџРѕРґС‚РІРµСЂР¶РґРµРЅРёРµ:** РќР° РјРѕРјРµРЅС‚ РїР°РЅРёРєРё zone_map Р±С‹Р» `0xffffffe2f7470000вЂ“0xffffffe8f7470000`,
Zone Metadata вЂ” `0xffffffdd8d9fc000вЂ“0xffffffdd8f1fc000`. РџСЂР°РІРёР»СЊРЅР°СЏ РЅРёР¶РЅСЏСЏ РіСЂР°РЅРёС†Р° в‰Ґ `0xffffffe0...`.

---

## Р‘Р°Рі #202: allproc NOT FOUND вЂ” РІРµСЃСЊ post-exploit С†РµРїРѕС‡РєР° РјРµСЂС‚РІР° (2026-03-31, СЃРµСЃСЃРёСЏ 2)

**РЎРёРјРїС‚РѕРј:** Р›РѕРі РїРѕРєР°Р·С‹РІР°РµС‚ С†РёРєР»РёС‡РµСЃРєРё:
```
[allproc] trying legacy __DATA+0x60 allproc offset 0x3198060 -> addr 0xfffffff02bd34060
[allproc] legacy __DATA+0x60 allproc validation failed
[allproc] ERROR: all strategies exhausted, allproc not found
[ourproc] ERROR: kernprocaddress() returned 0
```
Post-exploit С†РµРїРѕС‡РєР°: root=NO, unsandboxed=NO, platformized=NO, AMFI disabled=NO (4 РѕС€РёР±РєРё).

**Kernel base РёР· Р»РѕРіР°:** `kbase=0xfffffff028b9c000`, slide=`0x21b98000`

**Root cause:** РЎРјРµС‰РµРЅРёРµ `0x93B348` вЂ” СЂРµР°Р»СЊРЅРѕРµ СЃРјРµС‰РµРЅРёРµ `allproc` РѕС‚ `kbase` РЅР° iOS 17.3.1 / 21D61 / A12Z.
Р’С‹С‡РёСЃР»СЏРµС‚СЃСЏ РёР· РєРѕРЅСЃС‚Р°РЅС‚ `v109.c`: `UNSLID_ALLPROC (0xFFFFFFF00793F348) - UNSLID_BASE (0xFFFFFFF007004000) = 0x93B348`.
РћРЅРѕ Р±С‹Р»Рѕ **РѕС€РёР±РѕС‡РЅРѕ РїРѕРјРµС‡РµРЅРѕ РІ РєРѕРјРјРµРЅС‚Р°СЂРёРё РєР°Рє В«badВ»** (`0x93B348 в†’ __DATA_CONST (read-only data, NOT allproc)`) вЂ” РѕС€РёР±РѕС‡РЅРѕ.
РќР° СЃР°РјРѕРј РґРµР»Рµ СЌС‚Рѕ _mutable global_ РІ kernel __DATA, Р·Р°РїРѕР»РЅСЏРµС‚СЃСЏ СЏРґСЂРѕРј РїСЂРё Р±СѓС‚Рµ.
Р•РґРёРЅСЃС‚РІРµРЅРЅРѕРµ СЂР°Р±РѕС‡РµРµ СЃРјРµС‰РµРЅРёРµ Р±С‹Р»Рѕ РёСЃРєР»СЋС‡РµРЅРѕ, РїРѕСЌС‚РѕРјСѓ allproc РІСЃРµРіРґР° РЅРµ РЅР°С…РѕРґРёР»СЃСЏ.

**РџРѕС‡РµРјСѓ 0x3198060 (`__DATA+0x60`) РЅРµ СЂР°Р±РѕС‚Р°РµС‚:**
РЅР° СЌС‚РѕРј kernelcache РІ runtime РїРѕ `kbase+0x3198060` Р»РµР¶РёС‚ РґСЂСѓРіРѕРµ Р·РЅР°С‡РµРЅРёРµ, validate_allproc() РІРѕР·РІСЂР°С‰Р°РµС‚ false.

**Р¤Р°Р№Р»:** `darksword/utils.m`, С„СѓРЅРєС†РёСЏ `kernprocaddress()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” РІСЃС‘ post-exploitation РјРµСЂС‚РІРѕ: РЅРµС‚ root, РЅРµС‚ sandbox escape, РЅРµС‚ platformize, РЅРµС‚ AMFI bypass

```c
// Р‘Р«Р›Рћ (РѕС€РёР±РѕС‡РЅС‹Р№ РєРѕРјРјРµРЅС‚Р°СЂРёР№, СЃРјРµС‰РµРЅРёРµ РёСЃРєР»СЋС‡РµРЅРѕ РїРѕР»РЅРѕСЃС‚СЊСЋ):
/*
 * Verified bad offsets:
 *   0x93B348 в†’ __DATA_CONST (read-only data, NOT allproc)  в†ђ РќР•Р’Р•Р РќРћ!
 */
// ... С‚РѕР»СЊРєРѕ 0x3198060 РїСЂРѕР±РѕРІР°Р»СЃСЏ, РІСЃРµРіРґР° РїСЂРѕРІР°Р»РІРёРІР°Р»СЃСЏ

// РЎРўРђР›Рћ:
// iOS 17.3.1 21D61 A12Z: allproc at kbase+0x93B348
// UNSLID_ALLPROC (0xFFFFFFF00793F348) - UNSLID_BASE (0xFFFFFFF007004000) = 0x93B348
if (try_allproc_candidate("iOS17.3.1 kbase+0x93B348", kbase, 0x93B348ULL, true, &addr)) {
    return addr;
}
```

**Р”РѕРїРѕР»РЅРёС‚РµР»СЊРЅРѕ:** РЎРєР°РЅ `__DATA` СЂР°СЃС€РёСЂРµРЅ СЃ 16KB РґРѕ 256KB РґР»СЏ РїРѕРєСЂС‹С‚РёСЏ РґСЂСѓРіРёС… build-РІР°СЂРёР°РЅС‚РѕРІ.

---

## Р‘Р°Рі #203: Log spam вЂ” BLOCKED misaligned, 829KB Р»РѕРі, РїСЂРёР»РѕР¶РµРЅРёРµ РІРёСЃР»Рѕ (2026-03-31, СЃРµСЃСЃРёСЏ 2)

**РЎРёРјРїС‚РѕРј:** Р¤Р°Р№Р» Р»РѕРіР° `log.txt` = 829KB. РџРѕР»РѕРІРёРЅР° С„Р°Р№Р»Р° СЃРѕСЃС‚РѕРёС‚ РёР· СЃС‚СЂРѕРє:
```
[exploit] set_target_kaddr: BLOCKED misaligned addr 0xffffffe523231dcb
getsockopt failed (early_kread)!
[exploit] set_target_kaddr: BLOCKED misaligned addr 0xffffffe523231dd3
...
(СЃРѕС‚РЅРё РїРѕРІС‚РѕСЂРµРЅРёР№)
```
РџСЂРёР»РѕР¶РµРЅРёРµ Р·Р°РІРёСЃР°Р»Рѕ РЅР° РЅРµСЃРєРѕР»СЊРєРѕ РјРёРЅСѓС‚ РІРѕ РІСЂРµРјСЏ `tc_init` / trust cache scan.

**Root cause:** Trustcache scan РїРµСЂРµРґР°РІР°Р» misaligned Р°РґСЂРµСЃР° РІ `set_target_kaddr()`, РєРѕС‚РѕСЂР°СЏ
Р±РµР· РѕРіСЂР°РЅРёС‡РµРЅРёР№ Р»РѕРіРёСЂРѕРІР°Р»Р° РєР°Р¶РґС‹Р№ РёР· РЅРёС…. РџСЂРё СЃРєР°РЅРёСЂРѕРІР°РЅРёРё `__DATA` (4MB) + xref-СЃРєР°РЅРµ
РіРµРЅРµСЂРёСЂРѕРІР°Р»РёСЃСЊ С‚С‹СЃСЏС‡Рё РІС‹Р·РѕРІРѕРІ СЃ РЅРµС‡С‘С‚РЅРѕРІС‹СЂРѕРІРЅРµРЅРЅС‹РјРё heap-РєР°РЅРґРёРґР°С‚Р°РјРё. РљР°Р¶РґС‹Р№ РїРёС€РµС‚ РІ Р»РѕРі.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`, С„СѓРЅРєС†РёСЏ `set_target_kaddr()`
**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™ вЂ” РїСЂРёР»РѕР¶РµРЅРёРµ РєР°Р¶РµС‚СЃСЏ Р·Р°РІРёСЃС€РёРј, С„Р°Р№Р» Р»РѕРіР° СЂР°Р·РґСѓРІР°РµС‚СЃСЏ, Р°РЅР°Р»РёР· Р·Р°С‚СЂСѓРґРЅС‘РЅ

```c
// Р‘Р«Р›Рћ: Р±РµСЃРєРѕРЅС‚СЂРѕР»СЊРЅРѕРµ Р»РѕРіРёСЂРѕРІР°РЅРёРµ РєР°Р¶РґРѕРіРѕ misaligned Р°РґСЂРµСЃР°
pe_log("set_target_kaddr: BLOCKED misaligned addr 0x%llx", where);

// РЎРўРђР›Рћ: rate-limit, С‚РѕР»СЊРєРѕ РїРµСЂРІС‹Рµ 5 СЂР°Р·
static int s_misalign_log_count = 0;
if (++s_misalign_log_count <= 5) {
    pe_log("set_target_kaddr: BLOCKED misaligned addr 0x%llx (count=%d)", where, s_misalign_log_count);
}
```

---

## Р‘Р°Рі #204: trustcache xref-СЃРєР°РЅ Р±РµР· Р»РёРјРёС‚Р° kr64 в†’ Р·Р°РІРёСЃР°РЅРёРµ (2026-03-31, СЃРµСЃСЃРёСЏ 2)

**РЎРёРјРїС‚РѕРј:** `find_tc_head_by_string_xref()` СЃРєР°РЅРёСЂРѕРІР°Р»Р° РґРѕ 4MB `__DATA` (400 СЃС‚СЂР°РЅРёС† Г— 512 qwords),
РЅР° РєР°Р¶РґРѕРј kernel-text-pointer Р·Р°РїСѓСЃРєР°Р»Р° РґРѕ 17 kr64-РІС‹Р·РѕРІРѕРІ (xnext + 8Г—moff-РєР°РЅРґРёРґР°С‚РѕРІ).
РџСЂРё СЌС‚РѕРј РєР°Р¶РґС‹Р№ kr64 СЃ РЅРµС‡С‘С‚РЅС‹Рј Р°РґСЂРµСЃРѕРј Р»РѕРіРёСЂРѕРІР°Р» BLOCKED в†’ С‚С‹СЃСЏС‡Рё СЃС‚СЂРѕРє РІ Р»РѕРі в†’ Р·Р°РІРёСЃР°РЅРёРµ.

**Root cause:**
1. `seg_scan` РѕРіСЂР°РЅРёС‡РµРЅРёРµ: 4MB (`0x400000`) РЅР° СЃРµРіРјРµРЅС‚ вЂ” СЃР»РёС€РєРѕРј Р±РѕР»СЊС€РѕРµ РґР»СЏ xref-СЃРєР°РЅР°
2. РќРµС‚ СЃС‡С‘С‚С‡РёРєР° kr64-РІС‹Р·РѕРІРѕРІ в†’ РЅРµС‚ early exit
3. `__PPLDATA` РЅРµ РїСЂРѕРїСѓСЃРєР°Р»СЃСЏ вЂ” С‡С‚РµРЅРёРµ РёР· PPL-protected СЃРµРіРјРµРЅС‚Р° РІС‹Р·С‹РІР°РµС‚ panic РЅР° iPad8,9

**Р¤Р°Р№Р»:** `darksword/trustcache.m`, С„СѓРЅРєС†РёСЏ `find_tc_head_by_string_xref()`
**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™ вЂ” Р·Р°РІРёСЃР°РЅРёРµ РЅР° РЅРµСЃРєРѕР»СЊРєРѕ РјРёРЅСѓС‚, PPL panic-СЂРёСЃРє

```c
// Р‘Р«Р›Рћ:
uint64_t seg_scan = (data_segs[d].size < 0x400000) ? data_segs[d].size : 0x400000;
// Р±РµР· Р»РёРјРёС‚Р° kr64-РІС‹Р·РѕРІРѕРІ

// РЎРўРђР›Рћ:
// skip PPL-protected
if (strncmp(data_segs[d].name, "__PPLDATA", 9) == 0) { continue; }
// СѓРјРµРЅСЊС€РµРЅ СЃРєР°РЅ РґРѕ 256KB
uint64_t seg_scan = (data_segs[d].size < 0x40000) ? data_segs[d].size : 0x40000;
// Р»РёРјРёС‚ kr64 РІС‹Р·РѕРІРѕРІ
if (++xref_kread_calls > 300) { goto xref_scan_done; }
```

---

## Р‘Р°Рі #1: copy_validate kernel panic (Boot A)

**РЎРёРјРїС‚РѕРј:** Panic РЅР° `copy_validate` вЂ” РїС‹С‚Р°Р»СЃСЏ СЃРєРѕРїРёСЂРѕРІР°С‚СЊ РёР· userspace addressР°  
**Root cause:** OOB write target СѓРєР°Р·С‹РІР°Р» РЅР° userspace РІРјРµСЃС‚Рѕ kernel  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** Р”РѕР±Р°РІР»РµРЅР° РїСЂРѕРІРµСЂРєР° bounds РїРµСЂРµРґ corruption write

```c
// Р‘Р«Р›Рћ: СЃР»РµРїР°СЏ Р·Р°РїРёСЃСЊ
kw32(target, value);

// РЎРўРђР›Рћ: РїСЂРѕРІРµСЂРєР° bounds
if (!is_kernel_addr(target)) {
    LOG("SKIP: target 0x%llx is not kernel", target);
    continue;
}
kw32(target, value);
```

---

## Р‘Р°Рі #2: Zone metadata panic РќРР–Р• (Boot B)

**РЎРёРјРїС‚РѕРј:** `zone_require_ro: caller "zone_id_require_panic" mismatched zone`  
**FAR:** 0xffffff80bc3d1000 вЂ” metadata addr РЅРёР¶Рµ zone_map_min  
**Root cause:** Hardcoded zone bounds В±0x800000 (8MB) вЂ” СЃР»РёС€РєРѕРј РјР°Р»Рѕ РґР»СЏ СЂРµР°Р»СЊРЅРѕРіРѕ layout  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** Runtime Zone Discovery вЂ” scan kernel memory Р·Р° zone_map, РЅР°С…РѕРґРёРј СЂРµР°Р»СЊРЅС‹Рµ bounds

```c
// Р‘Р«Р›Рћ: hardcoded
#define ZONE_RANGE 0x800000

// РЎРўРђР›Рћ: runtime scan В±4MB
uint64_t zone_lo = 0, zone_hi = 0;
for (uint64_t addr = kernel_base; addr < kernel_base + 0x4000000; addr += 8) {
    uint64_t val = kr64(addr);
    if (is_zone_map_ptr(val)) {
        if (val < zone_lo || zone_lo == 0) zone_lo = val;
        if (val > zone_hi) zone_hi = val;
    }
}
```

---

## Р‘Р°Рі #3: Zone metadata panic Р’Р«РЁР• (Boot C)

**РЎРёРјРїС‚РѕРј:** РўРѕ Р¶Рµ panic, РЅРѕ FAR РІС‹С€Рµ zone_map_max  
**Root cause:** Boot layout shift вЂ” Р·РѕРЅС‹ СЃРґРІРёРіР°Р»РёСЃСЊ РјРµР¶РґСѓ РїРµСЂРµР·Р°РіСЂСѓР·РєР°РјРё  
**Fix:** Fallback Рє ZONE_SPAN/3 (~8GB) РµСЃР»Рё runtime scan РЅРµ РЅР°С…РѕРґРёС‚ bounds

---

## Р‘Р°Рі #4: Zone metadata panic Р’Р«РЁР• v2 (Boot D)

**РЎРёРјРїС‚РѕРј:** РўРѕС‚ Р¶Рµ pattern вЂ” metadata above zone_map  
**Root cause:** set_target_kaddr РЅРµ РїСЂРѕРІРµСЂСЏР» bounds  
**Fix:** Р”РѕР±Р°РІР»РµРЅР° bounds check РІ set_target_kaddr + 8Г— safety margin

---

## Р‘Р°Рі #5: Zone metadata via is_kptr (Boot E)

**РЎРёРјРїС‚РѕРј:** zone_require_ro panic РІ ourproc()  
**Root cause:** `is_kptr()` РїСЂРѕРїСѓСЃРєР°Р» Р°РґСЂРµСЃР° РєРѕС‚РѕСЂС‹Рµ РїРѕРїР°РґР°Р»Рё РІ zone metadata  
**Fix:** Р—Р°РјРµРЅР° `is_kptr()` в†’ `is_heap_ptr()` РІ 5 РјРµСЃС‚Р°С…:

```c
// Р‘Р«Р›Рћ (5 РјРµСЃС‚):
if (is_kptr(candidate)) { ...

// РЎРўРђР›Рћ:
if (is_heap_ptr(candidate)) { ...
```

`is_heap_ptr()` РїСЂРѕРІРµСЂСЏРµС‚ С‡С‚Рѕ addr РІ `[zone_lo, zone_hi]` discovered runtime.

---

## Р‘Р°Рі #6: KASLR slide not applied to vmaddr (allproc scan)

**РЎРёРјРїС‚РѕРј:** scan_for_allproc() РЅРёС‡РµРіРѕ РЅРµ РЅР°С…РѕРґРёС‚  
**Root cause:** РњР°СЃРєРё vmaddr РёР· Mach-O header РёСЃРїРѕР»СЊР·РѕРІР°Р»РёСЃСЊ Р±РµР· slide  
**Р¤Р°Р№Р»:** `utils.m`, `scan_for_allproc()`  
**Fix:** 2-pass architecture вЂ” find slide, then scan with slid addresses

```c
// Р‘Р«Р›Рћ:
uint64_t data_start = segment_vmaddr;  // UNSLID!

// РЎРўРђР›Рћ: pass 1 вЂ” find TEXT base, compute slide
uint64_t slide = kernel_base - text_vmaddr;
// pass 2 вЂ” apply slide
uint64_t data_start = segment_vmaddr + slide;
```

---

## Р‘Р°Рі #7: PROC_PID_OFFSET (0x28 в†’ 0x60)

**РЎРёРјРїС‚РѕРј:** РљР°Р¶РґС‹Р№ proc РїРѕРєР°Р·С‹РІР°РµС‚ PID 0 РёР»Рё РјСѓСЃРѕСЂ  
**Root cause:** XNU xnu-10002.1.13 struct proc РёРјРµРµС‚ p_pid at +0x60 (РїРѕСЃР»Рµ p_list, p_lock, p_stat, p_listflag, p_pid)  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** РљРѕРЅСЃС‚Р°РЅС‚Р° РёР·РјРµРЅРµРЅР° СЃ 0x28 РЅР° 0x60  
**Р’РµСЂРёС„РёРєР°С†РёСЏ:** XNU source `bsd/sys/proc_internal.h`

---

## Р‘Р°Рі #8: PROC_UID_OFFSET (0x30 в†’ 0x2C)

**РЎРёРјРїС‚РѕРј:** UID read РІРѕР·РІСЂР°С‰Р°Р» РјСѓСЃРѕСЂ  
**Root cause:** Р¤Р°РєС‚РёС‡РµСЃРєРё p_uid СЂР°СЃРїРѕР»РѕР¶РµРЅ РІ kauth_cred в†’ cr_posix в†’ uid at offset 0x2C РІ proc  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** РР·РјРµРЅС‘РЅ СЃ 0x30 РЅР° 0x2C

---

## Р‘Р°Рі #9: broad `__DATA` scan РІС‹Р·С‹РІР°Р» panic РІ kernel static region

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ С„РёРєСЃР° misaligned heap pointer exploit РґРѕС…РѕРґРёР» РґРѕ `allproc` scan, Р·Р°С‚РµРј СѓСЃС‚СЂРѕР№СЃС‚РІРѕ РїР°РЅРёРєРѕРІР°Р»Рѕ СЃ `Unexpected fault in kernel static region`  
**Root cause:** fallback `scan_for_allproc()` СЃС‡РёС‚Р°Р» РІРµСЃСЊ reported `__DATA` safe, РЅРѕ РЅР° iPad8,9 / iOS 17.3.1 РІС‚РѕСЂР°СЏ 16 KB СЃС‚СЂР°РЅРёС†Р° РґРёР°РїР°Р·РѕРЅР° (`scan start + 0x4000`) РІС‹Р·С‹РІР°Р»Р° panic. РџРѕ panic log: scan start `0xfffffff01ca40000`, FAR `0xfffffff01ca44000`.  
**Р¤Р°Р№Р»:** `utils.m`, `kernprocaddress()`, `scan_for_allproc()`  
**Fix:**
- РїРѕРїСЂРѕР±РѕРІР°С‚СЊ legacy runtime candidate `kbase + 0x3198060` (`__DATA + 0x60`) **РґРѕ** Р»СЋР±РѕРіРѕ broad scan;
- РѕРіСЂР°РЅРёС‡РёС‚СЊ fallback scan С‚РѕР»СЊРєРѕ РїРµСЂРІРѕР№ 16 KB СЃС‚СЂР°РЅРёС†РµР№ `__DATA`.

```c
// Р‘Р«Р›Рћ:
savekernproc(0);
filelog_write("[allproc] attempting PPL-safe __DATA segment scan");
uint64_t scanned = scan_for_allproc();

// РЎРўРђР›Рћ:
if (try_allproc_candidate("legacy __DATA+0x60 allproc", kbase, 0x3198060ULL, true, &addr)) {
  return addr;
}
filelog_write("[allproc] attempting conservative first-page __DATA scan");
```

---

## Р‘Р°Рі #9: PROC_GID_OFFSET (0x34 в†’ 0x30)

**РЎРёРјРїС‚РѕРј:** GID read РІРѕР·РІСЂР°С‰Р°Р» РјСѓСЃРѕСЂ  
**Root cause:** РђРЅР°Р»РѕРіРёС‡РЅРѕ, p_gid at +0x30  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** РР·РјРµРЅС‘РЅ СЃ 0x34 РЅР° 0x30

---

## Р‘Р°Рі #10: Hardcoded allproc offsets (4 С€С‚СѓРєРё)

**РЎРёРјРїС‚РѕРј:** allproc scan РїС‹С‚Р°Р»СЃСЏ С‡РёС‚Р°С‚СЊ РїРѕ РјСѓСЃРѕСЂРЅС‹Рј Р°РґСЂРµСЃР°Рј  
**Root cause:** 4 hardcoded allproc offset РїРѕРїС‹С‚РєРё (0x003C3798, 0x003C39F0, 0x003C2440, 0x003BF600) вЂ” РІСЃРµ РЅРµРІРµСЂРЅС‹ РґР»СЏ РЅР°С€РµРіРѕ kernelcache  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** Р’СЃРµ СѓРґР°Р»РµРЅС‹. `kernprocaddress()` С‚РµРїРµСЂСЊ РёСЃРїРѕР»СЊР·СѓРµС‚ С‚РѕР»СЊРєРѕ dynamic scan С‡РµСЂРµР· __DATA segment

---

## Р‘Р°Рі #11: OV_TYPE vnode.v_type (0x71 в†’ 0x70) в… РљР РРўРР§Р•РЎРљРР™

**РЎРёРјРїС‚РѕРј:** `find_rootvnode()` РќРРљРћР“Р”Рђ РЅРµ РЅР°С…РѕРґРёР» rootvnode в†’ РІРµСЃСЊ KFS РЅРµ СЂР°Р±РѕС‚Р°Р»  
**Root cause:** `v_type` is `uint16_t` at offset +0x70 РІ struct vnode. РљРѕРґ С‡РёС‚Р°Р» +0x71 = HIGH byte of uint16_t = РІСЃРµРіРґР° 0x00  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:**

```c
// Р‘Р«Р›Рћ:
#define OV_TYPE 0x71
uint8_t vtype = (uint8_t)kr32(vnode + OV_TYPE);

// РЎРўРђР›Рћ:
#define OV_TYPE 0x70
uint16_t vtype = (uint16_t)(kr32(vnode + OV_TYPE) & 0xFFFF);
```

**РџРѕС‡РµРјСѓ РєСЂРёС‚РёС‡РµСЃРєРёР№:** Р‘РµР· rootvnode РЅРµРІРѕР·РјРѕР¶РµРЅ path resolution в†’ РЅРµС‚ /var/jb в†’ РЅРµС‚ bootstrap в†’ РЅРµС‚ РґР¶РµР№Р»Р±СЂРµР№РєР°. Р’СЃРµ РїСЂРµРґС‹РґСѓС‰РёРµ Р·Р°РїСѓСЃРєРё СЂР°Р±РѕС‚Р°Р»Рё РґРѕ СЌС‚РѕР№ С‚РѕС‡РєРё Рё С‚РёС…Рѕ С„РµР№Р»РёР»РёСЃСЊ.

---

## Р‘Р°Рі #12: ONC_NEXT namecache linked list (0x00 в†’ 0x10)

**РЎРёРјРїС‚РѕРј:** kfs_listdir() РІРѕР·РІСЂР°С‰Р°Р» РјСѓСЃРѕСЂ РёР»Рё Р·Р°С†РёРєР»РёРІР°Р»СЃСЏ  
**Root cause:** Offset 0x00 = `nc_entry.tqe_next` (hash table chain). РќР°Рј РЅСѓР¶РµРЅ `nc_child.tqe_next` = +0x10 (child list chain)  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:**

```c
// Р‘Р«Р›Рћ: С…РѕРґРёР» РїРѕ hash table chain (С‡СѓР¶РѕР№ linked list)
#define ONC_NEXT  0x00  // nc_entry.tqe_next

// РЎРўРђР›Рћ: С…РѕРґРёРј РїРѕ children chain
#define ONC_CHILD_NEXT  0x10  // nc_child.tqe_next
```

**Struct layout:**
```
struct namecache {
    TAILQ_ENTRY(namecache) nc_entry;  // +0x00 (hash table)
    TAILQ_ENTRY(namecache) nc_child;  // +0x10 (children list) в†ђ РќРЈР–Р•Рќ Р­РўРћРў
    ...
};
```

---

## Р‘Р°Рі #13-14: ONC_VP/ONC_NAME (static в†’ dynamic auto-detect)

**РЎРёРјРїС‚РѕРј:** nc_vp/nc_name РІРѕР·РІСЂР°С‰Р°Р»Рё РјСѓСЃРѕСЂ РЅР° РЅРµРєРѕС‚РѕСЂС‹С… РІРµСЂСЃРёСЏС… iOS  
**Root cause:** smrq_link СЂР°Р·РјРµСЂ РјРµРЅСЏРµС‚СЃСЏ РјРµР¶РґСѓ iOS 17 Рё iOS 18 в†’ offset СЃРґРІРёРіР°РµС‚СЃСЏ  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** `verify_ncache()` РїСЂРѕР±СѓРµС‚ РѕР±Р° РІР°СЂРёР°РЅС‚Р°:

```c
// Probe 1: iOS 17 layout (smrq_link = 8 bytes)
g_onc_vp = 0x48;  g_onc_name = 0x58;

// Probe 2: iOS 18 layout (smrq_link = 16 bytes)
g_onc_vp = 0x50;  g_onc_name = 0x60;

// Auto-select based on:
// - nc_vp should be a valid kernel pointer
// - nc_name should point to readable ASCII string
```

---

## Feature #15: Trust cache scanning РІРєР»СЋС‡С‘РЅ

**Р¤Р°Р№Р»:** `trustcache.m`, `tc_init()`  
**Р§С‚Рѕ Р±С‹Р»Рѕ:** `return -1;` РІ РЅР°С‡Р°Р»Рµ tc_init() вЂ” РїРѕР»РЅРѕСЃС‚СЊСЋ РѕС‚РєР»СЋС‡Р°Р» trust cache  
**Р§С‚Рѕ СЃС‚Р°Р»Рѕ:** РЈР±СЂР°РЅ return -1. Р”РѕР±Р°РІР»РµРЅ `find_tc_head_by_string_xref()` (~130 СЃС‚СЂРѕРє):

```c
// РС‰РµС‚ СЃС‚СЂРѕРєРё РІ __cstring:
// "static trust cache"
// "loadable trust cache"  
// "pmap_cs_check_trust"
// РќР°С…РѕРґРёС‚ xref в†’ Р±РµСЂС‘С‚ nearby heap pointer РёР· DATA segments
```

---

## Feature #16: AMFI global kernel variable bypass

**Р¤Р°Р№Р»:** `postexploit.m`, `postexploit_patch_amfi()`  

---

## Р‘Р°Рі #119: Р±РµСЃРєРѕРЅРµС‡РЅС‹Р№ retry РІ `physical_oob_read_mo_with_retry()`

**РЎРёРјРїС‚РѕРј:** exploit РјРѕРі Р·Р°РІРёСЃРЅСѓС‚СЊ РЅР°РІСЃРµРіРґР°, РµСЃР»Рё physical OOB read РїРµСЂРµСЃС‚Р°РІР°Р» РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°С‚СЊСЃСЏ РёР·-Р·Р° РїР»РѕС…РѕРіРѕ `memory_object`/race window.  
**Root cause:** helper РєСЂСѓС‚РёР»СЃСЏ РІ `while (true)` Р±РµР· Р»РёРјРёС‚Р° Рё Р±РµР· СЃРёРіРЅР°Р»Р° caller-Сѓ Рѕ РїРµСЂРјР°РЅРµРЅС‚РЅРѕР№ РЅРµСѓРґР°С‡Рµ.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** helper С‚РµРїРµСЂСЊ РѕРіСЂР°РЅРёС‡РµРЅ 256 РїРѕРїС‹С‚РєР°РјРё Рё РІРѕР·РІСЂР°С‰Р°РµС‚ `bool`, Р° `find_and_corrupt_socket()` cleanly abort/retry РґРµР»Р°РµС‚ РЅР° РІРµСЂС…РЅРµРј СѓСЂРѕРІРЅРµ.

```c
// Р‘Р«Р›Рћ:
while (true) {
  if (physical_oob_read_mo(...) == KERN_SUCCESS) break;
}

// РЎРўРђР›Рћ:
for (int read_try = 0; read_try < 256; read_try++) {
  if (physical_oob_read_mo(...) == KERN_SUCCESS) return true;
}
return false;
```

---

## Р‘Р°Рі #120: СѓС‚РµС‡РєР° `control_socket` fd РЅР° failed corrupt-check

**РЎРёРјРїС‚РѕРј:** repeated socket-corruption retries РїРѕСЃС‚РµРїРµРЅРЅРѕ СЃСЉРµРґР°Р»Рё file descriptors Рё РјРѕРіР»Рё Р»РѕРјР°С‚СЊ РїРѕСЃР»РµРґСѓСЋС‰РёРµ spray/verification РїРѕРїС‹С‚РєРё.  
**Root cause:** `find_and_corrupt_socket()` РѕС‚РєСЂС‹РІР°Р» `fileport_makefd()` РґР»СЏ candidate control socket, РЅРѕ РЅРµ Р·Р°РєСЂС‹РІР°Р» fd РїСЂРё `getsockopt` fail, bad partner index, failed `rw_socket` creation Рё marker mismatch.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** РІСЃРµ early-failure РІРµС‚РєРё С‚РµРїРµСЂСЊ РІС‹Р·С‹РІР°СЋС‚ `close(sock)` / `close(control_socket)` РґРѕ РІРѕР·РІСЂР°С‚Р°.

```c
// Р‘Р«Р›Рћ:
if (res != 0) return -1;

// РЎРўРђР›Рћ:
if (res != 0) {
  close(sock);
  return -1;
}
```

---

## Р‘Р°Рі #121: `pe_v1()` РїСЂРѕРґРѕР»Р¶Р°Р» СЂР°Р±РѕС‚Сѓ РїРѕСЃР»Рµ С‡Р°СЃС‚РёС‡РЅРѕРіРѕ `search_mapping` alloc failure

**РЎРёРјРїС‚РѕРј:** РїСЂРё memory pressure exploit РјРѕРі РїСЂРѕРґРѕР»Р¶РёС‚СЊ spray/search СЃ С‡Р°СЃС‚РёС‡РЅРѕ Р·Р°РїРѕР»РЅРµРЅРЅС‹Рј РјР°СЃСЃРёРІРѕРј `search_mappings`, РїРѕСЃР»Рµ С‡РµРіРѕ РїС‹С‚Р°Р»СЃСЏ СЃС‚СЂРѕРёС‚СЊ memory entry РґР»СЏ РЅСѓР»РµРІС‹С…/РЅРµРёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅРЅС‹С… mapping slots.  
**Root cause:** С†РёРєР» allocation РґРµР»Р°Р» `break`, РЅРѕ РЅРµ РѕС‚СЃР»РµР¶РёРІР°Р» СЃРєРѕР»СЊРєРѕ mapping'РѕРІ СЂРµР°Р»СЊРЅРѕ СЃРѕР·РґР°Р»РѕСЃСЊ, Рё РєРѕРґ С€С‘Р» РґР°Р»СЊС€Рµ РєР°Рє Р±СѓРґС‚Рѕ setup complete.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ `allocated_search_mappings`, С‡Р°СЃС‚РёС‡РЅРѕ СЃРѕР·РґР°РЅРЅС‹Рµ mappings С‚РµРїРµСЂСЊ СЃСЂР°Р·Сѓ РґРµР°Р»Р»РѕС†РёСЂСѓСЋС‚СЃСЏ Рё РїРѕРїС‹С‚РєР° cleanly retry'РёС‚СЃСЏ.

```c
// РЎРўРђР›Рћ:
if (allocated_search_mappings != n_of_search_mappings) {
  for (uint64_t s = 0; s < allocated_search_mappings; s++) {
    mach_vm_deallocate(...);
  }
  free(search_mappings);
  continue;
}
```

---

## Р‘Р°Рі #122: race file descriptors СѓС‚РµРєР°Р»Рё РЅР° `pe_init()` failure / retry reset

**РЎРёРјРїС‚РѕРј:** РїСЂРё fail РїРѕСЃР»Рµ `init_target_file()` РѕС‚РєСЂС‹С‚С‹Рµ `read_fd` / `write_fd` РјРѕРіР»Рё РѕСЃС‚Р°С‚СЊСЃСЏ Р¶РёРІС‹РјРё РґРѕ РєРѕРЅС†Р° РїСЂРѕС†РµСЃСЃР°, Р° `reset_transient_state()` РїСЂРѕСЃС‚Рѕ Р·Р°С‚РёСЂР°Р» РёС… Р·РЅР°С‡РµРЅРёРµРј `-1`. Р­С‚Рѕ РїРѕСЃС‚РµРїРµРЅРЅРѕ Р¶РіР»Рѕ fd table Рё Р»РѕРјР°Р»Рѕ СЃР»РµРґСѓСЋС‰РёРµ РїРѕРїС‹С‚РєРё.  
**Root cause:** РЅРµ Р±С‹Р»Рѕ РѕР±С‰РµРіРѕ cleanup helper-Р° РґР»СЏ race file descriptors; СЂР°РЅРЅРёРµ `return false` РІ `pe_init()` Рё retry reset РЅРµ Р·Р°РєСЂС‹РІР°Р»Рё СѓР¶Рµ РѕС‚РєСЂС‹С‚С‹Рµ С„Р°Р№Р»С‹.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ `close_target_fds()`, РІС‹Р·С‹РІР°РµС‚СЃСЏ РёР· `reset_transient_state()`, fail-path'РѕРІ `pe_init()` Рё С„РёРЅР°Р»СЊРЅРѕРіРѕ cleanup РІ `pe()`.

```c
static void close_target_fds(void) {
  if (read_fd >= 0) close(read_fd);
  if (write_fd >= 0) close(write_fd);
}
```

---

## Р‘Р°Рі #123: `pe_v1()` РјРѕРі РІРёСЃРµС‚СЊ Р±РµСЃРєРѕРЅРµС‡РЅРѕ РЅР° Р±РµР·СѓСЃРїРµС€РЅС‹С… top-level retry

**РЎРёРјРїС‚РѕРј:** РЅР° РЅРµСЃРѕРІРјРµСЃС‚РёРјРѕРј boot layout РёР»Рё СѓСЃС‚РѕР№С‡РёРІРѕРј spray/search fail РїСЂРёР»РѕР¶РµРЅРёРµ РјРѕРіР»Рѕ РЅРёРєРѕРіРґР° РЅРµ РІС‹Р№С‚Рё РёР· outer retry loop РІ non-A18 path.  
**Root cause:** РѕСЃРЅРѕРІРЅРѕР№ С†РёРєР» `pe_v1()` РёСЃРїРѕР»СЊР·РѕРІР°Р» `while (true)` Р±РµР· РІРµСЂС…РЅРµР№ РіСЂР°РЅРёС†С‹ РїРѕРїС‹С‚РѕРє Рё Р±РµР· clean abort condition.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** outer retry loop РѕРіСЂР°РЅРёС‡РµРЅ `MAX_PE_V1_ATTEMPTS`, РїРѕСЃР»Рµ РёСЃС‡РµСЂРїР°РЅРёСЏ Р»РёРјРёС‚Р° exploit Р·Р°РІРµСЂС€Р°РµС‚ РїРѕРїС‹С‚РєСѓ СЃ СЏРІРЅС‹Рј log instead of hanging forever.

```c
for (int attempt = 1; attempt <= MAX_PE_V1_ATTEMPTS; attempt++) {
  ...
}
```

---

## Р‘Р°Рі #124: `pe_v2()` РјРѕРі РІРёСЃРµС‚СЊ Р±РµСЃРєРѕРЅРµС‡РЅРѕ РЅР° A18 retry path

**РЎРёРјРїС‚РѕРј:** A18 wired-page path РјРѕРі Р±РµСЃРєРѕРЅРµС‡РЅРѕ РєСЂСѓС‚РёС‚СЊСЃСЏ РїСЂРё РїРѕРІС‚РѕСЂСЏСЋС‰РµРјСЃСЏ miss/reallocation fail, РѕСЃРѕР±РµРЅРЅРѕ РїРѕСЃР»Рµ zone trimming waits.  
**Root cause:** outer retry loop РІ `pe_v2()` С‚РѕР¶Рµ Р±С‹Р» `while (true)` Р±РµР· Р»РёРјРёС‚Р° РїРѕРїС‹С‚РѕРє.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ bounded retry budget `MAX_PE_V2_ATTEMPTS` СЃ С„РёРЅР°Р»СЊРЅС‹Рј fail log РїРѕСЃР»Рµ РёСЃС‡РµСЂРїР°РЅРёСЏ РІСЃРµС… РїРѕРїС‹С‚РѕРє.

```c
for (int attempt = 1; attempt <= MAX_PE_V2_ATTEMPTS; attempt++) {
  ...
}
```

---

## Р‘Р°Рі #125: `discover_name_offset()` fallback РїСЂРёРЅРёРјР°Р» prefix-match Р·Р° С‚РѕС‡РЅРѕРµ РёРјСЏ

**РЎРёРјРїС‚РѕРј:** dynamic name-offset discovery РјРѕРі Р·Р°С„РёРєСЃРёСЂРѕРІР°С‚СЊ РЅРµРІРµСЂРЅС‹Р№ `PROC_NAME_OFFSET`, РµСЃР»Рё РІ proc struct РІСЃС‚СЂРµС‡Р°Р»Р°СЃСЊ СЃС‚СЂРѕРєР° СЃ С‚РµРј Р¶Рµ РїСЂРµС„РёРєСЃРѕРј, РЅРѕ СЌС‚Рѕ РЅРµ Р±С‹Р»Рѕ С‚РѕС‡РЅРѕРµ РёРјСЏ РїСЂРѕС†РµСЃСЃР°.  
**Root cause:** fallback-РїСЂРѕРІРµСЂРєР° РёР·РІРµСЃС‚РЅС‹С… offsets РёСЃРїРѕР»СЊР·РѕРІР°Р»Р° С‚РѕР»СЊРєРѕ `strncmp(buf, our_name, name_len) == 0` Р±РµР· РїСЂРѕРІРµСЂРєРё Р·Р°РІРµСЂС€Р°СЋС‰РµРіРѕ `\0`.  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** fallback С‚РµРїРµСЂСЊ РїСЂРёРЅРёРјР°РµС‚ С‚РѕР»СЊРєРѕ С‚РѕС‡РЅРѕРµ C-string СЃРѕРІРїР°РґРµРЅРёРµ, РєР°Рє Рё РѕСЃРЅРѕРІРЅРѕР№ scan path.

```c
if (strncmp(buf, our_name, name_len) == 0 && buf[name_len] == '\0') {
  PROC_NAME_OFFSET = known[i];
}
```

---

## Р‘Р°Рі #126: `procbyname()` РґРµР»Р°Р» unsafe guess `PROC_NAME_OFFSET = 0x56c`

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё dynamic discovery РЅРµ СЃРјРѕРіР»Р° РЅР°РґС‘Р¶РЅРѕ РЅР°Р№С‚Рё `p_name`, `procbyname()` РїСЂРѕРґРѕР»Р¶Р°Р» walk СЃ Р¶С‘СЃС‚РєРѕ guessed offset `0x56c`, С‡С‚Рѕ РјРѕРіР»Рѕ РґР°РІР°С‚СЊ false matches / false misses РїРѕ РёРјРµРЅР°Рј РїСЂРѕС†РµСЃСЃРѕРІ.  
**Root cause:** С„СѓРЅРєС†РёСЏ РїСЂРµРґРїРѕС‡РёС‚Р°Р»Р° РїСЂРѕРґРѕР»Р¶РёС‚СЊ СЂР°Р±РѕС‚Сѓ СЃ РЅРµРїРѕРґС‚РІРµСЂР¶РґС‘РЅРЅС‹Рј hardcoded offset РІРјРµСЃС‚Рѕ С‡РµСЃС‚РЅРѕРіРѕ fail.  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** РїСЂРё РЅРµРёР·РІРµСЃС‚РЅРѕРј `PROC_NAME_OFFSET` `procbyname()` С‚РµРїРµСЂСЊ cleanly abort'РёС‚СЃСЏ, Р° РЅРµ РґРµР»Р°РµС‚ РЅРµР±РµР·РѕРїР°СЃРЅРѕРµ РїСЂРµРґРїРѕР»РѕР¶РµРЅРёРµ.

```c
if (PROC_NAME_OFFSET == 0) {
  printf("procbyname: PROC_NAME_OFFSET unknown, aborting instead of guessing\n");
  return 0;
}
```

---

## Р‘Р°Рі #127: `discover_name_offset()` poisoned global state even on failed discovery

**РЎРёРјРїС‚РѕРј:** РЅРµСѓРґР°С‡РЅР°СЏ РїРѕРїС‹С‚РєР° dynamic `p_name` discovery РјРѕРіР»Р° РѕСЃС‚Р°РІРёС‚СЊ РіР»РѕР±Р°Р»СЊРЅС‹Р№ `PROC_NAME_OFFSET` РІ guessed СЃРѕСЃС‚РѕСЏРЅРёРё, РїРѕСЃР»Рµ С‡РµРіРѕ РїРѕСЃР»РµРґСѓСЋС‰РёРµ proc-name lookups СЂР°Р±РѕС‚Р°Р»Рё РїРѕ РЅРµРїРѕРґС‚РІРµСЂР¶РґС‘РЅРЅРѕРјСѓ offset.  
**Root cause:** helper Р·Р°РІРµСЂС€Р°Р» СЂР°Р±РѕС‚Сѓ СЃ hardcoded fallback РІРјРµСЃС‚Рѕ С‡РµСЃС‚РЅРѕРіРѕ fail, С…РѕС‚СЏ reliable match РЅРµ Р±С‹Р» РЅР°Р№РґРµРЅ.  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** РїСЂРё failed discovery РіР»РѕР±Р°Р»СЊРЅС‹Р№ offset Р±РѕР»СЊС€Рµ РЅРµ Р·Р°РїРѕР»РЅСЏРµС‚СЃСЏ guess-Р·РЅР°С‡РµРЅРёРµРј; С„СѓРЅРєС†РёСЏ РїСЂРѕСЃС‚Рѕ РІРѕР·РІСЂР°С‰Р°РµС‚ `false`.

---

## Р‘Р°Рі #128: `procbyname()` РЅРµ РїС‹С‚Р°Р»СЃСЏ СЃР°РјРѕСЃС‚РѕСЏС‚РµР»СЊРЅРѕ РІРѕСЃСЃС‚Р°РЅРѕРІРёС‚СЊ `our_proc`/name-offset

**РЎРёРјРїС‚РѕРј:** РІС‹Р·РѕРІ `procbyname()` РґРѕ РєСЌС€РёСЂРѕРІР°РЅРёСЏ `our_proc` РјРѕРі Р»РѕР¶РЅРѕ С„РµР№Р»РёС‚СЊСЃСЏ РґР°Р¶Рµ РїСЂРё СЂР°Р±РѕС‡РµРј KRW, РїРѕС‚РѕРјСѓ С‡С‚Рѕ name-offset discovery Р·Р°РїСѓСЃРєР°Р»Р°СЃСЊ С‚РѕР»СЊРєРѕ С‡РµСЂРµР· `ds_get_our_proc()`, РєРѕС‚РѕСЂС‹Р№ РјРѕРі Р±С‹С‚СЊ РµС‰С‘ РїСѓСЃС‚С‹Рј.  
**Root cause:** С„СѓРЅРєС†РёСЏ РЅРµ РїС‹С‚Р°Р»Р°СЃСЊ РІС‹Р·РІР°С‚СЊ `ourproc()` РґР»СЏ СЃР°РјРѕСЃС‚РѕСЏС‚РµР»СЊРЅРѕРіРѕ Р·Р°РїРѕР»РЅРµРЅРёСЏ `our_proc` Рё discovery `PROC_NAME_OFFSET`.  
**Р¤Р°Р№Р»:** `utils.m`  
**Fix:** РµСЃР»Рё `ds_get_our_proc()` РїСѓСЃС‚, `procbyname()` СЃРЅР°С‡Р°Р»Р° РІС‹Р·С‹РІР°РµС‚ `ourproc()`, Р·Р°С‚РµРј РїРѕРІС‚РѕСЂСЏРµС‚ discovery. РћРґРЅРѕРІСЂРµРјРµРЅРЅРѕ `ourproc()` С‚РµРїРµСЂСЊ РЅРµ С‡РёС‚Р°РµС‚ РёРјСЏ РїРѕ РЅСѓР»РµРІРѕРјСѓ offset Рё Р»РѕРіРёСЂСѓРµС‚ `<unknown>` РїСЂРё РѕС‚СЃСѓС‚СЃС‚РІРёРё РЅР°РґС‘Р¶РЅРѕРіРѕ `PROC_NAME_OFFSET`.

---

## Р‘Р°Рі #129: `kfs` file-overwrite path РЅРµ СѓРјРµР» РІРѕСЃСЃС‚Р°РЅРѕРІРёС‚СЊ task Р±РµР· РєСЌС€Р° exploit

**РЎРёРјРїС‚РѕРј:** `kfs_init()` РјРѕРі СѓСЃРїРµС€РЅРѕ РЅР°Р№С‚Рё РїСЂРѕС†РµСЃСЃС‹ С‡РµСЂРµР· fallback scan, РЅРѕ РїРѕСЃР»РµРґСѓСЋС‰РёР№ `kfs_overwrite_file*()` РІСЃС‘ СЂР°РІРЅРѕ С„РµР№Р»РёР»СЃСЏ, РїРѕС‚РѕРјСѓ С‡С‚Рѕ `get_our_task()` СЃРјРѕС‚СЂРµР» С‚РѕР»СЊРєРѕ РІ `ds_get_our_task()` / `ds_get_our_proc()` Рё РЅРµ РёСЃРїРѕР»СЊР·РѕРІР°Р» СѓР¶Рµ РЅР°Р№РґРµРЅРЅС‹Р№ `g_our_proc` РёР»Рё `ourtask()`.  
**Root cause:** helper РґР»СЏ task retrieval Р±С‹Р» РїСЂРёРІСЏР·Р°РЅ Рє exploit cache Рё РЅРµ РїРµСЂРµРёСЃРїРѕР»СЊР·РѕРІР°Р» proc, РЅР°Р№РґРµРЅРЅС‹Р№ СЃР°РјРёРј `kfs`.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** `get_our_task()` С‚РµРїРµСЂСЊ РґРµР»Р°РµС‚ fallback С‡РµСЂРµР· `g_our_proc`, `ourproc()` Рё `ourtask(proc)` РїРµСЂРµРґ РїСЂСЏРјС‹Рј `proc_ro->task` РІС‹С‡РёСЃР»РµРЅРёРµРј.

---

## Р‘Р°Рі #130: `postexploit` РІР°Р»РёРґРёСЂРѕРІР°Р» `proc` СЃР»РёС€РєРѕРј С€РёСЂРѕРєРёРј `is_kptr()`

**РЎРёРјРїС‚РѕРј:** stale/Р»РѕР¶РЅС‹Р№ canonical kernel pointer РјРѕРі РїСЂРѕР№С‚Рё initial proc validation РІ `postexploit_*` Рё РїРѕРІРµСЃС‚Рё РєРѕРґ РІ С‡С‚РµРЅРёСЏ РїРѕ РЅРµРІРµСЂРЅРѕРјСѓ `proc + offset`.  
**Root cause:** `proc` вЂ” СЌС‚Рѕ zone/heap object, РЅРѕ `postexploit` РїСЂРѕРІРµСЂСЏР» РµРіРѕ РѕР±С‰РёРј `is_kptr()`, РєРѕС‚РѕСЂС‹Р№ РЅРµ РѕРіСЂР°РЅРёС‡РёРІР°РµС‚ Р°РґСЂРµСЃ runtime zone-map РґРёР°РїР°Р·РѕРЅРѕРј.  
**Р¤Р°Р№Р»:** `postexploit.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ Р»РѕРєР°Р»СЊРЅС‹Р№ `is_heap_ptr()` РЅР° РѕСЃРЅРѕРІРµ runtime zone bounds; retrieval paths РґР»СЏ `ds_get_our_proc()` / `ourproc()` С‚РµРїРµСЂСЊ С‚СЂРµР±СѓСЋС‚ heap-valid proc pointer.

---

## Р‘Р°Рі #131: `postexploit` РёСЃРєР°Р» `ucred` С‡РµСЂРµР· СЃР»РёС€РєРѕРј С€РёСЂРѕРєСѓСЋ `is_kptr()` РІР°Р»РёРґР°С†РёСЋ

**РЎРёРјРїС‚РѕРј:** `discover_ucred_offset()` Рё РїРѕСЃР»РµРґСѓСЋС‰Р°СЏ РїСЂРѕРІРµСЂРєР° `ucred` РјРѕРіР»Рё РїСЂРёРЅСЏС‚СЊ Р»СЋР±РѕР№ canonical kernel pointer Р·Р° РІР°Р»РёРґРЅС‹Р№ `ucred`, РїРѕСЃР»Рµ С‡РµРіРѕ uid/gid/sandbox patch paths С‡РёС‚Р°Р»Рё Рё РїРёСЃР°Р»Рё РїРѕ РЅРµРІРµСЂРЅРѕРјСѓ РѕР±СЉРµРєС‚Сѓ.  
**Root cause:** `ucred` вЂ” heap object, РЅРѕ РєРѕРґ РІР°Р»РёРґРёСЂРѕРІР°Р» РєР°РЅРґРёРґР°С‚С‹ С‡РµСЂРµР· `is_kptr()` РІРјРµСЃС‚Рѕ heap-range check.  
**Р¤Р°Р№Р»:** `postexploit.m`  
**Fix:** discovery Рё С„РёРЅР°Р»СЊРЅР°СЏ РІР°Р»РёРґР°С†РёСЏ `ucred` РїРµСЂРµРІРµРґРµРЅС‹ РЅР° `is_heap_ptr()`.

---

## Р‘Р°Рі #132: `kfs` РїСЂРѕРІРµСЂСЏР» vnode/ubcinfo С‡РµСЂРµР· broad `is_kptr()`

**РЎРёРјРїС‚РѕРј:** `resolve_path()`, `kfs_listdir()`, `kfs_file_size()` Рё `vnode_file_size()` РјРѕРіР»Рё РїСЂРёРЅСЏС‚СЊ stale canonical kernel pointer Р·Р° РІР°Р»РёРґРЅС‹Р№ vnode/ubcinfo Рё СѓР№С‚Рё РІ С‡С‚РµРЅРёРµ РЅРµ-heap РѕР±СЉРµРєС‚Р°.  
**Root cause:** vnode Рё `ubc_info` вЂ” heap-backed kernel objects, РЅРѕ РЅРµСЃРєРѕР»СЊРєРѕ РїСѓС‚РµР№ РІ `kfs.m` РїСЂРѕРІРµСЂСЏР»Рё РёС… С‡РµСЂРµР· `is_kptr()` РІРјРµСЃС‚Рѕ `is_heap_ptr()`.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** vnode/ubcinfo validation tightened РґРѕ `is_heap_ptr()` РЅР° path-resolution Рё file-size РїСѓС‚СЏС….

---

## Р‘Р°Рі #133: `kfs` РЅРµ РёРјРµР» PID-fallback РґР»СЏ `launchd`, РµСЃР»Рё name-based proc lookup РЅРµРґРѕСЃС‚СѓРїРµРЅ

**РЎРёРјРїС‚РѕРј:** `find_procs()` РјРѕРі РїРѕР»РЅРѕСЃС‚СЊСЋ РїСЂРѕРІР°Р»РёС‚СЊСЃСЏ, РґР°Р¶Рµ РєРѕРіРґР° `our_proc` СѓР¶Рµ РЅР°Р№РґРµРЅ Рё proc list РґРѕСЃС‚СѓРїРµРЅ, РїСЂРѕСЃС‚Рѕ РїРѕС‚РѕРјСѓ С‡С‚Рѕ `procbyname("launchd")` Р·Р°РІРёСЃРµР» РѕС‚ working `PROC_NAME_OFFSET`.  
**Root cause:** `kfs` РёСЃРєР°Р» `launchd` С‚РѕР»СЊРєРѕ РїРѕ РёРјРµРЅРё Рё РЅРµ РёСЃРїРѕР»СЊР·РѕРІР°Р» СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ PID-РёРЅРІР°СЂРёР°РЅС‚: `launchd` РІСЃРµРіРґР° РёРјРµРµС‚ PID 1.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** РїРѕСЃР»Рµ failed `procbyname("launchd")` РґРѕР±Р°РІР»РµРЅ fallback walk РѕС‚ `g_our_proc` РїРѕ РѕР±РѕРёРј РЅР°РїСЂР°РІР»РµРЅРёСЏРј СЃРїРёСЃРєР°, РёС‰СѓС‰РёР№ PID 1.

---

## Р‘Р°Рі #134: `postexploit` РІС‹Р±РёСЂР°Р» `ucred` РїРѕ РѕРґРЅРѕРјСѓ С‚РѕР»СЊРєРѕ `uid`

**РЎРёРјРїС‚РѕРј:** РїСЂРё root/retry СЃРѕСЃС‚РѕСЏРЅРёСЏС… РёР»Рё РЅР° СЃРёСЃС‚РµРјР°С… СЃ РЅРµСЃРєРѕР»СЊРєРёРјРё `uid==0` РєР°РЅРґРёРґР°С‚С‹ РІ `proc_ro` scan РјРѕРіР»Рё Р»РѕР¶РЅРѕ СЃРѕРІРїР°СЃС‚СЊ Рё РїСЂРёРІРµСЃС‚Рё Рє РїР°С‚С‡Сѓ РЅРµ С‚РѕРіРѕ heap-РѕР±СЉРµРєС‚Р°.  
**Root cause:** `discover_ucred_offset()` СЃС‡РёС‚Р°Р» РєР°РЅРґРёРґР°С‚ РІР°Р»РёРґРЅС‹Рј, РµСЃР»Рё СЃРѕРІРїР°РґР°Р» С‚РѕР»СЊРєРѕ `cr_uid`, С…РѕС‚СЏ СЌС‚РѕРіРѕ РЅРµРґРѕСЃС‚Р°С‚РѕС‡РЅРѕ РґР»СЏ РЅР°РґС‘Р¶РЅРѕР№ РёРґРµРЅС‚РёС„РёРєР°С†РёРё `ucred`.  
**Р¤Р°Р№Р»:** `postexploit.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅР° СЃРѕСЃС‚Р°РІРЅР°СЏ РїСЂРѕРІРµСЂРєР° `ucred`: `uid/ruid/svuid`, `gid/rgid/svgid`, `ngroups` Рё РІР°Р»РёРґРЅРѕСЃС‚СЊ `label`.

---

## Р‘Р°Рі #135: `postexploit` РїСЂРѕРІРµСЂСЏР» sandbox `label` СЃР»РёС€РєРѕРј С€РёСЂРѕРєРёРј `is_kptr()`

**РЎРёРјРїС‚РѕРј:** stale canonical pointer РјРѕРі Р±С‹С‚СЊ РїСЂРёРЅСЏС‚ Р·Р° РІР°Р»РёРґРЅС‹Р№ MAC label, РїРѕСЃР»Рµ С‡РµРіРѕ unsandbox path РїРёСЃР°Р» `NULL` РІ РЅРµРІРµСЂРЅС‹Р№ kernel object.  
**Root cause:** `label` Рё Р°Р»СЊС‚РµСЂРЅР°С‚РёРІРЅС‹Рµ slot pointers вЂ” heap-backed MAC objects, РЅРѕ РєРѕРґ РІР°Р»РёРґРёСЂРѕРІР°Р» РёС… РѕР±С‰РёРј `is_kptr()` РІРјРµСЃС‚Рѕ heap-range checks.  
**Р¤Р°Р№Р»:** `postexploit.m`  
**Fix:** sandbox label validation Рё alt-slot probing РїРµСЂРµРІРµРґРµРЅС‹ РЅР° `is_heap_ptr()`.

---

## Р‘Р°Рі #136: `trustcache` inject path РїСЂРёРЅРёРјР°Р» broad canonical pointers Р·Р° node/module

**РЎРёРјРїС‚РѕРј:** `inject_entries()` РјРѕРі РїСЂРёРЅСЏС‚СЊ stale canonical kernel pointer Р·Р° РІР°Р»РёРґРЅС‹Р№ trust-cache node/module Рё С‡РёС‚Р°С‚СЊ `version`/`num_entries` РёР· РЅРµРІРµСЂРЅРѕРіРѕ РѕР±СЉРµРєС‚Р°.  
**Root cause:** head node Рё module pointer РІ inject path РІР°Р»РёРґРёСЂРѕРІР°Р»РёСЃСЊ С‡РµСЂРµР· `is_kptr()`, С…РѕС‚СЏ СЌС‚Рѕ heap-backed РѕР±СЉРµРєС‚С‹.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** `head_val` Рё candidate module pointers РІ `inject_entries()` РїРµСЂРµРІРµРґРµРЅС‹ РЅР° `is_heap_ptr()`.

---

## Р‘Р°Рі #137: `tc_trust_directory()` РјР°СЃРєРёСЂРѕРІР°Р» СЂРµРєСѓСЂСЃРёРІРЅС‹Рµ РѕС€РёР±РєРё Рё РјРѕРі РІРµСЂРЅСѓС‚СЊ Р»РѕР¶РЅС‹Р№ success-count

**РЎРёРјРїС‚РѕРј:** failed trust РІРѕ РІР»РѕР¶РµРЅРЅРѕР№ РґРёСЂРµРєС‚РѕСЂРёРё РёР»Рё failed `tc_trust_file()` РјРѕРі Р·Р°С‚РµСЂСЏС‚СЊСЃСЏ: С„СѓРЅРєС†РёСЏ РїСЂРѕРґРѕР»Р¶Р°Р»Р° СЃСѓРјРјРёСЂРѕРІР°С‚СЊ count Рё РёРЅРѕРіРґР° РІРѕР·РІСЂР°С‰Р°Р»Р° РїРѕР»РѕР¶РёС‚РµР»СЊРЅС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚, С…РѕС‚СЏ С‡Р°СЃС‚СЊ С„Р°Р№Р»РѕРІ СЂРµР°Р»СЊРЅРѕ РЅРµ Р±С‹Р»Р° trusted.  
**Root cause:** recursive result РґРѕР±Р°РІР»СЏР»СЃСЏ РЅР°РїСЂСЏРјСѓСЋ (`count += tc_trust_directory(full)`), Р° file failures РїСЂРѕСЃС‚Рѕ РёРіРЅРѕСЂРёСЂРѕРІР°Р»РёСЃСЊ.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ `had_error`; recursive/file failures С‚РµРїРµСЂСЊ РїРѕРјРµС‡Р°СЋС‚ РѕРїРµСЂР°С†РёСЋ РєР°Рє failed, Р° РёС‚РѕРіРѕРІР°СЏ С„СѓРЅРєС†РёСЏ РІРѕР·РІСЂР°С‰Р°РµС‚ `-1` РїРѕСЃР»Рµ flush.

---

## Р‘Р°Рі #138: `trustcache` РІСЃС‘ РµС‰С‘ РёСЃРїРѕР»СЊР·РѕРІР°Р» СЃС‚Р°С‚РёС‡РµСЃРєРёРµ heap ranges РІРјРµСЃС‚Рѕ runtime zone-map bounds

**РЎРёРјРїС‚РѕРј:** trustcache scan/inject РјРѕРі Р»РѕР¶РЅРѕ РѕС‚РІРµСЂРіР°С‚СЊ РІР°Р»РёРґРЅС‹Рµ heap-РѕР±СЉРµРєС‚С‹ РёР»Рё РїСЂРёРЅРёРјР°С‚СЊ РЅРµРІРµСЂРЅС‹Рµ РєР°РЅРґРёРґР°С‚С‹ РЅР° boot layout СЃ РґСЂСѓРіРёРј zone KASLR.  
**Root cause:** Р»РѕРєР°Р»СЊРЅС‹Р№ `is_heap_ptr()` РІ `trustcache.m` Р±С‹Р» Р·Р°С€РёС‚ РЅР° СЃС‚Р°С‚РёС‡РµСЃРєРёРµ РґРёР°РїР°Р·РѕРЅС‹ Рё РЅРµ РёСЃРїРѕР»СЊР·РѕРІР°Р» СѓР¶Рµ РЅР°Р№РґРµРЅРЅС‹Рµ runtime zone bounds.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** `is_heap_ptr()` РїРµСЂРµРІРµРґС‘РЅ РЅР° `ds_get_zone_map_min()/max()` СЃ РєРѕРЅСЃРµСЂРІР°С‚РёРІРЅС‹Рј fallback, РєР°Рє Рё РІ РґСЂСѓРіРёС… РјРѕРґСѓР»СЏС….

---

## Р‘Р°Рі #139: `tc_trust_directory()` РјРѕРі Р·Р°С†РёРєР»РёС‚СЊСЃСЏ РЅР° symlink recursion

**РЎРёРјРїС‚РѕРј:** РїСЂРё РІСЃС‚СЂРµС‡Рµ symlink РЅР° РґРёСЂРµРєС‚РѕСЂРёСЋ (РёР»Рё С†РёРєР»РёС‡РµСЃРєРѕР№ symlink-С†РµРїРѕС‡РєРё) recursive trust scan РјРѕРі СѓР№С‚Рё РІ Р±РµСЃРєРѕРЅРµС‡РЅС‹Р№ РѕР±С…РѕРґ РѕРґРЅРѕРіРѕ Рё С‚РѕРіРѕ Р¶Рµ РґРµСЂРµРІР°.  
**Root cause:** С„СѓРЅРєС†РёСЏ РёСЃРїРѕР»СЊР·РѕРІР°Р»Р° `stat()`, РєРѕС‚РѕСЂС‹Р№ СЂР°Р·РІРѕСЂР°С‡РёРІР°РµС‚ symlink, Рё Р·Р°С‚РµРј СЂРµРєСѓСЂСЃРёСЂРѕРІР°Р»Р° РІ С†РµР»СЊ РєР°Рє РІ РѕР±С‹С‡РЅСѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РїРµСЂРµС…РѕРґ РЅР° `lstat()` Рё СЏРІРЅС‹Р№ skip РґР»СЏ `S_ISLNK`.

---

## Р‘Р°Рі #140: `kfs_listdir()` РЅРµ РїСЂРѕРІРµСЂСЏР» output pointers Рё `calloc()`

**РЎРёРјРїС‚РѕРј:** caller СЃ `NULL` РІ `out`/`count` РёР»Рё memory pressure РЅР° `calloc()` РјРѕРі РїСЂРёРІРµСЃС‚Рё Рє userspace crash РґРѕ РІРѕР·РІСЂР°С‚Р° РѕС€РёР±РєРё.  
**Root cause:** public API `kfs_listdir()` Р±РµР·СѓСЃР»РѕРІРЅРѕ СЂР°Р·С‹РјРµРЅРѕРІС‹РІР°Р» outputs Рё РЅРµ РїСЂРѕРІРµСЂСЏР» РїРµСЂРІРёС‡РЅСѓСЋ allocation С‚Р°Р±Р»РёС†С‹ entries.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅР° РІР°Р»РёРґР°С†РёСЏ `out`/`count`, СЂР°РЅРЅСЏСЏ РёРЅРёС†РёР°Р»РёР·Р°С†РёСЏ `*out/*count`, Рё РїСЂРѕРІРµСЂРєР° `calloc()`.

---

## Р‘Р°Рі #141: `trustcache` silently truncated paths/commands РІ recursive scan Рё `.deb` flow

**РЎРёРјРїС‚РѕРј:** РґР»РёРЅРЅС‹Рµ РїСѓС‚Рё РјРѕРіР»Рё РѕР±СЂРµР·Р°С‚СЊСЃСЏ РІ `tc_trust_directory()` РёР»Рё `tc_trust_deb()`, С‡С‚Рѕ РїСЂРёРІРѕРґРёР»Рѕ Рє trust РЅРµ С‚РѕРіРѕ С„Р°Р№Р»Р°/РєР°С‚Р°Р»РѕРіР°, Р»РѕР¶РЅС‹Рј fail РёР»Рё broken cleanup/extraction.  
**Root cause:** `snprintf()` return value РЅРёРіРґРµ РЅРµ РїСЂРѕРІРµСЂСЏР»СЃСЏ РґР»СЏ `full`, `tmp_dir` Рё shell command buffers.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РІСЃРµ СЌС‚Рё РјРµСЃС‚Р° С‚РµРїРµСЂСЊ РїСЂРѕРІРµСЂСЏСЋС‚ truncation Рё cleanly fail/mark error РІРјРµСЃС‚Рѕ РїСЂРѕРґРѕР»Р¶РµРЅРёСЏ СЃ РѕР±СЂРµР·Р°РЅРЅС‹РјРё СЃС‚СЂРѕРєР°РјРё.

---

## Р‘Р°Рі #142: `kfs resolve_path()` silently truncРёСЂРѕРІР°Р» РґР»РёРЅРЅС‹Рµ РїСѓС‚Рё

**РЎРёРјРїС‚РѕРј:** РґР»РёРЅРЅС‹Р№ Р°Р±СЃРѕР»СЋС‚РЅС‹Р№ РїСѓС‚СЊ РјРѕРі Р±С‹С‚СЊ РѕР±СЂРµР·Р°РЅ РґРѕ 1023 Р±Р°Р№С‚ Рё Р·Р°С‚РµРј СЂРµР·РѕР»РІРёС‚СЊСЃСЏ РєР°Рє РґСЂСѓРіРѕР№ vnode, С‡С‚Рѕ РґР°РІР°Р»Рѕ Р»РѕР¶РЅС‹Рµ `not in ncache`/wrong file results.  
**Root cause:** `resolve_path()` РєРѕРїРёСЂРѕРІР°Р» `path` РІ С„РёРєСЃРёСЂРѕРІР°РЅРЅС‹Рµ `tmp[1024]` / `pb[1024]` С‡РµСЂРµР· `strncpy()`, РЅРѕ РЅРµ РїСЂРѕРІРµСЂСЏР» РёСЃС…РѕРґРЅСѓСЋ РґР»РёРЅСѓ.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ СЂР°РЅРЅРёР№ reject РґР»СЏ СЃР»РёС€РєРѕРј РґР»РёРЅРЅС‹С… РїСѓС‚РµР№ РґРѕ РєРѕРїРёСЂРѕРІР°РЅРёСЏ.

---

## Р‘Р°Рі #143: `kfs_listdir()` РЅРµ РіР°СЂР°РЅС‚РёСЂРѕРІР°Р» `NUL`-termination РґР»СЏ `ents[n].name`

**РЎРёРјРїС‚РѕРј:** РёРјСЏ РґР»РёРЅРѕР№ СЂРѕРІРЅРѕ 255 Р±Р°Р№С‚ РјРѕРіР»Рѕ РїРѕРїР°СЃС‚СЊ РІ `kfs_entry_t.name` Р±РµР· Р·Р°РІРµСЂС€Р°СЋС‰РµРіРѕ `\0`, РѕСЃРѕР±РµРЅРЅРѕ РїРѕСЃР»Рµ `realloc()` РЅР° РЅРµРёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅРЅСѓСЋ РїР°РјСЏС‚СЊ, С‡С‚Рѕ Р»РѕРјР°Р»Рѕ РїРѕСЃР»РµРґСѓСЋС‰РёРµ string operations Сѓ caller-Р°.  
**Root cause:** `strncpy(ents[n].name, nm, 255)` РЅРµ РіР°СЂР°РЅС‚РёСЂСѓРµС‚ Р·Р°РІРµСЂС€Р°СЋС‰РёР№ РЅСѓР»СЊ, РµСЃР»Рё РєРѕРїРёСЂСѓРµС‚СЃСЏ СЂРѕРІРЅРѕ 255 Р±Р°Р№С‚.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** РїРѕСЃР»Рµ РєРѕРїРёСЂРѕРІР°РЅРёСЏ С‚РµРїРµСЂСЊ СЏРІРЅРѕ СЃС‚Р°РІРёС‚СЃСЏ `ents[n].name[255] = 0`.

---

## Р‘Р°Рі #144: critical bootstrap failure РјРѕРі СѓРјРµРЅСЊС€РёС‚СЊ РѕР±С‰РёР№ СЃС‡С‘С‚С‡РёРє РѕС€РёР±РѕРє exploit chain

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё `bootstrap_install()` Р·Р°РІРµСЂС€Р°Р»СЃСЏ СЂР°РЅРЅРёРј critical fail Рё РІРѕР·РІСЂР°С‰Р°Р» `-1`, РІРµСЂС…РЅРёР№ orchestrator РґРµР»Р°Р» `errors += bs_errors`, РёР·-Р·Р° С‡РµРіРѕ bootstrap failure РјРѕРі РѕР±РЅСѓР»РёС‚СЊ РёР»Рё СѓРјРµРЅСЊС€РёС‚СЊ СѓР¶Рµ РЅР°РєРѕРїР»РµРЅРЅС‹Рµ РѕС€РёР±РєРё РёР· exploit/postexploit С„Р°Р· Рё РїРѕРєР°Р·Р°С‚СЊ СЃР»РёС€РєРѕРј optimistic РёС‚РѕРі.  
**Root cause:** `darksword_exploit.m` СЃРєР»Р°РґС‹РІР°Р» РѕС‚СЂРёС†Р°С‚РµР»СЊРЅС‹Р№ sentinel return РєР°Рє РѕР±С‹С‡РЅРѕРµ РєРѕР»РёС‡РµСЃС‚РІРѕ РѕС€РёР±РѕРє.  
**Р¤Р°Р№Р»:** `darksword_exploit.m`  
**Fix:** РѕС‚СЂРёС†Р°С‚РµР»СЊРЅС‹Р№ return С‚РµРїРµСЂСЊ РЅРѕСЂРјР°Р»РёР·СѓРµС‚СЃСЏ РІ `+1` failure bucket, Р° РїРѕР»РѕР¶РёС‚РµР»СЊРЅС‹Рµ partial-error counts РїСЂРѕРґРѕР»Р¶Р°СЋС‚ СЃСѓРјРјРёСЂРѕРІР°С‚СЊСЃСЏ РєР°Рє СЂР°РЅСЊС€Рµ.

---

## Р‘Р°Рі #145: `run_cmd()` РЅРµ РїСЂРѕРІРµСЂСЏР» `waitpid()` Рё РјРѕРі С‡РёС‚Р°С‚СЊ РЅРµРІР°Р»РёРґРЅС‹Р№ child status

**РЎРёРјРїС‚РѕРј:** РїСЂРё `EINTR` РёР»Рё РґСЂСѓРіРѕРј `waitpid()` fail bootstrap РјРѕРі РёРЅС‚РµСЂРїСЂРµС‚РёСЂРѕРІР°С‚СЊ РјСѓСЃРѕСЂРЅС‹Р№ `status` РєР°Рє normal exit, Р»РѕР¶РЅРѕ СЃС‡РёС‚Р°С‚СЊ РєРѕРјР°РЅРґСѓ СѓСЃРїРµС€РЅРѕР№ РёР»Рё Р»РѕРіРёСЂРѕРІР°С‚СЊ РЅРµРїСЂР°РІРёР»СЊРЅС‹Р№ exit code.  
**Root cause:** `run_cmd()` РІС‹Р·С‹РІР°Р» `waitpid(pid, &status, 0)` Р±РµР· retry/check Рё СЃСЂР°Р·Сѓ РїСЂРёРјРµРЅСЏР» `WIFEXITED(status)` Рє РїРѕС‚РµРЅС†РёР°Р»СЊРЅРѕ РЅРµРёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅРЅРѕРјСѓ Р·РЅР°С‡РµРЅРёСЋ.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ `EINTR`-safe wait loop, СЏРІРЅР°СЏ РїСЂРѕРІРµСЂРєР° `waitpid()` СЂРµР·СѓР»СЊС‚Р°С‚Р°, Р»РѕРіРёСЂРѕРІР°РЅРёРµ abnormal signal exits Рё guard РїСЂРѕС‚РёРІ path truncation РІРѕ fallback `"/var/jb%s"` spawn path.

---

## Р‘Р°Рі #146: `bootstrap_install_openssh()` Р»РѕР¶РЅРѕ СЃРѕРѕР±С‰Р°Р» РѕР± СѓСЃРїРµС€РЅРѕРј SSH launch

**РЎРёРјРїС‚РѕРј:** bootstrap РјРѕРі РЅР°РїРёСЃР°С‚СЊ `sshd launched` Рё РІРµСЂРЅСѓС‚СЊ success РґР°Р¶Рµ РµСЃР»Рё `ssh-keygen` РЅРµ СЃРѕР·РґР°Р» РЅРё РѕРґРЅРѕРіРѕ host key РёР»Рё СЃР°Рј `sshd` Р·Р°РІРµСЂС€РёР»СЃСЏ СЃ РѕС€РёР±РєРѕР№.  
**Root cause:** СЂРµР·СѓР»СЊС‚Р°С‚С‹ `run_cmd()` РґР»СЏ РіРµРЅРµСЂР°С†РёРё host keys Рё Р·Р°РїСѓСЃРєР° `sshd` РёРіРЅРѕСЂРёСЂРѕРІР°Р»РёСЃСЊ; С„СѓРЅРєС†РёСЏ РІСЃРµРіРґР° С€Р»Р° РІ success-path РїРѕСЃР»Рµ log message.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** С‚РµРїРµСЂСЊ keygen failures Р»РѕРіРёСЂСѓСЋС‚СЃСЏ, РѕС‚СЃСѓС‚СЃС‚РІРёРµ РѕР±РѕРёС… host keys РїРµСЂРµРІРѕРґРёС‚ С€Р°Рі РІ hard fail, Р° exit status `sshd` РїСЂРѕРІРµСЂСЏРµС‚СЃСЏ РґРѕ РїСѓР±Р»РёРєР°С†РёРё success log.

---

## Р‘Р°Рі #147: `bootstrap_install()` РЅРµ СѓС‡РёС‚С‹РІР°Р» РїСЂРѕРІР°Р» OpenSSH С€Р°РіР° РІ РёС‚РѕРіРѕРІРѕРј СЃС‚Р°С‚СѓСЃРµ

**РЎРёРјРїС‚РѕРј:** Step 6 РјРѕРі РІРµСЂРЅСѓС‚СЊ РѕС€РёР±РєСѓ, РЅРѕ РѕР±С‰РёР№ `errors` РЅРµ СѓРІРµР»РёС‡РёРІР°Р»СЃСЏ, РїРѕСЌС‚РѕРјСѓ РёС‚РѕРіРѕРІС‹Р№ bootstrap summary РІСЃС‘ РµС‰С‘ РјРѕРі СЃС‚Р°С‚СЊ `COMPLETE` Рё РІС‹СЃС‚Р°РІРёС‚СЊ `g_installed=true` Р±РµР· СЂР°Р±РѕС‡РµРіРѕ SSH.  
**Root cause:** РІРµС‚РєР° `bootstrap_install_openssh() != 0` Р»РѕРіРёСЂРѕРІР°Р»Р° warning, РЅРѕ РЅР°РјРµСЂРµРЅРЅРѕ РЅРµ СѓС‡Р°СЃС‚РІРѕРІР°Р»Р° РІ `errors`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** OpenSSH install/launch failure С‚РµРїРµСЂСЊ РїРѕРјРµС‡Р°РµС‚ bootstrap РєР°Рє partial install С‡РµСЂРµР· `errors++`.

---

## Р‘Р°Рі #148: РїСЂРѕРІР°Р» `dpkg --configure -a` РЅРµ РїРµСЂРµРІРѕРґРёР» bootstrap РІ partial state

**РЎРёРјРїС‚РѕРј:** broken package configuration РјРѕРіР»Р° РѕСЃС‚Р°С‚СЊСЃСЏ РїРѕСЃР»Рµ Step 7, РЅРѕ `g_installed` РІСЃС‘ СЂР°РІРЅРѕ СЃС‚Р°РЅРѕРІРёР»СЃСЏ `true`, РµСЃР»Рё РѕСЃС‚Р°Р»СЊРЅС‹Рµ С€Р°РіРё РїСЂРѕС€Р»Рё.  
**Root cause:** `bootstrap_run_dpkg_configure()` Р»РѕРіРёСЂРѕРІР°Р»СЃСЏ РєР°Рє warning Р±РµР· РёРЅРєСЂРµРјРµРЅС‚Р° СЃС‡С‘С‚С‡РёРєР° РѕС€РёР±РѕРє.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РЅРµСѓСЃРїРµС… `dpkg --configure -a` С‚РµРїРµСЂСЊ СѓРІРµР»РёС‡РёРІР°РµС‚ `errors`, С‡С‚РѕР±С‹ РёС‚РѕРіРѕРІС‹Р№ СЃС‚Р°С‚СѓСЃ С‡РµСЃС‚РЅРѕ РїРѕРєР°Р·С‹РІР°Р» partial bootstrap.

---

## Р‘Р°Рі #149: СЂРµР·СѓР»СЊС‚Р°С‚ `bootstrap_setup_sources()` РёРіРЅРѕСЂРёСЂРѕРІР°Р»СЃСЏ

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё Procursus sources file РЅРµ Р·Р°РїРёСЃС‹РІР°Р»СЃСЏ, bootstrap РїСЂРѕРґРѕР»Р¶Р°Р» С„РёРЅР°Р»СЊРЅС‹Р№ success-path Рё РјРѕРі РјР°СЂРєРёСЂРѕРІР°С‚СЊ `/var/jb` РєР°Рє РїРѕР»РЅРѕСЃС‚СЊСЋ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅС‹Р№ Р±РµР· СЂР°Р±РѕС‡РёС… apt sources.  
**Root cause:** Step 8 РІС‹Р·С‹РІР°Р» `bootstrap_setup_sources()` Р±РµР· РїСЂРѕРІРµСЂРєРё return value.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** С‚РµРїРµСЂСЊ failure setup sources Р»РѕРіРёСЂСѓРµС‚СЃСЏ Рё СѓС‡РёС‚С‹РІР°РµС‚СЃСЏ РІ `errors`, С‡С‚РѕР±С‹ bootstrap summary РЅРµ СЃРєСЂС‹РІР°Р» СЃР»РѕРјР°РЅРЅС‹Р№ APT configuration.

---

## Р‘Р°Рі #150: `bootstrap_install_sileo()` РЅРµ РїСЂРѕРІРµСЂСЏР», С‡С‚Рѕ `Sileo.app` СЂРµР°Р»СЊРЅРѕ РїРѕСЏРІРёР»СЃСЏ РїРѕСЃР»Рµ `dpkg -i`

**РЎРёРјРїС‚РѕРј:** `dpkg` РјРѕРі РІРµСЂРЅСѓС‚СЊ success, РЅРѕ expected app bundle РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р» РёР»Рё Р»РµР¶Р°Р» РЅРµ С‚Р°Рј, Р° bootstrap РІСЃС‘ СЂР°РІРЅРѕ РїСЂРѕРґРѕР»Р¶Р°Р» trust/uicache path Рё РІ РєРѕРЅС†Рµ РїРёСЃР°Р» `Sileo installed`.  
**Root cause:** РїРѕСЃР»Рµ `dpkg -i` РЅРµ Р±С‹Р»Рѕ РЅРёРєР°РєРѕР№ РІРµСЂРёС„РёРєР°С†РёРё СЃСѓС‰РµСЃС‚РІРѕРІР°РЅРёСЏ `${g_jb_root}/Applications/Sileo.app`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅР° СЏРІРЅР°СЏ РїСЂРѕРІРµСЂРєР° РЅР°Р»РёС‡РёСЏ `Sileo.app`; РѕС‚СЃСѓС‚СЃС‚РІРёРµ bundle С‚РµРїРµСЂСЊ immediately РїРµСЂРµРІРѕРґРёС‚ С€Р°Рі РІ fail.

---

## Р‘Р°Рі #151: `bootstrap_install_sileo()` РёРіРЅРѕСЂРёСЂРѕРІР°Р» РїСЂРѕРІР°Р» trust РґР»СЏ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅРѕРіРѕ Sileo

**РЎРёРјРїС‚РѕРј:** Sileo РјРѕРі СЃС‡РёС‚Р°С‚СЊСЃСЏ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅС‹Рј, РґР°Р¶Рµ РµСЃР»Рё trust cache injection РґР»СЏ `Sileo.app` Рё/РёР»Рё contents `.deb` РїРѕР»РЅРѕСЃС‚СЊСЋ РїСЂРѕРІР°Р»РёРІР°Р»Р°СЃСЊ, С‡С‚Рѕ РѕСЃС‚Р°РІР»СЏР»Рѕ РїСЂРёР»РѕР¶РµРЅРёРµ РЅРµРёСЃРїРѕР»РЅСЏРµРјС‹Рј.  
**Root cause:** return values `tc_trust_directory(sileo_app)` Рё `tc_trust_deb(g_sileo_deb)` РЅРёРєР°Рє РЅРµ РїСЂРѕРІРµСЂСЏР»РёСЃСЊ.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** С‚РµРїРµСЂСЊ trust СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ РґРІР°; РµСЃР»Рё РЅРµ СѓРґР°Р»СЃСЏ РЅРё trust app bundle, РЅРё trust `.deb` contents, Sileo step РІРѕР·РІСЂР°С‰Р°РµС‚ РѕС€РёР±РєСѓ Рё РЅРµ СЂРµРїРѕСЂС‚РёС‚ success.

---

## Р‘Р°Рі #152: `bootstrap_install_sileo()` Р»РѕР¶РЅРѕ СЃРѕРѕР±С‰Р°Р» `uicache done` РїСЂРё failed icon registration

**РЎРёРјРїС‚РѕРј:** `uicache` РјРѕРі Р·Р°РІРµСЂС€РёС‚СЊСЃСЏ СЃ РѕС€РёР±РєРѕР№, РЅРѕ bootstrap РІСЃС‘ СЂР°РІРЅРѕ РїРёСЃР°Р» `uicache done for Sileo.app` Рё `Sileo installed`, С…РѕС‚СЏ РёРєРѕРЅРєР° РЅРµ СЂРµРіРёСЃС‚СЂРёСЂРѕРІР°Р»Р°СЃСЊ.  
**Root cause:** СЂРµР·СѓР»СЊС‚Р°С‚ `run_cmd(uicache, "-p", sileo_app, NULL)` РёРіРЅРѕСЂРёСЂРѕРІР°Р»СЃСЏ.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** exit status `uicache` С‚РµРїРµСЂСЊ РїСЂРѕРІРµСЂСЏРµС‚СЃСЏ, Рё РѕС€РёР±РєР° СЂРµРіРёСЃС‚СЂР°С†РёРё РїРµСЂРµРІРѕРґРёС‚ Sileo install step РІ fail РІРјРµСЃС‚Рѕ Р»РѕР¶РЅРѕРіРѕ success log.

---

## Р‘Р°Рі #153: `download_file()` РѕСЃС‚Р°РІР»СЏР» partial destination РїРѕСЃР»Рµ failed download

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ РїСЂРѕРІР°Р»Р° `curl`/`wget`/`NSURLSession` РЅР° РґРёСЃРєРµ РјРѕРі РѕСЃС‚Р°С‚СЊСЃСЏ РѕР±СЂРµР·Р°РЅРЅС‹Р№ `dest`, РєРѕС‚РѕСЂС‹Р№ СЃР»РµРґСѓСЋС‰РёР№ retry РІРёРґРµР» РєР°Рє СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ С„Р°Р№Р».  
**Root cause:** helper Р·Р°РіСЂСѓР·РєРё РЅРµ СѓРґР°Р»СЏР» СЃС‚Р°СЂС‹Р№/partial target РЅРё РїРµСЂРµРґ РЅР°С‡Р°Р»РѕРј РЅРѕРІРѕР№ РїРѕРїС‹С‚РєРё, РЅРё РїРѕСЃР»Рµ РѕР±С‰РµРіРѕ fail.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** `download_file()` С‚РµРїРµСЂСЊ СѓРґР°Р»СЏРµС‚ СЃС‚Р°СЂС‹Р№ target РїРµСЂРµРґ Р·Р°РіСЂСѓР·РєРѕР№ Рё С‡РёСЃС‚РёС‚ partial file РЅР° Р»СЋР±РѕРј РїРѕР»РЅРѕРј fail.

---

## Р‘Р°Рі #154: `bootstrap_download()` РїСЂРёРЅРёРјР°Р» Р»СЋР±РѕР№ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ bootstrap archive Р·Р° РІР°Р»РёРґРЅС‹Р№

**РЎРёРјРїС‚РѕРј:** stale/partial `bootstrap.tar.xz` РёР»Рё `bootstrap.tar.zst` РїРѕСЃР»Рµ РЅРµСѓРґР°С‡РЅРѕР№ Р·Р°РіСЂСѓР·РєРё СЃС‡РёС‚Р°Р»СЃСЏ РіРѕС‚РѕРІС‹Рј payload'РѕРј Рё РїСЂРѕРїСѓСЃРєР°Р» download step, С‡С‚Рѕ Р»РѕРјР°Р»Рѕ extraction РЅР° СЃР»РµРґСѓСЋС‰РµРј Р·Р°РїСѓСЃРєРµ.  
**Root cause:** РЅР°Р»РёС‡РёРµ С„Р°Р№Р»Р° РїСЂРѕРІРµСЂСЏР»РѕСЃСЊ С‡РµСЂРµР· `access(..., F_OK)` Р±РµР· РїСЂРѕРІРµСЂРєРё С‚РёРїР°/РјРёРЅРёРјР°Р»СЊРЅРѕРіРѕ СЂР°Р·РјРµСЂР°.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** bootstrap caches С‚РµРїРµСЂСЊ РїСЂРёРЅРёРјР°СЋС‚СЃСЏ С‚РѕР»СЊРєРѕ РєР°Рє regular files СЃ РјРёРЅРёРјР°Р»СЊРЅС‹Рј size sanity check; РјР°Р»РµРЅСЊРєРёРµ/Р±РёС‚С‹Рµ РѕСЃС‚Р°С‚РєРё СѓРґР°Р»СЏСЋС‚СЃСЏ Рё СЃРєР°С‡РёРІР°СЋС‚СЃСЏ Р·Р°РЅРѕРІРѕ.

---

## Р‘Р°Рі #155: `bootstrap_install_sileo()` РїРµСЂРµРёСЃРїРѕР»СЊР·РѕРІР°Р» Р»СЋР±РѕР№ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ `Sileo.deb`

**РЎРёРјРїС‚РѕРј:** partial/Р±РёС‚С‹Р№ `Sileo.deb` РѕС‚ РїСЂРµРґС‹РґСѓС‰РµРіРѕ failed download РјРѕРі РїРѕРІС‚РѕСЂРЅРѕ РёСЃРїРѕР»СЊР·РѕРІР°С‚СЊСЃСЏ РєР°Рє РіРѕС‚РѕРІС‹Р№ РїР°РєРµС‚, РїРѕСЃР»Рµ С‡РµРіРѕ `dpkg` РїР°РґР°Р» РёР»Рё СѓСЃС‚Р°РЅР°РІР»РёРІР°Р» РЅРµРїСЂРµРґСЃРєР°Р·СѓРµРјРѕ.  
**Root cause:** РїРµСЂРµРґ Р·Р°РіСЂСѓР·РєРѕР№ Sileo РёСЃРїРѕР»СЊР·РѕРІР°Р»Р°СЃСЊ С‚РѕР»СЊРєРѕ РїСЂРѕРІРµСЂРєР° `access(g_sileo_deb, F_OK)`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** `Sileo.deb` С‚РµРїРµСЂСЊ С‚РѕР¶Рµ РїСЂРѕС…РѕРґРёС‚ minimum-size sanity check; СЃР»РёС€РєРѕРј РјР°Р»РµРЅСЊРєРёР№ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ С„Р°Р№Р» СѓРґР°Р»СЏРµС‚СЃСЏ Рё СЃРєР°С‡РёРІР°РµС‚СЃСЏ Р·Р°РЅРѕРІРѕ.

---

## Р‘Р°Рі #156: `bootstrap_prepare_rootless()` РјР°СЃРєРёСЂРѕРІР°Р» РїСЂРѕРІР°Р» СЃРѕР·РґР°РЅРёСЏ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹С… РїРѕРґРґРёСЂРµРєС‚РѕСЂРёР№

**РЎРёРјРїС‚РѕРј:** bootstrap РјРѕРі РїСЂРѕРґРѕР»Р¶Р°С‚СЊ pipeline РїРѕСЃР»Рµ СЃРµСЂРёРё `mkdir()` failures РІРЅСѓС‚СЂРё `/var/jb`, Р° РЅР°СЃС‚РѕСЏС‰Р°СЏ РїСЂРёС‡РёРЅР° РІСЃРїР»С‹РІР°Р»Р° С‚РѕР»СЊРєРѕ РїРѕР·Р¶Рµ РєР°Рє РєР°СЃРєР°РґРЅС‹Рµ РѕС€РёР±РєРё `dpkg`, `apt` РёР»Рё trust paths.  
**Root cause:** С„СѓРЅРєС†РёСЏ С‚РѕР»СЊРєРѕ СЃС‡РёС‚Р°Р»Р° `dir_fail`, РЅРѕ РІСЃРµРіРґР° РІРѕР·РІСЂР°С‰Р°Р»Р° success, РґР°Р¶Рµ РµСЃР»Рё РѕР±СЏР·Р°С‚РµР»СЊРЅС‹Рµ РєР°С‚Р°Р»РѕРіРё РЅРµ СЃРѕР·РґР°Р»РёСЃСЊ.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РµСЃР»Рё Р»СЋР±Р°СЏ РёР· bootstrap subdirectories РЅРµ СЃРѕР·РґР°Р»Р°СЃСЊ, С€Р°Рі РїРѕРґРіРѕС‚РѕРІРєРё С‚РµРїРµСЂСЊ СЃСЂР°Р·Сѓ Р·Р°РІРµСЂС€Р°РµС‚СЃСЏ РѕС€РёР±РєРѕР№.

---

## Р‘Р°Рі #157: СЃРѕР·РґР°РЅРёРµ temp directory `g_jb_tmp` РёРіРЅРѕСЂРёСЂРѕРІР°Р»Рѕ РѕС€РёР±РєРё

**РЎРёРјРїС‚РѕРј:** failed `mkdir(/var/tmp/jb_bootstrap)` РЅРµ РѕСЃС‚Р°РЅР°РІР»РёРІР°Р» pipeline, РїРѕСЃР»Рµ С‡РµРіРѕ download/extract path РјРѕРі Р»РѕРјР°С‚СЊСЃСЏ РЅРµРѕС‡РµРІРёРґРЅРѕ РЅР° РїРѕСЃР»РµРґСѓСЋС‰РёС… С€Р°РіР°С….  
**Root cause:** return value `mkdir(g_jb_tmp, 0755)` РїРѕР»РЅРѕСЃС‚СЊСЋ РёРіРЅРѕСЂРёСЂРѕРІР°Р»СЃСЏ.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** temp directory creation С‚РµРїРµСЂСЊ РїСЂРѕРІРµСЂСЏРµС‚СЃСЏ Рё РїРµСЂРµРІРѕРґРёС‚ bootstrap РІ fail РїСЂРё Р»СЋР±РѕР№ РѕС€РёР±РєРµ РєСЂРѕРјРµ `EEXIST`.

---

## Р‘Р°Рі #158: `bootstrap_extract()` СЃС‡РёС‚Р°Р» extraction СѓСЃРїРµС€РЅС‹Рј РґР°Р¶Рµ Р±РµР· СЂР°Р±РѕС‡РµРіРѕ `dpkg`

**РЎРёРјРїС‚РѕРј:** tar extract РјРѕРі С„РѕСЂРјР°Р»СЊРЅРѕ Р·Р°РІРµСЂС€РёС‚СЊСЃСЏ, РЅРѕ РµСЃР»Рё `dpkg` РїРѕСЃР»Рµ extraction РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р» РёР»Рё Р±С‹Р» РЅРµРёСЃРїРѕР»РЅСЏРµРј, С„СѓРЅРєС†РёСЏ РІСЃС‘ СЂР°РІРЅРѕ РІРѕР·РІСЂР°С‰Р°Р»Р° success Рё Р»РѕРјР°Р»Р° СЃР»РµРґСѓСЋС‰РёРµ install steps.  
**Root cause:** post-extract verification С‚РѕР»СЊРєРѕ РїРёСЃР°Р»Р° warning `dpkg not found after extraction`, РЅРµ РїРµСЂРµРІРѕРґСЏ С€Р°Рі РІ fail.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** extraction С‚РµРїРµСЂСЊ СЃС‡РёС‚Р°РµС‚СЃСЏ СѓСЃРїРµС€РЅС‹Рј С‚РѕР»СЊРєРѕ РµСЃР»Рё `${g_jb_root}/usr/bin/dpkg` СЃСѓС‰РµСЃС‚РІСѓРµС‚ Рё executable.

---

## Р‘Р°Рі #159: `bootstrap_setup_sources()` Р»РѕР¶РЅРѕ СЃРѕРѕР±С‰Р°Р» СѓСЃРїРµС… РїСЂРё failed `havoc.sources` write

**РЎРёРјРїС‚РѕРј:** С„СѓРЅРєС†РёСЏ РјРѕРіР»Р° РїРёСЃР°С‚СЊ `apt sources configured`, РґР°Р¶Рµ РµСЃР»Рё РІС‚РѕСЂР°СЏ repo-РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ РЅРµ СЃРѕР·РґР°Р»Р°СЃСЊ РёР·-Р·Р° `fopen()` failure.  
**Root cause:** return value РѕС‚РєСЂС‹С‚РёСЏ `havoc.sources` РїСЂРѕРІРµСЂСЏР»СЃСЏ С‚РѕР»СЊРєРѕ СѓСЃР»РѕРІРЅРѕ; РїСЂРё fail С„СѓРЅРєС†РёСЏ РїСЂРѕСЃС‚Рѕ РјРѕР»С‡Р° РїСЂРѕРїСѓСЃРєР°Р»Р° Р·Р°РїРёСЃСЊ Рё РІРѕР·РІСЂР°С‰Р°Р»Р° `0`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** failure Р·Р°РїРёСЃРё `havoc.sources` С‚РµРїРµСЂСЊ Р»РѕРіРёСЂСѓРµС‚СЃСЏ Рё РІРѕР·РІСЂР°С‰Р°РµС‚ РѕС€РёР±РєСѓ, С‡С‚РѕР±С‹ Step 8 С‡РµСЃС‚РЅРѕ СЃС‚Р°РЅРѕРІРёР»СЃСЏ partial.

---

## Р‘Р°Рі #160: `tc_trust_deb()` РЅРµ РїСЂРѕРІРµСЂСЏР» `waitpid()` Рё abnormal child exits

**РЎРёРјРїС‚РѕРј:** `.deb` extraction/cleanup РјРѕРіР»Рё Р·Р°РІРµСЂС€РёС‚СЊСЃСЏ РїРѕ СЃРёРіРЅР°Р»Сѓ РёР»Рё РїРѕСЃР»Рµ failed `waitpid()`, Р° trustcache path РёРЅС‚РµСЂРїСЂРµС‚РёСЂРѕРІР°Р» РЅРµРІР°Р»РёРґРЅС‹Р№ `ret` РєР°Рє РЅРѕСЂРјР°Р»СЊРЅС‹Р№ status Рё РїСЂРѕРґРѕР»Р¶Р°Р» СЃ Р»РѕР¶РЅРѕР№ РєР°СЂС‚РёРЅРѕР№ РїСЂРѕРёСЃС…РѕРґСЏС‰РµРіРѕ.  
**Root cause:** `tc_trust_deb()` РЅР°РїСЂСЏРјСѓСЋ РІС‹Р·С‹РІР°Р» `waitpid(pid, &ret, 0)` Рё РёСЃРїРѕР»СЊР·РѕРІР°Р» raw status Р±РµР· `EINTR` retry, result-check Рё `WIFEXITED()`-РІР°Р»РёРґР°С†РёРё.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ РѕР±С‰РёР№ `wait_for_child_status()` helper СЃ `EINTR`-safe wait, abnormal-exit logging Рё РєРѕСЂСЂРµРєС‚РЅС‹Рј РІРѕР·РІСЂР°С‚РѕРј child exit code.

---

## Р‘Р°Рі #161: `bootstrap_install_openssh()` РјР°СЃРєРёСЂРѕРІР°Р» failed `apt install`

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё fallback С‡РµСЂРµР· `apt install openssh-server openssh-client` Р·Р°РІРµСЂС€Р°Р»СЃСЏ РѕС€РёР±РєРѕР№, С„СѓРЅРєС†РёСЏ РІСЃС‘ СЂР°РІРЅРѕ РґРѕС…РѕРґРёР»Р° РґРѕ СЃРѕРѕР±С‰РµРЅРёСЏ `OpenSSH: will be available...` Рё РІРѕР·РІСЂР°С‰Р°Р»Р° success, РёР·-Р·Р° С‡РµРіРѕ Step 6 РјРѕРі РЅРµ РїРѕРїР°СЃС‚СЊ РІ bootstrap error count.  
**Root cause:** apt fallback path РїСЂРѕРІРµСЂСЏР» С‚РѕР»СЊРєРѕ `ret == 0`, Р° Р»СЋР±РѕР№ explicit install failure silently РїСЂРµРІСЂР°С‰Р°Р» С€Р°Рі РІ РјСЏРіРєРёР№ success-path.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** failed `apt install` С‚РµРїРµСЂСЊ Р»РѕРіРёСЂСѓРµС‚СЃСЏ РєР°Рє РѕС€РёР±РєР° Рё РІРѕР·РІСЂР°С‰Р°РµС‚ `-1`, С‡С‚РѕР±С‹ bootstrap summary С‡РµСЃС‚РЅРѕ СЃС‚Р°РЅРѕРІРёР»СЃСЏ partial.

---

## Р‘Р°Рі #162: OpenSSH apt fallback РЅРµ РїСЂРѕРІРµСЂСЏР» РЅР°Р»РёС‡РёРµ/trust `sshd` РїРѕСЃР»Рµ install

**РЎРёРјРїС‚РѕРј:** РґР°Р¶Рµ РїРѕСЃР»Рµ СѓСЃРїРµС€РЅРѕРіРѕ `apt` step С„СѓРЅРєС†РёСЏ РјРѕРіР»Р° РІРµСЂРЅСѓС‚СЊ success Р±РµР· СЂРµР°Р»СЊРЅРѕ СѓСЃС‚Р°РЅРѕРІР»РµРЅРЅРѕРіРѕ executable `sshd` РёР»Рё РїРѕСЃР»Рµ failed trust of `/var/jb/usr/sbin`, РѕСЃС‚Р°РІР»СЏСЏ SSH РЅРµРіРѕС‚РѕРІС‹Рј РїСЂРё optimistic log `OpenSSH installed via apt`.  
**Root cause:** apt branch РЅРµ РІРµСЂРёС„РёС†РёСЂРѕРІР°Р» `access(sshd, X_OK)` Рё РёРіРЅРѕСЂРёСЂРѕРІР°Р» СЂРµР·СѓР»СЊС‚Р°С‚ `tc_trust_directory()` РґР»СЏ СЃРІРµР¶РёС… OpenSSH binaries.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** apt fallback С‚РµРїРµСЂСЊ С‚СЂРµР±СѓРµС‚ executable `sshd` РїРѕСЃР»Рµ install Рё СѓСЃРїРµС€РЅС‹Р№ trust `/var/jb/usr/sbin`; РёРЅР°С‡Рµ С€Р°Рі РІРѕР·РІСЂР°С‰Р°РµС‚ РѕС€РёР±РєСѓ.

---

## Р‘Р°Рі #163: `tc_trust_deb()` РїСЂРёРЅРёРјР°Р» `NULL`/empty path Рё РјРѕРі СѓР№С‚Рё РІ UB/Р»РѕР¶РЅС‹Р№ shell command

**РЎРёРјРїС‚РѕРј:** РІС‹Р·РѕРІ `tc_trust_deb(NULL)` РёР»Рё СЃ РїСѓСЃС‚РѕР№ СЃС‚СЂРѕРєРѕР№ РјРѕРі РїСЂРёРІРѕРґРёС‚СЊ Рє РЅРµРѕРїСЂРµРґРµР»С‘РЅРЅРѕРјСѓ РїРѕРІРµРґРµРЅРёСЋ РІ Р»РѕРіРёСЂРѕРІР°РЅРёРё/command construction РІРјРµСЃС‚Рѕ С‡РёСЃС‚РѕРіРѕ РѕС‚РєР°Р·Р°.  
**Root cause:** С„СѓРЅРєС†РёСЏ РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р»Р° `deb_path` РїРµСЂРµРґ `tlog("%s")` Рё РїРѕСЃР»РµРґСѓСЋС‰РёРј `snprintf()` shell command.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ СЂР°РЅРЅРёР№ reject РґР»СЏ `NULL`/empty path СЃ СЏРІРЅС‹Рј log message.

---

## Р‘Р°Рі #164: `tc_trust_deb()` СЃС‚СЂРѕРёР» shell command РёР· РЅРµСЌРєСЂР°РЅРёСЂРѕРІР°РЅРЅРѕРіРѕ `deb_path`

**РЎРёРјРїС‚РѕРј:** `.deb` path СЃ РїСЂРѕР±РµР»Р°РјРё, РєР°РІС‹С‡РєР°РјРё РёР»Рё shell metacharacters Р»РѕРјР°Р» extraction command Рё РјРѕРі РїСЂРёРІРѕРґРёС‚СЊ Рє trust failure РЅРµ РёР·-Р·Р° РїР°РєРµС‚Р°, Р° РёР·-Р·Р° РЅРµРІРµСЂРЅРѕР№ СЃС‚СЂРѕРєРё `/bin/sh -c`.  
**Root cause:** `deb_path` Рё temp dir РІСЃС‚Р°РІР»СЏР»РёСЃСЊ РІ shell command Р±РµР· quoting/escaping.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ single-quote shell escaping helper; extraction/cleanup commands С‚РµРїРµСЂСЊ РёСЃРїРѕР»СЊР·СѓСЋС‚ Р±РµР·РѕРїР°СЃРЅРѕ quoted paths.

---

## Р‘Р°Рі #165: OpenSSH apt fallback Р·Р°РІРµСЂС€Р°Р»СЃСЏ success РґРѕ РіРµРЅРµСЂР°С†РёРё host keys Рё Р·Р°РїСѓСЃРєР° `sshd`

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ СѓСЃРїРµС€РЅРѕРіРѕ `apt install` С„СѓРЅРєС†РёСЏ РЅРµРјРµРґР»РµРЅРЅРѕ РІРѕР·РІСЂР°С‰Р°Р»Р° `0`, РЅРµ РїСЂРѕС…РѕРґСЏ С‡РµСЂРµР· С‚Сѓ Р¶Рµ РІРµС‚РєСѓ keygen/launch, С‡С‚Рѕ Рё bundled `sshd`; РёС‚РѕРіРѕРІС‹Р№ bootstrap РјРѕРі СЃС‡РёС‚Р°С‚СЊ SSH РіРѕС‚РѕРІС‹Рј, С…РѕС‚СЏ РґРµРјРѕРЅ РµС‰С‘ РЅРµ Р±С‹Р» РїРѕРґРЅСЏС‚.  
**Root cause:** apt fallback РёРјРµР» РѕС‚РґРµР»СЊРЅС‹Р№ early-return success path РІРјРµСЃС‚Рѕ РѕР±С‰РµРіРѕ post-install bootstrap sequence.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** bundled Рё apt-installed OpenSSH С‚РµРїРµСЂСЊ РёСЃРїРѕР»СЊР·СѓСЋС‚ РѕР±С‰РёР№ С…РІРѕСЃС‚: trust `sshd`, host-key generation Рё Р·Р°РїСѓСЃРє РґРµРјРѕРЅР°.

---

## Р‘Р°Рі #166: `bootstrap_install_openssh()` РёРіРЅРѕСЂРёСЂРѕРІР°Р» РїСЂРѕРІР°Р» trust РґР»СЏ `sshd`

**РЎРёРјРїС‚РѕРј:** С„СѓРЅРєС†РёСЏ РјРѕРіР»Р° РїСЂРѕРґРѕР»Р¶Р°С‚СЊ Р·Р°РїСѓСЃРє `sshd` Рё РІ РёС‚РѕРіРµ СЂРµРїРѕСЂС‚РёС‚СЊ success, РґР°Р¶Рµ РµСЃР»Рё trust cache injection РґР»СЏ СЃР°РјРѕРіРѕ Р±РёРЅР°СЂРЅРёРєР° `sshd` РЅРµ СѓРґР°Р»Р°СЃСЊ.  
**Root cause:** `tc_trust_file(sshd)` РІС‹Р·С‹РІР°Р»СЃСЏ Р±РµР· РїСЂРѕРІРµСЂРєРё СЂРµР·СѓР»СЊС‚Р°С‚Р°.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** failure trust `sshd` С‚РµРїРµСЂСЊ РЅРµРјРµРґР»РµРЅРЅРѕ Р·Р°РІРµСЂС€Р°РµС‚ OpenSSH step РѕС€РёР±РєРѕР№.

---

## Р‘Р°Рі #167: `bootstrap_install_openssh()` РёРіРЅРѕСЂРёСЂРѕРІР°Р» РїСЂРѕРІР°Р» trust РґР»СЏ `ssh-keygen`

**РЎРёРјРїС‚РѕРј:** bootstrap РјРѕРі РїСЂРѕРґРѕР»Р¶Р°С‚СЊ РїРѕРїС‹С‚РєСѓ `ssh-keygen`, С…РѕС‚СЏ trust cache injection РґР»СЏ СЌС‚РѕРіРѕ Р±РёРЅР°СЂРЅРёРєР° СѓР¶Рµ РЅРµ СѓРґР°Р»Р°СЃСЊ, С‡С‚Рѕ РїСЂРµРІСЂР°С‰Р°Р»Рѕ СЂРµР°Р»СЊРЅСѓСЋ РїСЂРёС‡РёРЅСѓ РІ РїРѕР·РґРЅРёР№/РЅРµРѕС‡РµРІРёРґРЅС‹Р№ command failure.  
**Root cause:** `tc_trust_file(keygen)` РІС‹Р·С‹РІР°Р»СЃСЏ Р±РµР· РїСЂРѕРІРµСЂРєРё СЂРµР·СѓР»СЊС‚Р°С‚Р°.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РµСЃР»Рё trust `ssh-keygen` РЅРµ СѓРґР°Р»СЃСЏ, OpenSSH step С‚РµРїРµСЂСЊ immediately fails СЃ СЏРІРЅС‹Рј log message.

---

## Р‘Р°Рі #168: СЃРѕР·РґР°РЅРёРµ `/var/jb/etc/ssh` РїРµСЂРµРґ key generation РёРіРЅРѕСЂРёСЂРѕРІР°Р»Рѕ РѕС€РёР±РєРё

**РЎРёРјРїС‚РѕРј:** failed `mkdir(/var/jb/etc/ssh)` РЅРµ РѕСЃС‚Р°РЅР°РІР»РёРІР°Р» pipeline, РїРѕСЃР»Рµ С‡РµРіРѕ host key generation РјРѕРіР»Р° С‚РёС…Рѕ РїР°РґР°С‚СЊ РЅР° РѕС‚СЃСѓС‚СЃС‚РІСѓСЋС‰РµРј РєР°С‚Р°Р»РѕРіРµ Рё РјР°СЃРєРёСЂРѕРІР°С‚СЊ СЂРµР°Р»СЊРЅС‹Р№ root cause.  
**Root cause:** СЂРµР·СѓР»СЊС‚Р°С‚ `mkdir(ssh_dir, 0755)` РЅРµ РїСЂРѕРІРµСЂСЏР»СЃСЏ.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** СЃРѕР·РґР°РЅРёРµ SSH directory С‚РµРїРµСЂСЊ РїСЂРѕРІРµСЂСЏРµС‚СЃСЏ Рё РїСЂРё Р»СЋР±РѕР№ РѕС€РёР±РєРµ РєСЂРѕРјРµ `EEXIST` РїРµСЂРµРІРѕРґРёС‚ OpenSSH step РІ fail.

---

## Р‘Р°Рі #169: `bootstrap_install()` РјРµРЅСЏР» `PATH/DPKG_ROOT` РґРѕ re-entrancy guard

**РЎРёРјРїС‚РѕРј:** РїРѕРІС‚РѕСЂРЅС‹Р№ РІС‹Р·РѕРІ РїСЂРё `g_running=true` РјРѕРі РІРµСЂРЅСѓС‚СЊ `0`, РЅРѕ РІСЃС‘ СЂР°РІРЅРѕ СѓСЃРїРµРІР°Р» РёР·РјРµРЅРёС‚СЊ process environment, РѕСЃС‚Р°РІР»СЏСЏ РїРѕР±РѕС‡РЅС‹Р№ СЌС„С„РµРєС‚ РґР°Р¶Рµ Р±РµР· СЂРµР°Р»СЊРЅРѕРіРѕ Р·Р°РїСѓСЃРєР° bootstrap pipeline.  
**Root cause:** `setenv("PATH"...)` Рё `setenv("DPKG_ROOT"...)` РІС‹РїРѕР»РЅСЏР»РёСЃСЊ СЂР°РЅСЊС€Рµ РїСЂРѕРІРµСЂРєРё `g_running`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** re-entrancy guard С‚РµРїРµСЂСЊ РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ РґРѕ Р»СЋР±С‹С… env mutations.

---

## Р‘Р°Рі #170: bootstrap РЅРµ РїСЂРѕРІРµСЂСЏР» truncation/РѕС€РёР±РєСѓ РїСЂРё РЅР°СЃС‚СЂРѕР№РєРµ process `PATH`

**РЎРёРјРїС‚РѕРј:** СЃР»РёС€РєРѕРј РґР»РёРЅРЅС‹Р№ РёСЃС…РѕРґРЅС‹Р№ `PATH` РёР»Рё failed `setenv()` РјРѕРіР»Рё silently РѕСЃС‚Р°РІРёС‚СЊ child processes Р±РµР· РѕР¶РёРґР°РµРјРѕРіРѕ `/var/jb/usr/bin:/var/jb/usr/sbin`, РїРѕСЃР»Рµ С‡РµРіРѕ РєРѕРјР°РЅРґС‹ bootstrap РїР°РґР°Р»Рё РїРѕ РєРѕСЃРІРµРЅРЅС‹Рј РїСЂРёС‡РёРЅР°Рј.  
**Root cause:** `snprintf(new_path, 1024, ...)` Рё РѕР±Р° `setenv()` РІС‹Р·С‹РІР°Р»РёСЃСЊ Р±РµР· РїСЂРѕРІРµСЂРєРё СЂРµР·СѓР»СЊС‚Р°С‚Р°.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅС‹ РїСЂРѕРІРµСЂРєРё truncation Рё РѕС€РёР±РѕРє `setenv(PATH/DPKG_ROOT)` СЃ СЂР°РЅРЅРёРј abort РІРјРµСЃС‚Рѕ РїСЂРѕРґРѕР»Р¶РµРЅРёСЏ РІ РїР»РѕС…РѕРј env state.

---

## Р‘Р°Рі #171: `bootstrap_install()` РЅРµ РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°Р» `PATH/DPKG_ROOT` РїРѕСЃР»Рµ Р·Р°РІРµСЂС€РµРЅРёСЏ

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ СѓСЃРїРµС…Р° РёР»Рё early fail bootstrap process environment РѕСЃС‚Р°РІР°Р»СЃСЏ РёР·РјРµРЅС‘РЅРЅС‹Рј, С‡С‚Рѕ РјРѕРіР»Рѕ РІР»РёСЏС‚СЊ РЅР° РїРѕСЃР»РµРґСѓСЋС‰РёРµ retries/steps РІ С‚РѕРј Р¶Рµ РїСЂРѕС†РµСЃСЃРµ Рё РґР°РІР°С‚СЊ С‚СЂСѓРґРЅРѕРѕС‚СЃР»РµР¶РёРІР°РµРјРѕРµ stale-state РїРѕРІРµРґРµРЅРёРµ.  
**Root cause:** `PATH` Рё `DPKG_ROOT` РїРµСЂРµРѕРїСЂРµРґРµР»СЏР»РёСЃСЊ РіР»РѕР±Р°Р»СЊРЅРѕ С‡РµСЂРµР· `setenv()`, РЅРѕ РЅРёРєРѕРіРґР° РЅРµ РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°Р»РёСЃСЊ РЅР° РІС‹С…РѕРґРµ РёР· С„СѓРЅРєС†РёРё.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** СЃС‚Р°СЂС‹Рµ Р·РЅР°С‡РµРЅРёСЏ С‚РµРїРµСЂСЊ СЃРѕС…СЂР°РЅСЏСЋС‚СЃСЏ, Р° РЅР° Р»СЋР±РѕРј РІС‹С…РѕРґРµ РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ restore/`unsetenv()` cleanup.

---

## Р‘Р°Рі #172: concurrent `bootstrap_install()` call РІРѕР·РІСЂР°С‰Р°Р» Р»РѕР¶РЅС‹Р№ success

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё С„СѓРЅРєС†РёСЏ РІС‹Р·С‹РІР°Р»Р°СЃСЊ РїРѕРІС‚РѕСЂРЅРѕ РІРѕ РІСЂРµРјСЏ СѓР¶Рµ РёРґСѓС‰РµР№ СѓСЃС‚Р°РЅРѕРІРєРё, РѕРЅР° Р»РѕРіРёСЂРѕРІР°Р»Р° `already running, skipping` Рё РІРѕР·РІСЂР°С‰Р°Р»Р° `0`, РёР·-Р·Р° С‡РµРіРѕ caller РјРѕРі РїРѕСЃС‡РёС‚Р°С‚СЊ bootstrap СѓСЃРїРµС€РЅС‹Рј, С…РѕС‚СЏ РІС‚РѕСЂРѕР№ РІС‹Р·РѕРІ РЅРёС‡РµРіРѕ РЅРµ СЃРґРµР»Р°Р».  
**Root cause:** re-entrancy guard РёСЃРїРѕР»СЊР·РѕРІР°Р» success return code РґР»СЏ skip-path.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** concurrent invocation С‚РµРїРµСЂСЊ РІРѕР·РІСЂР°С‰Р°РµС‚ РѕС€РёР±РєСѓ Рё Р±РѕР»СЊС€Рµ РЅРµ РјР°СЃРєРёСЂСѓРµС‚СЃСЏ РїРѕРґ СѓСЃРїРµС€РЅСѓСЋ СѓСЃС‚Р°РЅРѕРІРєСѓ.

---

## Р‘Р°Рі #173: `bootstrap_prepare_rootless()` РїСЂРёРЅРёРјР°Р» Р»СЋР±РѕР№ `EEXIST` РґР»СЏ `/var/jb` РєР°Рє РєРѕСЂСЂРµРєС‚РЅС‹Р№ РєР°С‚Р°Р»РѕРі

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё `/var/jb` СѓР¶Рµ СЃСѓС‰РµСЃС‚РІРѕРІР°Р» РєР°Рє РѕР±С‹С‡РЅС‹Р№ С„Р°Р№Р» РёР»Рё РґСЂСѓРіРѕР№ РЅРµ-directory entry, bootstrap РїСЂРѕРґРѕР»Р¶Р°Р» СЂР°Р±РѕС‚Сѓ С‚Р°Рє, Р±СѓРґС‚Рѕ root directory РіРѕС‚РѕРІ, Р° СЂРµР°Р»СЊРЅС‹Рµ РѕС€РёР±РєРё РІСЃРїР»С‹РІР°Р»Рё РїРѕР·РґРЅРµРµ РЅР° РІР»РѕР¶РµРЅРЅС‹С… РїСѓС‚СЏС….  
**Root cause:** РєРѕРґ С‚СЂР°РєС‚РѕРІР°Р» `mkdir(...)=EEXIST` РєР°Рє success Р±РµР· РїСЂРѕРІРµСЂРєРё, С‡С‚Рѕ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ path РґРµР№СЃС‚РІРёС‚РµР»СЊРЅРѕ directory.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ `ensure_directory_exists()`, РєРѕС‚РѕСЂС‹Р№ РїРѕСЃР»Рµ `EEXIST` РїСЂРѕРІРµСЂСЏРµС‚ `stat()` + `S_ISDIR()` Рё С„РµР№Р»РёС‚ РЅР° non-directory entries.

---

## Р‘Р°Рі #174: bootstrap subdirectories Рё `g_jb_tmp` РїСЂРёРЅРёРјР°Р»Рё non-directory `EEXIST` РєР°Рє success

**РЎРёРјРїС‚РѕРј:** Р»СЋР±РѕР№ С„Р°Р№Р»/СЃСЃС‹Р»РєР° РЅР° РјРµСЃС‚Рµ РѕР±СЏР·Р°С‚РµР»СЊРЅРѕРіРѕ РїРѕРґРєР°С‚Р°Р»РѕРіР° (`usr`, `etc`, `var`, temp dir Рё С‚.Рґ.) РјРѕРі РїСЂРѕРїСѓСЃРєР°С‚СЊ prepare step, РїРѕСЃР»Рµ С‡РµРіРѕ СЃР»РµРґСѓСЋС‰РёРµ РѕРїРµСЂР°С†РёРё РїР°РґР°Р»Рё РґР°Р»РµРєРѕ РѕС‚ РЅР°СЃС‚РѕСЏС‰РµР№ РїСЂРёС‡РёРЅС‹.  
**Root cause:** Рё С†РёРєР» СЃРѕР·РґР°РЅРёСЏ subdirs, Рё СЃРѕР·РґР°РЅРёРµ `g_jb_tmp` СЃС‡РёС‚Р°Р»Рё `errno == EEXIST` РґРѕСЃС‚Р°С‚РѕС‡РЅС‹Рј РґР»СЏ success Р±РµР· РїСЂРѕРІРµСЂРєРё С‚РёРїР° СЃСѓС‰РµСЃС‚РІСѓСЋС‰РµРіРѕ entry.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РІСЃРµ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹Рµ bootstrap directories С‚РµРїРµСЂСЊ РїСЂРѕС…РѕРґСЏС‚ С‡РµСЂРµР· РѕР±С‰РёР№ helper, РєРѕС‚РѕСЂС‹Р№ С‚СЂРµР±СѓРµС‚ РёРјРµРЅРЅРѕ directory, Р° РЅРµ РїСЂРѕСЃС‚Рѕ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ path.

---

## Р‘Р°Рі #175: СЃРѕР·РґР°РЅРёРµ `/var/jb/etc/ssh` РїСЂРёРЅРёРјР°Р»Рѕ non-directory `EEXIST` Рё Р»РѕРјР°Р»Рѕ keygen path

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё `/var/jb/etc/ssh` СЃСѓС‰РµСЃС‚РІРѕРІР°Р» РЅРµ РєР°Рє РєР°С‚Р°Р»РѕРі, OpenSSH step РјРѕРі РїСЂРѕР№С‚Рё РјРёРјРѕ СЂРµР°Р»СЊРЅРѕР№ РїСЂРёС‡РёРЅС‹ Рё Р·Р°С‚РµРј РїР°РґР°С‚СЊ РЅР° host key generation/launch СЃ Р·Р°РїСѓС‚Р°РЅРЅС‹РјРё РѕС€РёР±РєР°РјРё.  
**Root cause:** SSH setup С‚РѕР¶Рµ СЂР°РЅСЊС€Рµ СЃС‡РёС‚Р°Р» Р»СЋР±РѕР№ `EEXIST` РґРѕСЃС‚Р°С‚РѕС‡РЅС‹Рј РґР»СЏ success РїСЂРё `mkdir(ssh_dir, 0755)`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** `ssh_dir` С‚РµРїРµСЂСЊ СЃРѕР·РґР°С‘С‚СЃСЏ С‡РµСЂРµР· С‚РѕС‚ Р¶Рµ directory-validation helper Рё cleanly fails РЅР° non-directory collisions.

---

## Р‘Р°Рі #176: `bootstrap_setup_sources()` РЅРµ РїСЂРѕРІРµСЂСЏР» Р·Р°РїРёСЃСЊ/flush `procursus.sources`

**РЎРёРјРїС‚РѕРј:** РїСЂРё РѕС€РёР±РєРµ `fprintf()` РёР»Рё РїРѕР·РґРЅРµРј flush error РЅР° `fclose()` bootstrap РјРѕРі Р»РѕРіРёСЂРѕРІР°С‚СЊ `apt sources configured`, С…РѕС‚СЏ РѕСЃРЅРѕРІРЅРѕР№ Procursus repo С„Р°Р№Р» Р·Р°РїРёСЃР°Р»СЃСЏ С‡Р°СЃС‚РёС‡РЅРѕ РёР»Рё РЅРµ Р·Р°РїРёСЃР°Р»СЃСЏ РІРѕРѕР±С‰Рµ.  
**Root cause:** РєРѕРґ РїСЂРѕРІРµСЂСЏР» С‚РѕР»СЊРєРѕ `fopen()`, РЅРѕ РїРѕР»РЅРѕСЃС‚СЊСЋ РёРіРЅРѕСЂРёСЂРѕРІР°Р» СЂРµР·СѓР»СЊС‚Р°С‚ `fprintf()` Рё `fclose()` РґР»СЏ `procursus.sources`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** Р·Р°РїРёСЃСЊ `procursus.sources` С‚РµРїРµСЂСЊ РІР°Р»РёРґРёСЂСѓРµС‚ Рё `fprintf()`, Рё `fclose()`, РїРµСЂРµРІРѕРґСЏ Step 8 РІ fail РїСЂРё Р»СЋР±РѕР№ РѕС€РёР±РєРµ Р·Р°РїРёСЃРё/flush.

---

## Р‘Р°Рі #177: `bootstrap_setup_sources()` РЅРµ РїСЂРѕРІРµСЂСЏР» Р·Р°РїРёСЃСЊ/flush `havoc.sources`

**РЎРёРјРїС‚РѕРј:** РІС‚РѕСЂРёС‡РЅС‹Р№ repo file РјРѕРі Р·Р°РїРёСЃР°С‚СЊСЃСЏ С‡Р°СЃС‚РёС‡РЅРѕ РёР»Рё РЅРµ Р·Р°РїРёСЃР°С‚СЊСЃСЏ РёР·-Р·Р° flush error, РЅРѕ bootstrap РІСЃС‘ СЂР°РІРЅРѕ РґРѕС…РѕРґРёР» РґРѕ `apt sources configured` Рё СЃС‡РёС‚Р°Р» Step 8 СѓСЃРїРµС€РЅС‹Рј.  
**Root cause:** РїРѕСЃР»Рµ `fopen()` РґР»СЏ `havoc.sources` РЅРµ РїСЂРѕРІРµСЂСЏР»РёСЃСЊ РЅРё `fprintf()`, РЅРё `fclose()`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** Р·Р°РїРёСЃСЊ `havoc.sources` С‚РµРїРµСЂСЊ С‚РѕР¶Рµ С‚СЂРµР±СѓРµС‚ СѓСЃРїРµС€РЅС‹С… `fprintf()` Рё `fclose()`, РёРЅР°С‡Рµ bootstrap С‡РµСЃС‚РЅРѕ РїРѕРјРµС‡Р°РµС‚ sources setup РєР°Рє failed.

---

## Р‘Р°Рі #178: `bootstrap_trust_binaries()` РјР°СЃРєРёСЂРѕРІР°Р» partial trust failures

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё trust РѕРґРЅРѕР№ bootstrap-РґРёСЂРµРєС‚РѕСЂРёРё РїР°РґР°Р», Р° РІ РґСЂСѓРіРѕР№ СѓРґР°РІР°Р»РѕСЃСЊ РґРѕР±Р°РІРёС‚СЊ С…РѕС‚СЏ Р±С‹ С‡Р°СЃС‚СЊ Р±РёРЅР°СЂРЅРёРєРѕРІ, Step 4 РІСЃС‘ СЂР°РІРЅРѕ РІРѕР·РІСЂР°С‰Р°Р» success Рё СЃРєСЂС‹РІР°Р» РЅРµРїРѕР»РЅС‹Р№ trust coverage.  
**Root cause:** С„СѓРЅРєС†РёСЏ СЃСѓРјРјРёСЂРѕРІР°Р»Р° С‚РѕР»СЊРєРѕ `n > 0` Рё РёРіРЅРѕСЂРёСЂРѕРІР°Р»Р° `n < 0`, РїРѕСЃР»Рµ С‡РµРіРѕ СЃС‡РёС‚Р°Р»Р° С€Р°Рі СѓСЃРїРµС€РЅС‹Рј РїРѕ СѓСЃР»РѕРІРёСЋ `total > 0`.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ `had_error`; Р»СЋР±РѕР№ failed directory trust С‚РµРїРµСЂСЊ РїРµСЂРµРІРѕРґРёС‚ Step 4 РІ fail РґР°Р¶Рµ РїСЂРё РЅРµРЅСѓР»РµРІРѕРј РѕР±С‰РµРј С‡РёСЃР»Рµ trusted binaries.

---

## Р‘Р°Рі #179: `tc_trust_file()` РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» `NULL`/empty path

**РЎРёРјРїС‚РѕРј:** public trustcache API РјРѕРі РїРѕР»СѓС‡Р°С‚СЊ `NULL` РёР»Рё РїСѓСЃС‚СѓСЋ СЃС‚СЂРѕРєСѓ Рё СѓС…РѕРґРёС‚СЊ РІ Р±РµСЃСЃРјС‹СЃР»РµРЅРЅС‹Р№ `stat()`/РґР°Р»СЊРЅРµР№С€СѓСЋ РѕР±СЂР°Р±РѕС‚РєСѓ РІРјРµСЃС‚Рѕ clean reject.  
**Root cause:** `tc_trust_file()` РїСЂРѕРІРµСЂСЏР» С‚РѕР»СЊРєРѕ `g_ready`, РЅРѕ РЅРµ СЃР°Рј Р°СЂРіСѓРјРµРЅС‚ `path`.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ СЂР°РЅРЅРёР№ reject РґР»СЏ invalid `path` СЃ СЏРІРЅС‹Рј log message `trust_file: invalid path`.

---

## Р‘Р°Рі #180: `tc_trust_directory()` РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» `NULL`/empty path

**РЎРёРјРїС‚РѕРј:** recursive trust API РјРѕРі СЃС‚Р°СЂС‚РѕРІР°С‚СЊ СЃ РїСѓСЃС‚РѕРіРѕ/`NULL` path Рё Р·Р°С‚РµРј СѓС…РѕРґРёС‚СЊ РІ `opendir()`/path formatting СЃ РЅРµРІР°Р»РёРґРЅС‹Рј РІС…РѕРґРѕРј, С‡С‚Рѕ РјР°СЃРєРёСЂРѕРІР°Р»Рѕ СЂРµР°Р»СЊРЅСѓСЋ РїСЂРёС‡РёРЅСѓ РІС‹Р·РѕРІР°.  
**Root cause:** `tc_trust_directory()` РЅРµ РґРµР»Р°Р» СЂР°РЅРЅРµР№ РїСЂРѕРІРµСЂРєРё РІС…РѕРґРЅРѕРіРѕ Р°СЂРіСѓРјРµРЅС‚Р°, РµСЃР»Рё trustcache СѓР¶Рµ Р±С‹Р» ready.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ СЂР°РЅРЅРёР№ reject РґР»СЏ invalid directory path РґРѕ `opendir()`.

---

## Р‘Р°Рі #181: `kfs_overwrite_file()` РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» `NULL`/empty source Рё target paths

**РЎРёРјРїС‚РѕРј:** public overwrite API РјРѕРі РїРѕР»СѓС‡Р°С‚СЊ РїСѓСЃС‚РѕР№ РёР»Рё `NULL` РїСѓС‚СЊ Рё РёРґС‚Рё РґР°Р»СЊС€Рµ РІ log/open flow СЃ Р±РµСЃСЃРјС‹СЃР»РµРЅРЅС‹Рј input, С‡С‚Рѕ РґР°РІР°Р»Рѕ РЅРµС‡С‘С‚РєРёР№ root cause Рё Р·Р°РІРёСЃРµР»Рѕ РѕС‚ РїРѕРІРµРґРµРЅРёСЏ libc РЅР° `%s`/`open(NULL)`.  
**Root cause:** С„СѓРЅРєС†РёСЏ РїСЂРѕРІРµСЂСЏР»Р° С‚РѕР»СЊРєРѕ `g_ready`, РЅРѕ РЅРµ РѕР±Р° РІС…РѕРґРЅС‹С… path arguments РґРѕ Р»РѕРіРёСЂРѕРІР°РЅРёСЏ Рё `open()`.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ СЂР°РЅРЅРёР№ reject РґР»СЏ invalid `to`/`from` СЃ СЏРІРЅС‹Рј log message.

---

## Р‘Р°Рі #182: KFS overwrite paths РёРіРЅРѕСЂРёСЂРѕРІР°Р»Рё `lseek()` failure РїСЂРё РѕРїСЂРµРґРµР»РµРЅРёРё СЂР°Р·РјРµСЂРѕРІ С„Р°Р№Р»РѕРІ

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё size query РґР»СЏ target/source С„Р°Р№Р»Р° РїР°РґР°Р», overwrite path РјРѕРі РїСЂРѕРґРѕР»Р¶РёС‚СЊ СЂР°Р±РѕС‚Сѓ СЃ `-1` length Рё РґРѕР№С‚Рё РґРѕ `mmap()`/subsequent logic СЃ РЅРµРІР°Р»РёРґРЅС‹Рј СЂР°Р·РјРµСЂРѕРј.  
**Root cause:** Рё `kfs_overwrite_file()`, Рё `kfs_overwrite_file_bytes()` РёСЃРїРѕР»СЊР·РѕРІР°Р»Рё return value `lseek()` Р±РµР· РїСЂРѕРІРµСЂРєРё РЅР° РѕС€РёР±РєСѓ.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** size discovery С‚РµРїРµСЂСЊ РїСЂРѕРІРµСЂСЏРµС‚ `lseek() < 0` Рё cleanly aborts РґРѕ `mmap()`.

---

## Р‘Р°Рі #183: `kfs_overwrite_file_bytes()` РїСЂРёРЅРёРјР°Р» negative offsets / `NULL` data Рё РґРµР»Р°Р» overflow-prone bounds check

**РЎРёРјРїС‚РѕРј:** caller РјРѕРі РїРµСЂРµРґР°С‚СЊ `offset < 0` РёР»Рё `data == NULL` РїСЂРё `len > 0`, РїРѕСЃР»Рµ С‡РµРіРѕ overwrite path Р»РёР±Рѕ РїРёСЃР°Р» РґРѕ РЅР°С‡Р°Р»Р° mapping, Р»РёР±Рѕ РїР°РґР°Р» РЅР° `memcpy()`; РІРґРѕР±Р°РІРѕРє РїСЂРµР¶РЅСЏСЏ РїСЂРѕРІРµСЂРєР° `file_size < offset + len` Р·Р°РІРёСЃРµР»Р° РѕС‚ signed arithmetic Рё Р±С‹Р»Р° С…СЂСѓРїРєРѕР№.  
**Root cause:** public byte-overwrite API РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» offset/data Рё РёСЃРїРѕР»СЊР·РѕРІР°Р» bounds check С‡РµСЂРµР· РїСЂСЏРјРѕРµ СЃР»РѕР¶РµРЅРёРµ signed `off_t` Рё `size_t`.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅС‹ early guards РґР»СЏ negative offset Рё `NULL` data, Р° РіСЂР°РЅРёС†С‹ С‚РµРїРµСЂСЊ СЃС‡РёС‚Р°СЋС‚СЃСЏ С‡РµСЂРµР· overflow-safe remaining-size check; zero-length writes treated as no-op.

---

## Р‘Р°Рі #184: `tc_trust_deb()` РїРµСЂРµРёСЃРїРѕР»СЊР·РѕРІР°Р» stale temporary extraction directory

**РЎРёРјРїС‚РѕРј:** РїРѕРІС‚РѕСЂРЅС‹Р№ trust РѕРґРЅРѕРіРѕ РёР»Рё РЅРµСЃРєРѕР»СЊРєРёС… `.deb` РІ СЂР°РјРєР°С… С‚РѕРіРѕ Р¶Рµ РїСЂРѕС†РµСЃСЃР° РјРѕРі РёСЃРїРѕР»СЊР·РѕРІР°С‚СЊ СЃС‚Р°СЂС‹Рµ С„Р°Р№Р»С‹ РёР· `/var/tmp/tc_deb_<pid>`, РµСЃР»Рё РїСЂРµРґС‹РґСѓС‰Р°СЏ РїРѕРїС‹С‚РєР° РѕСЃС‚Р°РІРёР»Р° РјСѓСЃРѕСЂ РїРѕСЃР»Рµ failed extract/cleanup. Р­С‚Рѕ РјРѕРіР»Рѕ РґР°С‚СЊ false trust count РёР»Рё trust РЅРµР°РєС‚СѓР°Р»СЊРЅРѕРіРѕ СЃРѕРґРµСЂР¶РёРјРѕРіРѕ.  
**Root cause:** temp directory СЃС‚СЂРѕРёР»СЃСЏ С‚РѕР»СЊРєРѕ РёР· `getpid()` Рё РїРµСЂРµРґ РЅРѕРІРѕР№ extraction РЅРµ РѕС‡РёС‰Р°Р»СЃСЏ.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РїРµСЂРµРґ РєР°Р¶РґС‹Рј `.deb` extract С‚РµРїРµСЂСЊ РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ РѕР±СЏР·Р°С‚РµР»СЊРЅС‹Р№ pre-cleanup РІСЂРµРјРµРЅРЅРѕР№ РґРёСЂРµРєС‚РѕСЂРёРё.

---

## Р‘Р°Рі #185: `tc_trust_deb()` РјР°СЃРєРёСЂРѕРІР°Р» failed cleanup РїРѕСЃР»Рµ extract/trust

**РЎРёРјРїС‚РѕРј:** С„СѓРЅРєС†РёСЏ РјРѕРіР»Р° РІРµСЂРЅСѓС‚СЊ success count РґР°Р¶Рµ РµСЃР»Рё СѓРґР°Р»РµРЅРёРµ temporary extraction directory РЅРµ РІС‹РїРѕР»РЅРёР»РѕСЃСЊ, РёР·-Р·Р° С‡РµРіРѕ СЃР»РµРґСѓСЋС‰РёР№ РІС‹Р·РѕРІ РїРѕР»СѓС‡Р°Р» poisoned stale state. Failed extract path С‚РѕР¶Рµ РІРѕР·РІСЂР°С‰Р°Р»СЃСЏ Р±РµР· best-effort cleanup.  
**Root cause:** cleanup Р±С‹Р» best-effort Рё РµРіРѕ СЂРµР·СѓР»СЊС‚Р°С‚ РЅРµ РІР»РёСЏР» РЅР° РёС‚РѕРі `tc_trust_deb()`; РїСЂРё extraction fail cleanup РІРѕРѕР±С‰Рµ РЅРµ РІС‹РїРѕР»РЅСЏР»СЃСЏ.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** cleanup РІС‹РЅРµСЃРµРЅ РІ РѕР±С‰РёР№ helper, РІС‹Р·С‹РІР°РµС‚СЃСЏ Рё РґРѕ extraction, Рё РїРѕСЃР»Рµ failed/success paths; failed cleanup С‚РµРїРµСЂСЊ РІРѕР·РІСЂР°С‰Р°РµС‚ РѕС€РёР±РєСѓ.

---

## Р‘Р°Рі #186: `bootstrap_install_sileo()` РёРіРЅРѕСЂРёСЂРѕРІР°Р» failed trust `uicache`

**РЎРёРјРїС‚РѕРј:** Sileo step РјРѕРі РґРѕР№С‚Рё РґРѕ `uicache -p` Рё РґР°Р¶Рµ Р»РѕРіРёСЂРѕРІР°С‚СЊ СѓСЃРїРµС€РЅСѓСЋ СЂРµРіРёСЃС‚СЂР°С†РёСЋ РёРєРѕРЅРєРё, С…РѕС‚СЏ СЃР°Рј `uicache` binary РЅРµ Р±С‹Р» СѓСЃРїРµС€РЅРѕ trusted. Р­С‚Рѕ РѕСЃС‚Р°РІР»СЏР»Рѕ Р»РѕР¶РЅС‹Р№ success-path РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ, РіРґРµ execution СЂРµР°Р»СЊРЅРѕ Р·Р°РІРёСЃРёС‚ РѕС‚ trust cache.  
**Root cause:** РїРµСЂРµРґ Р·Р°РїСѓСЃРєРѕРј `uicache` РІС‹Р·С‹РІР°Р»СЃСЏ `tc_trust_file(uicache)`, РЅРѕ РµРіРѕ СЂРµР·СѓР»СЊС‚Р°С‚ РїРѕР»РЅРѕСЃС‚СЊСЋ РёРіРЅРѕСЂРёСЂРѕРІР°Р»СЃСЏ.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** Р·Р°РїСѓСЃРє `uicache` С‚РµРїРµСЂСЊ СЂР°Р·СЂРµС€С‘РЅ С‚РѕР»СЊРєРѕ РїРѕСЃР»Рµ СѓСЃРїРµС€РЅРѕРіРѕ `tc_trust_file(uicache)`; trust failure Р·Р°РІРµСЂС€Р°РµС‚ Sileo step РѕС€РёР±РєРѕР№.

---

## Р‘Р°Рі #187: `bootstrap_install()` РёРіРЅРѕСЂРёСЂРѕРІР°Р» failed restore `PATH/DPKG_ROOT` Рё РјРѕРі Р»РѕРіРёСЂРѕРІР°С‚СЊ Р»РѕР¶РЅС‹Р№ `COMPLETE`

**РЎРёРјРїС‚РѕРј:** bootstrap РјРѕРі Р·Р°РІРµСЂС€РёС‚СЊ pipeline Р±РµР· functional РѕС€РёР±РѕРє, РЅР°РїРµС‡Р°С‚Р°С‚СЊ С„РёРЅР°Р»СЊРЅС‹Р№ `COMPLETE`, Р° Р·Р°С‚РµРј С‚РёС…Рѕ РїСЂРѕРІР°Р»РёС‚СЊ РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёРµ `PATH` РёР»Рё `DPKG_ROOT`. Р­С‚Рѕ РѕСЃС‚Р°РІР»СЏР»Рѕ poisoned process environment РґР»СЏ СЃР»РµРґСѓСЋС‰РёС… С„Р°Р·/retry РїСЂРё misleading final summary.  
**Root cause:** restore-path РІ `out:` РІС‹Р·С‹РІР°Р» `setenv()`/`unsetenv()` Р±РµР· РїСЂРѕРІРµСЂРєРё return value, Р° С„РёРЅР°Р»СЊРЅС‹Р№ summary РїРµС‡Р°С‚Р°Р»СЃСЏ РµС‰С‘ РґРѕ РїРѕРїС‹С‚РєРё restore.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅРёРµ env РІС‹РЅРµСЃРµРЅРѕ РІ checked helper; failed restore С‚РµРїРµСЂСЊ СЃР±СЂР°СЃС‹РІР°РµС‚ installed-state, СѓРІРµР»РёС‡РёРІР°РµС‚ РёС‚РѕРіРѕРІС‹Р№ error count Рё РІР»РёСЏРµС‚ РЅР° С„РёРЅР°Р»СЊРЅС‹Р№ summary.

---

## Р‘Р°Рі #188: `bootstrap_set_procursus_url()` РїСЂРёРЅРёРјР°Р» `NULL`/empty override Рё РјРѕРі РѕС‚СЂР°РІРёС‚СЊ download pipeline

**РЎРёРјРїС‚РѕРј:** РІРЅРµС€РЅРёР№ caller РјРѕРі РїРµСЂРµРґР°С‚СЊ РїСѓСЃС‚РѕР№ РёР»Рё `NULL` URL РґР»СЏ Procursus bootstrap, РїРѕСЃР»Рµ С‡РµРіРѕ СЃР»РµРґСѓСЋС‰РёР№ download path СЂР°Р±РѕС‚Р°Р» СЃ РЅРµРІР°Р»РёРґРЅРѕР№ РєРѕРЅС„РёРіСѓСЂР°С†РёРµР№ Рё РїР°РґР°Р» РґР°Р»РµРєРѕ РѕС‚ СЂРµР°Р»СЊРЅРѕР№ РїСЂРёС‡РёРЅС‹.  
**Root cause:** public configuration API Р±РµР·СѓСЃР»РѕРІРЅРѕ Р·Р°РїРёСЃС‹РІР°Р» РІС…РѕРґРЅРѕР№ pointer РІ `g_bootstrap_url`, РЅРµ СЃРѕС…СЂР°РЅСЏСЏ safe default.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** invalid Procursus override С‚РµРїРµСЂСЊ РѕС‚РІРµСЂРіР°РµС‚СЃСЏ СЃ warning, Р° bootstrap URL РІРѕР·РІСЂР°С‰Р°РµС‚СЃСЏ Рє default value.

---

## Р‘Р°Рі #189: `bootstrap_set_sileo_url()` РїСЂРёРЅРёРјР°Р» `NULL`/empty override Рё Р»РѕРјР°Р» Sileo install retries

**РЎРёРјРїС‚РѕРј:** Sileo download/install path РјРѕРі Р±С‹С‚СЊ poisoned РїСѓСЃС‚С‹Рј РёР»Рё `NULL` URL override, РёР·-Р·Р° С‡РµРіРѕ retry РїСЂРѕРґРѕР»Р¶Р°Р» СЂР°Р±РѕС‚Р°С‚СЊ СЃ РЅРµРІР°Р»РёРґРЅС‹Рј config state РІРјРµСЃС‚Рѕ РЅРѕСЂРјР°Р»СЊРЅРѕРіРѕ fallback РЅР° default release URL.  
**Root cause:** setter РґР»СЏ `g_sileo_url` РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» РІС…РѕРґ Рё РЅРµ РІРѕСЃСЃС‚Р°РЅР°РІР»РёРІР°Р» РёСЃС…РѕРґРЅС‹Р№ Р±РµР·РѕРїР°СЃРЅС‹Р№ URL.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** invalid Sileo override С‚РµРїРµСЂСЊ РїСЂРёРІРѕРґРёС‚ Рє warning Рё РІРѕР·РІСЂР°С‚Сѓ РЅР° default URL.

---

## Р‘Р°Рі #190: `tc_trust_deb()` РїСЂРёРЅРёРјР°Р» РЅРµ-regular path Рё РґРѕС…РѕРґРёР» РґРѕ shell extract flow

**РЎРёРјРїС‚РѕРј:** public `.deb` trust API РјРѕРі РїРѕР»СѓС‡РёС‚СЊ РґРёСЂРµРєС‚РѕСЂРёСЋ, symlink-target РёР»Рё РґСЂСѓРіРѕР№ РЅРµ-regular path Рё РІСЃС‘ СЂР°РІРЅРѕ РїС‹С‚Р°С‚СЊСЃСЏ Р·Р°РїСѓСЃРєР°С‚СЊ extraction shell pipeline, СЃРєСЂС‹РІР°СЏ РЅР°СЃС‚РѕСЏС‰РёР№ РёСЃС‚РѕС‡РЅРёРє РѕС€РёР±РєРё Р·Р° РѕР±С‰РёРј extract failure.  
**Root cause:** `tc_trust_deb()` РІР°Р»РёРґРёСЂРѕРІР°Р» С‚РѕР»СЊРєРѕ СЃС‚СЂРѕРєСѓ РїСѓС‚Рё, РЅРѕ РЅРµ С‚РёРї СЃР°РјРѕРіРѕ filesystem object.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ СЂР°РЅРЅРёР№ `stat()` + С‚СЂРµР±РѕРІР°РЅРёРµ `S_ISREG()` РґРѕ Р·Р°РїСѓСЃРєР° extraction.

---

## Р‘Р°Рі #191: `tc_trust_deb()` РїСЂРёРЅРёРјР°Р» Р·Р°РІРµРґРѕРјРѕ СЃР»РёС€РєРѕРј РјР°Р»РµРЅСЊРєРёР№ `.deb`

**РЎРёРјРїС‚РѕРј:** РїСѓСЃС‚РѕР№ РёР»Рё РѕР±СЂРµР·Р°РЅРЅС‹Р№ С„Р°Р№Р» РјРѕРі СѓС…РѕРґРёС‚СЊ РІ `ar`/`tar` pipeline РєР°Рє Р±СѓРґС‚Рѕ СЌС‚Рѕ РЅР°СЃС‚РѕСЏС‰РёР№ package, С‡С‚Рѕ РїСЂРµРІСЂР°С‰Р°Р»Рѕ РїСЂРѕСЃС‚СѓСЋ invalid-input СЃРёС‚СѓР°С†РёСЋ РІ РїРѕР·РґРЅРёР№ Рё РјРµРЅРµРµ РґРёР°РіРЅРѕСЃС‚РёС‡РЅС‹Р№ extract failure.  
**Root cause:** API РЅРµ РґРµР»Р°Р» РјРёРЅРёРјР°Р»СЊРЅРѕР№ sanity-РїСЂРѕРІРµСЂРєРё СЂР°Р·РјРµСЂР° С„Р°Р№Р»Р° РїРµСЂРµРґ shell extraction.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** СЃР»РёС€РєРѕРј РјР°Р»РµРЅСЊРєРёРµ `.deb` С‚РµРїРµСЂСЊ РѕС‚РІРµСЂРіР°СЋС‚СЃСЏ СЃСЂР°Р·Сѓ СЃ СЏРІРЅС‹Рј log message РґРѕ extract path.

---

## Р‘Р°Рі #192: `tc_add_cdhash()` РјРѕРі РїСЂРёРЅРёРјР°С‚СЊ РІС‹Р·РѕРІ РґРѕ `tc_init()` Рё silently queue state

**РЎРёРјРїС‚РѕРј:** public CDHash API РјРѕРі РїСЂРёРЅРёРјР°С‚СЊ Р·Р°РїРёСЃРё РґРѕ С‚РѕРіРѕ, РєР°Рє trustcache СЂРµР°Р»СЊРЅРѕ ready. Р­С‚Рѕ СЃРѕР·РґР°РІР°Р»Рѕ Р»РѕР¶РЅРѕРµ РѕС‰СѓС‰РµРЅРёРµ СѓСЃРїРµС€РЅРѕРіРѕ queue path Рё РѕСЃС‚Р°РІР»СЏР»Рѕ РІРЅСѓС‚СЂРµРЅРЅРµРµ СЃРѕСЃС‚РѕСЏРЅРёРµ Р·Р°РІРёСЃРёРјС‹Рј РѕС‚ СЃР»СѓС‡Р°Р№РЅРѕРіРѕ РїРѕСЃР»РµРґСѓСЋС‰РµРіРѕ init/flush РїРѕРІРµРґРµРЅРёСЏ.  
**Root cause:** `tc_add_cdhash()` РїСЂРѕРІРµСЂСЏР» `g_ready` С‚РѕР»СЊРєРѕ РІ РІРµС‚РєРµ overflow/auto-flush, РЅРѕ РЅРµ РІ РѕР±С‹С‡РЅРѕРј add path.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** С„СѓРЅРєС†РёСЏ С‚РµРїРµСЂСЊ СЃСЂР°Р·Сѓ РѕС‚РІРµСЂРіР°РµС‚ Р»СЋР±С‹Рµ add requests, РµСЃР»Рё trustcache РЅРµ РёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅ Рё РЅРµ ready.

---

## Р‘Р°Рі #193: `tc_add_cdhash()` РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» `NULL` input

**РЎРёРјРїС‚РѕРј:** caller СЃ `NULL` РІРјРµСЃС‚Рѕ 20-byte CDHash РјРѕРі РґРѕР№С‚Рё РґРѕ `memcpy()` Рё РІС‹Р·РІР°С‚СЊ userspace crash/UB РІРЅСѓС‚СЂРё trustcache API.  
**Root cause:** public add API РЅРµ РїСЂРѕРІРµСЂСЏР» РІС…РѕРґРЅРѕР№ pointer РїРµСЂРµРґ РєРѕРїРёСЂРѕРІР°РЅРёРµРј РІ entry buffer.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ СЂР°РЅРЅРёР№ reject РґР»СЏ `NULL` CDHash.

---

## Р‘Р°Рі #194: `tc_init()` РЅРµ СЃР±СЂР°СЃС‹РІР°Р» pending `g_nentries` РјРµР¶РґСѓ РїРѕРїС‹С‚РєР°РјРё

**РЎРёРјРїС‚РѕРј:** РµСЃР»Рё РїСЂРµРґС‹РґСѓС‰РёР№ trust flow РЅР°РєРѕРїРёР» CDHashes РІ Р±СѓС„РµСЂРµ, Р° Р·Р°С‚РµРј init/retry РЅР°С‡РёРЅР°Р»СЃСЏ Р·Р°РЅРѕРІРѕ, РЅРѕРІС‹Р№ trustcache session РјРѕРі СѓРЅР°СЃР»РµРґРѕРІР°С‚СЊ stale pending entries Рё РїРѕР·Р¶Рµ inject'РёС‚СЊ РЅРµР°РєС‚СѓР°Р»СЊРЅС‹Рµ hashes РІРјРµСЃС‚Рµ СЃ РЅРѕРІС‹РјРё.  
**Root cause:** reset РІ `tc_init()` РѕС‡РёС‰Р°Р» `g_ready`, `g_tc_head` Рё `g_injected`, РЅРѕ РѕСЃС‚Р°РІР»СЏР» `g_nentries` РЅРµС‚СЂРѕРЅСѓС‚С‹Рј.  
**Р¤Р°Р№Р»:** `trustcache.m`  
**Fix:** `tc_init()` С‚РµРїРµСЂСЊ РІСЃРµРіРґР° СЃР±СЂР°СЃС‹РІР°РµС‚ Рё pending entry count, С‡С‚РѕР±С‹ РєР°Р¶РґР°СЏ РЅРѕРІР°СЏ trustcache РїРѕРїС‹С‚РєР° СЃС‚Р°СЂС‚РѕРІР°Р»Р° СЃ С‡РёСЃС‚РѕРіРѕ Р±СѓС„РµСЂР°.

---

## Р‘Р°Рі #195: `bootstrap_set_procursus_url()` РїСЂРёРЅРёРјР°Р» malformed non-HTTP URL override

**РЎРёРјРїС‚РѕРј:** caller РјРѕРі РїРµСЂРµРґР°С‚СЊ РЅРµРїСѓСЃС‚СѓСЋ, РЅРѕ Р·Р°РІРµРґРѕРјРѕ РЅРµРІР°Р»РёРґРЅСѓСЋ СЃС‚СЂРѕРєСѓ РІСЂРѕРґРµ Р»РѕРєР°Р»СЊРЅРѕРіРѕ path/garbage Р±РµР· `http(s)://`, РїРѕСЃР»Рµ С‡РµРіРѕ bootstrap download path РїР°РґР°Р» СѓР¶Рµ РІ networking helper РґР°Р»РµРєРѕ РѕС‚ СЂРµР°Р»СЊРЅРѕР№ РїСЂРёС‡РёРЅС‹ РєРѕРЅС„РёРіСѓСЂР°С†РёРё.  
**Root cause:** setter РїСЂРѕРІРµСЂСЏР» С‚РѕР»СЊРєРѕ `NULL`/empty input, РЅРѕ РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» Р±Р°Р·РѕРІС‹Р№ URL format/scheme.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** Procursus override С‚РµРїРµСЂСЊ РїСЂРёРЅРёРјР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РґР»СЏ `http://`/`https://`; РёРЅР°С‡Рµ РєРѕРЅС„РёРі РѕС‚РєР°С‚С‹РІР°РµС‚СЃСЏ Рє default URL.

---

## Р‘Р°Рі #196: `bootstrap_set_sileo_url()` РїСЂРёРЅРёРјР°Р» malformed non-HTTP URL override

**РЎРёРјРїС‚РѕРј:** Sileo download retries РјРѕРіР»Рё РёСЃРїРѕР»СЊР·РѕРІР°С‚СЊ СЃС‚СЂРѕРєСѓ Р±РµР· РІР°Р»РёРґРЅРѕР№ URL scheme, С‡С‚Рѕ РѕСЃС‚Р°РІР»СЏР»Рѕ install path poisoned Рё РґР°РІР°Р»Рѕ РїРѕР·РґРЅРёР№ failure РІРјРµСЃС‚Рѕ СЂР°РЅРЅРµРіРѕ config reject.  
**Root cause:** setter РІР°Р»РёРґРёСЂРѕРІР°Р» С‚РѕР»СЊРєРѕ РїСѓСЃС‚РѕР№ pointer/string, РЅРѕ РЅРµ Р±Р°Р·РѕРІСѓСЋ РєРѕСЂСЂРµРєС‚РЅРѕСЃС‚СЊ URL scheme.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** Sileo override С‚РµРїРµСЂСЊ С‚Р°РєР¶Рµ С‚СЂРµР±СѓРµС‚ `http://`/`https://`, РёРЅР°С‡Рµ Р±РµР·РѕРїР°СЃРЅРѕ РІРѕР·РІСЂР°С‰Р°РµС‚СЃСЏ default URL.

---

## Р‘Р°Рі #197: `download_file()` РЅРµ РІР°Р»РёРґРёСЂРѕРІР°Р» malformed URL РїРµСЂРµРґ `NSURLSession` fallback

**РЎРёРјРїС‚РѕРј:** РїСЂРё РЅРµРІР°Р»РёРґРЅРѕРј URL helper РґРѕС…РѕРґРёР» РґРѕ `NSURL URLWithString()` Рё РјРѕРі РїСЂРѕРґРѕР»Р¶Р°С‚СЊ fallback path СЃ `nil` `NSURL`, С‡С‚Рѕ РјР°СЃРєРёСЂРѕРІР°Р»Рѕ РїСЂРёС‡РёРЅСѓ Рё РґРµР»Р°Р»Рѕ networking failure РјРµРЅРµРµ РїСЂРµРґСЃРєР°Р·СѓРµРјС‹Рј.  
**Root cause:** `download_file()` СЃСЂР°Р·Сѓ РїРµСЂРµС…РѕРґРёР» Рє curl/wget/NSURLSession flow Р±РµР· СЂР°РЅРЅРµР№ РїСЂРѕРІРµСЂРєРё URL scheme Рё СЂРµР·СѓР»СЊС‚Р°С‚Р° `NSURL` conversion.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** helper С‚РµРїРµСЂСЊ Р·Р°СЂР°РЅРµРµ РІР°Р»РёРґРёСЂСѓРµС‚ `url`/`dest` Рё cleanly aborts, РµСЃР»Рё `NSURL` РЅРµ СЃРѕР·РґР°С‘С‚СЃСЏ.

---

## Р‘Р°Рі #198: РїСЂРёР»РѕР¶РµРЅРёРµ РЅРµ РїРѕРєР°Р·С‹РІР°Р»Рѕ РїРѕР»РЅС‹Р№ live log РІС‹РїРѕР»РЅРµРЅРёСЏ РІ UI

**РЎРёРјРїС‚РѕРј:** РїРѕР»СЊР·РѕРІР°С‚РµР»СЊ РІРёРґРµР» С‚РѕР»СЊРєРѕ СЃС‚Р°СЂС‚РѕРІС‹Рµ СЃС‚СЂРѕРєРё Рё С‡Р°СЃС‚СЊ СЂР°РЅРЅРёС… СЃРѕРѕР±С‰РµРЅРёР№, Р° РѕСЃРЅРѕРІРЅРѕР№ runtime log РёР· `jailbreak_full()`/`bootstrap`/`trustcache` СѓС…РѕРґРёР» РІ С„Р°Р№Р» Рё `NSLog`, РЅРѕ РЅРµ РІ `UITextView` РїСЂРёР»РѕР¶РµРЅРёСЏ.  
**Root cause:** app РІС‹СЃС‚Р°РІР»СЏР» `ds_set_log_callback(ui_log_callback)`, РЅРѕ `jailbreak_full()` Р·Р°С‚РµРј РїРµСЂРµРЅР°Р·РЅР°С‡Р°Р» module callbacks РЅР° `exploit_log`, РєРѕС‚РѕСЂС‹Р№ РЅРµ С„РѕСЂРІР°СЂРґРёР» СЃРѕРѕР±С‰РµРЅРёСЏ РѕР±СЂР°С‚РЅРѕ РІ UI.  
**Р¤Р°Р№Р»:** `app/main.m`, `darksword_exploit.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅ РѕС‚РґРµР»СЊРЅС‹Р№ frontend log bridge `exploit_set_ui_log_callback()`, Р° `exploit_log()` С‚РµРїРµСЂСЊ С„РѕСЂРІР°СЂРґРёС‚ РІСЃРµ module messages РІ UI callback.

---

## Р‘Р°Рі #199: `kfs.m` РЅРµ СЃРѕР±РёСЂР°Р»СЃСЏ РёР·-Р·Р° РёСЃРїРѕР»СЊР·РѕРІР°РЅРёСЏ `g_our_proc` РґРѕ РѕР±СЉСЏРІР»РµРЅРёСЏ

**РЎРёРјРїС‚РѕРј:** РїРѕР»РЅРѕС†РµРЅРЅР°СЏ WSL-СЃР±РѕСЂРєР° РїР°РґР°Р»Р° РЅР° compile stage РІ `get_our_task()` СЃ `use of undeclared identifier 'g_our_proc'`, РїРѕСЌС‚РѕРјСѓ IPA РЅРµР»СЊР·СЏ Р±С‹Р»Рѕ РїРµСЂРµСЃРѕР±СЂР°С‚СЊ РїРѕСЃР»Рµ С„РёРєСЃРѕРІ.  
**Root cause:** cached proc globals Р±С‹Р»Рё РѕР±СЉСЏРІР»РµРЅС‹ РЅРёР¶Рµ РїРѕ С„Р°Р№Р»Сѓ, С…РѕС‚СЏ `get_our_task()` СѓР¶Рµ РёСЃРїРѕР»СЊР·РѕРІР°Р» `g_our_proc`. Editor diagnostics СЌС‚Рѕ РЅРµ Р»РѕРІРёР»Рё, РЅРѕ clang РЅР° СЂРµР°Р»СЊРЅРѕР№ СЃР±РѕСЂРєРµ Р»РѕРјР°Р»СЃСЏ.  
**Р¤Р°Р№Р»:** `kfs.m`  
**Fix:** РѕР±СЉСЏРІР»РµРЅРёСЏ `g_launchd_proc`/`g_our_proc` РїРѕРґРЅСЏС‚С‹ РІС‹С€Рµ РїРµСЂРІРѕРіРѕ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёСЏ.

---

## Р‘Р°Рі #200: `bootstrap.m` РїРµСЂРµСЃС‚Р°Р» СЃРѕР±РёСЂР°С‚СЊСЃСЏ РёР·-Р·Р° РїРѕСЂСЏРґРєР° РѕР±СЉСЏРІР»РµРЅРёСЏ `is_http_url_string()`

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ РґРѕР±Р°РІР»РµРЅРёСЏ URL validation СЂРµР°Р»СЊРЅР°СЏ clang-СЃР±РѕСЂРєР° РїР°РґР°Р»Р° РЅР° `implicit declaration of function 'is_http_url_string'`, С‡С‚Рѕ СЃРЅРѕРІР° Р±Р»РѕРєРёСЂРѕРІР°Р»Рѕ РІС‹РїСѓСЃРє IPA.  
**Root cause:** helper РёСЃРїРѕР»СЊР·РѕРІР°Р»СЃСЏ РІ config setters СЂР°РЅСЊС€Рµ СЃРІРѕРµРіРѕ `static` РѕРїСЂРµРґРµР»РµРЅРёСЏ, Р° C99 С‚СЂР°РєС‚РѕРІР°Р» СЌС‚Рѕ РєР°Рє error.  
**Р¤Р°Р№Р»:** `bootstrap.m`  
**Fix:** РґРѕР±Р°РІР»РµРЅРѕ РїСЂРµРґРІР°СЂРёС‚РµР»СЊРЅРѕРµ РѕР±СЉСЏРІР»РµРЅРёРµ helper РїРµСЂРµРґ РїРµСЂРІС‹РјРё РІС‹Р·РѕРІР°РјРё.

---

## Р‘Р°Рі #201: `spray_socket()` РЅРµРІРµСЂРЅРѕ РІС‹Р·С‹РІР°Р» `proc_pidfdinfo` РІРѕ РІСЂРµРјСЏ socket spray

**РЎРёРјРїС‚РѕРј:** РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ exploit Р·Р°СЃС‚СЂРµРІР°Р» РЅР° СЃР°РјРѕРј РЅР°С‡Р°Р»Рµ spray stage СЃ РїРѕРІС‚РѕСЂСЏСЋС‰РёРјРёСЃСЏ `spray_socket: proc_info syscall failed`, `failed to spray sockets: 0x0` Рё `socket spray produced 0 sockets, retrying ds...`.  
**Root cause:** `spray_socket()` РґРµР»Р°Р» РґРІРµ РѕС€РёР±РєРё СЃСЂР°Р·Сѓ: РїРµСЂРµРґР°РІР°Р» РІ `proc_info` fileport name РІРјРµСЃС‚Рѕ live file descriptor Рё С‚СЂР°РєС‚РѕРІР°Р» Р»СЋР±РѕР№ РЅРµРЅСѓР»РµРІРѕР№ return РєР°Рє РѕС€РёР±РєСѓ, С…РѕС‚СЏ `proc_pidfdinfo` РІРѕР·РІСЂР°С‰Р°РµС‚ РїРѕР»РѕР¶РёС‚РµР»СЊРЅС‹Р№ СЂР°Р·РјРµСЂ Р±СѓС„РµСЂР° РЅР° success. Р’ РёС‚РѕРіРµ РґР°Р¶Рµ СѓСЃРїРµС€РЅС‹Р№ query СЃС‡РёС‚Р°Р»СЃСЏ failure Рё spray РЅРёРєРѕРіРґР° РЅРµ Р·Р°РїРёСЃС‹РІР°Р» РЅРё РѕРґРЅРѕРіРѕ `inp_gencnt`.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** `proc_info` С‚РµРїРµСЂСЊ РІС‹Р·С‹РІР°РµС‚СЃСЏ РЅР° РѕС‚РєСЂС‹С‚РѕРј `fd` РґРѕ `fileport_makeport()`, success-path РїСЂРѕРІРµСЂСЏРµС‚СЃСЏ РєР°Рє `ret >= 0`, short reply РѕС‚РґРµР»СЊРЅРѕ РІР°Р»РёРґРёСЂСѓРµС‚СЃСЏ, Р° failure log С‚РµРїРµСЂСЊ РїРµС‡Р°С‚Р°РµС‚ `errno`.

---

## Р‘Р°Рі #202: `spray_socket()` РІС‹Р·С‹РІР°Р» `proc_info` СЃ selector РѕС‚ fileport, С…РѕС‚СЏ СѓР¶Рµ СЂР°Р±РѕС‚Р°Р» СЃ live fd

**РЎРёРјРїС‚РѕРј:** РїРѕСЃР»Рµ С„РёРєСЃР° #201 exploit РґРµР№СЃС‚РІРёС‚РµР»СЊРЅРѕ РґРѕС…РѕРґРёР» РґРѕ РЅРѕРІРѕРіРѕ РєРѕРґР°, РЅРѕ РєР°Р¶РґС‹Р№ СЃРІРµР¶РёР№ Р·Р°РїСѓСЃРє РІСЃС‘ СЂР°РІРЅРѕ РїР°РґР°Р» РЅР° РїРµСЂРІРѕРј socket spray СЃ `spray_socket: proc_info syscall failed for fd=5 errno=22 (Invalid argument)`.  
**Root cause:** РїСЂРё РїРµСЂРµРІРѕРґРµ `spray_socket()` РЅР° live file descriptor Р±С‹Р» РёСЃРїСЂР°РІР»РµРЅ Р°СЂРіСѓРјРµРЅС‚ `arg`, РЅРѕ РЅРµ `callnum`: syscall `336` РІСЃС‘ РµС‰С‘ РІС‹Р·С‹РІР°Р»СЃСЏ РєР°Рє `PROC_INFO_CALL_PIDFILEPORTINFO` (`6`), С…РѕС‚СЏ РґР»СЏ РѕР±С‹С‡РЅРѕРіРѕ `fd` РЅСѓР¶РµРЅ `PROC_INFO_CALL_PIDFDINFO` (`3`). РЇРґСЂРѕ РїРѕР»СѓС‡Р°Р»Рѕ РЅРµСЃРѕРІРјРµСЃС‚РёРјСѓСЋ РєРѕРјР±РёРЅР°С†РёСЋ selector + arg Рё РІРѕР·РІСЂР°С‰Р°Р»Рѕ `EINVAL`.  
**Р¤Р°Р№Р»:** `darksword_core.m`  
**Fix:** selector `proc_info` РїРµСЂРµРєР»СЋС‡С‘РЅ СЃ `6` РЅР° `3`, С‚Р°Рє С‡С‚Рѕ live `fd` С‚РµРїРµСЂСЊ СЂРµР°Р»СЊРЅРѕ РїСЂРѕС…РѕРґРёС‚ С‡РµСЂРµР· `proc_pidfdinfo` / `PROC_PIDFDSOCKETINFO` path.

---

**Р§С‚Рѕ РґРµР»Р°РµС‚:** РС‰РµС‚ Рё РїР°С‚С‡РёС‚ 4 kernel variables:

| Variable | Р—РЅР°С‡РµРЅРёРµ | Р­С„С„РµРєС‚ |
|----------|---------|--------|
| amfi_get_out_of_my_way | 1 | AMFI РїСЂРѕРїСѓСЃРєР°РµС‚ РІСЃРµ РїСЂРѕРІРµСЂРєРё |
| cs_enforcement_disable | 1 | Kernel РЅРµ РїСЂРѕРІРµСЂСЏРµС‚ code signatures |
| proc_enforce | 0 | РќРµ РїСЂРёРјРµРЅСЏРµС‚ process policy |
| vnode_enforce | 0 | РќРµ РїСЂРёРјРµРЅСЏРµС‚ vnode MAC policy |

**РњРµС‚РѕРґ РїРѕРёСЃРєР°:**
1. `find_kernel_string()` вЂ” РёС‰РµС‚ РёРјСЏ РїРµСЂРµРјРµРЅРЅРѕР№ РІ __cstring
2. `find_variable_near_string_ref()` вЂ” РЅР°С…РѕРґРёС‚ sysctl_oid в†’ oid_arg1 = addr РїРµСЂРµРјРµРЅРЅРѕР№
3. `kw32(addr, value)` вЂ” СЃС‚Р°РІРёС‚ РЅСѓР¶РЅРѕРµ Р·РЅР°С‡РµРЅРёРµ

---

## Feature #17: PPL-aware platformize

**Р¤Р°Р№Р»:** `postexploit.m`, `postexploit_platformize_proc()`  
**Р§С‚Рѕ Р±С‹Р»Рѕ:** РџСЂСЏРјРѕР№ kw32 РІ csflags вЂ” panic РµСЃР»Рё PPL Р·Р°С‰РёС‰Р°РµС‚  
**Р§С‚Рѕ СЃС‚Р°Р»Рѕ:**
1. РџРѕРїС‹С‚РєР° kw32 РІ procв†’csflags
2. Р•СЃР»Рё РЅРµ Р·Р°РїРёСЃР°Р»РѕСЃСЊ в†’ scan task struct РЅР° secondary csflags location
3. Fallback Рє AMFI global bypass (feature #16) вЂ” РµСЃР»Рё РіР»РѕР±Р°Р»СЊРЅРѕ РѕС‚РєР»СЋС‡РµРЅР° CS, platformize РЅРµ РєСЂРёС‚РёС‡РµРЅ

---

## Feature #18: CS_DEBUGGED РІРѕ РІСЃРµС… csflags patches

**Р¤Р°Р№Р»:** `postexploit.m`  
**Р§С‚Рѕ Р±С‹Р»Рѕ:** `csflags |= CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW`  
**Р§С‚Рѕ СЃС‚Р°Р»Рѕ:** `csflags |= CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED`

CS_DEBUGGED (0x800) вЂ” РјР°СЂРєРёСЂСѓРµС‚ РїСЂРѕС†РµСЃСЃ РєР°Рє "РѕС‚Р»Р°Р¶РёРІР°РµРјС‹Р№", С‡С‚Рѕ РїРѕР·РІРѕР»СЏРµС‚:
- Attach debugger
- Modify memory  
- Bypass some AMFI per-process checks

---

## Timeline

```
РЎРµСЃСЃРёСЏ 1 (2026-03-19):
  в””в”Ђв”Ђ Bugs #1-5 (kernel panics) в†’ zone discovery

РЎРµСЃСЃРёСЏ 2 (2026-03-21):
  в””в”Ђв”Ђ Bugs #6-10 (offsets) в†’ kernelcache analysis

РЎРµСЃСЃРёСЏ 3 (2026-03-22):
  в””в”Ђв”Ђ Bugs #11-14 (kfs) + Features #15-18 в†’ XNU source verification

РЎРµСЃСЃРёСЏ 4 (2026-03-30):
  в””в”Ђв”Ђ Deep audit в†’ 12 new bug fixes:
      в”њв”Ђв”Ђ kfs.m: PAC v_parent/v_name fix (#19-21)
      в”њв”Ђв”Ђ postexploit.m:
      в”‚   в”њв”Ђв”Ђ csflags scan step 8в†’4 + remove task scan (#22)
      в”‚   в”њв”Ђв”Ђ sandbox fallback return -1 fix (#23)
      в”‚   в”њв”Ђв”Ђ AMFI search in kext __cstring + 32KB header (#24)
      в”‚   в”њв”Ђв”Ђ ucred GID read-back verification (#25)
      в”‚   в””в”Ђв”Ђ page-boundary string search overlap (#26)
      в””в”Ђв”Ђ bootstrap.m:
          в”њв”Ђв”Ђ sandbox/AMFI prerequisite checks
          в”њв”Ђв”Ђ mkdir error handling
          в”њв”Ђв”Ђ NSURLSession with 30s timeout
          в”њв”Ђв”Ђ critical error early exit
          в”њв”Ђв”Ђ PATH env for child processes
          в””в”Ђв”Ђ trust after dpkg install

РЎРµСЃСЃРёСЏ 5 (2026-03-30):
  в””в”Ђв”Ђ Systematic audit of ALL modules в†’ 27 new fixes:
      в”њв”Ђв”Ђ kfs.m (10 PAC fixes):
      в”‚   в”њв”Ђв”Ђ verify_ncache: kr64в†’kreadptr for nc_vp, nc_name (#27-28)
      в”‚   в”њв”Ђв”Ђ nc_lookup_child: kreadptr for OV_NCCHILDREN, nc_name, nc_vp, ONC_CHILD_NEXT (#29-32)
      в”‚   в”њв”Ђв”Ђ kfs_listdir: kreadptr for OV_NCCHILDREN, nc_name, nc_vp, ONC_CHILD_NEXT (#33-36)
      в”‚   в”њв”Ђв”Ђ vnode_file_size: kreadptr for OV_UBCINFO (#37)
      в”‚   в”њв”Ђв”Ђ kfs_init: return -1 on failure instead of always 0 (#38)
      в”‚   в””в”Ђв”Ђ kfs_listdir: realloc NULL check (#39)
      в”њв”Ђв”Ђ trustcache.m (7 fixes):
      в”‚   в”њв”Ђв”Ђ KASLR slide: seg->vmaddr + KSLIDE for all segments (#40) в…CRITICAL
      в”‚   в”њв”Ђв”Ђ SuperBlob: count from +8 not +4, offset from +4 in BlobIndex (#41) в…CRITICAL
      в”‚   в”њв”Ђв”Ђ Entry sorting: insertion sort by cdhash for binary search (#42) в…CRITICAL
      в”‚   в”њв”Ђв”Ђ Header buffer: 4096в†’32768 for fileset KC (#43)
      в”‚   в”њв”Ђв”Ђ FAT binary: prefer arm64e (subtype=2) over arm64 (#44)
      в”‚   в”њв”Ђв”Ђ malloc/fread checks in tc_trust_file (#45)
      в”‚   в””в”Ђв”Ђ tc_add_cdhash: warn on inject_entries failure (#46)
      в”њв”Ђв”Ђ darksword_core.m (6 PAC + safety fixes):
      в”‚   в”њв”Ђв”Ђ Added pac_strip() function to file (#47)
      в”‚   в”њв”Ђв”Ђ pac_strip for control_socket_pcb, pcbinfo, ipi_zone, zv_name (#48-51)
      в”‚   в”њв”Ђв”Ђ pac_strip for inp_list_next_pointer from raw physical read (#52)
      в”‚   в”њв”Ђв”Ђ kernel_base search: bounded loop + 0xfffffff000000000 guard (#53)
      в”‚   в””в”Ђв”Ђ target_inp_gencnt_count bounds check (#54)
      в””в”Ђв”Ђ darksword_exploit.m (4 chain fixes):
          в”њв”Ђв”Ђ postexploit_run() error check: >0 в†’ !=0 (#55)
          в”њв”Ђв”Ђ kbase != 0 check before ds_kread32 (#56)
          в”њв”Ђв”Ђ magic == 0xFEEDFACF validation (#57)
          в””в”Ђв”Ђ VFS race retry loop (5 attempts) (#58)

РЎРµСЃСЃРёСЏ 5 РїСЂРѕРґРѕР»Р¶РµРЅРёРµ (2026-03-30):
  в””в”Ђв”Ђ Deep audit СѓС‚РёР»РёС‚, bootstrap, UI в†’ 17 new fixes:
      в”њв”Ђв”Ђ utils.m (2 safety fixes):
      в”‚   в”њв”Ђв”Ђ sysctlbyname return check + iOS 17.3.1 fallback (#59)
      в”‚   в””в”Ђв”Ђ ourtask() Strategy 3: return 0 instead of garbage ptr (#60)
      в”њв”Ђв”Ђ bootstrap.m (10 critical + hardening fixes):
      в”‚   в”њв”Ђв”Ђ tar.zst в†’ tar.xz (iOS has NO zstd!) (#61) в…CRITICAL
      в”‚   в”њв”Ђв”Ђ Disk space check: statfs /var, 400MB min (#62)
      в”‚   в”њв”Ђв”Ђ Re-entrancy guard: g_running flag (#63)
      в”‚   в”њв”Ђв”Ђ errors counter: increments on TC + Sileo fail (#64)
      в”‚   в”њв”Ђв”Ђ uicache after Sileo install (#65) в…HIGH
      в”‚   в”њв”Ђв”Ђ SSH host key generation (rsa + ed25519) (#66)
      в”‚   в”њв”Ђв”Ђ sshd launch with config (#67)
      в”‚   в”њв”Ђв”Ђ Cleanup temp files after install (#68)
      в”‚   в”њв”Ђв”Ђ dpkg configure return value check (#69)
      в”‚   в””в”Ђв”Ђ Added sys/mount.h for statfs (#70)
      в””в”Ђв”Ђ app/main.m (5 UI + safety fixes):
          в”њв”Ђв”Ђ Signal handler: async-signal-safe write() (#71) в…HIGH
          в”њв”Ђв”Ђ O(nВІ) в†’ O(1) log append via textStorage (#72)
          в”њв”Ђв”Ђ Weak g_vc strongify pattern (#73)
          в”њв”Ђв”Ђ beginBackgroundTaskWithExpirationHandler (#74) в…HIGH
          в””в”Ђв”Ђ Remove duplicate ds_install_panic_resilient_logging (#75)

РЎРµСЃСЃРёСЏ 5 С„РёРЅР°Р» (2026-03-30):
  в””в”Ђв”Ђ Cross-module exploit chain audit в†’ 5 critical/high fixes:
      в”њв”Ђв”Ђ darksword_core.m (3 exploit chain fixes):
      в”‚   в”њв”Ђв”Ђ ds_run() state reset between retries (#76) в…CRITICAL
      в”‚   в”‚   вЂ” zeroes control_socket/rw_socket/pcb/kernel_base/zone_map before pe()
      в”‚   в”‚   вЂ” prevents double-corruption of kernel PCBs on retry
      в”‚   в”њв”Ђв”Ђ pe() panic guard cleanup (#77) в…HIGH
      в”‚   в”‚   вЂ” all 6 PANIC GUARD return -1 paths now zero *_pcb
      в”‚   в”‚   вЂ” prevents stale pointers from leaking to next retry
      в”‚   в””в”Ђв”Ђ Note: old corrupted sockets intentionally NOT closed
      в”‚       (closing socket with corrupted icmp6filt в†’ kernel panic)
      в”њв”Ђв”Ђ postexploit.m (2 logic fixes):
      в”‚   в”њв”Ђв”Ђ postexploit_patch_credentials: syscall verification (#78) в…CRITICAL
      в”‚   в”‚   вЂ” g_is_root = true ONLY if getuid()==0 && geteuid()==0
      в”‚   в”‚   вЂ” detects PPL copy-on-write where kernel read shows 0
      в”‚   в”‚     but syscall still sees original uid
      в”‚   в”њв”Ђв”Ђ postexploit_root_proc: GID retry verification (#79)
      в”‚   в”‚   вЂ” after retry writes, re-reads and logs if still failed
      в”‚   в””в”Ђв”Ђ postexploit_run: sandbox skip if not root (#80) в…HIGH
      в”‚       вЂ” skips sandbox escape if credentials failed
      в”‚       вЂ” prevents discover_ucred_offset finding wrong ucred
      в”‚         and writing NULL to arbitrary kernel memory
      в””в”Ђв”Ђ build_sign_install.sh (1 build fix):
          в””в”Ђв”Ђ Entitlements merge from app/entitlements.plist (#81)
              вЂ” adds extended-virtual-addressing, increased-memory-limit
              вЂ” merged from app/entitlements.plist into provisioning profile entitlements

РЎРµСЃСЃРёСЏ 6 (2026-03-31):
  в””в”Ђв”Ђ Р“Р»СѓР±РѕРєРёР№ Р°СѓРґРёС‚ вЂ” 2 РЅРѕРІС‹С… Р±Р°РіР°:
      в”њв”Ђв”Ђ postexploit.m (1 CRITICAL fix, 6 РјРµСЃС‚):
      в”‚   в””в”Ђв”Ђ AMFI patching: KASLR slide РЅРµ РїСЂРёРјРµРЅСЏР»СЃСЏ Рє vmaddr (#82) в…в…в…CRITICAL
      в”‚       вЂ” cstring_addr = sect->addr в†’ sect->addr + kslide
      в”‚       вЂ” data_addrs[n] = seg->vmaddr в†’ seg->vmaddr + kslide
      в”‚       вЂ” amfi_kext_vmaddr = fe_vmaddr в†’ fe_vmaddr + kslide
      в”‚       вЂ” AMFI kext inner __cstring: asect->addr в†’ asect->addr + kslide
      в”‚       вЂ” AMFI kext inner __DATA: aseg->vmaddr в†’ aseg->vmaddr + kslide
      в”‚       вЂ” Р‘РµР· СЌС‚РѕРіРѕ С„РёРєСЃР°: kernel data abort РЅР° unmapped UNSLID address в†’ PANIC
      в”‚       вЂ” trustcache.m РґРµР»Р°Р» СЌС‚Рѕ РїСЂР°РІРёР»СЊРЅРѕ, postexploit.m РќР•Рў
      в””в”Ђв”Ђ bootstrap.m (1 fix):
          в””в”Ђв”Ђ apt sources URI: /2000 СѓРґР°Р»С‘РЅ РёР· URIs (#83)
              вЂ” URI Р±С‹Р»Рѕ: https://apt.procurs.us/2000
              вЂ” URI СЃС‚Р°Р»Рѕ: https://apt.procurs.us/
              вЂ” /2000 СѓР¶Рµ РІРєР»СЋС‡С‘РЅ РІ Suites: iphoneos-arm64e/2000
              вЂ” РґРІРѕР№РЅРѕР№ /2000 РґРµР»Р°Р» apt РЅРµСЂР°Р±РѕС‚РѕСЃРїРѕСЃРѕР±РЅС‹Рј

    РЎРµСЃСЃРёСЏ 7 (2026-03-30):
      в””в”Ђв”Ђ РџСЂРѕРґРѕР»Р¶РµРЅРёРµ РѕС„Р»Р°Р№РЅ-Р°СѓРґРёС‚Р° вЂ” 10 РЅРѕРІС‹С… С„РёРєСЃРѕРІ:
        в”њв”Ђв”Ђ kfs.m (3 fixes):
        в”‚   в”њв”Ђв”Ђ is_kptr canonical check (#84) в…в…в…CRITICAL
        в”‚   в”‚   вЂ” Р±С‹Р»Рѕ: ((p >> 40) & 0xFF) == 0xFE
        в”‚   в”‚   вЂ” СЃС‚Р°Р»Рѕ: top 16 bits == 0xffff after PAC strip
        в”‚   в”‚   вЂ” РёРЅР°С‡Рµ rootvnode/ncache СЃС‚СЂРѕРєРё РѕС‚Р±СЂР°СЃС‹РІР°Р»РёСЃСЊ РєР°Рє "РЅРµ kernel ptr"
        в”‚   в”њв”Ђв”Ђ kfs_overwrite_file_bytes MAP_PRIVATE в†’ MAP_SHARED (#86) в…CRITICAL
        в”‚   в”‚   вЂ” Р·Р°РїРёСЃСЊ РІ private mmap РЅРµ РїРѕРїР°РґР°Р»Р° РІ С„Р°Р№Р»
        в”‚   в””в”Ђв”Ђ kfs_init state reset on retry (#90)
        в”‚       вЂ” СЃР±СЂРѕСЃ g_ready/g_ncache_ok/g_rootvnode/g_launchd_proc/g_our_proc
        в”‚       вЂ” РїСЂРµРґРѕС‚РІСЂР°С‰Р°РµС‚ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёРµ stale rootvnode РїРѕСЃР»Рµ РЅРµСѓРґР°С‡РЅРѕРіРѕ re-init
        в”њв”Ђв”Ђ trustcache.m (2 fixes):
        в”‚   в”њв”Ђв”Ђ is_heap_ptr upper-range typo (#85)
        в”‚   в”‚   вЂ” РЅРµРІРµСЂРЅР°СЏ hex-РєРѕРЅСЃС‚Р°РЅС‚Р° СЃСЂРµР·Р°Р»Р° С‡Р°СЃС‚СЊ РґРѕРїСѓСЃС‚РёРјРѕРіРѕ heap range
        в”‚   в””в”Ђв”Ђ tc_init state reset (#92)
        в”‚       вЂ” СЃР±СЂРѕСЃ g_ready/g_tc_head/g_injected РЅР° РєР°Р¶РґС‹Р№ РЅРѕРІС‹Р№ scan
        в”‚       вЂ” РїСЂРµРґРѕС‚РІСЂР°С‰Р°РµС‚ Р»РѕР¶РЅС‹Р№ success СЃРѕ stale head pointer
        в”њв”Ђв”Ђ bootstrap.m (4 fixes):
        в”‚   в”њв”Ђв”Ђ g_running sticky after early fail (#87)
        в”‚   в”‚   вЂ” bootstrap Р±РѕР»СЊС€Рµ РЅРµ Р·Р°Р»РёРїР°РµС‚ РІ "already running"
        в”‚   в”њв”Ђв”Ђ g_bootstrap_tar .zst path stickiness (#88)
        в”‚   в”‚   вЂ” РЅРѕРІР°СЏ РїРѕРїС‹С‚РєР° Р±РѕР»СЊС€Рµ РЅРµ РїСѓС‚Р°РµС‚ .xz payload СЃ .zst filename
        в”‚   в”њв”Ђв”Ђ NSURLSession false-success on timeout/write failure (#89)
        в”‚   в”‚   вЂ” С‚РµРїРµСЂСЊ timeout Рё writeToFile failure РєРѕСЂСЂРµРєС‚РЅРѕ РІР°Р»СЏС‚ download
        в”‚   в””в”Ђв”Ђ g_installed stale true on critical early return (#93)
        в”‚       вЂ” UI/summary Р±РѕР»СЊС€Рµ РЅРµ СЃРѕРѕР±С‰Р°СЋС‚ Р»РѕР¶РЅС‹Р№ fully installed status
        в””в”Ђв”Ђ postexploit.m (1 fix):
          в””в”Ђв”Ђ postexploit_run state reset (#91) в…CRITICAL
            вЂ” СЃР±СЂРѕСЃ g_is_root/g_is_unsandboxed/g_is_platformized/g_amfi_patched/g_cs_disabled
            вЂ” РїСЂРµРґРѕС‚РІСЂР°С‰Р°РµС‚ РѕРїР°СЃРЅС‹Р№ sandbox step РЅР° retry СЃРѕ stale g_is_root=true

      РЎРµСЃСЃРёСЏ 8 (2026-03-30):
        в””в”Ђв”Ђ Trustcache false-success audit вЂ” 3 fixes:
          в”њв”Ђв”Ђ tc_add_cdhash auto-flush data loss (#94)
          в”‚   вЂ” РїСЂРё failed inject_entries() Р±СѓС„РµСЂ Р±РѕР»СЊС€Рµ РЅРµ РѕР±РЅСѓР»СЏРµС‚СЃСЏ silently
          в”‚   вЂ” С‚РµРїРµСЂСЊ С„СѓРЅРєС†РёСЏ РІРѕР·РІСЂР°С‰Р°РµС‚ -1 Рё СЃРѕС…СЂР°РЅСЏРµС‚ pending state РґР»СЏ РґРёР°РіРЅРѕСЃС‚РёРєРё
          в”њв”Ђв”Ђ tc_trust_file / tc_trust_directory Р±РµР· tc_init (#95)
          в”‚   вЂ” СЂР°РЅСЊС€Рµ РєРѕРґ РјРѕРі СЃС‡РёС‚Р°С‚СЊ С„Р°Р№Р»С‹ "trusted" РґР°Р¶Рµ РїСЂРё g_ready=false
          в”‚   вЂ” С‚РµРїРµСЂСЊ СЂР°РЅРЅРёР№ fail РµСЃР»Рё trust cache РЅРµ РіРѕС‚РѕРІ
          в””в”Ђв”Ђ tc_trust_directory final flush ignored result (#96)
            вЂ” inject_entries() РІ РєРѕРЅС†Рµ РґРёСЂРµРєС‚РѕСЂРёРё С‚РµРїРµСЂСЊ РѕР±СЏР·Р°С‚РµР»РµРЅ
            вЂ” count Р±РѕР»СЊС€Рµ РЅРµ РІРѕР·РІСЂР°С‰Р°РµС‚СЃСЏ РєР°Рє success РїСЂРё failed injection

        РЎРµСЃСЃРёСЏ 9 (2026-03-30):
          в””в”Ђв”Ђ Utils/Core offline audit вЂ” 3 fixes:
            в”њв”Ђв”Ђ utils.m (1 fix):
            в”‚   в””в”Ђв”Ђ procbyname() heap-vs-kptr validation (#97)
            в”‚       вЂ” proc list walkers С‚РµРїРµСЂСЊ РёСЃРїРѕР»СЊР·СѓСЋС‚ is_heap_ptr, РЅРµ is_kptr
            в”‚       вЂ” РёРЅР°С‡Рµ metadata/text pointers РјРѕРіР»Рё РїСЂРѕС…РѕРґРёС‚СЊ РєР°Рє "valid proc"
            в”‚       вЂ” Р·Р°С‚СЂР°РіРёРІР°РµС‚ launchd lookup РІ kfs_init()
            в””в”Ђв”Ђ darksword_core.m (2 fixes):
              в”њв”Ђв”Ђ initialize_physical_read_write unchecked failure (#98) в…HIGH
              в”‚   вЂ” create_physically_contiguous_mapping С‚РµРїРµСЂСЊ bool
              в”‚   вЂ” null/failed IOSurface path Р±РѕР»СЊС€Рµ РЅРµ РІРµРґС‘С‚ Рє uwrite64(0 + i)
              в””в”Ђв”Ђ create_surface_with_address NULL IOSurface (#99)
                вЂ” Р±РѕР»СЊС€Рµ РЅРµС‚ IOSurfacePrefetchPages(NULL)
                вЂ” surface_mlock РѕСЃРІРѕР±РѕР¶РґР°РµС‚ surf РїСЂРё overflow MAX_MLOCK

          РЎРµСЃСЃРёСЏ 10 (2026-03-30):
            в””в”Ђв”Ђ Core exploit guard audit вЂ” 2 fixes:
              в”њв”Ђв”Ђ pe_v1/pe_v2 ignored phys-map init failure (#100)
              в”‚   вЂ” callers initialize_physical_read_write() С‚РµРїРµСЂСЊ bail out cleanly
              в”‚   вЂ” РїСЂРµРґРѕС‚РІСЂР°С‰Р°РµС‚ РїСЂРѕРґРѕР»Р¶РµРЅРёРµ exploit path СЃ РЅРµРёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅРЅС‹Рј pc_object/pc_address
              в””в”Ђв”Ђ socket_ports_count underflow indexing (#101)
                вЂ” guard before socket_pcb_ids[socket_ports_count - 1]
                вЂ” spray==0 С‚РµРїРµСЂСЊ retry, Р° РЅРµ OOB read on empty array

            РЎРµСЃСЃРёСЏ 11 (2026-03-30):
              в””в”Ђв”Ђ Retry cleanup audit вЂ” 1 fix:
                в””в”Ђв”Ђ pe_v1 zero-socket retry leaked search mappings (#102)
                  вЂ” РїРµСЂРµРґ continue С‚РµРїРµСЂСЊ deallocate РІСЃРµС… СѓР¶Рµ РІС‹РґРµР»РµРЅРЅС‹С… mappings
                  вЂ” РёРЅР°С‡Рµ repeated zero-spray path СЂР°Р·РґСѓРІР°Р» userspace VM Рё СѓС…СѓРґС€Р°Р» retry stability

            РЎРµСЃСЃРёСЏ 12 (2026-03-30):
              в””в”Ђв”Ђ Core setup hardening вЂ” 2 fixes:
                  в”њв”Ђв”Ђ init_target_file unchecked fd failure (#103)
                  в”‚   вЂ” exploit Р±РѕР»СЊС€Рµ РЅРµ РёРґС‘С‚ РґР°Р»СЊС€Рµ СЃ read_fd/write_fd == -1
                  в”‚   вЂ” pwritev/preadv РЅР° invalid fd С‚РµРїРµСЂСЊ РїСЂРµРґРѕС‚РІСЂР°С‰РµРЅС‹ СЂР°РЅРЅРёРј bail
                  в””в”Ђв”Ђ pe_init unchecked alloc/thread startup (#104)
                      вЂ” РїСЂРѕРІРµСЂСЏСЋС‚СЃСЏ calloc Рё pthread_create
                      вЂ” pe() now aborts cleanly if race infrastructure not started

                РЎРµСЃСЃРёСЏ 13 (2026-03-30):
                  в””в”Ђв”Ђ Socket spray validation вЂ” 1 fix:
                    в””в”Ђв”Ђ spray_socket() accepted invalid ports/gencnt (#105)
                      вЂ” now checks MAX_SOCKET_PORTS, fileport_makeport, proc_info syscall, inp_gencnt != 0
                      вЂ” prevents poisoned spray set and bogus pcb-id comparisons later

                РЎРµСЃСЃРёСЏ 14 (2026-03-30):
                  в””в”Ђв”Ђ Allocation hardening вЂ” 2 fixes:
                      в”њв”Ђв”Ђ pe_v1/pe_v2 unchecked calloc buffers (#106)
                      в”‚   вЂ” read_buffer/write_buffer/search_mappings/wired_mapping_entries now validated
                      в”‚   вЂ” prevents null deref on memory pressure
                      в””в”Ђв”Ђ ds_run unchecked default_file_content alloc (#107)
                          вЂ” exploit now fails cleanly instead of writing random_marker into NULL

                    РЎРµСЃСЃРёСЏ 15 (2026-03-30):
                      в””в”Ђв”Ђ A18 path liveness audit вЂ” 1 fix:
                        в””в”Ђв”Ђ pe_v2 infinite allocation loops (#108)
                          вЂ” wired-page mach_vm_allocate retries are now bounded
                          вЂ” failure no longer spins forever under memory pressure / fragmentation

                    РЎРµСЃСЃРёСЏ 16 (2026-03-30):
                      в””в”Ђв”Ђ Core FD/CF cleanup audit вЂ” 3 fixes:
                          в”њв”Ђв”Ђ create_surface_with_address unchecked CF allocs (#109)
                          в”‚   вЂ” now validates CFDictionaryCreateMutable and both CFNumberCreate calls
                          в”‚   вЂ” prevents CFDictionarySetValue with NULL object
                          в”њв”Ђв”Ђ unchecked fileport_makefd for control/rw sockets (#110)
                          в”‚   вЂ” exploit no longer proceeds with invalid userspace socket fd
                          в”‚   вЂ” avoids getsockopt/set_target path on fd < 0
                          в””в”Ђв”Ђ pe_v2 leaked search mapping on mach_make_memory_entry_64 fail (#111)
                              вЂ” now deallocates search_mapping_address before aborting that retry loop

                        РЎРµСЃСЃРёСЏ 17 (2026-03-30):
                          в””в”Ђв”Ђ Free-thread liveness audit вЂ” 1 fix:
                            в””в”Ђв”Ђ pe() could deadlock on pthread_join after early exploit return (#112) в…HIGH
                              вЂ” free_thread now observes an abort flag in all wait loops
                              вЂ” pe() signals abort before join, so setup failures no longer hang forever

                        РЎРµСЃСЃРёСЏ 18 (2026-03-30):
                          в””в”Ђв”Ђ Retry-state cleanup audit вЂ” 1 fix:
                              в””в”Ђв”Ђ ds_run() left stale spray/IOSurface counters across attempts (#113)
                                  вЂ” resets socket_ports_count, target_inp_gencnt_count, success counters, pc_* state
                                  вЂ” releases stale IOSurface refs in mlock_dict before next run
                                  вЂ” prevents MAX_GENCNT / MAX_MLOCK exhaustion across repeated retries

                        РЎРµСЃСЃРёСЏ 19 (2026-03-30):
                          в””в”Ђв”Ђ Socket-pair bounds audit вЂ” 1 fix:
                              в””в”Ђв”Ђ control_socket_idx + 1 could read past socket_ports[] (#114)
                                  вЂ” added explicit bounds check before selecting rw_socket partner
                                  вЂ” prevents OOB access if control socket is last valid sprayed port

                        РЎРµСЃСЃРёСЏ 20 (2026-03-30):
                          в””в”Ђв”Ђ Core setup hygiene audit вЂ” 3 fixes:
                              в”њв”Ђв”Ђ init_target_file unchecked temp path creation (#115)
                              в”‚   вЂ” `confstr(_CS_DARWIN_USER_TEMP_DIR)` now validated for failure/truncation
                              в”‚   вЂ” prevents `strcat()` on uninitialized/truncated temp path buffers
                              в”њв”Ђв”Ђ create_target_file ignored short fwrite (#116)
                              в”‚   вЂ” target race files now must be fully written or setup aborts
                              в”‚   вЂ” prevents exploit starting with malformed backing files
                              в””в”Ђв”Ђ pe_init path/buffer hygiene (#117)
                                  вЂ” `_NSGetExecutablePath` resize path handled correctly
                                  вЂ” executable basename duplicated safely
                                  вЂ” race-thread arg buffer tracked and freed after join/reset

                            РЎРµСЃСЃРёСЏ 21 (2026-03-30):
                              в””в”Ђв”Ђ Corruption liveness audit вЂ” 1 fix:
                                в””в”Ђв”Ђ unbounded icmp6filter corruption loop (#118)
                                  вЂ” `find_and_corrupt_socket()` no longer spins forever if overwrite never sticks
                                  вЂ” bounded to 256 tries, then returns clean retry failure
```


---

## Р‘Р°Рі #205: kbase+0x93B348 вЂ” РќР• allproc (__DATA_CONST READ-ONLY) (2026-03-31, СЃРµСЃСЃРёСЏ 3)

**РЎРёРјРїС‚РѕРј:** Fix #202 РѕС€РёР±РѕС‡РЅРѕ РґРѕР±Р°РІРёР» `0x93B348` РєР°Рє РїРµСЂРІС‹Р№ РєР°РЅРґРёРґР°С‚ allproc.
`validate_allproc()` РєРѕСЂСЂРµРєС‚РЅРѕ РµРіРѕ РѕС‚РІРµСЂРіР°РµС‚, РЅРѕ С‚СЂР°С‚РёС‚ ~200 kr64-РІС‹Р·РѕРІРѕРІ РІРїСѓСЃС‚СѓСЋ.

**Root cause (РѕС„Р»Р°Р№РЅ-Р°РЅР°Р»РёР· kernelcache 21D61):**
- `kbase+0x93B348` = VA `0xfffffff00793f348` = СЃРµРіРјРµРЅС‚ `__DATA_CONST` (READ-ONLY).
- RAW Р·РЅР°С‡РµРЅРёРµ РІ С„Р°Р№Р»Рµ: `0x80114a6a012e2af8` вЂ” PAC `auth_rebase` pointer.
- Decode: `auth=1, bind=0, target=0x12e2af8` в†’ `KBASE+0x12e2af8` = `__TEXT_EXEC` (РєРѕРґ!).
- Р­С‚Рѕ РќР• mutable allproc LIST_HEAD вЂ” СЌС‚Рѕ PAC-signed pointer to function code.

**Р¤Р°Р№Р»:** `darksword/utils.m`, `kernprocaddress()`
**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ вЂ” Р»РёС€РЅРёРµ 200 kr64 РЅР° РєР°Р¶РґС‹Р№ РІС‹Р·РѕРІ, Р·Р°РјРµРґР»РµРЅРёРµ
**Р¤РёРєСЃ:** РЈРґР°Р»С‘РЅ `try_allproc_candidate("iOS17.3.1 kbase+0x93B348", ...)`.

---

## Р‘Р°Рі #206: kbase+0x3198060 = __PPLDATA в†’ kernel panic РїСЂРё С‡С‚РµРЅРёРё (2026-03-31, СЃРµСЃСЃРёСЏ 3)

**РЎРёРјРїС‚РѕРј:** "legacy __DATA+0x60" РєР°РЅРґРёРґР°С‚ РІС‹Р·С‹РІР°РµС‚ kernel panic РЅР° iPad8,9/A12Z
РїСЂРё РїРµСЂРІРѕРј Р¶Рµ РѕР±СЂР°С‰РµРЅРёРё С‡РµСЂРµР· exploit РїСЂРёРјРёС‚РёРІ.

**Root cause (РѕС„Р»Р°Р№РЅ-Р°РЅР°Р»РёР·):**
- `kbase+0x3198060` = outer fileset `__DATA` + 0x60 = `__PPLDATA` + 0x60.
- РџРµСЂРІС‹Рµ `0x8000` Р±Р°Р№С‚ outer `__DATA` вЂ” СЌС‚Рѕ `__PPLDATA`(16KB) + `__KLDDATA`(16KB).
- РћР±Р° PPL-protected РЅР° Apple Silicon (A12Z). Р›СЋР±РѕРµ С‡С‚РµРЅРёРµ С‡РµСЂРµР· exploit:
  `"Unexpected fault in kernel static region"` в†’ kernel panic.

**Р¤Р°Р№Р»:** `darksword/utils.m`, `kernprocaddress()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” kernel panic РїСЂРё РєР°Р¶РґРѕРј Р·Р°РїСѓСЃРєРµ
**Р¤РёРєСЃ:** РЈРґР°Р»С‘РЅ `try_allproc_candidate("legacy __DATA+0x60 allproc", ...)`.

---

## Р‘Р°Рі #207: scan_for_allproc С‡РёС‚Р°РµС‚ PPL-region + СЃРєР°РЅ РЅРµ РїРѕРєСЂС‹РІР°РµС‚ __DATA.__common (2026-03-31, СЃРµСЃСЃРёСЏ 3)

**РЎРёРјРїС‚РѕРј:** `scan_for_allproc()` Р»РёР±Рѕ РїР°РЅРёРєСѓРµС‚ РїСЂРё С‡С‚РµРЅРёРё PPL-Р·Р°С‰РёС‰С‘РЅРЅРѕРіРѕ РЅР°С‡Р°Р»Р°
outer `__DATA`, Р»РёР±Рѕ РЅРµ РЅР°С…РѕРґРёС‚ allproc РїРѕС‚РѕРјСѓ С‡С‚Рѕ РєР°РЅРґРёРґР°С‚С‹ РІ `__DATA.__common`
Р»РµР¶Р°С‚ Р·Р° РіСЂР°РЅРёС†РµР№ 256KB СЃРєР°РЅР°.

**Root cause (РѕС„Р»Р°Р№РЅ-Р°РЅР°Р»РёР·):**
- outer `__DATA` vmaddr РЅР°С‡РёРЅР°РµС‚СЃСЏ СЃ `__PPLDATA` (РїРµСЂРІС‹Рµ 0x8000 Р±Р°Р№С‚).
- РЎРєР°РЅ СЃС‚Р°СЂС‚РѕРІР°Р» СЃ `vmaddr` (Р±РµР· skip) в†’ С‡С‚РµРЅРёРµ PPL в†’ panic.
- Top-РєР°РЅРґРёРґР°С‚С‹ РёР· ADRP-Р°РЅР°Р»РёР·Р° РІ `__DATA.__common`:
  - `kbase+0x31fff30` (389 refs) = outer `__DATA` + 0x67f30.
  - `kbase+0x31f4188` (154 refs) = outer `__DATA` + 0x5c188.
- РЎС‚Р°СЂС‹Р№ scan_size = 0x40000 (256KB) РЅРµ РґРѕС…РѕРґРёС‚ РґРѕ 0x67f30. РќСѓР¶РЅРѕ 0x80000+ (512KB).

**Р¤Р°Р№Р»:** `darksword/utils.m`, `scan_for_allproc()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” panic РёР»Рё allproc РЅРµ РЅР°Р№РґРµРЅ в†’ РІРµСЃСЊ post-exploit РјС‘СЂС‚РІ

**Р¤РёРєСЃ:**
```c
// Р‘Р«Р›Рћ:
uint64_t scan_size = (vmsize < 0x40000ULL) ? vmsize : 0x40000ULL;
uint64_t found = scan_range_for_allproc(vmaddr, scan_size, kbase);
// vmaddr = РЅР°С‡Р°Р»Рѕ outer __DATA = __PPLDATA в†’ PANIC

// РЎРўРђР›Рћ:
const uint64_t PPL_SKIP = 0x8000ULL;           // РїСЂРѕРїСѓСЃС‚РёС‚СЊ __PPLDATA + __KLDDATA
uint64_t scan_vm_start = vmaddr + PPL_SKIP;
uint64_t scan_vm_avail = vmsize - PPL_SKIP;
uint64_t scan_size = (scan_vm_avail < 0x80000ULL) ? scan_vm_avail : 0x80000ULL;
// 512KB СЃРєР°РЅ РѕС‚ +0x8000 РїРѕРєСЂС‹РІР°РµС‚ __DATA.__common РґРѕ +0x88000 РІРєР»СЋС‡РёС‚РµР»СЊРЅРѕ
uint64_t found = scan_range_for_allproc(scan_vm_start, scan_size, kbase);
```


---

## Bug #208 вЂ” kfs.m: find_rootvnode() РІСЃРµРіРґР° РїСЂРѕРїСѓСЃРєР°РµС‚ root vnode (v_name == NULL)

**РЎРµСЃСЃРёСЏ:** 4
**Р¤Р°Р№Р»:** `darksword/kfs.m`, С„СѓРЅРєС†РёСЏ `find_rootvnode()`
**РЎС‚Р°С‚СѓСЃ:** РРЎРџР РђР’Р›Р•Рќ

**РЎРёРјРїС‚РѕРј:** `kfs_init()` в†’ `find_rootvnode()` РІРѕР·РІСЂР°С‰Р°РµС‚ -1 в†’ `g_rootvnode = 0`
в†’ `kfs_listdir()` РІСЃРµРіРґР° РІРѕР·РІСЂР°С‰Р°РµС‚ -1 в†’ С„Р°Р№Р»РѕРІР°СЏ СЃРёСЃС‚РµРјР° РЅРµРґРѕСЃС‚СѓРїРЅР°.

**Root cause (XNU source xnu-10002.1.13):**
Р’ XNU `struct vnode.v_name` РґР»СЏ root vnode Р’РЎР•Р“Р”Рђ NULL.
Root-vnode СЃРѕР·РґР°С‘С‚СЃСЏ РІ `vfs_mountroot()` Р±РµР· СЂРѕРґРёС‚РµР»СЊСЃРєРѕРіРѕ РёРјРµРЅРё.
РЎС‚Р°СЂС‹Р№ РєРѕРґ: `if (!is_kptr(root_name)) continue;` вЂ” РїСЂРѕРїСѓСЃРєР°Р» СЂРµР°Р»СЊРЅС‹Р№ root vnode РєР°Р¶РґС‹Р№ СЂР°Р·.

**Р¤Р°Р№Р»:** `darksword/kfs.m`, `find_rootvnode()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” kfs РЅРµ СЂР°Р±РѕС‚Р°РµС‚, rootvnode РЅРµ РЅР°Р№РґРµРЅ

**Р¤РёРєСЃ:** РЈР±СЂР°РЅР° РїСЂРѕРІРµСЂРєР° `is_kptr(root_name)` РґР»СЏ root vnode.
NULL v_name РїСЂРёРЅРёРјР°РµС‚СЃСЏ РєР°Рє РІР°Р»РёРґРЅС‹Р№ (РЅРѕСЂРјР°Р»СЊРЅС‹Р№ СЃР»СѓС‡Р°Р№ XNU).
РћСЃС‚Р°РІР»РµРЅР° С‚РѕР»СЊРєРѕ РїСЂРѕРІРµСЂРєР° `v_type == VDIR (2)`.

---

## Bug #209 вЂ” postexploit.m: Р·Р°РіРѕР»РѕРІРѕРє KC 32KB вЂ” AMFI kext РЅРµ РЅР°Р№РґРµРЅ РІ iOS 17 fileset

**РЎРµСЃСЃРёСЏ:** 4
**Р¤Р°Р№Р»:** `darksword/postexploit.m`, С„СѓРЅРєС†РёСЏ `postexploit_patch_amfi()`
**РЎС‚Р°С‚СѓСЃ:** РРЎРџР РђР’Р›Р•Рќ

**РЎРёРјРїС‚РѕРј:** "amfi_get_out_of_my_way string not found in kernel" РІ Р»РѕРіР°С…. AMFI РЅРµ РѕС‚РєР»СЋС‡Р°РµС‚СЃСЏ.

**Root cause:**
Р‘СѓС„РµСЂ Р·Р°РіРѕР»РѕРІРєР° kernelcache Р±С‹Р» РѕРіСЂР°РЅРёС‡РµРЅ 32KB (8 Г— 0x1000).
РќР° iOS 17.3.1 fileset KC sizeofcmds > 32KB (200+ LC_FILESET_ENTRY, РїРѕ РѕРґРЅРѕРјСѓ РЅР° kext).
AMFI kext (com.apple.driver.AppleMobileFileIntegrity) РЅР°С…РѕРґРёС‚СЃСЏ Р·Р° РїСЂРµРґРµР»Р°РјРё
РїРµСЂРІС‹С… 32KB load commands в†’ amfi_kext_vmaddr = 0 в†’ СЃС‚СЂРѕРєР° РЅРµ РЅР°Р№РґРµРЅР°.

**Р¤Р°Р№Р»:** `darksword/postexploit.m`, `postexploit_patch_amfi()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” AMFI РѕС‚РєР»СЋС‡РµРЅРёРµ РІСЃРµРіРґР° РїСЂРѕРІР°Р»РёРІР°РµС‚СЃСЏ

**Р¤РёРєСЃ:** РЈРІРµР»РёС‡РµРЅ Р±СѓС„РµСЂ СЃ 32KB РґРѕ 256KB (64 СЃС‚СЂР°РЅРёС† Г— 0x1000),
hdr_limit clamped СЃ 0x8000 РґРѕ 0x40000.


---

## Bug #210 вЂ” trustcache.m: find_tc_head_by_scan() С‡РёС‚Р°РµС‚ PPL-protected РїР°РјСЏС‚СЊ в†’ panic

**РЎРµСЃСЃРёСЏ:** 5
**Р¤Р°Р№Р»:** `darksword/trustcache.m`, С„СѓРЅРєС†РёРё `find_tc_head_by_scan()` Рё `scan_segment_for_tc()`
**РЎС‚Р°С‚СѓСЃ:** РРЎРџР РђР’Р›Р•Рќ

**РЎРёРјРїС‚РѕРј:** Kernel panic РїСЂРё РІС‹Р·РѕРІРµ `tc_init()` РїРѕСЃР»Рµ СѓСЃРїРµС€РЅРѕРіРѕ kernel R/W.
Р›РѕРі РѕР±СЂС‹РІР°РµС‚СЃСЏ РЅР° "tc_init: looking for trust cache..." Р±РµР· РґР°Р»СЊРЅРµР№С€РµРіРѕ РІС‹РІРѕРґР°.

**Root cause:**
`find_tc_head_by_scan()` СЏРІРЅРѕ РґРѕР±Р°РІР»СЏР» `__PPLDATA` СЃРµРіРјРµРЅС‚С‹ РІ СЃРїРёСЃРѕРє РґР»СЏ СЃРєР°РЅР°:
```c
if (strncmp(seg->segname, "__DATA", 6) == 0 ||
    strncmp(seg->segname, "__PPLDATA", 9) == 0 ||    // в†ђ PPL-protected в†’ panic!
    strncmp(seg->segname, "__LASTDATA", 10) == 0) {
    segs[nsegs].addr = seg->vmaddr + kslide;
```
Р—Р°С‚РµРј `scan_segment_for_tc()` РЅР°С‡РёРЅР°Р»Р° СЃРєР°РЅРёСЂРѕРІР°С‚СЊ СЃ `off=0` (РЅР°С‡Р°Р»Рѕ СЃРµРіРјРµРЅС‚Р°):
```c
krd(seg_addr + off, page, 0x1000);  // в†ђ __PPLDATA = PPL-protected в†’ PANIC
```

Р”РѕРїРѕР»РЅРёС‚РµР»СЊРЅРѕ: РґР»СЏ outer `__DATA` СЃРµРіРјРµРЅС‚ РЅР°С‡РёРЅР°РµС‚СЃСЏ СЃ vmaddr = РЅР°С‡Р°Р»Р° `__PPLDATA`
(РїРµСЂРІС‹Рµ 0x8000 = `__PPLDATA` + `__KLDDATA`, PPL-protected). РЎРєР°РЅ Р±РµР· skip = panic.

Р”Р»СЏ СЃСЂР°РІРЅРµРЅРёСЏ: `find_tc_head_by_string_xref()` СѓР¶Рµ РёРјРµР»Р° РєРѕСЂСЂРµРєС‚РЅС‹Р№ skip:
```c
if (strncmp(data_segs[d].name, "__PPLDATA", 9) == 0) {
    tlog("string xref: skipping %s (PPL-protected)", data_segs[d].name);
    continue;
}
```
...РЅРѕ `find_tc_head_by_scan()` вЂ” РќР• РёРјРµР»Р°.

**Р¤Р°Р№Р»:** `darksword/trustcache.m`, `find_tc_head_by_scan()` + `scan_segment_for_tc()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” panic РЅР° tc_init() = trust cache РІСЃРµРіРґР° РЅРµРґРѕСЃС‚СѓРїРµРЅ = bootstrap binaries РЅРµ РґРѕРІРµСЂРµРЅС‹ = dpkg/apt/Sileo РЅРµ Р·Р°РїСѓСЃРєР°СЋС‚СЃСЏ

**Р¤РёРєСЃ:**
1. `scan_segment_for_tc()` РїРѕР»СѓС‡РёР»Р° РїР°СЂР°РјРµС‚СЂ `start_skip` вЂ” С‡РёС‚Р°РµС‚ СЃ `seg_addr + start_skip + off`
2. `find_tc_head_by_scan()`:
   - РЈР±СЂР°РЅР° РёР· СЃРїРёСЃРєР°: `__PPLDATA` (skip entirely вЂ” trust cache head РЅРёРєРѕРіРґР° РЅРµ РІ PPL)
   - РЈР±СЂР°РЅР° РёР· СЃРїРёСЃРєР°: `__LASTDATA` (unknown, may be PPL-protected)
   - Р”Р»СЏ `__DATA` СЃРµРіРјРµРЅС‚Р°: `skip = PPL_SKIP = 0x8000` (РїСЂРѕРїСѓСЃРєР°РµС‚ __PPLDATA+__KLDDATA prefix)
   - Р”Р»СЏ РѕСЃС‚Р°Р»СЊРЅС‹С… (`__DATA_CONST` Рё РїРѕРґРѕР±РЅС‹С…): `skip = 0`


---

## Р‘Р°Рі #211: set_target_kaddr вЂ” hardcoded РЅРёР¶РЅРёР№ РїРѕСЂРѕРі 0xffffffe0 Р±Р»РѕРєРёСЂСѓРµС‚ A12Z PCBs (2026-03-31, СЃРµСЃСЃРёСЏ 6)

**РЎРёРјРїС‚РѕРј (РёР· Р»РѕРіР°):** Р’СЃРµ 5 РїРѕРїС‹С‚РѕРє СЌРєСЃРїР»РѕРёС‚Р° РїР°РґР°СЋС‚:
```
rw_socket_pcb validated: 0xffffffdd37e4c400
set_target_kaddr: BLOCKED addr 0xffffffdd37e4c420 (no zone bounds, static_max=0xffffffe337e4c400)
getsockopt failed (early_kread)!
PANIC GUARD: control_socket_pcb=0x0 в†’ abort
```

**Root cause (РѕС„Р»Р°Р№РЅ-Р°РЅР°Р»РёР· v4):**
Р’ `set_target_kaddr()` fallback РІРµС‚РєР° (РґРѕ zone discovery) РёРјРµР»Р° С…Р°СЂРґРєРѕРґРёСЂРѕРІР°РЅРЅС‹Р№ РЅРёР¶РЅРёР№ РїРѕСЂРѕРі:
`if (where < 0xffffffe000000000ULL || where >= static_max) { BLOCKED }`
РќР° A12Z/iOS 17.3.1 zone_map РЅР°С‡РёРЅР°РµС‚СЃСЏ РІ СЂРµРіРёРѕРЅРµ `0xffffffdd...` (РЅРµ `0xffffffe2...`).
PCB = `0xffffffdd37e4c400` < `0xffffffe000000000` в†’ ALL PCB reads blocked в†’ exploit РІСЃРµРіРґР° РїСЂРµСЂС‹РІР°Р»СЃСЏ.

**РћС„Р»Р°Р№РЅ РІРµСЂРёС„РёРєР°С†РёСЏ (v4, СЃРµРєС†РёСЏ C):** Р’СЃРµ 5 РїРѕРїС‹С‚РѕРє РёР· Р»РѕРіР°: OLD=BLOCKED, NEW=OK

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`, `set_target_kaddr()`, СЃС‚СЂРѕРєР° ~663
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” exploit РїРѕР»РЅРѕСЃС‚СЊСЋ РЅРµ СЂР°Р±РѕС‚Р°Р» РЅР° A12Z

**Р¤РёРєСЃ:** Р”РёРЅР°РјРёС‡РµСЃРєРёР№ zone_lower = СЂw_socket_pcb & ~0xffff РїСЂРё pcb < 0xffffffe0.
PCB вЂ” proven zone_map object (validated by inp_gencnt), РµРіРѕ СЃС‚СЂР°РЅРёС†Р° РіР°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕ mapped.

---

## Р‘Р°Рі #212: discover_zone_boundaries_raw() вЂ” fallback/emergency clamp Рє 0xffffffe0 (2026-03-31, СЃРµСЃСЃРёСЏ 6)

**РЎРёРјРїС‚РѕРј:** Р•СЃР»Рё zone_info РЅРµ РЅР°Р№РґРµРЅР° РІ backward scan, fallback СѓСЃС‚Р°РЅР°РІР»РёРІР°РµС‚
`g_zone_map_min = 0xffffffe000000000` С‡С‚Рѕ Р’Р«РЁР• PCB (0xffffffdd...) в†’
РІСЃРµ kernel reads С‡РµСЂРµР· g_zone_map_min/max РІРµС‚РєСѓ СЃРЅРѕРІР° Р±Р»РѕРєРёСЂСѓСЋС‚СЃСЏ.

**Root cause (РѕС„Р»Р°Р№РЅ-Р°РЅР°Р»РёР· v4, СЃРµРєС†РёСЏ E):**
11 РІС…РѕР¶РґРµРЅРёР№ `0xffffffe000000000` РІ darksword_core.m, РёР· РєРѕС‚РѕСЂС‹С… 5 РІ fallback/emergency РїСѓС‚СЏС…:
- Emergency path (ipi_zone=0): `g_zone_map_min = max(pcb-8GB, 0xffffffe0...)` в†’ РІС‹С€Рµ PCB
- Last resort path: `g_zone_map_min = 0xffffffe000000000` в†’ РІС‹С€Рµ PCB
- Main fallback (zone_info not found): `if (min < 0xffffffe0) min = 0xffffffe0` в†’ РІС‹С€Рµ PCB

**РЎРёРјСѓР»СЏС†РёСЏ (v4):**
OLD: g_zone_map_min=0xffffffe0..., pcb (0xffffffdd...) NOT РІ РґРёР°РїР°Р·РѕРЅРµ в†’ BLOCKED
NEW: g_zone_map_min=pcb-8GB=0xffffffdb..., pcb Р’ РґРёР°РїР°Р·РѕРЅРµ в†’ ALLOWED вњ…

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`, `discover_zone_boundaries_raw()`, ~СЃС‚СЂРѕРєРё 793-803, 885-890
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” Р±РµР· СЌС‚РѕРіРѕ С„РёРєСЃР° Bug #211 fix РЅРµРїРѕР»РЅС‹Р№:
РїРѕСЃР»Рµ zone discovery g_zone_map_min СѓСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ Р’Р«РЁР• PCB в†’ СЃРЅРѕРІР° block

**Р¤РёРєСЃ:** РЈРґР°Р»РµРЅС‹ РІСЃРµ clamp Рє `0xffffffe000000000` РёР· fallback/emergency.
Р—Р°РјРµРЅРµРЅРѕ РЅР° `0xffffffd000000000` (Р±РµР·РѕРїР°СЃРЅС‹Р№ РЅРёР¶РЅРёР№ РїСЂРµРґРµР» РґР»СЏ arm64e iOS kernel pointers).

---

## Р‘Р°Рі #213: free_thread / physical_oob_read_mo incomplete port РёР· original exploit Р»РѕРјР°Р» VFS race (2026-03-31, СЃРµСЃСЃРёСЏ 7)

**РЎРёРјРїС‚РѕРј (РЅРѕРІС‹Р№ Р»РѕРі РїРѕСЃР»Рµ С„РёРєСЃРѕРІ #211/#212):** exploit Р·Р°РІРёСЃР°РµС‚ РЅР° search mappings Рё РїРµС‡Р°С‚Р°РµС‚ С‚С‹СЃСЏС‡Рё СЃС‚СЂРѕРє:
```text
[11:55:48] looking in search mapping: 0
[11:56:21] mach_vm_map failed in free_thread!
[11:56:21]     free_target: 0x2e06c8000, target_object: 0x58f603
...
[11:58:41] looking in search mapping: 5
```
РџСЂРё СЌС‚РѕРј Р»РѕРі **РЅРµ РґРѕС…РѕРґРёС‚** РґРѕ `found control_socket`, `rw_socket_pcb validated` РёР»Рё `kernel r/w is ready!`.

**Root cause (СЃСЂР°РІРЅРµРЅРёРµ СЃ original `kernel_research/456/src/main.m`):**
РџСЂРё Р°РґР°РїС‚Р°С†РёРё exploit РІ `darksword_core.m` Р±С‹Р»Рё РїРѕС‚РµСЂСЏРЅС‹ 4 РєСЂРёС‚РёС‡РµСЃРєРёРµ С‡Р°СЃС‚Рё original race path:

1. **`targetObjectSize` РЅРµ СЃРѕС…СЂР°РЅСЏР»СЃСЏ** РїРѕСЃР»Рµ `mach_make_memory_entry_64()`
  - original: `targetObjectSize = memoryObjectSize;`
  - port: РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р»Рѕ

2. **`targetObjectOffset` РЅРµ clamp'РёР»СЃСЏ РІ РіСЂР°РЅРёС†С‹ memory object**
  - original:
    ```c
    off = memoryObjectOffset & ~(PAGE_SIZE - 1);
    if (targetObjectSize >= freeTargetSize && (off + freeTargetSize > targetObjectSize)) {
      off = (targetObjectSize - freeTargetSize) & ~(PAGE_SIZE - 1);
    }
    ```
  - port: Р·Р°РїРёСЃС‹РІР°Р» СЃС‹СЂРѕР№ `mo_offset` Р±РµР· РїСЂРѕРІРµСЂРєРё СЂР°Р·РјРµСЂР° РѕР±СЉРµРєС‚Р°

3. **`free_thread()` РґРµР»Р°Р» single-shot `mach_vm_map()` Р±РµР· retry**
  - original: РґРѕ 5 retry + `usleep(200)`
  - port: 1 РІС‹Р·РѕРІ в†’ transient fail РїСЂРµРІСЂР°С‰Р°Р»СЃСЏ РІ hard fail

4. **Р›РѕРі map fail РЅРµ Р±С‹Р» rate-limited**
  - original: Р»РѕРі 1 СЂР°Р· РЅР° 128 fail'РѕРІ
  - port: Р»РѕРіРёСЂРѕРІР°Р» РљРђР–Р”Р«Р™ fail в†’ С‚С‹СЃСЏС‡РµСЃС‚СЂРѕС‡РЅС‹Р№ spam, РѕРіСЂРѕРјРЅР°СЏ РїРѕС‚РµСЂСЏ РІСЂРµРјРµРЅРё

**РџРѕС‡РµРјСѓ СЌС‚Рѕ РєСЂРёС‚РёС‡РЅРѕ:**
VFS race Р·Р°РІРёСЃРёС‚ РѕС‚ Р±С‹СЃС‚СЂРѕРіРѕ overwrite remap `free_target` named-entry memory object'РѕРј.
Р•СЃР»Рё `target_object_offset` РІС‹С…РѕРґРёС‚ Р·Р° РіСЂР°РЅРёС†С‹ РѕР±СЉРµРєС‚Р° Р»РёР±Рѕ transient `mach_vm_map()` fail РЅРµ СЂРµС‚СЂР°РёС‚СЃСЏ,
РїРѕРёСЃРє СЃРѕРєРµС‚Р° РЅРёРєРѕРіРґР° РЅРµ РїРѕР»СѓС‡Р°РµС‚ СѓСЃРїРµС€РЅС‹Р№ OOB read в†’ `find_and_corrupt_socket()` РЅРµ СЃСЂР°Р±Р°С‚С‹РІР°РµС‚.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**Р¤СѓРЅРєС†РёРё:** `free_thread()`, `physical_oob_read_mo()`, `physical_oob_write_mo()`, `pe_v1()`, `pe_v2()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” exploit Р·Р°СЃС‚СЂРµРІР°Р» РІ search-mapping phase Рё РЅРµ РґРѕС…РѕРґРёР» РґРѕ kernel R/W

**Р¤РёРєСЃ:**
- РґРѕР±Р°РІР»РµРЅ `target_object_size` Рё РѕРЅ Р·Р°РїРѕР»РЅСЏРµС‚СЃСЏ РїРѕСЃР»Рµ `mach_make_memory_entry_64()`
- `mo_offset` С‚РµРїРµСЂСЊ page-aligned Рё clamp'РёС‚СЃСЏ РІ `[0, target_object_size - free_target_size]`
- `free_thread()` С‚РµРїРµСЂСЊ РґРµР»Р°РµС‚ РґРѕ 5 retry `mach_vm_map()`
- Р»РѕРі fail'РѕРІ rate-limited: 1 СЂР°Р· РЅР° 128 СЃРѕР±С‹С‚РёР№ СЃ РІС‹РІРѕРґРѕРј `kr`, `off`, `adjusted`, `obj_size`

**РћР¶РёРґР°РµРјС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚ СЃР»РµРґСѓСЋС‰РµРіРѕ С‚РµСЃС‚Р°:**
Р»РѕРі РґРѕР»Р¶РµРЅ РїРµСЂРµСЃС‚Р°С‚СЊ Р·Р°СЃС‚СЂРµРІР°С‚СЊ РЅР° `mach_vm_map failed in free_thread` Рё СЃРЅРѕРІР° РґРѕР№С‚Рё РґРѕ
`found control_socket at idx`, Р·Р°С‚РµРј РґРѕ СЂР°РЅРЅРёС… kernel reads (`rw_socket_pcb validated`, `control_socket_pcb`, `ipi_zone`).

---

## Р‘Р°Рі #214: kernel_base/zone-discovery path СЃР»РёС€РєРѕРј РґРѕРІРµСЂСЏР» `pcbinfo -> ipi_zone -> zv_name` (2026-03-31, СЃРµСЃСЃРёСЏ 8)

**РЎРёРјРїС‚РѕРј:** РїРѕР»СЊР·РѕРІР°С‚РµР»СЊ СЃРѕРѕР±С‰РёР», С‡С‚Рѕ РїРѕСЃР»Рµ СѓСЃС‚Р°РЅРѕРІРєРё РЅРѕРІРѕРіРѕ Р±РёР»РґР° СѓСЃС‚СЂРѕР№СЃС‚РІРѕ РїР°РґР°РµС‚ РїСЂРёРјРµСЂРЅРѕ С‡РµСЂРµР· 10 СЃРµРєСѓРЅРґ Рё Р»РѕРі РЅРµ СѓСЃРїРµРІР°РµС‚ СЃРѕС…СЂР°РЅРёС‚СЊСЃСЏ. Р—РЅР°С‡РёС‚ СЃР»РµРґСѓСЋС‰РёР№ Р±Р»РѕРєРµСЂ СѓР¶Рµ РјРѕР¶РµС‚ Р±С‹С‚СЊ kernel panic РґРѕ flush `darksword_log.txt`.

**Root cause (РѕС„Р»Р°Р№РЅ-Р°РЅР°Р»РёР· v5 + СЃСЂР°РІРЅРµРЅРёРµ СЃ original exploit):**
РўРµРєСѓС‰РёР№ РїРѕСЂС‚ РїРѕСЃР»Рµ `control_socket_pcb` РїРѕР»РЅРѕСЃС‚СЊСЋ РїРѕР»Р°РіР°Р»СЃСЏ РЅР° С†РµРїРѕС‡РєСѓ:
```c
control_socket_pcb -> pcbinfo(+0x38) -> ipi_zone(+0x68) -> zv_name(+0x10)
```
Рё РїСЂРёРЅРёРјР°Р» РµС‘ РєР°Рє РІР°Р»РёРґРЅСѓСЋ С‚РѕР»СЊРєРѕ РїРѕ range-check (`>= 0xfffffff0...`).

РџСЂРѕР±Р»РµРјР°: canonical-looking kernel ptr РµС‰С‘ РЅРµ РѕР·РЅР°С‡Р°РµС‚, С‡С‚Рѕ СЌС‚Рѕ РґРµР№СЃС‚РІРёС‚РµР»СЊРЅРѕ РїСЂР°РІРёР»СЊРЅС‹Р№ `ipi_zone`.
Р•СЃР»Рё `ipi_zone` РёР»Рё `zv_name` РјСѓСЃРѕСЂРЅС‹Рµ, РЅРѕ РїРѕРїР°РґР°СЋС‚ РІ kernel static range, РєРѕРґ РјРѕРі:
1. РїСЂРёРЅСЏС‚СЊ РёС… Р·Р° РІР°Р»РёРґРЅС‹Рµ;
2. РІС‹Р·РІР°С‚СЊ `discover_zone_boundaries_raw(ipi_zone)`;
3. РЅР°С‡Р°С‚СЊ backward/forward scan РѕС‚ РЅРµРїСЂР°РІРёР»СЊРЅРѕРіРѕ РјРµСЃС‚Р°;
4. СЃР»РѕРІРёС‚СЊ kernel panic РґРѕ flush Р»РѕРіР°.

**Р§С‚Рѕ РїРѕРєР°Р·Р°Р» РѕС„Р»Р°Р№РЅ-Р°РЅР°Р»РёР· v5:**
- original exploit already had Р±РѕР»РµРµ РЅР°РґС‘Р¶РЅС‹Р№ РїСѓС‚СЊ РґР»СЏ kernel base:
  `control_socket_pcb + 0x40 -> socket`, `socket + 0x18 -> so_proto`, `protosw + 0x28 -> pr_input`
- `pr_input` РѕР±СЏР·Р°РЅ СѓРєР°Р·С‹РІР°С‚СЊ РІ `__TEXT_EXEC`, РїРѕСЌС‚РѕРјСѓ СЌС‚Рѕ Р±РµР·РѕРїР°СЃРЅС‹Р№ fallback РґР»СЏ РїРѕРёСЃРєР° `kernel_base`
- zone names РґР»СЏ ICMP6 PCB zone РІ kernelcache вЂ” printable cstrings РІ `__PRELINK_TEXT`: `icmp6`, `ripcb`, `inpcb`
- Р·РЅР°С‡РёС‚ `zv_name` РјРѕР¶РЅРѕ Рё РЅСѓР¶РЅРѕ РІРµСЂРёС„РёС†РёСЂРѕРІР°С‚СЊ РєР°Рє ASCII-СЃС‚СЂРѕРєСѓ РґРѕ zone scan

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” РЅРµРїСЂР°РІРёР»СЊРЅС‹Р№, РЅРѕ canonical-looking `ipi_zone` РјРѕРі РїСЂРёРІРѕРґРёС‚СЊ Рє panic РґРѕ СЃРѕС…СЂР°РЅРµРЅРёСЏ Р»РѕРіР°

**Р¤РёРєСЃ:**
1. Р”РѕР±Р°РІР»РµРЅ `derive_kernel_base_via_protosw()` вЂ” original fallback С‡РµСЂРµР· `socket -> so_proto -> pr_input`
2. Р”РѕР±Р°РІР»РµРЅ `early_kread_cstring()`
3. `zv_name` С‚РµРїРµСЂСЊ РїСЂРёРЅРёРјР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РµСЃР»Рё С‡РёС‚Р°РµС‚СЃСЏ РєР°Рє printable ASCII cstring Рё СЃРѕРґРµСЂР¶РёС‚ `icmp6` / `ripcb` / `inpcb` / `raw6`
4. Р•СЃР»Рё zone name РЅРµРІР°Р»РёРґРµРЅ, `discover_zone_boundaries_raw()` РІС‹Р·С‹РІР°РµС‚СЃСЏ СЃ `0` в†’ Р±РµР·РѕРїР°СЃРЅС‹Р№ emergency bounds path РІРјРµСЃС‚Рѕ СЃРєР°РЅР° РѕС‚ РјСѓСЃРѕСЂРЅРѕРіРѕ `ipi_zone`

**РћР¶РёРґР°РµРјС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚:** РЅРѕРІС‹Р№ Р±РёР»Рґ РґРѕР»Р¶РµРЅ РїРµСЂРµР¶РёРІР°С‚СЊ СЌС‚РѕС‚ СЌС‚Р°Рї С‡Р°С‰Рµ Рё Р»РёР±Рѕ:
- РґРѕС…РѕРґРёС‚СЊ РґРѕ `zone_info FOUND` / `kernel r/w is ready!`, Р»РёР±Рѕ
- С…РѕС‚СЏ Р±С‹ РїР°РґР°С‚СЊ РїРѕР·Р¶Рµ Рё СѓСЃРїРµРІР°С‚СЊ СЃРѕС…СЂР°РЅРёС‚СЊ Р»РѕРі РґР»СЏ СЃР»РµРґСѓСЋС‰РµРіРѕ Р°РЅР°Р»РёР·Р°.

---

## Р‘Р°Рі #215: `site.struct inpcb` Р»РѕР¶РЅРѕ РїСЂРѕС…РѕРґРёР» РІР°Р»РёРґР°С†РёСЋ РєР°Рє zone name (2026-03-31, СЃРµСЃСЃРёСЏ 9)

**РЎРёРјРїС‚РѕРј (РїРѕ screenshot РЅРѕРІРѕРіРѕ Р·Р°РїСѓСЃРєР°):**
СЌРєСЂР°РЅ РїРѕРєР°Р·С‹РІР°РµС‚ СѓСЃРїРµС€РЅС‹Р№ РїСЂРѕС…РѕРґ РґРѕ:
```text
found control_socket at idx: ...
rw_socket_pcb validated: ...
control_socket_pcb: ...
pcbinfo_pointer: ...
ipi_zone: ...
zv_name: ...
zone name: site.struct inpcb
discovering zone boundaries...
zone discovery: ipi_zone=... rw_pcb=...
```
РїРѕСЃР»Рµ С‡РµРіРѕ СѓСЃС‚СЂРѕР№СЃС‚РІРѕ Р±С‹СЃС‚СЂРѕ РїР°РґР°РµС‚ / СЂРµР±СѓС‚Р°РµС‚СЃСЏ Рё Р»РѕРі РЅРµ СѓСЃРїРµРІР°РµС‚ Р·Р°РїРёСЃР°С‚СЊСЃСЏ.

**Root cause:**
Fix #214 РїСЂРѕРІРµСЂСЏР» `zv_name` СЃР»РёС€РєРѕРј РјСЏРіРєРѕ:
```c
if (strstr(zone_name, "icmp6") || strstr(zone_name, "ripcb") ||
  strstr(zone_name, "inpcb") || strstr(zone_name, "raw6")) {
  have_valid_zone_name = true;
}
```
Р­С‚Рѕ РїРѕР·РІРѕР»СЏР»Рѕ СЃС‚СЂРѕРєР°Рј РІРёРґР° `site.struct inpcb` РїСЂРѕР№С‚Рё РєР°Рє Р±СѓРґС‚Рѕ СЌС‚Рѕ СЂРµР°Р»СЊРЅРѕРµ РёРјСЏ zone.

Workspace-Р°РЅР°Р»РёР· РїРѕРєР°Р·Р°Р»:
- `site.struct inpcb` РґРµР№СЃС‚РІРёС‚РµР»СЊРЅРѕ РІСЃС‚СЂРµС‡Р°РµС‚СЃСЏ РІ kernelcache РєР°Рє debug/assert-style string
- РѕР¶РёРґР°РµРјС‹Рµ РЅРѕСЂРјР°Р»СЊРЅС‹Рµ zone names РґР»СЏ СЌС‚РѕР№ С†РµРїРѕС‡РєРё: `icmp6`, `ripcb`, `inpcb`, `inp6`, `in6pcb`, `raw6`, `icmp6pcb`
- Р·РЅР°С‡РёС‚ `site.struct inpcb` вЂ” СЃРёР»СЊРЅС‹Р№ РїСЂРёР·РЅР°Рє Р»РѕР¶РЅРѕРїРѕР»РѕР¶РёС‚РµР»СЊРЅРѕРіРѕ `zv_name`

**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” Р»РѕР¶РЅРѕРїРѕР»РѕР¶РёС‚РµР»СЊРЅС‹Р№ `zv_name` Р·Р°РїСѓСЃРєР°Р» `discover_zone_boundaries_raw()` РѕС‚ РЅРµРІРµСЂРЅРѕРіРѕ `ipi_zone`, С‡С‚Рѕ РІРµСЂРѕСЏС‚РЅРѕ Рё РІС‹Р·С‹РІР°Р»Рѕ panic РґРѕ flush Р»РѕРіР°.

**Р¤РёРєСЃ:**
Р”РѕР±Р°РІР»РµРЅ `is_expected_ipi_zone_name()`; С‚РµРїРµСЂСЊ РїСЂРёРЅРёРјР°СЋС‚СЃСЏ С‚РѕР»СЊРєРѕ С‚РѕС‡РЅС‹Рµ СЃРѕРІРїР°РґРµРЅРёСЏ:
`icmp6`, `ripcb`, `inpcb`, `inp6`, `in6pcb`, `raw6`, `icmp6pcb`.
Р’СЃРµ `site.struct ...` Рё РїРѕС…РѕР¶РёРµ debug strings С‚РµРїРµСЂСЊ РїСЂРёРЅСѓРґРёС‚РµР»СЊРЅРѕ РІРµРґСѓС‚ РІ emergency path.

---

## Р‘Р°Рі #216: `ourproc()` crash вЂ” РѕРїР°СЃРЅС‹Р№ scan_for_allproc РІРјРµСЃС‚Рѕ ADRP-based offset (2026-03-31, СЃРµСЃСЃРёСЏ 10)

**РЎРёРјРїС‚РѕРј (РїРѕ screenshot):**
Exploit РІРїРµСЂРІС‹Рµ РґРѕСЃС‚РёРі `kernel r/w is ready!` (РІСЃРµ С„РёРєСЃС‹ #211-#215 СЃСЂР°Р±РѕС‚Р°Р»Рё).
Р”Р°Р»РµРµ:
```text
kernel r/w is ready!
about to call ourproc()
```
в†’ device crash/reboot. Р›РѕРі РЅРµ СЃРѕРґРµСЂР¶РёС‚ `returned from ourproc()`.

**Root cause:**
`kernprocaddress()` РЅРµ СЃРѕРґРµСЂР¶Р°Р» РЅРё РѕРґРЅРѕРіРѕ known-good offset (РІСЃРµ Р±С‹Р»Рё СѓРґР°Р»РµРЅС‹ bugs #205/#206).
Р•РґРёРЅСЃС‚РІРµРЅРЅР°СЏ СЃС‚СЂР°С‚РµРіРёСЏ вЂ” `scan_for_allproc()`, РєРѕС‚РѕСЂС‹Р№:
1. РЎРєР°РЅРёСЂСѓРµС‚ 512KB kernel `__DATA` (16KB-С‡Р°РЅРєР°РјРё РїРѕ 32 Р±Р°Р№С‚Р° С‡РµСЂРµР· exploit kread)
2. Р”Р»СЏ РєР°Р¶РґРѕРіРѕ Р·РЅР°С‡РµРЅРёСЏ, РїРѕС…РѕР¶РµРіРѕ РЅР° heap pointer, РґРµР»Р°РµС‚ pre-filter: С‡С‚РµРЅРёРµ РёР· HEAP Р°РґСЂРµСЃР° (`first_q + PROC_PID_OFFSET`)
3. РЎ emergency zone bounds В±8GB (16GB total), HEAP-like Р°РґСЂРµСЃР° РјРѕРіСѓС‚ СѓРєР°Р·С‹РІР°С‚СЊ РЅР° zone metadata pages
4. Zone metadata pages РќР• mapped в†’ `getsockopt()` в†’ `copyout()` в†’ translation fault L3 в†’ **kernel panic**

**РћС„Р»Р°Р№РЅ ADRP Р°РЅР°Р»РёР· (PHASE2_SYMBOLS_REPORT.md):**
- РљР°РЅРґРёРґР°С‚ #3 РїРѕ С‡Р°СЃС‚РѕС‚Рµ СЃСЃС‹Р»РѕРє: VA `0xfffffff00a203f30` = kbase + 0x31FFF30
- 389 ADRP+ADD/LDR cross-references РёР· `__TEXT_EXEC`
- Р Р°СЃРїРѕР»РѕР¶РµРЅ РІ `__DATA.__common` + 0x3CF30 (РќР• РІ __PPLDATA)
- Outer `__DATA + 0x67f30` вЂ” safe РґР»СЏ С‡С‚РµРЅРёСЏ

**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” crash РІ post-exploit `ourproc()` РєР°Р¶РґС‹Р№ СЂР°Р·.

**Р¤РёРєСЃ (3 С‡Р°СЃС‚Рё):**
1. **Known ADRP offset**: РґРѕР±Р°РІР»РµРЅ `kbase + 0x31FFF30` РєР°Рє РџР•Р Р’Р«Р™ РєР°РЅРґРёРґР°С‚ РІ `kernprocaddress()` (РїРµСЂРµРґ scan). РџР»СЋСЃ В±0x1000 nearby РїСЂРѕРІРµСЂРєР° РґР»СЏ minor build variations.
2. **Narrowed scan range**: СЃРєР°РЅРёСЂРѕРІР°РЅРёРµ СЃСѓР¶РµРЅРѕ СЃ РїРѕР»РЅРѕРіРѕ `__DATA` (0x8000 + 512KB) РґРѕ С‚РѕР»СЊРєРѕ `__DATA.__common` (0x27000 - 0x83000, ~376KB). Р­С‚Рѕ РёСЃРєР»СЋС‡Р°РµС‚ `__DATA.__data`/`__lock_grp`/`__percpu` РєРѕС‚РѕСЂС‹Рµ СЃРѕРґРµСЂР¶Р°С‚ Р»РѕР¶РЅРѕРїРѕР»РѕР¶РёС‚РµР»СЊРЅС‹Рµ heap pointers.
3. **Tighter pre-filter**: РґРѕР±Р°РІР»РµРЅР° РїСЂРѕРІРµСЂРєР° СЂР°СЃСЃС‚РѕСЏРЅРёСЏ heap pointer РѕС‚ rw_socket_pcb (В±2GB), С‡С‚Рѕ С„РёР»СЊС‚СЂСѓРµС‚ zone metadata Р°РґСЂРµСЃР° РЅР° РєСЂР°СЏС… emergency bounds.
4. **Health check**: РІ РЅР°С‡Р°Р»Рµ `ourproc()` РґРѕР±Р°РІР»РµРЅР° РІРµСЂРёС„РёРєР°С†РёСЏ kread С‡РµСЂРµР· С‡С‚РµРЅРёРµ kernel magic (`0xFEEDFACF`), С‡С‚РѕР±С‹ РёСЃРєР»СЋС‡РёС‚СЊ corrupt primitive.
5. **Diagnostic logging**: granular log messages РїРѕ РІСЃРµРјСѓ `ourproc()` flow РґР»СЏ Р±СѓРґСѓС‰РµР№ РѕС‚Р»Р°РґРєРё.

---

## Р‘Р°Рі #220: РїРµСЂРІС‹Р№ read `rw_socket_pcb + 0x20` Р·Р°РІРёСЃРµР» РѕС‚ РЅРµРїСЂРѕРёРЅРёС†РёР°Р»РёР·РёСЂРѕРІР°РЅРЅС‹С… bounds (2026-03-31, СЃРµСЃСЃРёСЏ 11)

**РЎРёРјРїС‚РѕРј:** СЌРєСЂР°РЅ СЃС‚Р°Р±РёР»СЊРЅРѕ РґРѕС…РѕРґРёР» РґРѕ `rw_socket_pcb validated` Рё РѕСЃС‚Р°РЅР°РІР»РёРІР°Р»СЃСЏ.
Р›РѕРі С„РёР·РёС‡РµСЃРєРё РЅРµ СЃРѕС…СЂР°РЅСЏР»СЃСЏ РЅР° РџРљ.

**Root cause:** `g_zone_map_min/max` = 0 РЅР° РјРѕРјРµРЅС‚ РїРµСЂРІРѕРіРѕ PCB-read. `set_target_kaddr()` fallback
РІС‹С‡РёСЃР»СЏР» `zone_lower` / `static_max` РёР· `rw_socket_pcb`, РЅРѕ РїСЂРё РѕРїСЂРµРґРµР»С‘РЅРЅС‹С… race conditions РёР»Рё retry-state
СЌС‚Рё bounds РЅРµ СѓСЃС‚Р°РЅР°РІР»РёРІР°Р»РёСЃСЊ.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” СЂР°РЅРЅРёР№ abort РјР°СЃРєРёСЂРѕРІР°Р» РІСЃРµ РґР°Р»СЊРЅРµР№С€РёРµ С„РёРєСЃС‹

**Р¤РёРєСЃ:** `prime_zone_bounds_from_rw_pcb()` вЂ” Р°РІР°СЂРёР№РЅРѕ РїСЂР°Р№РјРёС‚ `В±8 GB` РѕС‚ `rw_socket_pcb` РїРµСЂРµРґ РїРµСЂРІС‹Рј heap read.

---

## Р‘Р°Рі #221: `socket_so_count_offset = 0x228` вЂ” РЅРµРІРµСЂРЅС‹Р№ offset РґР»СЏ iOS 17 (2026-03-31, СЃРµСЃСЃРёСЏ 12)

**РЎРёРјРїС‚РѕРј (СЃРєСЂРёРЅС€РѕС‚ СЃ СѓСЃС‚СЂРѕР№СЃС‚РІР°):**
Р­РєСЃРїР»РѕРёС‚ СѓСЃРїРµС€РЅРѕ РґРѕС…РѕРґРёС‚ РґРѕ `kernel_base`, `kernel_slide`, `krw_sockets_leak_forever()`:
```
kernel_base: 0xfffffff012c38000
kernel_slide: 0xbc34000
about to enter krw_sockets_leak_forever()
krw leak: control_socket=0xffffffe0922ded68 rw_socket=0xffffffe0922df120
krw leak: so_count control=0x1a800000000 rw=0x1a800000000
krw leak: refcount patch applied successfully
```
РЎСЂР°Р·Сѓ РїРѕСЃР»Рµ вЂ” kernel panic. РЈСЃС‚СЂРѕР№СЃС‚РІРѕ СЂРµР±СѓС‚Р°РµС‚СЃСЏ.

**Root cause:**
Offset `0x228` РґР»СЏ `so_count` РІ `struct socket` РІР·СЏС‚ РёР· РѕСЂРёРіРёРЅР°Р»СЊРЅРѕРіРѕ СЌРєСЃРїР»РѕРёС‚Р° `456/src/main.m`,
РєРѕС‚РѕСЂС‹Р№ Р±С‹Р» РЅР°РїРёСЃР°РЅ РґР»СЏ iOS 16 / xnu-8792. Р’ iOS 17 (`xnu-10002`) Apple РґРѕР±Р°РІРёР»Р° ~36 Р±Р°Р№С‚
РІ `struct socket`, СЃРґРІРёРЅСѓРІ `so_count` СЃ `0x228` РЅР° `0x24c`.

Р”РѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ: Р»РѕРі РѕС‚ 29 РјР°СЂС‚Р° (`darksword_live2.txt`) СЃ offset `0x24c` РїРѕРєР°Р·С‹РІР°Р» **РІР°Р»РёРґРЅС‹Рµ**
refcount'С‹: `so_count raw=0x1` (control) Рё `raw=0x2` (rw). РўРµРєСѓС‰РёР№ `0x228` С‡РёС‚Р°РµС‚
`0x1a800000000` (lower 32b = 0, upper 32b = 0x1a8 вЂ” С‡СѓР¶РѕРµ РїРѕР»Рµ, РІРµСЂРѕСЏС‚РЅРѕ СѓРєР°Р·Р°С‚РµР»СЊ).

Р—Р°РїРёСЃСЊ `leak_ref_bump = 0x0000100100001001` РїРѕ СЃРјРµС‰РµРЅРёСЋ `0x228` РїРµСЂРµР·Р°РїРёСЃС‹РІР°Р»Р° РєСЂРёС‚РёС‡РµСЃРєРѕРµ
РїРѕР»Рµ socket struct в†’ СЃР»РµРґСѓСЋС‰РёР№ `setsockopt`/`getsockopt` РЅР° СЌС‚РѕРј СЃРѕРєРµС‚Рµ РІС‹Р·С‹РІР°Р» kernel panic.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`, `krw_sockets_leak_forever()`
**РРјРїР°РєС‚:** РљР РРўРР§РќРћ вЂ” kernel panic РїРѕСЃР»Рµ РїРѕР»СѓС‡РµРЅРёСЏ kernel R/W, РґРѕ `ourproc()`

**Р¤РёРєСЃ:**
1. `socket_so_count_offset` С‚РµРїРµСЂСЊ РґРёРЅР°РјРёС‡РµСЃРєРёР№: `0x24c` РґР»СЏ iOS 17+, `0x228` РґР»СЏ iOS в‰¤16
2. Р”РѕР±Р°РІР»РµРЅР° СЃР°РЅРёС‚Р°СЂРЅР°СЏ РїСЂРѕРІРµСЂРєР°: РµСЃР»Рё lower 32 Р±РёС‚Р° РїСЂРѕС‡РёС‚Р°РЅРЅРѕРіРѕ `so_count` = 0 РёР»Рё > 0x10000,
   refcount bump РїСЂРѕРїСѓСЃРєР°РµС‚СЃСЏ СЃ Р»РѕРіРѕРј `SKIPPING refcount bump вЂ” so_count looks invalid`
3. `icmp6filt` cleanup (clearing second qword) РѕСЃС‚Р°РІР»РµРЅ РєР°Рє РµСЃС‚СЊ

---

## Р‘Р°Рі #222: `set_target_kaddr` Р±Р»РѕРєРёСЂРѕРІР°Р» 4-byte-aligned Р°РґСЂРµСЃР° вЂ” so_count read/write РЅРµРІРѕР·РјРѕР¶РµРЅ (2026-03-31, СЃРµСЃСЃРёСЏ 12)

**РЎРёРјРїС‚РѕРј (СЃРєСЂРёРЅС€РѕС‚/РІРёРґРµРѕ СЃ СѓСЃС‚СЂРѕР№СЃС‚РІР°):**
```
krw leak: using so_count offset 0x24c (iOS 17)
set_target_kaddr: BLOCKED misaligned addr 0x...bf36c (count=1)
getsockopt failed (early_kread)!
set_target_kaddr: BLOCKED misaligned addr 0x...bf724 (count=2)
getsockopt failed (early_kread)!
krw leak: so_count control=0x0 rw=0x0
krw leak: SKIPPING refcount bump вЂ” so_count looks invalid (ctl_lo=0x0 rw_lo=0x0), wrong offset?
```
РЎР°РЅРёС‚Р°СЂРЅР°СЏ РїСЂРѕРІРµСЂРєР° РёР· Bug #221 СЃРїР°СЃР»Р° РѕС‚ kernel panic, РЅРѕ refcount РЅРµ Р±С‹Р» Р±Р°РјРїРЅСѓС‚.

**Root cause:**
`set_target_kaddr()` РїСЂРѕРІРµСЂСЏР» `where & 7` Рё Р±Р»РѕРєРёСЂРѕРІР°Р» РІСЃРµ Р°РґСЂРµСЃР°, РЅРµ РєСЂР°С‚РЅС‹Рµ 8 Р±Р°Р№С‚Р°Рј.
Offset `so_count` = `0x24c`: `0x24c & 7 = 4` вЂ” 4-byte aligned, РЅРѕ РќР• 8-byte aligned.
`socket_addr + 0x24c` в†’ Р°РґСЂРµСЃ `...36c` в†’ `0x36c & 7 = 4` в†’ BLOCKED.

РџСЂРµРґС‹РґСѓС‰РёР№ offset `0x228` СЂР°Р±РѕС‚Р°Р»: `0x228 & 7 = 0` (8-byte aligned). РџРѕСЌС‚РѕРјСѓ РїСЂРѕР±Р»РµРјР°
РїРѕСЏРІРёР»Р°СЃСЊ С‚РѕР»СЊРєРѕ РїРѕСЃР»Рµ РїРµСЂРµС…РѕРґР° РЅР° РїСЂР°РІРёР»СЊРЅС‹Р№ offset РІ Bug #221.

`copyout()`/`copyin()` РЅР° ARM64 СЂР°Р±РѕС‚Р°СЋС‚ СЃ Р»СЋР±С‹Рј Р±Р°Р№С‚РѕРІС‹Рј РІС‹СЂР°РІРЅРёРІР°РЅРёРµРј.
Zone metadata lookup вЂ” per-page (16KB), РЅРµ Р·Р°РІРёСЃРёС‚ РѕС‚ byte alignment.
Р РµР°Р»СЊРЅР°СЏ РѕРїР°СЃРЅРѕСЃС‚СЊ вЂ” С‚РѕР»СЊРєРѕ РЅРµС‡С‘С‚РЅС‹Рµ (bit0=1) tagged pointer Р°РґСЂРµСЃР°.

**Р¤Р°Р№Р»:** `darksword/darksword_core.m`, `set_target_kaddr()`
**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™ вЂ” refcount РЅРµ Р±Р°РјРїРёС‚СЃСЏ в†’ socket РјРѕР¶РµС‚ Р±С‹С‚СЊ РѕСЃРІРѕР±РѕР¶РґС‘РЅ РїСЂРё РІС‹С…РѕРґРµ РёР· app в†’ UAF

**Р¤РёРєСЃ:**
РР·РјРµРЅРµРЅР° РїСЂРѕРІРµСЂРєР° РІС‹СЂР°РІРЅРёРІР°РЅРёСЏ СЃ `where & 7` РЅР° `where & 3`:
- РџСЂРѕРїСѓСЃРєР°РµС‚ 4-byte-aligned Р°РґСЂРµСЃР° (РїРѕРєСЂС‹РІР°РµС‚ so_count 0x24c)
- Р‘Р»РѕРєРёСЂСѓРµС‚ РЅРµС‡С‘С‚РЅС‹Рµ Рё 2-byte-aligned (tagged pointer defense)
- `copyout`/`copyin` РЅР° ARM64 РЅРµ С‚СЂРµР±СѓСЋС‚ 8-byte alignment

---

## РЎРµСЃСЃРёСЏ 13 (2026-03-31) вЂ” Bug #226b

### Bug #226b: allproc scan kernel data abort on unmapped zone pages

**РЎРёРјРїС‚РѕРј:** РџР°РЅРёРєР° `Kernel data abort` at PC 0xfffffff02620c810 (pid 542: DarkSword)
РїСЂРё СЃРєР°РЅРёСЂРѕРІР°РЅРёРё `__DATA.__common` РґР»СЏ РїРѕРёСЃРєР° allproc.

**Р¤Р°Р№Р» РїР°РЅРёРєРё:** `crashes_session13/panic-full-2026-03-31-195420.0002.ips`
**Syslog:** `log/syslog_session13.txt`

**РђРЅР°Р»РёР·:**
```
zone_map [0xffffffdd9faf0000 - 0xffffffe39faf0000] safe_min=0xffffffdf1faf0000
kbase=0xfffffff025408000, slide=0x1e404000
__DATA.__common scan: 0xfffffff0285cb000..0xfffffff028623000 (0x58000 bytes)

Chunk 0 (0xfffffff0285c8000): OK, 2 candidates в†’ disc_layout FAILED (non-proc)
Chunk 1 (0xfffffff0285cc000): OK, 1 candidate в†’ disc_layout FAILED (non-proc)
Chunk 2 (0xfffffff0285d0000): в†’ [disconnected] KERNEL PANIC
```

**Root cause:** Р”Р’Р• РїСЂРѕР±Р»РµРјС‹:

1. **РќРµРїСЂР°РІРёР»СЊРЅС‹Р№ РїСЂСЏРјРѕР№ РєР°РЅРґРёРґР°С‚ 0x93B348:**
   - Р‘С‹Р» РІС‹С‡РёСЃР»РµРЅ РєР°Рє UNSLID_ALLPROC(0xFFFFFFF00793F348) - OUTER_KBASE(0xfffffff007004000)
   - РќРћ outer kbase в‰  inner kernel TEXT base РІ fileset kernelcache
   - kbase + 0x93B348 = 0xfffffff025D43348 вЂ” СЌС‚Рѕ РџР•Р Р•Р” __DATA.__common (0xfffffff0285CB000)
   - РџРѕРїР°РґР°РµС‚ РІ kernel TEXT/DATA_CONST, РќР• РІ __DATA.__common в†’ РІСЃРµРіРґР° fail

2. **РџРѕСЂСЏРґРѕРє СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ __DATA.__common:**
   - allproc РЅР°С…РѕРґРёС‚СЃСЏ РїСЂРё outer __DATA + 0x67F30 = kbase + 0x31FFF30
   - Р­С‚Рѕ 68% С‡РµСЂРµР· __DATA.__common (chunk ~15 РёР· 22)
   - РќРѕ СЃРєР°РЅРёСЂРѕРІР°РЅРёРµ РёРґС‘С‚ СЃ РќРђР§РђР›Рђ (chunk 0), Р° СЂР°РЅРЅСЏСЏ С‡Р°СЃС‚СЊ __DATA.__common
     СЃРѕРґРµСЂР¶РёС‚ heap-like СѓРєР°Р·Р°С‚РµР»Рё РЅР° GEN1/GEN2 zone pages
   - РќРµРєРѕС‚РѕСЂС‹Рµ zone pages РќР• Р·Р°РјР°РїР»РµРЅС‹ (РЅРµ РІС‹РґРµР»РµРЅС‹ Р°Р»Р»РѕРєР°С‚РѕСЂРѕРј)
   - `ds_kread_checked()` РЅРµ РјРѕР¶РµС‚ РѕР±РЅР°СЂСѓР¶РёС‚СЊ unmapped pages:
     Р°РґСЂРµСЃ РїСЂРѕС…РѕРґРёС‚ РїСЂРѕРІРµСЂРєСѓ `[zone_map_min, zone_map_max)`,
     РЅРѕ kernel РїР°РґР°РµС‚ РІ copyout() РЅР° translation fault L3
   - Crash РїСЂРё chunk 2 вЂ” Р”Рћ С‚РѕРіРѕ РєР°Рє scan РґРѕС€С‘Р» РґРѕ РїСЂР°РІРёР»СЊРЅРѕРіРѕ offset

**Р¤РёРєСЃ РІ `darksword/utils.m`:**

1. `kernprocaddress()`: Р·Р°РјРµРЅС‘РЅ РїСЂСЏРјРѕР№ РєР°РЅРґРёРґР°С‚ 0x93B348 в†’ 0x31FFF30
   - 0x31FFF30 = outer __DATA(0x3198000) + 0x67F30 (offline analysis build 21D61)
   - РџСЂРѕРІРµСЂРµРЅРѕ: РїРѕРїР°РґР°РµС‚ РІ __DATA.__common [0x31C3000, 0x3223000)

2. `scan_allproc_known_range()`: РёР·РјРµРЅС‘РЅ РїРѕСЂСЏРґРѕРє СЃРєР°РЅРёСЂРѕРІР°РЅРёСЏ:
   - РџР•Р Р’Р«Р™: СѓР·РєРѕРµ РѕРєРЅРѕ В±0x4000 РІРѕРєСЂСѓРі kbase+0x31FFF30 (48 KB, Р±РµР·РѕРїР°СЃРЅР°СЏ Р·РѕРЅР°)
   - Р’РўРћР РћР™: РІС‚РѕСЂР°СЏ РїРѕР»РѕРІРёРЅР° __DATA.__common (176 KB)
   - РўР Р•РўРР™: РїРѕР»РЅС‹Р№ __DATA.__common (360 KB, РѕРїР°СЃРЅС‹Р№ РЅРѕ last resort)
   - Р§Р•РўР’РЃР РўР«Р™: __DATA.__bss fallback

3. РЈРґР°Р»С‘РЅ РѕС€РёР±РѕС‡РЅС‹Р№ scan range `{ 0x933000, 0x10000, "__DATA_allproc_region" }`

**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” kernel panic РїСЂРё РєР°Р¶РґРѕР№ Р·Р°РіСЂСѓР·РєРµ, allproc РЅРµРґРѕСЃС‚СѓРїРµРЅ

---

## РЎРµСЃСЃРёРё 15вЂ“16 (2026-03-31) вЂ” Bug #227 / Bug #228

### Bug #227: `g_zone_safe_min` РѕС‚СЂРµР·Р°Р» РІР°Р»РёРґРЅС‹Рµ proc pointers

**РЎРёРјРїС‚РѕРј:** СЃРёР»СЊРЅС‹Р№ РєР°РЅРґРёРґР°С‚ РІ `allproc` narrow window РІС‹РіР»СЏРґРµР» СЂРµР°Р»СЊРЅС‹Рј proc, РЅРѕ
`discover_proc_list_layout()` РІСЃС‘ СЂР°РІРЅРѕ РµРіРѕ РѕС‚РІРµСЂРіР°Р».

**РќР°Р±Р»СЋРґРµРЅРёРµ РёР· `syslog_session15.txt`:**
- candidate addr: `kbase + 0x31FFB50`
- `raw_head=0xffffffde2c3c8bc0`
- `pid=0`
- `le_next=0xffffffdcf911a500`
- `nextpid=0`

РЎС‚Р°СЂС‹Р№ `is_heap_ptr()` РёСЃРїРѕР»СЊР·РѕРІР°Р» `g_zone_safe_min`, РєРѕС‚РѕСЂС‹Р№ РЅСѓР¶РµРЅ РґР»СЏ Р‘Р›РРќР”-СЃРєР°РЅР°,
РЅРѕ СЃР»РёС€РєРѕРј СЃС‚СЂРѕРі РґР»СЏ СѓР¶Рµ РЅР°Р№РґРµРЅРЅС‹С… curated candidates. Р§Р°СЃС‚СЊ РІР°Р»РёРґРЅС‹С… proc pointers
Р»РµР¶Р°Р»Р° РЅРёР¶Рµ `safe_min`, РЅРѕ РІСЃС‘ РµС‰С‘ РІРЅСѓС‚СЂРё РЅР°СЃС‚РѕСЏС‰РµРіРѕ `zone_map`.

**Р¤РёРєСЃ:**
- РґРѕР±Р°РІР»РµРЅ `is_heap_ptr_relaxed()`
- РІ `discover_proc_list_layout()` Рё `validate_proc_chain()` РїРµСЂРµС…РѕРґ РЅР° raw
  `zone_map_min..zone_map_max` Р±РµР· `safe_min`

### Bug #228: validator РѕР¶РёРґР°Р» С‚РѕР»СЊРєРѕ РїР°С‚С‚РµСЂРЅ `pid0 -> pid1`

**РЎРёРјРїС‚РѕРј:** РґР°Р¶Рµ РїРѕСЃР»Рµ relaxed zone bounds РєР°РЅРґРёРґР°С‚ `0x31FFB50` РЅРµ РїСЂРёРЅРёРјР°Р»СЃСЏ.

**Root cause:** Р»РѕРіРёРєР° РІР°Р»РёРґР°С†РёРё Р±С‹Р»Р° СЃР»РёС€РєРѕРј Р¶С‘СЃС‚РєРѕР№:
- РѕР¶РёРґР°Р»Р°, С‡С‚Рѕ СЃР»РµРґСѓСЋС‰РёР№ proc РїРѕСЃР»Рµ kernel proc СЃСЂР°Р·Сѓ РґР°СЃС‚ `pid=1`
- Р»РёР±Рѕ С‡С‚Рѕ РїРѕР»РЅР°СЏ chain validation РјРіРЅРѕРІРµРЅРЅРѕ РЅР°Р№РґС‘С‚ `pid 1`

РќР° СЂРµР°Р»СЊРЅРѕРј iPad8,9 РЅР°Р±Р»СЋРґР°Р»СЃСЏ РїР°С‚С‚РµСЂРЅ `pid0 -> pid0 -> ...`, С‡С‚Рѕ Р»РѕРјР°Р»Рѕ СЌРІСЂРёСЃС‚РёРєСѓ,
С…РѕС‚СЏ СЃР°Рј РєР°РЅРґРёРґР°С‚ РІС‹РіР»СЏРґРµР» РЅР°РјРЅРѕРіРѕ РїСЂР°РІРґРѕРїРѕРґРѕР±РЅРµРµ РѕСЃС‚Р°Р»СЊРЅС‹С….

**Р¤РёРєСЃ РІ `darksword/utils.m`:**
1. РґРѕР±Р°РІР»РµРЅ РґРёРЅР°РјРёС‡РµСЃРєРёР№ РїРµСЂРµР±РѕСЂ `PROC_PID_OFFSET`: `0x60`, `0x28`, `0x10`
2. РґРѕР±Р°РІР»РµРЅР° helper-С„СѓРЅРєС†РёСЏ С‡С‚РµРЅРёСЏ pid СЃ СЂР°Р·РЅС‹РјРё offset
3. РґРѕР±Р°РІР»РµРЅР° РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅР°СЏ РїСЂРѕРІРµСЂРєР° `pid0 -> pid0 -> nextnextpid`
4. РґРѕР±Р°РІР»РµРЅС‹ curated nearby candidates:
   - `kbase + 0x31FFB50`
   - `kbase + 0x31FFC68`
5. РІРµСЂСЃРёСЏ РїСЂРёР»РѕР¶РµРЅРёСЏ РїРѕРґРЅСЏС‚Р° РґРѕ `1.0.16` / build `16`, С‡С‚РѕР±С‹ install Р±С‹Р» РІРёРґРµРЅ РЅР° СѓСЃС‚СЂРѕР№СЃС‚РІРµ

**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™ вЂ” Р±РµР· С„РёРєСЃР° exploit РґРѕС…РѕРґРёР» РґРѕ post-kernel-r/w, РЅРѕ РЅРµ РјРѕРі РЅР°РґС‘Р¶РЅРѕ
РїРѕР»СѓС‡РёС‚СЊ `ourproc()` Рё РїСЂРѕРґРѕР»Р¶РёС‚СЊ post-exploitation.

### Bug #241: ourproc() С…РѕРґРёС‚ РѕС‚ kernel_task (tail), РЅРµ РѕС‚ allproc HEAD

**РЎРµСЃСЃРёСЏ:** 25c (3-Р№ Р·Р°РїСѓСЃРє, PID 362)

**РЎРёРјРїС‚РѕРј:** `kernprocaddress()` РІРѕР·РІСЂР°С‰Р°РµС‚ `kbase+0x321C480` (score=49, 198 procs). РќРѕ `ourproc()` С…РѕРґРёС‚ РїРѕ 198 РїСЂРѕС†РµСЃСЃР°Рј (pid 0в†’262в†’...в†’225в†’NULL) Рё РќР• РЅР°С…РѕРґРёС‚ PID 362.

**Root cause:** `kbase+0x321C480` вЂ” СЌС‚Рѕ `kernproc` (tail pointer РЅР° kernel_task), Р° РќР• `allproc.lh_first`. Р’ XNU `LIST_INSERT_HEAD` СЃС‚Р°РІРёС‚ РЅРѕРІС‹Рµ РїСЂРѕС†РµСЃСЃС‹ РІ РіРѕР»РѕРІСѓ в†’ head РґРѕР»Р¶РµРЅ СѓРєР°Р·С‹РІР°С‚СЊ РЅР° PIDв‰Ґ362.

**Р¤РёРєСЃ:** ~~Nearby-head scan В±0x90~~ **Р—Р°РјРµРЅС‘РЅ Bug #243** (offline analysis РґРѕРєР°Р·Р°Р»Р° РЅРµСЌС„С„РµРєС‚РёРІРЅРѕСЃС‚СЊ).

**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ в†’ Р—РђРњР•РќРЃРќ #243


### Bug #242: zone scan СЏРєРѕСЂСЊ РІ Р·РѕРЅРµ kernel_task, РґР°Р»РµРєРѕ РѕС‚ user procs

**РЎРµСЃСЃРёСЏ:** 25c

**РЎРёРјРїС‚РѕРј:** Zone scan anchor = kernel_task addr (`0xffffffe1...`), user procs РІ `0xffffffdf...` вЂ” СЂР°Р·СЂС‹РІ ~3.7 Р“Р‘, scan РїРѕРєСЂС‹РІР°РµС‚ С‚РѕР»СЊРєРѕ 267 РљР‘.

**Р¤РёРєСЃ:** РћС‚РґРµР»СЊРЅРѕРµ РѕС‚СЃР»РµР¶РёРІР°РЅРёРµ `user_max`/`user_min` (PID > 0). `SCAN_STEPS` в†’ 2000, fine-grained range в†’ В±1 РњР‘, `MAX_FINE_READS` в†’ 40000.

**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™


### Bug #243: offline analysis вЂ” backward walk + alt list offsets (Р—РђРњР•РќРЇР•Рў Bug #241)

**РЎРµСЃСЃРёСЏ:** 25c в†’ offline_test_v6

**РЎРёРјРїС‚РѕРј:** Bug #241 nearby-head scan (В±0x90 = В±144 Р±Р°Р№С‚) РЅРµ РјРѕР¶РµС‚ РґРѕСЃС‚РёС‡СЊ РЅРё РѕРґРЅРѕРіРѕ РєР°РЅРґРёРґР°С‚Р° allproc. Р‘Р»РёР¶Р°Р№С€РёР№ РєР°РЅРґРёРґР°С‚ РІ 23 РљР‘, СЂРµР°Р»СЊРЅС‹Р№ allproc (PPLDATA) РІ 529 РљР‘.

**Root cause (offline_test_v6):**
- `kbase+0x321C480` РёРјРµРµС‚ **0 code xrefs** РІ kernelcache в†’ СЌС‚Рѕ runtime-var РІ __DATA.__bss, РќР• allproc
- `list_off=0xb0` РјРѕР¶РµС‚ Р±С‹С‚СЊ `p_pglist` (РїСЂРѕС†РµСЃСЃ-РіСЂСѓРїРїР°), Р° РќР• `p_list` (allproc)
- Р РµР°Р»СЊРЅС‹Р№ allproc РІ `__PPLDATA` (`kbase+0x3198060`) вЂ” РґРѕСЃС‚СѓРїРµРЅ РўРћР›Р¬РљРћ РёР· `__PPLTEXT` (PPL code), kread РЅРµ РјРѕР¶РµС‚ РїСЂРѕС‡РёС‚Р°С‚СЊ
- PPLDATA allproc РёРјРµРµС‚ РІСЃРµРіРѕ 2 code xrefs РёР· PPL text (0x84b1278, 0x84b1450)
- РўРѕРї allproc-РєР°РЅРґРёРґР°С‚: `kbase+0x31C3000` (2727 code xrefs, __DATA.__common) вЂ” РЅРѕ С‚РѕР¶Рµ РЅРµ РґРѕСЃС‚СѓРїРµРЅ РєР°Рє allproc variable

**Р¤РёРєСЃ (Bug #243A вЂ” backward walk):**
- РџРѕСЃР»Рµ forward walk РЅРµ РЅР°С€С‘Р» РЅР°С€ PID в†’ С…РѕРґРёРј РќРђР—РђР” С‡РµСЂРµР· `le_prev`
- `le_prev` = `&prev_proc->le_next` = `prev_proc + list_off`
- `prev_proc = le_prev_value - list_off`
- РћСЃС‚Р°РЅР°РІР»РёРІР°РµРјСЃСЏ РєРѕРіРґР° `le_prev` СѓРєР°Р·С‹РІР°РµС‚ РЅР° kernel data (= `&allproc.lh_first`)
- РџРѕРєСЂС‹РІР°РµС‚ РІСЃРµ РїСЂРѕС†РµСЃСЃС‹ РџР•Р Р•Р” РЅР°С€РµР№ СЃС‚Р°СЂС‚РѕРІРѕР№ С‚РѕС‡РєРѕР№

**Р¤РёРєСЃ (Bug #243B вЂ” alt list offsets):**
- Р•СЃР»Рё `list_off=0xb0` вЂ” СЌС‚Рѕ `p_pglist`, СЂРµР°Р»СЊРЅР°СЏ `p_list` РЅР° РґСЂСѓРіРѕРј РѕС„С„СЃРµС‚Рµ
- РџСЂРѕР±СѓРµРј `list_off` = 0x00, 0x08, 0x10, 0x18, 0xa8 (РіРґРµ РѕР±С‹С‡РЅРѕ Р¶РёРІС‘С‚ p_list)
- Р”Р»СЏ РєР°Р¶РґРѕРіРѕ: forward + backward walk РѕС‚ kernel_task proc

**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™


### Bug #244: runtime fallback РїСЂРѕРїСѓСЃРєР°Р» `list_off=0xa8`, С…РѕС‚СЏ offline refs СѓРєР°Р·С‹РІР°СЋС‚ РЅР° mixed-layout СЃС†РµРЅР°СЂРёР№

**РЎРµСЃСЃРёСЏ:** offline_test_v7 / v8 / v9

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ Bug #243 СЂР°РЅС‚Р°Р№Рј-РїСЂРѕР±СЂРѕСЃ list offsets РІ `ourproc()` РїСЂРѕР±РѕРІР°Р» С‚РѕР»СЊРєРѕ `0x00, 0x08, 0x10, 0x18`, С…РѕС‚СЏ `validate_direct_allproc_v2()` СѓР¶Рµ РёСЃРїРѕР»СЊР·РѕРІР°Р» `0xa8` РєР°Рє РґРѕРїСѓСЃС‚РёРјС‹Р№ SMRQ/BSD hybrid candidate.

**Root cause:** РџСЂРѕРґРѕР»Р¶РµРЅРёРµ offline-Р°РЅР°Р»РёР·Р° РїРѕРєР°Р·Р°Р»Рѕ:
- `kbase+0x321C480` Рё `kbase+0x321C400` РёРјРµСЋС‚ 0 exact xrefs
- СЂСЏРґРѕРј РµСЃС‚СЊ exact-referenced cluster: `0x321C220`, `0x321C240`, `0x321C248`
- refined runtime path РґРѕР»Р¶РµРЅ РїРѕРєСЂС‹РІР°С‚СЊ РЅРµ С‚РѕР»СЊРєРѕ РєР»Р°СЃСЃРёС‡РµСЃРєРёРµ РјР°Р»РµРЅСЊРєРёРµ offsets, РЅРѕ Рё `0xa8`, РєРѕС‚РѕСЂС‹Р№ СѓР¶Рµ С„РёРіСѓСЂРёСЂРѕРІР°Р» РІ direct validation

**Р¤РёРєСЃ:** Р’ Bug #243B runtime fallback СЂР°СЃС€РёСЂРµРЅ: `alt_list_offs[] = { 0x00, 0x08, 0x10, 0x18, 0xa8 }`.

**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ в†’ Р’Р«РЎРћРљРР™


### Bug #245: strongest offline allproc-РєР°РЅРґРёРґР°С‚С‹ Р±С‹Р»Рё С‚РѕР»СЊРєРѕ РІ range-scan, Р° РЅРµ РІ СЂР°РЅРЅРµРј direct-path

**РЎРµСЃСЃРёСЏ:** offline_test_v10

**РЎРёРјРїС‚РѕРј:** Р”Р°Р¶Рµ РїРѕСЃР»Рµ Bug #243/#244 РјС‹ РІСЃС‘ РµС‰С‘ РїРѕР»Р°РіР°Р»РёСЃСЊ РЅР° noisy `scan_allproc_known_range()` РґР»СЏ Р»СѓС‡С€РёС… offline-РєР°РЅРґРёРґР°С‚РѕРІ, С…РѕС‚СЏ refined focused analysis РїРѕ proc-related windows СѓР¶Рµ РІС‹РґРµР»РёР»Р° shortlist СЃРёР»СЊРЅС‹С… Р°РґСЂРµСЃРѕРІ.

**Root cause:** `kernprocaddress()` РїСЂРѕР±РѕРІР°Р» С‚РѕР»СЊРєРѕ runtime-РєР°РЅРґРёРґР°С‚С‹ `0x321C400/408/3F8`, Р° strongest offline candidates (`0x31C3000`, `0x31C30B0`, `0x3213EC8`) РѕСЃС‚Р°РІР°Р»РёСЃСЊ РґРѕСЃС‚СѓРїРЅС‹РјРё Р»РёС€СЊ С‡РµСЂРµР· С€РёСЂРѕРєРёР№ scan. Р­С‚Рѕ С…СѓР¶Рµ РїРѕ Р±РµР·РѕРїР°СЃРЅРѕСЃС‚Рё Рё РґРёР°РіРЅРѕСЃС‚РёРєРµ: single 8-byte reads Р±РµР·РѕРїР°СЃРЅРµРµ 16KB scan chunks.

**Р¤РёРєСЃ:** Р’ direct path РґРѕР±Р°РІР»РµРЅС‹:
- `kbase+0x31C3000` вЂ” strongest focused candidate РёР· proc-related windows
- `kbase+0x31C30B0` вЂ” companion candidate РІ РїРµСЂРІРѕР№ СЃС‚СЂР°РЅРёС†Рµ `__common`
- `kbase+0x3213EC8` вЂ” strongest non-page-boundary `__common` candidate

РўРµРїРµСЂСЊ direct shortlist:
`{ 0x31C3000, 0x31C30B0, 0x3213EC8, 0x321C400, 0x321C408, 0x321C3F8 }`

**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™


### Bug #247: direct-path РЅРµ РІРєР»СЋС‡Р°Р» РЅРѕРІС‹Рµ list-head РєР°РЅРґРёРґР°С‚С‹ РёР· `offline_test_v11/v12/v14`

**РЎРµСЃСЃРёСЏ:** offline_test_v11 / v12 / v13 / v14

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ Bug #246 direct-path СѓР¶Рµ РІРєР»СЋС‡Р°Р» runtime-cluster `0x321C220/240/248`, РЅРѕ РЅРµ РІРєР»СЋС‡Р°Р» РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅС‹Рµ РѕС„Р»Р°Р№РЅ-РєР°РЅРґРёРґР°С‚С‹, РїРѕСЏРІРёРІС€РёРµСЃСЏ РІ СЃР»РµРґСѓСЋС‰РёС… С‚РµСЃС‚Р°С…:
- `0x3213680` вЂ” strongest `__common` doubly-linked candidate РёР· `v14`
- `0x3214850` вЂ” runtime-adjacent next-like candidate РёР· `v11/v12`

**Root cause:** shortlist direct candidates РѕС‚СЃС‚Р°РІР°Р» РѕС‚ latest offline analysis. Р’ СЂРµР·СѓР»СЊС‚Р°С‚Рµ С‡Р°СЃС‚СЊ Р±РµР·РѕРїР°СЃРЅС‹С… single-read probes РѕСЃС‚Р°РІР°Р»Р°СЃСЊ РґРѕСЃС‚СѓРїРЅРѕР№ С‚РѕР»СЊРєРѕ РєРѕСЃРІРµРЅРЅРѕ С‡РµСЂРµР· С€РёСЂРѕРєРёР№ scan.

**Р¤РёРєСЃ:** Р’ `kernprocaddress()` direct shortlist СЂР°СЃС€РёСЂРµРЅ:
- `0x3213680`
- `0x3214850`

РС‚РѕРіРѕРІС‹Р№ shortlist С‚РµРїРµСЂСЊ:
`{ 0x31C3000, 0x3213680, 0x3214850, 0x31C30B0, 0x3213EC8, 0x321C220, 0x321C240, 0x321C248, 0x321C400, 0x321C408, 0x321C3F8 }`

**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ в†’ Р’Р«РЎРћРљРР™


### Bug #248: strongest runtime-cluster candidate `0x321C240` РїСЂРѕР±РѕРІР°Р»СЃСЏ СЃР»РёС€РєРѕРј РїРѕР·РґРЅРѕ РІ direct-path

**РЎРµСЃСЃРёСЏ:** offline_test_v15

**РЎРёРјРїС‚РѕРј:** even after Bug #247 shortlist РІСЃС‘ РµС‰С‘ РЅР°С‡РёРЅР°Р»СЃСЏ СЃ `0x31C3000`, Р° runtime-cluster candidate `0x321C240` РїСЂРѕР±РѕРІР°Р»СЃСЏ С‚РѕР»СЊРєРѕ РїРѕСЃР»Рµ РЅРµСЃРєРѕР»СЊРєРёС… Р±РѕР»РµРµ СЃР»Р°Р±С‹С… РѕС„Р»Р°Р№РЅ-Р°РґСЂРµСЃРѕРІ. Р­С‚Рѕ Р·Р°РјРµРґР»СЏР»Рѕ РїСѓС‚СЊ Рє РЅР°РёР±РѕР»РµРµ semantically convincing single-read probe.

**Root cause:** РїРѕСЂСЏРґРѕРє direct shortlist РёСЃС‚РѕСЂРёС‡РµСЃРєРё СЂРѕСЃ РїРѕ РјРµСЂРµ РґРѕР±Р°РІР»РµРЅРёСЏ РєР°РЅРґРёРґР°С‚РѕРІ, РЅРѕ РЅРµ Р±С‹Р» РїРµСЂРµСЃРѕР±СЂР°РЅ РїРѕСЃР»Рµ `offline_test_v12/v14/v15`. РњРµР¶РґСѓ С‚РµРј РёРјРµРЅРЅРѕ `0x321C240` РґР°Р» strongest runtime-adjacent doubly-linked head pattern:
- `LDR head`
- С‡С‚РµРЅРёРµ `head->prev` Рё `head->next`
- Р·Р°С‚РµРј Р·Р°РїРёСЃРё РІРёРґР° `STR ..., [node,#0x8]` Рё `STR ..., [head]`

`0x323C058/0x323C068` РїРѕСЃР»Рµ `v15` РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅРѕ РѕСЃР»Р°Р±Р»Рё, РїРѕС‚РѕРјСѓ С‡С‚Рѕ РёС… СѓР·Р»С‹ РёСЃРїРѕР»СЊР·СѓСЋС‚ РїРѕР»СЏ `+0x50/+0x54`, РЅРµ РїРѕС…РѕР¶РёРµ РЅР° `proc`.

**Р¤РёРєСЃ:** Р’ `kernprocaddress()` direct shortlist reordered С‚Р°Рє, С‡С‚РѕР±С‹ `0x321C240` РїСЂРѕР±РѕРІР°Р»СЃСЏ РїРµСЂРІС‹Рј, Р° РµРіРѕ СЃРѕСЃРµРґРё `0x321C220/0x321C248` РѕСЃС‚Р°Р»РёСЃСЊ РєР°Рє weaker follow-up probes.

РќРѕРІС‹Р№ shortlist:
`{ 0x321C240, 0x31C3000, 0x3213680, 0x3214850, 0x31C30B0, 0x3213EC8, 0x321C220, 0x321C248, 0x321C400, 0x321C408, 0x321C3F8 }`

**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ в†’ Р’Р«РЎРћРљРР™


### Bug #249: direct-path РІСЃС‘ РµС‰С‘ РїРµСЂРµРѕС†РµРЅРёРІР°Р» next-only `0x3213EC8` Рё РЅРµРґРѕРѕС†РµРЅРёРІР°Р» doubly-linked `0x3213680`

**РЎРµСЃСЃРёСЏ:** offline_test_v16 / v17

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ Bug #248 strongest runtime candidate `0x321C240` СѓР¶Рµ С€С‘Р» РїРµСЂРІС‹Рј, РЅРѕ РґР°Р»СЊС€Рµ shortlist РІСЃС‘ РµС‰С‘ СЂР°РЅСЊС€Рµ РїСЂРѕР±РѕРІР°Р» `0x31C3000` Рё РґРµСЂР¶Р°Р» `0x3213EC8` СЃР»РёС€РєРѕРј РІС‹СЃРѕРєРѕ, С…РѕС‚СЏ РЅРѕРІС‹Рµ offline semantics РїРѕРєР°Р·С‹РІР°Р»Рё, С‡С‚Рѕ `0x3213EC8` вЂ” СЌС‚Рѕ noisy next-only list, Р° РЅРµ convincing proc-list head.

**Root cause:** РїСЂРµР¶РЅРёР№ shortlist РІСЃС‘ РµС‰С‘ РѕРїРёСЂР°Р»СЃСЏ РЅР° СЃС‚Р°СЂС‹Рµ focused/xref heuristics. `offline_test_v16` РїРѕРєР°Р·Р°Р» РїРµСЂРµРєРѕСЃ: `0x3213EC8` РїРѕР»СѓС‡Р°РµС‚ РѕРіСЂРѕРјРЅС‹Р№ score С‚РѕР»СЊРєРѕ Р·Р° РјР°СЃСЃРѕРІС‹Рµ `next` hops Р±РµР· `prev`, `PID@0x60` Рё head-mutation РїР°С‚С‚РµСЂРЅРѕРІ. РџРѕСЃР»Рµ СЌС‚РѕРіРѕ `offline_test_v17` СЃ double-link-only ranking РїРѕРґС‚РІРµСЂРґРёР» Р±РѕР»РµРµ РїСЂР°РІРёР»СЊРЅС‹Р№ РїРѕСЂСЏРґРѕРє confidence:
- `0x321C240` вЂ” strongest runtime doubly-linked head
- `0x3213680` вЂ” strongest `__common` doubly-linked fallback
- `0x31C3000` вЂ” РїРѕР»РµР·РЅС‹Р№ fallback, РЅРѕ СѓР¶Рµ СЃР»Р°Р±РµРµ РїРѕ СЃС‚СЂСѓРєС‚СѓСЂРЅРѕР№ СЃРµРјР°РЅС‚РёРєРµ
- `0x3213EC8` вЂ” noisy next-only РѕР±СЉРµРєС‚РЅС‹Р№ СЃРїРёСЃРѕРє, РіРѕРґРёС‚СЃСЏ Р»РёС€СЊ РєР°Рє last resort

**Р¤РёРєСЃ:** Р’ `kernprocaddress()` direct shortlist reordered:
- `0x3213680` РїРѕРґРЅСЏС‚ РІС‹С€Рµ `0x31C3000`
- `0x3213EC8` РїРµСЂРµРЅРµСЃС‘РЅ РІ СЃР°РјС‹Р№ РєРѕРЅРµС†

РќРѕРІС‹Р№ shortlist:
`{ 0x321C240, 0x3213680, 0x31C3000, 0x3214850, 0x31C30B0, 0x321C220, 0x321C248, 0x321C400, 0x321C408, 0x321C3F8, 0x3213EC8 }`

**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ в†’ Р’Р«РЎРћРљРР™


### Bug #250: `0x3214850` РѕСЃС‚Р°РІР°Р»СЃСЏ СЃР»РёС€РєРѕРј РІС‹СЃРѕРєРѕ, С…РѕС‚СЏ `offline_test_v18` РїРѕРґС‚РІРµСЂРґРёР» С‚РѕР»СЊРєРѕ next-like СЃРµРјР°РЅС‚РёРєСѓ

**РЎРµСЃСЃРёСЏ:** offline_test_v18

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ Bug #249 shortlist СѓР¶Рµ РЅР°С‡РёРЅР°Р»СЃСЏ РїСЂР°РІРёР»СЊРЅРѕ (`0x321C240`, `0x3213680`), РЅРѕ `0x3214850` РІСЃС‘ РµС‰С‘ РїСЂРѕР±РѕРІР°Р»СЃСЏ СЂР°РЅСЊС€Рµ С‡Р°СЃС‚Рё Р±РѕР»РµРµ СЃС‚СЂСѓРєС‚СѓСЂРЅС‹С… fallback-РєР°РЅРґРёРґР°С‚РѕРІ, РЅРµСЃРјРѕС‚СЂСЏ РЅР° РѕС‚СЃСѓС‚СЃС‚РІРёРµ РЅРѕРІС‹С… РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІ proc-list СЃРµРјР°РЅС‚РёРєРё.

**Root cause:** `offline_test_v18` СЂР°Р·РѕР±СЂР°Р» evidence windows РїРѕ СЃРїРѕСЂРЅС‹Рј РєР°РЅРґРёРґР°С‚Р°Рј Рё РїРѕРєР°Р·Р°Р»:
- `0x31C3000` РІСЃС‘ РµС‰С‘ РёРјРµРµС‚ РѕРіСЂР°РЅРёС‡РµРЅРЅС‹Рµ, РЅРѕ СЂРµР°Р»СЊРЅС‹Рµ СЃРёРіРЅР°Р»С‹ (`PID@+0x60`, `store [head]`, СЂРµРґРєРёРµ link accesses)
- `0x31C30B0` С…РѕС‚СЏ Рё РЅРµ РґР°С‘С‚ proc traversal, Р·Р°С‚Рѕ СЃС‚Р°Р±РёР»СЊРЅРѕ РёСЃРїРѕР»СЊР·СѓРµС‚ paired-head reads `LDR [head,#0]` + `LDR [head,#0x8]`
- `0x3214850` РІРѕ РІСЃРµС… РѕРєРЅР°С… РѕСЃС‚Р°С‘С‚СЃСЏ С‚РѕР»СЊРєРѕ `next`-like РєР°РЅРґРёРґР°С‚РѕРј Р±РµР· `prev`, Р±РµР· `PID`, Р±РµР· doubly-linked head mutation
- `0x3213EC8` РѕРєРѕРЅС‡Р°С‚РµР»СЊРЅРѕ РїРѕРґС‚РІРµСЂР¶РґС‘РЅ РєР°Рє next-only object-list noise

РўРѕ РµСЃС‚СЊ `0x3214850` РѕРєР°Р·Р°Р»СЃСЏ СЃР»Р°Р±РµРµ РЅРµ С‚РѕР»СЊРєРѕ `0x321C240/0x3213680/0x31C3000`, РЅРѕ Рё СЃР»Р°Р±РµРµ paired-head fallback `0x31C30B0` Рё runtime-cluster neighbors.

**Р¤РёРєСЃ:** Р’ `kernprocaddress()` direct shortlist reordered РµС‰С‘ СЂР°Р·:
- `0x31C30B0` РѕСЃС‚Р°РІР»РµРЅ СЂР°РЅСЊС€Рµ
- `0x321C220/0x321C248/0x321C400/0x321C408/0x321C3F8` С‚РµРїРµСЂСЊ С‚РѕР¶Рµ РёРґСѓС‚ СЂР°РЅСЊС€Рµ `0x3214850`
- `0x3214850` РѕРїСѓС‰РµРЅ РїРѕС‡С‚Рё РІ С…РІРѕСЃС‚, РїРµСЂРµРґ СѓР¶Рµ СЃРѕРІСЃРµРј noisy `0x3213EC8`

РќРѕРІС‹Р№ shortlist:
`{ 0x321C240, 0x3213680, 0x31C3000, 0x31C30B0, 0x321C220, 0x321C248, 0x321C400, 0x321C408, 0x321C3F8, 0x3214850, 0x3213EC8 }`

**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ в†’ Р’Р«РЎРћРљРР™


### Bug #251: С…РІРѕСЃС‚ direct-path РІСЃС‘ РµС‰С‘ СЃРѕРґРµСЂР¶Р°Р» zero-xref session artifacts СЃР»РёС€РєРѕРј СЂР°РЅРѕ

**РЎРµСЃСЃРёСЏ:** offline_test_v19

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ Bug #250 shortlist СѓР¶Рµ РїРѕРЅРёР·РёР» `0x3214850`, РЅРѕ РІ РЅС‘Рј РІСЃС‘ РµС‰С‘ СЃСЂР°РІРЅРёС‚РµР»СЊРЅРѕ СЂР°РЅРѕ РѕСЃС‚Р°РІР°Р»РёСЃСЊ СЃС‚Р°СЂС‹Рµ session-time offsets `0x321C3F8/0x321C400/0x321C408`, Р° С‚Р°РєР¶Рµ СЃРѕСЃРµРґРЅРёР№ `0x321C248`, С…РѕС‚СЏ РёС… offline evidence РѕСЃС‚Р°РІР°Р»СЃСЏ СЃР»Р°Р±С‹Рј РёР»Рё РЅСѓР»РµРІС‹Рј.

**Root cause:** `offline_test_v19` СЃРґРµР»Р°Р» РѕС‚РґРµР»СЊРЅС‹Р№ exact-reference audit РїРѕ runtime cluster `0x321C220/240/248/3F8/400/408/480` Рё РїРѕРґС‚РІРµСЂРґРёР»:
- `0x321C240` вЂ” 1 exact-ref window Рё strongest doubly-linked semantics
- `0x321C220` вЂ” 2 exact-ref windows, РЅРѕ Р±РµР· СЃРёР»СЊРЅРѕР№ list semantics
- `0x321C248` вЂ” 0 exact head-load windows РІ С‚РµРєСѓС‰РµРј audit
- `0x321C3F8`, `0x321C400`, `0x321C408`, `0x321C480` вЂ” 0 exact refs Рё 0 semantic windows

Р—РЅР°С‡РёС‚ СЂР°РЅРЅРёР№ direct-path РЅРµ РґРѕР»Р¶РµРЅ С‚СЂР°С‚РёС‚СЊ РїРѕРїС‹С‚РєРё РЅР° СЌС‚Рё zero-xref session artifacts РґРѕ С‚РѕРіРѕ, РєР°Рє Р±СѓРґСѓС‚ РёСЃС‡РµСЂРїР°РЅС‹ С…РѕС‚СЏ Р±С‹ exact-referenced РёР»Рё РїСѓСЃС‚СЊ noisy, РЅРѕ СЂРµР°Р»СЊРЅРѕ РёСЃРїРѕР»СЊР·СѓРµРјС‹Рµ globals.

**Р¤РёРєСЃ:** Р’ `kernprocaddress()` direct shortlist reordered РµС‰С‘ СЂР°Р·:
- `0x321C220` РѕСЃС‚Р°РІР»РµРЅ РєР°Рє РµРґРёРЅСЃС‚РІРµРЅРЅС‹Р№ СЂР°РЅРЅРёР№ weak runtime-neighbor
- `0x3214850` Рё РґР°Р¶Рµ noisy `0x3213EC8` С‚РµРїРµСЂСЊ РёРґСѓС‚ СЂР°РЅСЊС€Рµ С‡РёСЃС‚С‹С… zero-xref session artifacts
- `0x321C248`, `0x321C3F8`, `0x321C400`, `0x321C408` РїРµСЂРµРЅРµСЃРµРЅС‹ РІ СЃР°РјС‹Р№ С…РІРѕСЃС‚

РќРѕРІС‹Р№ shortlist:
`{ 0x321C240, 0x3213680, 0x31C3000, 0x31C30B0, 0x321C220, 0x3214850, 0x3213EC8, 0x321C248, 0x321C3F8, 0x321C400, 0x321C408 }`

**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ в†’ Р’Р«РЎРћРљРР™


### Bug #252: `0x31C30B0` Рё `0x321C220` Р±С‹Р»Рё Р·Р°РІС‹С€РµРЅС‹, С…РѕС‚СЏ РЅРµ РІС‹РіР»СЏРґСЏС‚ РєР°Рє `LIST_HEAD.lh_first`

**РЎРµСЃСЃРёСЏ:** offline_test_v20

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ Bug #251 shortlist СѓР¶Рµ РѕС‚РѕРґРІРёРЅСѓР» zero-xref offsets, РЅРѕ РІСЃС‘ РµС‰С‘ РґРµСЂР¶Р°Р» СЃСЂР°РІРЅРёС‚РµР»СЊРЅРѕ РІС‹СЃРѕРєРѕ `0x31C30B0` Рё `0x321C220`, РёСЃС…РѕРґСЏ РёР· С‚РѕРіРѕ, С‡С‚Рѕ РѕРЅРё exact-referenced РёР»Рё СЃС‚СЂСѓРєС‚СѓСЂРЅРѕ Р±Р»РёР·РєРё Рє runtime area.

**Root cause:** `offline_test_v20` РїРѕРєР°Р·Р°Р», С‡С‚Рѕ РёС… С„РѕСЂРјР° РґРѕСЃС‚СѓРїР° РїР»РѕС…Рѕ СЃРѕРІРїР°РґР°РµС‚ СЃ С‚РµРј, РєР°Рє РґРѕР»Р¶РµРЅ РІС‹РіР»СЏРґРµС‚СЊ `allproc`:
- `0x31C30B0` РїРѕС‡С‚Рё РІ РєР°Р¶РґРѕРј РѕРєРЅРµ РґРµР»Р°РµС‚ РїР°СЂСѓ `LDR [head,#0]` Рё `LDR [head,#0x8]` СЃ compare/branch, РЅРѕ Р±РµР· РїРµСЂРµС…РѕРґР° `head -> node -> next/prev`
- СЌС‚Рѕ Р±РѕР»СЊС€Рµ РїРѕС…РѕР¶Рµ РЅР° paired queue-head / state struct, Р° РЅРµ РЅР° `LIST_HEAD` СЃ РµРґРёРЅСЃС‚РІРµРЅРЅС‹Рј `lh_first`
- `0x321C220` С…РѕС‚СЊ Рё exact-referenced, РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ РєР°Рє anchor РґР»СЏ address arithmetic Рё helper-РІС‹Р·РѕРІРѕРІ, Р° РЅРµ РєР°Рє head pointer СЃРїРёСЃРєР°
- РЅР° СЌС‚РѕРј С„РѕРЅРµ РґР°Р¶Рµ СЃР»Р°Р±С‹Р№ `0x3214850` Рё noisy `0x3213EC8` РІСЃС‘ Р¶Рµ Р±Р»РёР¶Рµ Рє СЂРµР°Р»СЊРЅС‹Рј object/head probes, С‡РµРј СЌС‚Рё РґРІР° structurally incompatible globals

**Р¤РёРєСЃ:** Р’ `kernprocaddress()` direct shortlist reordered РµС‰С‘ СЂР°Р·:
- `0x31C30B0` Рё `0x321C220` РїРµСЂРµРЅРµСЃРµРЅС‹ РЅРёР¶Рµ `0x3214850` Рё `0x3213EC8`
- top-3 РѕСЃС‚Р°С‘С‚СЃСЏ Р±РµР· РёР·РјРµРЅРµРЅРёР№: `0x321C240`, `0x3213680`, `0x31C3000`

РќРѕРІС‹Р№ shortlist:
`{ 0x321C240, 0x3213680, 0x31C3000, 0x3214850, 0x3213EC8, 0x321C220, 0x31C30B0, 0x321C248, 0x321C3F8, 0x321C400, 0x321C408 }`

**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ в†’ Р’Р«РЎРћРљРР™


### Bug #253: direct shortlist РѕС‚Р±СЂР°СЃС‹РІР°Р» relaxed-heap `LIST_ENTRY` pointers РґРѕ Р·Р°РїСѓСЃРєР° `direct_v2`

**РЎРµСЃСЃРёСЏ:** runtime screenshot after Bug #252

**РЎРёРјРїС‚РѕРј:** РќР° РЅРѕРІРѕРј runtime Р»РѕРіРµ exploit РґРѕС€С‘Р» РґРѕ `kernprocaddress()`, РЅРѕ РґР°Р»СЊС€Рµ direct shortlist СЂР°РЅРѕ Р»РѕРіРёСЂРѕРІР°Р» СЃС‚СЂРѕРєРё РІРёРґР°:
- `direct 0x...: val=0x... not heap`

Р­С‚Рѕ РїСЂРѕРёСЃС…РѕРґРёР»Рѕ РµС‰С‘ РґРѕ `direct_v2`, С…РѕС‚СЏ СЃР°Рј `direct_v2` Р±С‹Р» СЃРїРµС†РёР°Р»СЊРЅРѕ РЅР°РїРёСЃР°РЅ РїРѕРґ iOS 17 SMRQ/LIST_ENTRY layout:
- `*(candidate)` РјРѕР¶РµС‚ Р±С‹С‚СЊ РЅРµ base `proc`, Р° `proc + list_off`
- РґР»СЏ СЌС‚РѕРіРѕ РІРЅСѓС‚СЂРё `direct_v2` СѓР¶Рµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ `is_heap_ptr_relaxed(entry_ptr)` Рё Р·Р°С‚РµРј РЅРѕСЂРјР°Р»РёР·Р°С†РёСЏ РІ `first_proc = entry_ptr - list_off`

**Root cause:** РІ `kernprocaddress()` РїРµСЂРµРґ РІС‹Р·РѕРІРѕРј `validate_direct_allproc_v2(candidate)` СЃС‚РѕСЏР» СЃР»РёС€РєРѕРј СЃС‚СЂРѕРіРёР№ prefilter:
- direct path С‚СЂРµР±РѕРІР°Р» `is_heap_ptr(stripped)`
- РЅРѕ `is_heap_ptr()` РѕС‚РІРµСЂРіР°РµС‚ РЅРµРєРѕС‚РѕСЂС‹Рµ interior/list-entry pointers, РєРѕС‚РѕСЂС‹Рµ РµС‰С‘ РґРѕР»Р¶РЅС‹ Р±С‹Р»Рё РїСЂРѕР№С‚Рё С‡РµСЂРµР· relaxed path
- РІ СЂРµР·СѓР»СЊС‚Р°С‚Рµ promising direct candidates СѓРјРёСЂР°Р»Рё РµС‰С‘ РґРѕ РїРѕРїС‹С‚РєРё `direct_v2`

**Р¤РёРєСЃ:** direct shortlist validation reordered С‚Р°Рє:
- СЃРЅР°С‡Р°Р»Р° С‡РёС‚Р°РµС‚СЃСЏ `head_val`
- Р·Р°С‚РµРј РґРѕРїСѓСЃРєР°СЋС‚СЃСЏ РІСЃРµ `is_heap_ptr_relaxed(stripped)` РєР°РЅРґРёРґР°С‚С‹ РІ `validate_direct_allproc_v2(candidate)`
- РµСЃР»Рё РєР°РЅРґРёРґР°С‚ С‚РѕР»СЊРєРѕ relaxed-heap Рё `direct_v2` РЅРµ СЃСЂР°Р±РѕС‚Р°Р», legacy validator СѓР¶Рµ РЅРµ РІС‹Р·С‹РІР°РµС‚СЃСЏ
- strict-heap С‚РµРїРµСЂСЊ РЅСѓР¶РµРЅ С‚РѕР»СЊРєРѕ РґР»СЏ legacy `validate_allproc(candidate)`

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** runtime shortlist Р±РѕР»СЊС€Рµ РЅРµ Р±СѓРґРµС‚ С‚РµСЂСЏС‚СЊ SMRQ/LIST_ENTRY head pointers РЅР° СЂР°РЅРЅРµРј `not heap` prefilter Рё СЃРјРѕР¶РµС‚ СЂРµР°Р»СЊРЅРѕ РїСЂРѕРІРµСЂСЏС‚СЊ РёС… С‡РµСЂРµР· `direct_v2`.

**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™


### Bug #254: `direct_v2` РїСЂРёРЅРёРјР°Р» Р»РѕР¶РЅСѓСЋ proc-РїРѕРґС†РµРїРѕС‡РєСѓ, РєРѕС‚РѕСЂР°СЏ РЅРµ РґРѕС…РѕРґРёР»Р° РґРѕ С‚РµРєСѓС‰РµРіРѕ PID range

**РЎРµСЃСЃРёСЏ:** runtime screenshots after Bug #253

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ РѕСЃР»Р°Р±Р»РµРЅРёСЏ prefilter `direct_v2` РЅР°РєРѕРЅРµС† РЅР°С‡Р°Р» СЃСЂР°Р±Р°С‚С‹РІР°С‚СЊ, РЅРѕ РЅРѕРІС‹Р№ Р»РѕРі РїРѕРєР°Р·Р°Р» СЃР»РµРґСѓСЋС‰СѓСЋ РєР°СЂС‚РёРЅСѓ:
- `direct_v2 SUCCESS`
- `ourproc` РёСЃРїРѕР»СЊР·СѓРµС‚ `list_off=0xb0`
- РґР°Р»СЊС€Рµ РїСЂСЏРјРѕР№ walk РїРѕРєР°Р·С‹РІР°РµС‚ С‚РѕР»СЊРєРѕ РЅРёР·РєРёРµ PID (`0`, `13`, `15`, `16`, ...)
- РЅР°С€ `pid` РІ СЌС‚РѕР№ С†РµРїРѕС‡РєРµ РЅРµ РїРѕСЏРІР»СЏРµС‚СЃСЏ

Р­С‚Рѕ СѓР¶Рµ Р»СѓС‡С€Рµ РїСЂРµР¶РЅРµРіРѕ `not heap`, РЅРѕ РІСЃС‘ РµС‰С‘ Р»РѕР¶РЅРѕРїРѕР»РѕР¶РёС‚РµР»СЊРЅС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚: РЅР°Р№РґРµРЅ РЅРµ `allproc`, Р° РєР°РєР°СЏ-С‚Рѕ proc-like sublist.

**Root cause:** РєСЂРёС‚РµСЂРёРё `direct_v2` РїРѕСЃР»Рµ СЂР°РЅРЅРёС… offline СЌС‚Р°РїРѕРІ Р±С‹Р»Рё СЃР»РёС€РєРѕРј РјСЏРіРєРёРјРё:
- `chain_len >= 5`
- `unique_pids >= 3`

РўР°РєРѕР№ РїРѕСЂРѕРі РґРµР№СЃС‚РІРёС‚РµР»СЊРЅРѕ РїСЂРѕРїСѓСЃРєР°РµС‚ РєРѕСЂРѕС‚РєРёРµ proc-sublists СЃ РЅРµСЃРєРѕР»СЊРєРёРјРё РІР°Р»РёРґРЅС‹РјРё PID, РѕСЃРѕР±РµРЅРЅРѕ РїРѕСЃР»Рµ Bug #253, РєРѕРіРґР° relaxed LIST_ENTRY pointers РЅР°РєРѕРЅРµС† РЅР°С‡Р°Р»Рё РґРѕС…РѕРґРёС‚СЊ РґРѕ validator.

**Р¤РёРєСЃ:** validator `validate_direct_allproc_v2_with_layout()` СѓР¶РµСЃС‚РѕС‡С‘РЅ:
- С‚РµРїРµСЂСЊ Р»РѕРіРёСЂСѓРµС‚ `max_pid_seen` Рё `ourpid`
- С‚СЂРµР±СѓРµС‚:
  - `chain_len >= 8`
  - `unique_pids >= 5`
  - `first_pid != 0`
  - `max_pid_seen >= getpid()`

РўРѕ РµСЃС‚СЊ direct candidate С‚РµРїРµСЂСЊ РґРѕР»Р¶РµРЅ РЅРµ РїСЂРѕСЃС‚Рѕ Р±С‹С‚СЊ proc-like, Р° СЂРµР°Р»СЊРЅРѕ РґРѕС…РѕРґРёС‚СЊ РґРѕ Р°РєС‚СѓР°Р»СЊРЅРѕРіРѕ РїРѕР»СЊР·РѕРІР°С‚РµР»СЊСЃРєРѕРіРѕ PID range С‚РµРєСѓС‰РµРіРѕ РїСЂРѕС†РµСЃСЃР°.

**РћР¶РёРґР°РµРјС‹Р№ СЌС„С„РµРєС‚:** РєРѕСЂРѕС‚РєРёРµ proc-РїРѕРґС†РµРїРѕС‡РєРё СЃ PID `0/13/15/16` Р±СѓРґСѓС‚ РѕС‚РІРµСЂРіР°С‚СЊСЃСЏ РµС‰С‘ РІ `direct_v2`, Рё РїРѕРёСЃРє РїРѕР№РґС‘С‚ РґР°Р»СЊС€Рµ Рє Р±РѕР»РµРµ РїСЂР°РІРґРѕРїРѕРґРѕР±РЅС‹Рј `allproc` РєР°РЅРґРёРґР°С‚Р°Рј.

**РРјРїР°РєС‚:** Р’Р«РЎРћРљРР™

---

### Bug #255: `0x3213680` вЂ” СЌС‚Рѕ `kernproc` (kernel_task, PID 0), Р° РЅРµ `allproc`; РЅСѓР¶РµРЅ backward walk С‡РµСЂРµР· BSD le_prev

**РЎРµСЃСЃРёСЏ:** runtime screenshot build 38

**РЎРёРјРїС‚РѕРј:** РџРѕСЃР»Рµ Bug #254 (СѓР¶РµСЃС‚РѕС‡С‘РЅРЅС‹Р№ direct_v2 validator) РЅРѕРІС‹Р№ Р»РѕРі РїРѕРєР°Р·Р°Р»:
- `0x321C240` в†’ val `0xfffffff023418400` вЂ” "not even relaxed-heap" (kernel data pointer, РЅРµ heap)
- `0x3213680` в†’ `direct_v2: chain=1 unique_pids=1 first_pid=0 max_pid=0 ourpid=421` вЂ” РєРѕСЂСЂРµРєС‚РЅРѕ РѕС‚РІРµСЂРіРЅСѓС‚
- `list_off=0: le_prev=0xffffffe270b9000 != candidate` вЂ” le_prev РЅРµ СЃРѕРІРїР°РґР°РµС‚ СЃ Р°РґСЂРµСЃРѕРј candidate

**РђРЅР°Р»РёР·:** candidate `0x3213680` С…СЂР°РЅРёС‚ СѓРєР°Р·Р°С‚РµР»СЊ РЅР° SMRQ entry РІРЅСѓС‚СЂРё kernel_task (PID 0). kernel_task РІСЃРµРіРґР° РІ РҐР’РћРЎРўР• allproc BSD LIST. Forward walk: chain=1.

**Root cause:** РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р» РїСѓС‚СЊ "kernproc detection". chain=1 + PID 0 = `kernproc` variable. РР· kernel_task РјРѕР¶РЅРѕ РёРґС‚Рё РќРђР—РђР” С‡РµСЂРµР· BSD LIST le_prev (proc+0x08) РґРѕ РЅР°С€РµРіРѕ PID.

**Р¤РёРєСЃ:**
1. `detect_kernproc_variable()` вЂ” РїСЂРѕР±СѓРµС‚ РѕР±Рµ РёРЅС‚РµСЂРїСЂРµС‚Р°С†РёРё (direct ptr vs SMRQ entry), РїСЂРѕРІРµСЂСЏРµС‚ PID==0, p_proc_ro, le_prev validity
2. РРЅС‚РµРіСЂР°С†РёСЏ РІ direct shortlist loop РїРѕСЃР»Рµ `validate_direct_allproc_v2()` РїСЂРѕРІР°Р»РёР»СЃСЏ
3. Backward walk РІ `ourproc()` РїСЂРё `g_kernproc_is_pid0` вЂ” BSD LIST offsets (list=0x00, prev=0x08) РІРјРµСЃС‚Рѕ SMRQ
4. Relaxed heap checks РґР»СЏ kernproc path (kernel_task РјРѕР¶РµС‚ Р±С‹С‚СЊ РЅРёР¶Рµ safe_min)
5. Zone map diagnostics РІ detect_kernproc_variable

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.39 (39)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™

---

### Bug #256: allproc (0x321C240) СѓРєР°Р·С‹РІР°РµС‚ РЅР° DATA-СЂРµР·РёРґРµРЅС‚РЅС‹Р№ proc0, Р° detect_kernproc_variable РјРѕР»С‡Р° РїР°РґР°РµС‚

**РЎРµСЃСЃРёСЏ:** runtime build 39 + offline_test_v21

**РЎРёРјРїС‚РѕРј:** РќР° СЃРєСЂРёРЅС€РѕС‚Рµ:
- kernel_base: `0xfffffff016e08000`
- zone_map: `[0xffffffe2fdbd0000..0xfffffffe8fda0000]`
- `0x321C240` в†’ val=`0xfffffff01a024500` в†’ "not even relaxed-heap"
- `0x3213680` в†’ val=`0xffffffe4399a5000` в†’ relaxed-heap, РЅРѕ detect_kernproc_variable РЅРµ СЃСЂР°Р±РѕС‚Р°Р» (РјРѕР»С‡Р°)
- `0x31C3000` в†’ not even relaxed-heap
- Remaining candidates also fail

**РђРЅР°Р»РёР· (2 РїРѕРґР±Р°РіР°):**

**Bug #256A**: `detect_kernproc_variable()` РґР»СЏ `0x3213680` РјРѕР»С‡Р° РІРѕР·РІСЂР°С‰Р°РµС‚ false Р±РµР· РґРёР°РіРЅРѕСЃС‚РёРєРё вЂ” РЅРµРІРѕР·РјРѕР¶РЅРѕ РїРѕРЅСЏС‚СЊ, РїРѕС‡РµРјСѓ PID 0 РЅРµ РЅР°Р№РґРµРЅ. Р’РµСЂРѕСЏС‚РЅРѕ: entry_ptr (`0xffffffe4399a5000`) РЅРµ РІРµРґС‘С‚ Рє proc СЃ PID 0 С‡РµСЂРµР· РѕР±Рµ РёРЅС‚РµСЂРїСЂРµС‚Р°С†РёРё.

**Bug #256B**: `0x321C240` вЂ” РїРѕРґС‚РІРµСЂР¶РґС‘РЅРЅС‹Р№ offline_test_v21 РєР°Рє **РЅР°СЃС‚РѕСЏС‰РёР№ allproc** (LIST_TRAVERSAL + HEAD_MUTATION). Р—РЅР°С‡РµРЅРёРµ `0xfffffff01a024500` = kbase+0x321C500 вЂ” СЌС‚Рѕ DATA-СЂРµР·РёРґРµРЅС‚РЅС‹Р№ proc0 (kernel_task), Р° РќР• heap pointer! РќР° iOS 17 kernel_task РјРѕР¶РµС‚ Р±С‹С‚СЊ СЃС‚Р°С‚РёС‡РµСЃРєРё Р°Р»Р»РѕС†РёСЂРѕРІР°РЅ РІ __DATA РІРјРµСЃС‚Рѕ heap zone. Р¤СѓРЅРєС†РёСЏ `is_heap_ptr_relaxed()` РїСЂРѕРІРµСЂСЏРµС‚ `< 0xfffffff000000000`, РїРѕСЌС‚РѕРјСѓ Р·РЅР°С‡РµРЅРёРµ `0xfffffff01a...` Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РѕС‚Р±СЂР°СЃС‹РІР°РµС‚СЃСЏ.

**Root cause:** allproc.lh_first РјРѕР¶РµС‚ СѓРєР°Р·С‹РІР°С‚СЊ РЅРµ РЅР° heap, Р° РЅР° kernel __DATA, РїРѕС‚РѕРјСѓ С‡С‚Рѕ proc0 (kernel_task) вЂ” СЌС‚Рѕ СЃС‚Р°С‚РёС‡РµСЃРєРёР№ РѕР±СЉРµРєС‚. РўРµРєСѓС‰РёР№ РєРѕРґ РѕС‚Р±СЂР°СЃС‹РІР°РµС‚ РІСЃРµ DATA pointers РµС‰С‘ РґРѕ РїСЂРѕРІРµСЂРєРё.

**Р¤РёРєСЃ:**
1. **Р”РёР°РіРЅРѕСЃС‚РёРєР° detect_kernproc_variable** вЂ” РґРѕР±Р°РІР»РµРЅРѕ РїРѕР»РЅРѕРµ Р»РѕРіРёСЂРѕРІР°РЅРёРµ: PID values РёР· РѕР±РµРёС… РёРЅС‚РµСЂРїСЂРµС‚Р°С†РёР№, kread status, base addresses
2. **DATA-resident proc0 path** вЂ” РµСЃР»Рё `is_heap_ptr_relaxed` РїСЂРѕРІР°Р»РёР»СЃСЏ Рё Р·РЅР°С‡РµРЅРёРµ вЂ” kernel DATA pointer (`kbase <= val < kbase+0x4000000`), РїСЂРѕР±СѓРµРј: С‡РёС‚Р°РµРј PID РїРѕ val+0x60; РµСЃР»Рё PID=0, С‡РёС‚Р°РµРј le_next РїРѕ val+0x00 Рё РїСЂРѕРІРµСЂСЏРµРј С‡С‚Рѕ РѕРЅ РІ heap; РµСЃР»Рё РґР° вЂ” РїСЂРёРЅРёРјР°РµРј candidate СЃ list_off=0x00 (BSD LIST)
3. **ourproc() forward walk** вЂ” СЂР°Р·СЂРµС€С‘РЅ РїРµСЂРІС‹Р№ proc (count==0) РІ kernel DATA РєРѕРіРґР° g_direct_layout_set; РґР°Р»СЊРЅРµР№С€РёРµ procs РґРѕР»Р¶РЅС‹ Р±С‹С‚СЊ РІ heap
4. **ourproc() heap_ok check** вЂ” РґРѕР±Р°РІР»РµРЅ fallback РґР»СЏ DATA-СЂРµР·РёРґРµРЅС‚ proc0 РїСЂРё g_direct_layout_set
5. **Bug #238 le_prev section** вЂ” СЂР°СЃС€РёСЂРµРЅРѕ СѓСЃР»РѕРІРёРµ РґР»СЏ DATA-СЂРµР·РёРґРµРЅС‚РЅС‹С… pointers

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`, `ipsw_analysis/offline_test_v21.py` (РІРµСЂРёС„РёРєР°С†РёСЏ)
**Р’РµСЂСЃРёСЏ:** 1.0.40 (40)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” РїРµСЂРІС‹Р№ РїСѓС‚СЊ С‡РµСЂРµР· СЂРµР°Р»СЊРЅС‹Р№ allproc в†’ proc0(DATA) в†’ heap chain

### Bug #257: allproc РЅР° iOS 17 вЂ” SMRQ-linked (proc+0xb0), Р° РєРѕРґ С‡РёС‚Р°РµС‚ BSD le_next (proc+0x00)

**РЎРµСЃСЃРёСЏ:** runtime build 40

**РЎРёРјРїС‚РѕРј:** РќР° СЃРєСЂРёРЅС€РѕС‚Рµ build 40:
- `0x321C240` в†’ val = kbase+0x321c400 вЂ” DATA pointer, РєРѕСЂСЂРµРєС‚РЅРѕ РѕР±РЅР°СЂСѓР¶РµРЅ
- PID at val+0x60 = 44392616 (РќР• 0) в†’ BSD РёРЅС‚РµСЂРїСЂРµС‚Р°С†РёСЏ FAIL
- SMRQ interp: base = val-0xb0, PID at base+0x60 = **0** в†’ kernel_task РїРѕРґС‚РІРµСЂР¶РґС‘РЅ!
- РќРѕ: SMRQ le_next РѕС‚ `d_base2+0x00` (proc+0x00, BSD le_next) в†’ **heap=0** в†’ FAIL
- Р’РµСЃСЊ DATA-proc0 path РѕС‚РєР»РѕРЅС‘РЅ, РЅРµСЃРјРѕС‚СЂСЏ РЅР° СѓСЃРїРµС€РЅРѕРµ РѕР±РЅР°СЂСѓР¶РµРЅРёРµ proc0

**Root cause:**
allproc РЅР° iOS 17 РёСЃРїРѕР»СЊР·СѓРµС‚ SMRQ (SMR Queue), Р° РЅРµ BSD LIST:
- allproc С…СЂР°РЅРёС‚ `&proc0->p_smrq_list` = `proc0+0xb0`, РќР• `proc0+0x00`
- Р”Р»СЏ PID: proc0 base = val - 0xb0, PID at (val-0xb0)+0x60 = 0 вњ“
- SMRQ next pointer: `*(proc+0xb0)` = `next_proc+0xb0`, Р° РќР• `*(proc+0x00)` (BSD le_next)
- РљРѕРґ С‡РёС‚Р°Р» BSD le_next (proc+0x00) вЂ” СЌС‚Рѕ РґСЂСѓРіРѕР№ СЃРїРёСЃРѕРє, РјРѕР¶РµС‚ Р±С‹С‚СЊ stale/РїСѓСЃС‚РѕР№

**Р¤РёРєСЃ:**
1. **SMRQ next read**: С‡РёС‚Р°РµРј РёР· `stripped` (= proc+0xb0), Р° РЅРµ РёР· `d_base2+0x00` (= proc+0x00)
2. **Р’С‹С‡РёСЃР»РµРЅРёРµ next_proc**: smrq_next = pac_strip(*(proc+0xb0)), next_proc = smrq_next - 0xb0
3. **Р’РµСЂРёС„РёРєР°С†РёСЏ**: next_proc РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ heap + PID plausible
4. **PROC_LIST_OFFSET = 0xb0**: ourproc() РІС‹С‡РёС‚Р°РµС‚ 0xb0 РёР· SMRQ entry в†’ proc base
5. **TAILQ fallback**: РµСЃР»Рё smrq_next=0 (kernel_task вЂ” РїРѕСЃР»РµРґРЅРёР№ РІ SMRQ), РїСЂРѕР±СѓРµРј candidate-8 РєР°Рє tqh_first (TAILQ_HEAD: tqh_first at -8, tqh_last at 0)
6. **normalize_proc_link_target_with_pid**: СЃ LIST_OFFSET=0xb0 РєРѕСЂСЂРµРєС‚РЅРѕ РІС‹С‡РёС‚Р°РµС‚ 0xb0 РїСЂРё walk

**РћР¶РёРґР°РЅРёРµ:** Р”РІР° РІР°СЂРёР°РЅС‚Р° runtime:
- (A) kernel_task = HEAD SMRQ: smrq_next в†’ next_proc (heap) в†’ forward walk в†’ РЅР°С€ PID
- (B) kernel_task = TAIL SMRQ: smrq_next=0, TAILQ fallback в†’ tqh_first в†’ newest proc в†’ walk в†’ РЅР°С€ PID

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.41 (41)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· СЌС‚РѕРіРѕ SMRQ allproc РЅРµ РїСЂРѕС…РѕРґРёС‚ РІР°Р»РёРґР°С†РёСЋ

---

### Bug #258: Circular list support вЂ” 4 РїРѕРґР±Р°РіР° (A/B/C/D)

**РЎРµСЃСЃРёСЏ:** offline_test_v22 + РїРѕР»РЅС‹Р№ Р°СѓРґРёС‚ РєРѕРґР°

**РЎРёРјРїС‚РѕРј:** offline_test_v22 РґРѕРєР°Р·Р°Р», С‡С‚Рѕ allproc 0x321C240 вЂ” **circular doubly-linked list**:
- РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ: `STP X9,X9,[X9,#0]` в†’ head.next = &head, head.prev = &head (self-pointer sentinel)
- BSD evidence=6, SMRQ evidence=0 (entry at proc+0xb0, le_next at +0, le_prev at +8)
- РљРѕРЅРµС† СЃРїРёСЃРєР°: entry.next == &allproc (РќР• NULL)

**Root cause (4 РїРѕРґР±Р°РіР°):**

**#258A: validate_direct_allproc_v2 вЂ” circular sentinel.**
entry==candidate = РїСѓСЃС‚РѕР№ circular list. next_entry==candidate = РєРѕРЅРµС† СЃРїРёСЃРєР°.

**#258B: validate_direct_allproc_v2_with_layout вЂ” DATA entry rejection.**
`!is_heap_ptr_relaxed(entry_ptr)` РЅРµРјРµРґР»РµРЅРЅРѕ РѕС‚РєР»РѕРЅСЏРµС‚ DATA-СЂРµР·РёРґРµРЅС‚РЅС‹Р№ proc0.
Р¤РёРєСЃ: РґРѕР±Р°РІР»РµРЅ entry_in_data check, skip proc0 РїСЂРё HEAD, relaxed first_pid.

**#258C: Forward walk uses strict is_heap_ptr.**
РџСЂРё g_direct_layout_set РїСЂРѕС†РµСЃСЃС‹ РјРµР¶РґСѓ zone_map_min Рё safe_min РѕС‚РєР»РѕРЅСЏСЋС‚СЃСЏ.
Р¤РёРєСЃ: `g_direct_layout_set в†’ is_heap_ptr_relaxed` РІ ptr_ok Рё next check.

**#258D: Circular sentinel detection РІ ourproc.**
Р‘РµР· РїСЂРѕРІРµСЂРєРё walk СѓС…РѕРґРёР» РІ &allproc (DATA ptr) в†’ В«proc outside zone_mapВ».
Р¤РёРєСЃ: `raw_stripped == kernprocaddr в†’ break` РїРµСЂРµРґ heap check.

**Р¤РёРєСЃ (РІСЃРµРіРѕ ~60 СЃС‚СЂРѕРє):**
- validate_direct_allproc_v2_with_layout: entry_in_data flag, empty circular check, proc0 skip, sentinel break
- ourproc forward walk: sentinel detection, relaxed heap for ptr_ok and next
- ourproc backward walk: DATA-proc0 first iter allowed

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.42 (42)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· СЌС‚РѕРіРѕ circular list РЅРµ Р±СѓРґРµС‚ РѕР±РЅР°СЂСѓР¶РµРЅ РїСЂРё head = heap ptr

---

### Bug #259: Cache + procbyname + PAC le_prev вЂ” 3 РїРѕРґР±Р°РіР° (A/B/C)

**РЎРµСЃСЃРёСЏ:** РїРѕР»РЅС‹Р№ Р°СѓРґРёС‚ РєРѕРґР° (С„РёРЅР°Р»СЊРЅР°СЏ СЂРµРІРёР·РёСЏ)

**Root cause (3 РїРѕРґР±Р°РіР°):**

**#259A: Cache validation РІ kernprocaddress() РЅРµ РїРѕРґРґРµСЂР¶РёРІР°РµС‚ DATA-proc0.**
`validate_allproc()` С‚СЂРµР±СѓРµС‚ heap-head. РџСЂРё DATA-proc0 РєРµС€ РЅРµРІР°Р»РёРґРЅС‹Р№ в†’
РєР°Р¶РґС‹Р№ РІС‹Р·РѕРІ kernprocaddress() РїРѕРІС‚РѕСЂСЏРµС‚ РїРѕР»РЅС‹Р№ СЃРєР°РЅ (РґРµСЃСЏС‚РєРё kread).
Р¤РёРєСЃ: РїСЂРё g_direct_layout_set вЂ” lightweight check *(allproc) heap|DATA.

**#259B: procbyname() РїР°РґР°РµС‚ РЅР° DATA-proc0.**
`discover_proc_list_layout` С‚СЂРµР±СѓРµС‚ heap. `is_heap_ptr(kernproc)` РѕС‚РєР»РѕРЅСЏРµС‚ DATA proc0.
Walk loop РЅРµ РїРѕРґРґРµСЂР¶РёРІР°РµС‚ DATA entry Рё circular sentinel.
Р¤РёРєСЃ: g_direct_layout_set path (РєР°Рє ourproc), DATA proc0 at HEAD support,
sentinel detection, relaxed heap for next.

**#259C: le_prev comparison uses raw PAC value.**
`first_leprev != kernprocaddr` СЃСЂР°РІРЅРёРІР°РµС‚ raw value (СЃ PAC bits) vs clean address.
РќР° arm64e stored le_prev РјРѕР¶РµС‚ РёРјРµС‚СЊ PAC в†’ Р»РѕР¶РЅРѕРµ mismatch.
Р¤РёРєСЃ: `pac_strip(first_leprev)` РґР»СЏ СЃСЂР°РІРЅРµРЅРёСЏ.

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.42 (42)
**РРјРїР°РєС‚:** РЎР Р•Р”РќРР™ вЂ” #259A РІС‹Р·С‹РІР°РµС‚ Р»РёС€РЅРёРµ kread, #259B Р±Р»РѕРєРёСЂСѓРµС‚ procbyname, #259C Р»РѕР¶РЅР°СЏ РєРѕСЂСЂРµРєС†РёСЏ head

---

### Bug #260: DATA-resident proc chain вЂ” РЅРµ С‚РѕР»СЊРєРѕ proc0 РІ __DATA (build 43в†’44)

**РЎРµСЃСЃРёСЏ:** runtime build 43 screenshot

**Root cause:**
Runtime РїРѕРєР°Р·Р°Р» `DATA-proc0 SMRQ next_proc=0x...01f3104d0 heap=0 relaxed=0`.
РЎР»РµРґСѓСЋС‰РёР№ proc **РїРѕСЃР»Рµ proc0** С‚РѕР¶Рµ РЅР°С…РѕРґРёС‚СЃСЏ РІ kernel `__DATA` СЃРµРіРјРµРЅС‚Рµ (РЅРµ heap!).
РљРѕРґ РґРѕРїСѓСЃРєР°Р» DATA С‚РѕР»СЊРєРѕ РґР»СЏ proc0, РЅРѕ РІ iOS 17 РЅРµСЃРєРѕР»СЊРєРѕ СЃС‚Р°С‚РёС‡РµСЃРєРёС… proc struct
(kernel_task + РІРµСЂРѕСЏС‚РЅРѕ launchd) Р¶РёРІСѓС‚ РІ `__DATA` (kbase..kbase+0x4000000).

**РСЃРїСЂР°РІР»РµРЅРёСЏ:**
- вњ… Р”РѕР±Р°РІР»РµРЅ helper `is_kernel_data_ptr()`: `is_kptr(p) && p >= kbase && p < kbase+0x4000000`
- вњ… `validate_direct_allproc_v2_with_layout()` вЂ” DATA entries РїСЂРёРЅРёРјР°СЋС‚СЃСЏ РЅР° РІСЃРµС… С€Р°РіР°С…
- вњ… SMRQ discovery вЂ” `next_proc` РїСЂРёРЅРёРјР°РµС‚СЃСЏ РµСЃР»Рё `is_heap_ptr_relaxed || is_kernel_data_ptr`
- вњ… `ourproc()` forward walk вЂ” `g_direct_layout_set в†’ is_heap_ptr_relaxed || is_kernel_data_ptr`
- вњ… `procbyname()` вЂ” Р°РЅР°Р»РѕРіРёС‡РЅР°СЏ РїРѕРґРґРµСЂР¶РєР° DATA chain

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.44 (44)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· СЌС‚РѕРіРѕ walk РѕР±СЂС‹РІР°Р»СЃСЏ РЅР° РІС‚РѕСЂРѕРј СѓР·Р»Рµ (DATA-proc1)

---

### Bug #261: normalize_proc_link_target_with_pid РѕС‚РІРµСЂРіР°РµС‚ DATA-СѓРєР°Р·Р°С‚РµР»Рё (build 44в†’45)

**РЎРµСЃСЃРёСЏ:** runtime build 44 screenshot analysis

**Root cause (3 РїРѕРґР±Р°РіР°):**

**#261A: `normalize_proc_link_target_with_pid()` РѕС‚РІРµСЂРіР°Р» DATA-СѓРєР°Р·Р°С‚РµР»Рё.**
Р¤СѓРЅРєС†РёСЏ РїСЂРѕРІРµСЂСЏР»Р° `is_heap_ptr_relaxed(cand)` Рё РїСЂРѕРїСѓСЃРєР°Р»Р° РІСЃРµ Р°РґСЂРµСЃР° РёР· `__DATA` СЏРґСЂР°.
РљРѕРіРґР° proc1 (РїРѕСЃР»Рµ proc0) С‚РѕР¶Рµ РІ `__DATA`, РЅРѕСЂРјР°Р»РёР·Р°С†РёСЏ РІРѕР·РІСЂР°С‰Р°Р»Р° 0 в†’ РѕР±С…РѕРґ Р»РѕРјР°Р»СЃСЏ.
Р¤РёРєСЃ: РґРѕР±Р°РІР»РµРЅР° РїСЂРѕРІРµСЂРєР° `is_kernel_data_ptr(cand)` РїСЂРё `g_direct_layout_set`.

**#261B: SMRQ discovery С‚СЂРµР±РѕРІР°Р» PID-РІР°Р»РёРґР°С†РёСЋ РЅР° СЃР»РµРґСѓСЋС‰РµРј СѓР·Р»Рµ.**
proc0 PID=0 СѓР¶Рµ РїРѕРґС‚РІРµСЂР¶РґС‘РЅ; Р»СЋР±РѕР№ РІР°Р»РёРґРЅС‹Р№ kptr (DATA РёР»Рё heap) РІ smrq_next вЂ”
РґРѕСЃС‚Р°С‚РѕС‡РЅРѕРµ РѕСЃРЅРѕРІР°РЅРёРµ РґР»СЏ allproc SUCCESS. PID Р»РѕРіРёСЂСѓРµС‚СЃСЏ, РЅРѕ РЅРµ Р±Р»РѕРєРёСЂСѓРµС‚.

**#261C: РќРµРґРѕСЃС‚Р°С‚РѕС‡РЅР°СЏ РґРёР°РіРЅРѕСЃС‚РёРєР° РѕР±С…РѕРґР°.**
Р”РѕР±Р°РІР»РµРЅ РґР°РјРї proc0 entry (le_next/le_prev) РґР»СЏ РїРѕРґС‚РІРµСЂР¶РґРµРЅРёСЏ РєРѕР»СЊС†РµРІРѕР№ СЃС‚СЂСѓРєС‚СѓСЂС‹.
РџРµСЂРІС‹Рµ 8 hop'РѕРІ РїРѕРєР°Р·С‹РІР°СЋС‚ `heap=` Рё `data=` СЃС‚Р°С‚СѓСЃ.

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.45 (45)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· СЌС‚РѕРіРѕ РІРµСЃСЊ РѕР±С…РѕРґ СЃРїРёСЃРєР° Р±Р»РѕРєРёСЂРѕРІР°Р»СЃСЏ РІ normalize

---

### Bug #262: Kernel panic РїСЂРё РѕР±С…РѕРґРµ РёР· DATA-proc0 вЂ” 3 РїРѕРґР±Р°РіР° (build 45в†’46)

**РЎРµСЃСЃРёСЏ:** runtime build 45 вЂ” РјРіРЅРѕРІРµРЅРЅР°СЏ РїР°РЅРёРєР°, РїР»Р°РЅС€РµС‚ РїРµСЂРµР·Р°РіСЂСѓР¶Р°Р»СЃСЏ

**Root cause (3 РїРѕРґР±Р°РіР°):**

**#262A: le_prev mismatch check РІС‹Р·С‹РІР°Р» РїР°РЅРёРєСѓ РЅР° DATA-proc0.**
Р‘Р»РѕРє Bug #238 СЂР°Р·С‹РјРµРЅРѕРІС‹РІР°Р» `le_prev` РёР· SMRQ-Р·Р°РїРёСЃРё proc0. Р”Р»СЏ DATA-proc0
le_prev РјРѕР¶РµС‚ СѓРєР°Р·С‹РІР°С‚СЊ РЅР° PPLDATA-Р·Р°С‰РёС‰С‘РЅРЅС‹Р№ Р°РґСЂРµСЃ в†’ kernel panic.
Р¤РёРєСЃ: РїСЂРѕРІРµСЂРєР° le_prev РІС‹РїРѕР»РЅСЏРµС‚СЃСЏ С‚РѕР»СЊРєРѕ РґР»СЏ heap-РїСЂРѕС†РµСЃСЃРѕРІ; DATA-proc0 РїСЂРѕРїСѓСЃРєР°РµС‚СЃСЏ.

**#262B: `is_plausible_pid(0)` РІРѕР·РІСЂР°С‰Р°Р» false в†’ break РЅР° step 0.**
proc0 (kernel_task) РёРјРµРµС‚ PID=0, РєРѕС‚РѕСЂС‹Р№ fail'РёР» plausibility check.
РћР±С…РѕРґ Р»РѕРјР°Р»СЃСЏ СЃСЂР°Р·Сѓ РЅР° РїРµСЂРІРѕРј СѓР·Р»Рµ.
Р¤РёРєСЃ: PID=0 РїСЂРёРЅРёРјР°РµС‚СЃСЏ РґР»СЏ step 0 РїСЂРё DATA-СЂРµР·РёРґРµРЅС‚РЅРѕРј proc0.

**#262C: Unchecked `ds_kread64` РґР»СЏ next_raw.**
`ds_kread64()` (Р±РµР· checked) РјРѕРі РІС‹Р·РІР°С‚СЊ РїР°РЅРёРєСѓ РЅР° Р·Р°С‰РёС‰С‘РЅРЅРѕРј Р°РґСЂРµСЃРµ.
Р¤РёРєСЃ: Р·Р°РјРµРЅС‘РЅ РЅР° `ds_kread64_checked()` СЃ graceful break.

**Р”РѕРїРѕР»РЅРёС‚РµР»СЊРЅРѕ:** `usleep(50ms)` Р·Р°РґРµСЂР¶РєРё РїРѕСЃР»Рµ РєР»СЋС‡РµРІС‹С… Р»РѕРіРѕРІ РґР»СЏ РІРёРґРёРјРѕСЃС‚Рё
РїРµСЂРµРґ РїРѕС‚РµРЅС†РёР°Р»СЊРЅРѕ РѕРїР°СЃРЅС‹РјРё С‡С‚РµРЅРёСЏРјРё. РџРµСЂРІС‹Рµ 5 С€Р°РіРѕРІ РѕР±С…РѕРґР° Р»РѕРіРёСЂСѓСЋС‚ `heap=/data=`.

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.46 (46)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” РїСЂСЏРјР°СЏ РїСЂРёС‡РёРЅР° kernel panic РїСЂРё РєР°Р¶РґРѕРј Р·Р°РїСѓСЃРєРµ

---

### Bug #263: РќРµРїСЂР°РІРёР»СЊРЅС‹Р№ allproc вЂ” 0x321C240 СЌС‚Рѕ РјР°СЃСЃРёРІ Р·РѕРЅРЅС‹С… РґРµСЃРєСЂРёРїС‚РѕСЂРѕРІ, Р° РЅРµ allproc (build 46в†’47)

**РЎРµСЃСЃРёСЏ:** runtime build 46 вЂ” РЅРµ РїР°РЅРёРєСѓРµС‚, РЅРѕ 762 Р·Р°РїРёСЃРё, РІСЃРµ PID=0, PID=437 РќР• РЅР°Р№РґРµРЅ

**Root cause (6 РїРѕРґР±Р°РіРѕРІ):**

**#263A: SMRQ discovery РЅРµ РїСЂРѕРІРµСЂСЏР» PID РІС‚РѕСЂРѕРіРѕ СѓР·Р»Р°.**
762-Р·Р°РїРёСЃРЅС‹Р№ РјР°СЃСЃРёРІ РїРѕ Р°РґСЂРµСЃСѓ kbase+0x321C240 РїСЂРѕС…РѕРґРёР» РІСЃРµ РїСЂРѕРІРµСЂРєРё РїРѕС‚РѕРјСѓ С‡С‚Рѕ
РїРµСЂРІС‹Р№ СЌР»РµРјРµРЅС‚ (PID=0) РјРёРјРёРєСЂРёСЂРѕРІР°Р» proc0 (kernel_task). РњР°СЃСЃРёРІ вЂ” СЃС‚СЂСѓРєС‚СѓСЂС‹ ~0x80 Р±Р°Р№С‚
РєР°Р¶РґР°СЏ, РІСЃРµ РІ kernel DATA.
Р¤РёРєСЃ: SMRQ discovery С‚РµРїРµСЂСЊ С‚СЂРµР±СѓРµС‚ plausible PID (>0 Рё <65536) РЅР° Р’РўРћР РћРњ СѓР·Р»Рµ.

**#263B: РџРѕСЂСЏРґРѕРє shortlist вЂ” 0x321C240 СЃС‚РѕСЏР» РїРµСЂРІС‹Рј.**
Shortlist РґР»СЏ `kernprocaddress()` РЅР°С‡РёРЅР°Р»СЃСЏ СЃ 0x321C240 (DATA array).
Р¤РёРєСЃ: РїРµСЂРµСЃС‚Р°РІР»РµРЅ 0x3213680 (heap kernproc) РЅР° РїРµСЂРІРѕРµ РјРµСЃС‚Рѕ.

**#263C: proc0 memory dump.**
Р”РѕР±Р°РІР»РµРЅ РґР°РјРї РїРµСЂРІС‹С… 0x100 Р±Р°Р№С‚ proc0 РїСЂРё РѕР±РЅР°СЂСѓР¶РµРЅРёРё РґР»СЏ offline-РґРёР°РіРЅРѕСЃС‚РёРєРё.

**#263D: PID offset auto-probing.**
РђРІС‚РѕРїСЂРѕР±Р° PID РїРѕ РґРёР°РїР°Р·РѕРЅСѓ 0x40..0xA8 СЃ С€Р°РіРѕРј 8 РґР»СЏ Р±СѓРґСѓС‰РёС… РЅРµСЃРѕРІРїР°РґРµРЅРёР№.

**#263E: Cache invalidation РґР»СЏ false allproc.**
Р•СЃР»Рё РІС‚РѕСЂРѕР№ СѓР·РµР» РЅРµ РїСЂРѕС€С‘Р» PID-РІР°Р»РёРґР°С†РёСЋ, РєР°РЅРґРёРґР°С‚ РїРѕРјРµС‡Р°РµС‚СЃСЏ РЅРµРґРµР№СЃС‚РІРёС‚РµР»СЊРЅС‹Рј.

**#263F: Retry walk РїРѕСЃР»Рµ false-allproc.**
ourproc() РїРµСЂРµР·Р°РїСѓСЃРєР°РµС‚ РѕР±С…РѕРґ РїРѕСЃР»Рµ invalidation Р»РѕР¶РЅРѕРіРѕ allproc РєР°РЅРґРёРґР°С‚Р°.

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.47 (47)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· СЌС‚РѕРіРѕ ourproc() С…РѕРґРёР» РїРѕ РјР°СЃСЃРёРІСѓ Р·РѕРЅРЅС‹С… СЃС‚СЂСѓРєС‚СѓСЂ Рё РЅРёРєРѕРіРґР° РЅРµ РЅР°С…РѕРґРёР» PID

---

### Bug #264: krw_sockets_leak_forever() РѕС‚РєР»СЋС‡РµРЅР° в†’ panic РїСЂРё РєР°Р¶РґРѕРј РІС‹С…РѕРґРµ РёР· РїСЂРёР»РѕР¶РµРЅРёСЏ (build 47в†’48)

**РЎРµСЃСЃРёСЏ:** runtime builds 42-47 вЂ” panic РїСЂРё РљРђР–Р”РћРњ Р·Р°РІРµСЂС€РµРЅРёРё РїСЂРёР»РѕР¶РµРЅРёСЏ

**Root cause:**
Р’ Bug #234 (СЃРµСЃСЃРёСЏ 21) С„СѓРЅРєС†РёСЏ `krw_sockets_leak_forever()` Р±С‹Р»Р° РѕС‚РєР»СЋС‡РµРЅР°
(hardcoded skip РІ darksword_core.m:2046) РїРѕС‚РѕРјСѓ С‡С‚Рѕ refcount-РїР°С‚С‡ РІС‹Р·С‹РІР°Р» РїР°РЅРёРєСѓ.
РќРѕ С‚Р° РїР°РЅРёРєР° РёРјРµР»Р° РґСЂСѓРіСѓСЋ РїСЂРёС‡РёРЅСѓ:
- Bug #221: `so_count` offset `0x228` (iOS 16) в†’ `0x24c` (iOS 17) вЂ” РїРµСЂРµР·Р°РїРёСЃС‹РІР°Р»Рѕ С‡СѓР¶РѕРµ РїРѕР»Рµ
- Bug #222/#223: `early_kwrite64` (8 Р±Р°Р№С‚) РїРѕСЂС‚РёР»Р° СЃРѕСЃРµРґРЅРµРµ 32-bit РїРѕР»Рµ socket struct

Р’СЃРµ С‚СЂРё Р±Р°РіР° Р±С‹Р»Рё РёСЃРїСЂР°РІР»РµРЅС‹ (aligned 32-bit R/W, РїСЂР°РІРёР»СЊРЅС‹Р№ offset).
РќРѕ skip **РѕСЃС‚Р°Р»СЃСЏ** вЂ” Рё СЃ С‚РµС… РїРѕСЂ РєР°Р¶РґС‹Р№ РїСЂРѕРіРѕРЅ Р·Р°РєР°РЅС‡РёРІР°Р»СЃСЏ РїР°РЅРёРєРѕР№ СЏРґСЂР°:
РїСЂРё РІС‹С…РѕРґРµ РїСЂРёР»РѕР¶РµРЅРёСЏ СЏРґСЂРѕ РїС‹С‚Р°РµС‚СЃСЏ Р·Р°РєСЂС‹С‚СЊ ~22528 corrupted СЃРѕРєРµС‚РѕРІ в†’ data abort.

**Fix:**
РЈР±СЂР°РЅ skip, РІРѕСЃСЃС‚Р°РЅРѕРІР»РµРЅ РІС‹Р·РѕРІ `krw_sockets_leak_forever()`.
Р¤СѓРЅРєС†РёСЏ РёРјРµРµС‚ РІСЃРµ РЅРµРѕР±С…РѕРґРёРјС‹Рµ Р·Р°С‰РёС‚С‹:
- Zone bounds РїСЂРѕРІРµСЂРєР° PCB Рё socket Р°РґСЂРµСЃРѕРІ
- 32-bit aligned С‡С‚РµРЅРёРµ/Р·Р°РїРёСЃСЊ (`kread32_aligned`/`kwrite32_aligned`)
- Sanity check РЅР° refcount (0 < count < 0x10000)
- РџСЂР°РІРёР»СЊРЅС‹Р№ `so_count` offset РґР»СЏ iOS 17 (0x24c)
- РћС‡РёСЃС‚РєР° corrupted ICMPv6 filter qword

**Р¤Р°Р№Р»С‹:** `darksword/darksword_core.m`
**Р’РµСЂСЃРёСЏ:** 1.0.48 (48)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· СЌС‚РѕРіРѕ СѓСЃС‚СЂРѕР№СЃС‚РІРѕ РџРђРќРРљРћР’РђР›Рћ РїРѕСЃР»Рµ РєР°Р¶РґРѕРіРѕ РїСЂРѕРіРѕРЅР°

---

### Bug #265: detect_kernproc_variable() С‚РёС…Рѕ РѕС‚РєР»РѕРЅСЏРµС‚ Р Р•РђР›Р¬РќР«Р™ kernproc (build 48в†’49)

**РЎРµСЃСЃРёСЏ:** runtime build 48 вЂ” syslog + panic log analysis

**Root cause:**
`detect_kernproc_variable()` РЅР°С…РѕРґРёС‚ kernel_task РїРѕ PID=0 вњ“, РЅРѕ РїРѕС‚РѕРј **С‚РёС…Рѕ** 
РІРѕР·РІСЂР°С‰Р°РµС‚ `false` РЅР° РїСЂРѕРІРµСЂРєРµ `proc_ro` (РїРѕР»Рµ proc_base+0x18). 

РўСЂРё РїСЂРѕР±Р»РµРјС‹:

**#265A: Silent failure РІ detect_kernproc_variable().**
РџРѕСЃР»Рµ РїРѕРґС‚РІРµСЂР¶РґРµРЅРёСЏ PID=0 РєРѕРґ РїСЂРѕРІРµСЂСЏРµС‚:
1. `ds_kread64_checked(proc_base + 0x18)` в†’ proc_ro 
2. `is_kptr(proc_ro)` 
3. `ds_kread64_checked(proc_base + 0x08)` в†’ le_prev

РќРё РѕРґРёРЅ РёР· СЌС‚РёС… `return false` РЅРµ РёРјРµР» Р»РѕРіРёСЂРѕРІР°РЅРёСЏ. РќР° iOS 17.3.1 РїРѕР»Рµ +0x18 
РЅРµ СЏРІР»СЏРµС‚СЃСЏ proc_ro (layout proc struct РѕС‚Р»РёС‡Р°РµС‚СЃСЏ), РїРѕСЌС‚РѕРјСѓ is_kptr() 
РІРѕР·РІСЂР°С‰Р°РµС‚ false в†’ С„СѓРЅРєС†РёСЏ РјРѕР»С‡Р° РѕС‚РєР»РѕРЅСЏРµС‚ РµРґРёРЅСЃС‚РІРµРЅРЅС‹Р№ РїСЂР°РІРёР»СЊРЅС‹Р№ РєР°РЅРґРёРґР°С‚.

Р¤РёРєСЃ: proc_ro check СЃРґРµР»Р°РЅ non-fatal (С‚РѕР»СЊРєРѕ Р»РѕРіРёСЂРѕРІР°РЅРёРµ).
Р”Р°РјРї proc0 (0x100 Р±Р°Р№С‚) РїРµСЂРµРјРµС‰С‘РЅ РџР•Р Р•Р” РїСЂРѕРІРµСЂРєР°РјРё РґР»СЏ РґРёР°РіРЅРѕСЃС‚РёРєРё.
Р’СЃРµ `return false` РїСѓС‚Рё РїРѕР»СѓС‡РёР»Рё СЏРІРЅРѕРµ Р»РѕРіРёСЂРѕРІР°РЅРёРµ.

**#265B: Blacklist РґР»СЏ РєР°РЅРґРёРґР°С‚РѕРІ РїРѕСЃР»Рµ Bug #263F.**
РџРѕСЃР»Рµ invalidation Р»РѕР¶РЅРѕРіРѕ allproc (0x321C240), `kernprocaddress()` 
РїРµСЂРµР·Р°РїСѓСЃРєР°Р»Р°СЃСЊ Рё РїСЂРѕС…РѕРґРёР»Р° РўРћРў Р–Р• shortlist, СЃРЅРѕРІР° РїСЂРёРЅРёРјР°СЏ С‚РѕС‚ Р¶Рµ Р°РґСЂРµСЃ.
Р¤РёРєСЃ: РґРѕР±Р°РІР»РµРЅ РјР°СЃСЃРёРІ `g_blacklisted_candidates[]` вЂ” invalidated РєР°РЅРґРёРґР°С‚С‹ 
РїСЂРѕРїСѓСЃРєР°СЋС‚СЃСЏ РїСЂРё РїРѕРІС‚РѕСЂРЅРѕРј РѕР±С…РѕРґРµ shortlist.

**#265C: Р”Р°РјРї proc0 РїРµСЂРµРјРµС‰С‘РЅ РїРµСЂРµРґ РїСЂРѕРІРµСЂРєР°РјРё.**
Bug #263C РґРѕР±Р°РІРёР» РґР°РјРї kernel_task, РЅРѕ РѕРЅ СЃС‚РѕСЏР» РџРћРЎР›Р• proc_ro/le_prev checks.
Р•СЃР»Рё РїСЂРѕРІРµСЂРєРё РЅРµ РїСЂРѕС…РѕРґРёР»Рё, РґР°РјРї РЅРёРєРѕРіРґР° РЅРµ РІС‹РїРѕР»РЅСЏР»СЃСЏ. РўРµРїРµСЂСЊ РґР°РјРї РїРµСЂРІС‹Р№.

**Р¦РµРїРѕС‡РєР° СЃР±РѕСЏ (build 48):**
1. `0x3213680` (РџР РђР’РР›Р¬РќР«Р™ kernproc) в†’ `detect_kernproc_variable` РЅР°С…РѕРґРёС‚ PID=0 
2. в†’ proc_base+0x18 РЅРµ kptr в†’ silent `return false` (NO LOG!)
3. в†’ Fallback Рє `0x321C240` (Р›РћР–РќР«Р™ allproc) в†’ РїСЂРёРЅСЏС‚ С‡РµСЂРµР· DATA-proc0 SMRQ
4. в†’ 762 DATA entries РІСЃРµ PID=0 в†’ ourproc() РЅРµ РЅР°С…РѕРґРёС‚ PID
5. в†’ Bug #263F invalidation в†’ retry в†’ РќРћ 0x321C240 РЅРµ blacklisted в†’ РўРћР–Р• РЎРђРњРћР•!
6. в†’ Zone scan span=0x0 в†’ watchdog timeout (panic bug_type 210)

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.49 (49)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· СЌС‚РѕРіРѕ jailbreak РЅРµ РјРѕР¶РµС‚ РЅР°Р№С‚Рё СЃРІРѕР№ РїСЂРѕС†РµСЃСЃ РІ СЏРґСЂРµ

---

### Bug #266: PID offset Р»РѕР¶РЅРѕ РѕР±РЅР°СЂСѓР¶РµРЅ РєР°Рє 0x90, allproc РЅРµ РІ РєР°РЅРґРёРґР°С‚Р°С… (build 49в†’50)

**РЎРµСЃСЃРёСЏ:** runtime build 49 вЂ” syslog analysis

**Root cause:**
Bug #265 РРЎРџР РђР’РР› detect_kernproc вЂ” kernproc С‚РµРїРµСЂСЊ РѕР±РЅР°СЂСѓР¶РµРЅ РЅР° `kbase+0x3213680`.
РќРѕ С‚СЂРё РЅРѕРІС‹С… РїСЂРѕР±Р»РµРјС‹ РїРѕРјРµС€Р°Р»Рё РЅР°Р№С‚Рё PID 521:

**#266A: PID offset probe РїСЂРёРЅСЏР» РјСѓСЃРѕСЂРЅРѕРµ Р·РЅР°С‡РµРЅРёРµ.**
`detect_kernproc_variable()` РїСЂРѕРІРµСЂСЏР»Р° *(next_proc+offset) РІ РґРёР°РїР°Р·РѕРЅРµ 0x40..0xA8.
РќР° next_proc (0xffffffdfad872000) offset +0x90 СЃРѕРґРµСЂР¶РёС‚ Р·РЅР°С‡РµРЅРёРµ 9984 вЂ” 
С„СѓРЅРєС†РёСЏ СЂРµС€РёР»Р° С‡С‚Рѕ СЌС‚Рѕ PID Рё СѓСЃС‚Р°РЅРѕРІРёР»Р° `PROC_PID_OFFSET = 0x90`.
РќРѕ kernel_task+0x90 = 0x07732835 в‰  0 вЂ” СЌС‚Рѕ РќР• РїРѕР»Рµ PID.

Р¤РёРєСЃ: РїРѕСЃР»Рµ РѕР±РЅР°СЂСѓР¶РµРЅРёСЏ PID offset, РІРµСЂРёС„РёС†РёСЂРѕРІР°С‚СЊ С‡С‚Рѕ kernel_task+offset = 0.
Р•СЃР»Рё РЅРµС‚ вЂ” РѕС‚РєР»РѕРЅРёС‚СЊ РЅР°Р№РґРµРЅРЅС‹Р№ offset, РѕСЃС‚Р°РІРёС‚СЊ РїСЂРµР¶РЅРёР№.
РўР°РєР¶Рµ СЂР°СЃС€РёСЂРµРЅ РґРёР°РїР°Р·РѕРЅ РїРѕРёСЃРєР°: 0x40-0xA8 в†’ 0x00-0x300.

**#266B: allproc (kbase+0x3213678) РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р» РІ direct_offs.**
Alt walk РІ ourproc() Р·Р°РєР°РЅС‡РёРІР°Р»СЃСЏ РЅР° `0xfffffff00e977678` = kbase+0x3213678 вЂ”
СЌС‚Рѕ allproc LIST_HEAD (8 Р±Р°Р№С‚ РїРµСЂРµРґ kernproc). РќРѕ СЌС‚РѕС‚ Р°РґСЂРµСЃ
РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р» РІ direct_offs shortlist.

Р¤РёРєСЃ: РґРѕР±Р°РІР»РµРЅ `0x3213678` РєР°Рє РџР•Р Р’Р«Р™ РєР°РЅРґРёРґР°С‚ (РґР»СЏ forward walk).

**#266C: Backward walk РІРёРґРёС‚ РІСЃРµ PID=0 РїРѕС‚РѕРјСѓ С‡С‚Рѕ +0x60 вЂ” РЅРµ PID.**
Р”Р°РјРї proc0 РїРѕРєР°Р·Р°Р»:
- +0x60 = `0000000000000000` вЂ” РЅРѕ СЌС‚Рѕ TAILQ self-pointer, РЅРµ PID
- +0x68 = `0xffffffdfad870060` вЂ” self-pointer
- +0xD0 = "apfs", +0xE0 = "/private/var/mobile" вЂ” СЃС‚СЂРѕРєРѕРІС‹Рµ РїРѕР»СЏ

Backward walk СЃ pid_off=0x60 С‡РёС‚Р°РµС‚ 0 РґР»СЏ РІСЃРµС… 10 procs в†’ РЅРµ РЅР°С…РѕРґРёС‚ PID 521.

Р¤РёРєСЃ: brute-force PID search. РџРѕСЃР»Рµ backward walk, СЃРєР°РЅРёСЂСѓРµС‚
РѕС„С„СЃРµС‚С‹ 0x00..0x300 РЅР° РєР°Р¶РґРѕРј walked proc РёС‰Р° Р·РЅР°С‡РµРЅРёРµ == ourpid.
Р’РµСЂРёС„РёРєР°С†РёСЏ: kernel_task+РЅР°Р№РґРµРЅРЅС‹Р№_offset РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ 0.

**Р¦РµРїРѕС‡РєР° СЃР±РѕСЏ (build 49):**
1. KERNPROC РѕР±РЅР°СЂСѓР¶РµРЅ вњ“ РЅР° kbase+0x3213680
2. PID probe: +0x90 next_proc = 9984 в†’ PID_OFFSET=0x90 (РќР•Р’Р•Р РќРћ!)
3. Forward walk: le_next=0 (tail) в†’ 0 iterations
4. Backward walk (pid_off=0x90): 3 procs, РІСЃРµ pid=9984 в†’ РЅРµ РЅР°Р№РґРµРЅ
5. Retry #2+ (pid_off СЃР±СЂРѕС€РµРЅ 0x60): backward 10 procs, РІСЃРµ pid=0 в†’ РЅРµ РЅР°Р№РґРµРЅ
6. Zone scan: 40000 reads, РЅРµ РЅР°Р№РґРµРЅ
7. РџРѕРІС‚РѕСЂС‹ 5x в†’ watchdog timeout

**Р¤Р°Р№Р»С‹:** `darksword/utils.m`
**Р’РµСЂСЃРёСЏ:** 1.0.50 (50)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” Р±РµР· РїСЂР°РІРёР»СЊРЅРѕРіРѕ PID offset РЅРµРІРѕР·РјРѕР¶РЅРѕ РЅР°Р№С‚Рё СЃРµР±СЏ РІ proc list

---

### Bug #267: PID probe Р·Р°РїРёСЃС‹РІР°Р» С‚РѕР»СЊРєРѕ РџР•Р Р’Р«Р™ РєР°РЅРґРёРґР°С‚ + brute-force РЅРµ РЅР° forward walk (build 50в†’51)

**РЎРµСЃСЃРёСЏ:** runtime build 50 вЂ” syslog + panic analysis

**Р”Р°РЅРЅС‹Рµ:** kbase=0xfffffff022bb8000, slide=0x1bbb4000, DarkSword PID=624
allproc=kbase+0x3213678, kernel_task=0xffffffe062696000 (HEAD of list)

**Root cause:**
Bug #266 РґРѕР±Р°РІРёР» РІРµСЂРёС„РёРєР°С†РёСЋ PID offset С‡РµСЂРµР· kernel_task. Р’РµСЂРёС„РёРєР°С†РёСЏ Р РђР‘РћРўРђР•Рў,
РЅРѕ РѕР±РЅР°СЂСѓР¶РµРЅС‹ РґРІР° РЅРѕРІС‹С… Р±Р°РіР°:

**#267A: PID probe Р·Р°РїРёСЃС‹РІР°РµС‚ С‚РѕР»СЊРєРѕ РџР•Р Р’Р«Р™ РєР°РЅРґРёРґР°С‚-offset.**
`detect_kernproc_variable()` СЃРєР°РЅРёСЂСѓРµС‚ РѕС„С„СЃРµС‚С‹ 0x00-0x300 РЅР° next_proc.
РЎС‚СЂРѕРєР° `if (!discovered_pid_off) discovered_pid_off = poff;` Р·Р°РїРёСЃС‹РІР°Р»Р°
С‚РѕР»СЊРєРѕ РџР•Р Р’Р«Р™ РЅР°Р№РґРµРЅРЅС‹Р№ offset. Р’СЃРµ РѕСЃС‚Р°Р»СЊРЅС‹Рµ РєР°РЅРґРёРґР°С‚С‹ РёРіРЅРѕСЂРёСЂРѕРІР°Р»РёСЃСЊ.

РР· syslog build 50:
- +0x10 = 17 в†’ РџР•Р Р’Р«Р™, Р·Р°РїРёСЃР°РЅ РІ discovered_pid_off
- +0x88 = 512 в†’ РќР• Р·Р°РїРёСЃР°РЅ (discovered_pid_off СѓР¶Рµ != 0)
- +0x90 = 96 в†’ РќР• Р·Р°РїРёСЃР°РЅ
- +0xB0 = 166 в†’ РќР• Р·Р°РїРёСЃР°РЅ
- +0xD8 = 115 в†’ РќР• Р·Р°РїРёСЃР°РЅ в†ђ **Р­РўРћ РџР РђР’РР›Р¬РќР«Р™ PID OFFSET!**

Р’РµСЂРёС„РёРєР°С†РёСЏ kernel_task+0x10 = 1711 в‰  0 в†’ REJECTED.
РќРѕ discovered_pid_off = 0 в†’ Р±РѕР»СЊС€Рµ РєР°РЅРґРёРґР°С‚РѕРІ РЅРµС‚. Offset 0xd8 РЅРёРєРѕРіРґР° РЅРµ РїСЂРѕРІРµСЂРµРЅ,
С…РѕС‚СЏ kernel_task+0xd8 = 0 в†’ РїСЂРѕС€С‘Р» Р±С‹ РІРµСЂРёС„РёРєР°С†РёСЋ.

**Р¤РёРєСЃ:** РЈР±СЂР°РЅР° guard `if (!discovered_pid_off)`. РўРµРїРµСЂСЊ РљРђР–Р”Р«Р™ РєР°РЅРґРёРґР°С‚
(val > 0 && val < 10000) РЅРµРјРµРґР»РµРЅРЅРѕ РїСЂРѕРІРµСЂСЏРµС‚СЃСЏ РїСЂРѕС‚РёРІ kernel_task+poff.
РџРµСЂРІС‹Р№ РїСЂРѕС€РµРґС€РёР№ РћР‘Рђ РїСЂРѕРІРµСЂРєРё РїСЂРёРЅРёРјР°РµС‚СЃСЏ. РћС‚РєР»РѕРЅС‘РЅРЅС‹Рµ Р»РѕРіРёСЂСѓСЋС‚СЃСЏ Рё СЃРєР°РЅРёСЂРѕРІР°РЅРёРµ
РїСЂРѕРґРѕР»Р¶Р°РµС‚СЃСЏ Рє СЃР»РµРґСѓСЋС‰РµРјСѓ РєР°РЅРґРёРґР°С‚Сѓ.

**#267B: Brute-force PID search С‚РѕР»СЊРєРѕ РЅР° backward-walked procs.**
Brute-force (Bug #266C) Р·Р°РїСѓСЃРєР°Р»СЃСЏ РїСЂРё `bcount >= 3` вЂ” С‚РѕР»СЊРєРѕ РєРѕРіРґР° backward walk
РЅР°С€С‘Р» в‰Ґ3 РїСЂРѕС†РµСЃСЃРѕРІ. Р’ build 50 kernel_task IS the HEAD of allproc list
(prev = 0xfffffff025dcb678 = allproc variable itself), РїРѕСЌС‚РѕРјСѓ backward walk
РЅР°С€С‘Р» 0 РїСЂРѕС†РµСЃСЃРѕРІ. Brute-force РЅРёРєРѕРіРґР° РЅРµ Р·Р°РїСѓСЃС‚РёР»СЃСЏ.

Forward walk РЅР°С€С‘Р» 11 РїСЂРѕС†РµСЃСЃРѕРІ, РЅРѕ РІСЃРµ С‡РёС‚Р°Р»Рё pid=0 (РЅРµРїСЂР°РІРёР»СЊРЅС‹Р№ offset 0x60).
РџРѕСЃР»Рµ "NOT FOUND" РЅРёРєР°РєРѕРіРѕ fallback РЅРµ Р±С‹Р»Рѕ.

**Р¤РёРєСЃ:** Р”РѕР±Р°РІР»РµРЅ СЃР±РѕСЂ Р°РґСЂРµСЃРѕРІ РїСЂРѕС†РµСЃСЃРѕРІ РІ forward walk (РјР°СЃСЃРёРІ fwd_procs[20]).
РџРѕСЃР»Рµ "NOT FOUND", РµСЃР»Рё fwd_count >= 2, Р·Р°РїСѓСЃРєР°РµС‚СЃСЏ brute-force PID offset scan
РЅР° forward-walked РїСЂРѕС†РµСЃСЃР°С…: СЃРєР°РЅРёСЂСѓРµС‚ РѕС„С„СЃРµС‚С‹ 0x00-0x300 РёС‰Р° val == ourpid,
СЃ РІРµСЂРёС„РёРєР°С†РёРµР№ kernel_task+poff == 0. РџСЂРё СѓСЃРїРµС…Рµ РѕР±РЅРѕРІР»СЏРµС‚ PROC_PID_OFFSET
Рё РґРµР»Р°РµС‚ re-walk РґР»СЏ РЅР°С…РѕР¶РґРµРЅРёСЏ РЅР°С€РµРіРѕ proc.

**Р¦РµРїРѕС‡РєР° СЃР±РѕСЏ (build 50):**
1. KERNPROC РѕР±РЅР°СЂСѓР¶РµРЅ вњ“ РЅР° kbase+0x3213678 (allproc), kernel_task=0xffffffe062696000
2. PID probe: offset 0x10 val=17 в†’ FIRST candidate в†’ kernel_task+0x10=1711 в†’ REJECTED
3. Offset 0xd8 val=115 РЅР°Р№РґРµРЅ РЅРѕ РќР• Р·Р°РїРёСЃР°РЅ (guard `if (!discovered_pid_off)`)
4. PID_OFFSET РѕСЃС‚Р°Р»СЃСЏ 0x60, forward walk: 11 procs РІСЃРµ pid=0 в†’ NOT FOUND
5. Backward walk: kernel_task IS HEAD в†’ 0 procs в†’ bcount < 3 в†’ NO brute-force
6. 4x ourproc() РІС‹Р·РѕРІР°, РІСЃРµ РёРґРµРЅС‚РёС‡РЅРѕ РїСЂРѕРІР°Р»РµРЅС‹
7. Post-exploit: root=NO, unsandbox=NO, platform=NO, AMFI=NO
8. Trust cache scan РЅР° __DATA_CONST (0x4b4000 bytes) в†’ kernel data abort
9. Panic: FAR=0xffffffec385224a0 (Metadata region), pc=0xfffffff0239bc810
10. РџР°РЅРёС‡РµСЃРєРёР№ Р»РѕРі: pid 624 (DarkSword), ~90 РїСЂРѕС†РµСЃСЃРѕРІ РІ stackshot

**РџР°РЅРёРєР°:** kernel data abort РІРѕ РІСЂРµРјСЏ trust cache scan Р±РµР· root/sandbox escape.
FAR РІ Metadata region вЂ” РґРѕСЃС‚СѓРї Рє unmapped/protected memory Р±РµР· proper entitlements.

**Р¤Р°Р№Р»С‹:** `darksword/utils.m` (lines 1452-1480 РґР»СЏ #267A, lines 2092+2130+2215-2265 РґР»СЏ #267B)
**Р’РµСЂСЃРёСЏ:** 1.0.51 (51)
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™ вЂ” PID offset 0xd8 РїСЂР°РІРёР»СЊРЅС‹Р№ РЅРѕ РЅРµ РїСЂРѕРІРµСЂСЏР»СЃСЏ; brute-force РЅРµ СЂР°Р±РѕС‚Р°Р» РЅР° forward walk

---

### Bug #293: allproc LIST_HEAD offset 0x31FFF30 РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р» РІ direct shortlist (build 5152)

**РЎРµСЃСЃРёСЏ:** 25d  syslog_2026-04-02_15-00

**РЎРёРјРїС‚РѕРј:** kernel panic РІ Mach-O scan  allproc РЅРµ РЅР°Р№РґРµРЅ.
allproc РЅР° iOS 17.3.1 (21D61) A12Z РЅР°С…РѕРґРёС‚СЃСЏ РІ kbase+0x31FFF30 (outer __DATA+0x67F30),
РЅРѕ СЌС‚РѕС‚ offset РѕС‚СЃСѓС‚СЃС‚РІРѕРІР°Р» РІ shortlist.

**Р¤РёРєСЃ:**  x31FFF30ULL РґРѕР±Р°РІР»РµРЅ РџР•Р Р’Р«Рњ СЌР»РµРјРµРЅС‚РѕРј РІРѕ РІСЃРµ С‚СЂРё shortlist-РјР°СЃСЃРёРІР°
(direct_offs_minimal, direct_offs_safe, direct_offs_full).

**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™

---

### Bug #294: Mach-O scan С‡РёС‚Р°Р» Metadata zone Рё РІС‹Р·С‹РІР°Р» kernel panic (build 5152)

**РЎРµСЃСЃРёСЏ:** 25d  syslog_2026-04-02_15-00, kernel panic

**РЎРёРјРїС‚РѕРј:** panic: FAR РІ Metadata zone ( xffffffe2...) РїСЂРё Mach-O scan.
Scan РЅР°С‡РёРЅР°Р»СЃСЏ СЃ COMMON_START=0x27000 Рё РґРѕС…РѕРґРёР» РґРѕ Metadata region.

**Р¤РёРєСЃ:** РЎСѓР¶РµРЅ РґРёР°РїР°Р·РѕРЅ Mach-O scan: COMMON_START = 0x63000, COMMON_END = 0x70000.
32KB РѕРєРЅРѕ РІРѕРєСЂСѓРі allproc (kbase+0x3213678), РЅРµ Р·Р°С‚СЂР°РіРёРІР°РµС‚ Metadata zone.

**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™  Р±РµР· СЌС‚РѕРіРѕ РїСЂРё РєР°Р¶РґРѕРј Р·Р°РїСѓСЃРєРµ kernel panic

---

### Bug #295: proc0.le_prev == candidate  definitРІРЅРѕРµ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ allproc РёРіРЅРѕСЂРёСЂРѕРІР°Р»РѕСЃСЊ (build 5253)

**РЎРµСЃСЃРёСЏ:** 25e  syslog_2026-04-02_15-42

**РЎРёРјРїС‚РѕРј:** allproc РЅР°Р№РґРµРЅ РїРѕ  x3213678, proc0 РѕР±РЅР°СЂСѓР¶РµРЅ (heap ptr), РЅРѕ
chain validator (Bug #268) РѕС‚РєР»РѕРЅСЏР» РєР°РЅРґРёРґР°С‚Р°:
- PID probe РЅР° next_proc (РІС‚РѕСЂРѕР№ РІ С†РµРїРё  С‚РѕР¶Рµ PID=0 kernel thread) РІС‹Р±СЂР°Р» pid_off=0xd8
- Bug #268 chain validation СЃ pid_off=0xd8: len=11, unique_nonzero=2, found_ourpid=0  REJECTED

РџСЂРѕР±Р»РµРјР°: РєРѕРґ РЅРµ РїСЂРѕРІРµСЂСЏР» С‡С‚Рѕ proc0.le_prev == candidate  СЃС‚СЂСѓРєС‚СѓСЂРЅРѕРµ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ
TAILQ, С‡С‚Рѕ candidate IS allproc. BSD LIST le_prev РїРµСЂРІРѕРіРѕ СЌР»РµРјРµРЅС‚Р° СѓРєР°Р·С‹РІР°РµС‚ РЅР°Р·Р°Рґ
РЅР° &allproc.lh_first = candidate. Р­С‚Рѕ РјР°С‚РµРјР°С‚РёС‡РµСЃРєРё С‚РѕС‡РЅРѕРµ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ.

**Р¤РёРєСЃ:** РџРµСЂРµРґ Р±Р»РѕРєРѕРј Bug #268 РґРѕР±Р°РІР»РµРЅР° РїСЂРѕРІРµСЂРєР°:
`objc
bool skip_chain_validate = false;
if (!is_heap_ptr_relaxed(le_prev) && is_kptr(le_prev) && le_prev == candidate) {
    filelog_write("[allproc] Bug #295: proc0.le_prev == candidate ... definitive allproc proof");
    if (discovered_pid_off && discovered_pid_off != original_pid_off)
        discovered_pid_off = 0;  // discard wrong probed pid_off
    skip_chain_validate = true;
}
if (!skip_chain_validate) { /* Bug #268 block */ }
`

**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™  Р±РµР· СЌС‚РѕРіРѕ РµРґРёРЅСЃС‚РІРµРЅРЅС‹Р№ РїСЂР°РІРёР»СЊРЅС‹Р№ allproc offset РѕС‚РєР»РѕРЅСЏР»СЃСЏ РєР°Р¶РґС‹Р№ СЂР°Р·

---

### Bug #296: ourproc zone scan РїР°РґР°РµС‚ РЅР° РїРµСЂРІРѕР№ Р¶Рµ РѕС€РёР±РєРµ kread, РЅРµ РЅР°С…РѕРґРёС‚ user procs (build 5354)

**РЎРµСЃСЃРёСЏ:** 25e  syslog_2026-04-02_15-56

**РЎРёРјРїС‚РѕРј:** allproc РЅР°Р№РґРµРЅ (Bug #295 СЃСЂР°Р±РѕС‚Р°Р»), KERNPROC SUCCESS. РќРѕ ourproc() РќР• РќРђРҐРћР”РРў
DarkSword (PID=449): allproc С†РµРїРѕС‡РєР° СЃРѕРґРµСЂР¶РёС‚ С‚РѕР»СЊРєРѕ 11 kernel threads (РІСЃРµ PID=0),
user procs РІ СЌС‚РѕР№ С†РµРїРѕС‡РєРµ РѕС‚СЃСѓС‚СЃС‚РІСѓСЋС‚. Zone scan РїР°РґР°РµС‚ РЅР° С€Р°РіРµ 2.

**Root cause (3 РєРѕРјРїРѕРЅРµРЅС‚Р°):**

1. **allproc chain = С‚РѕР»СЊРєРѕ kernel threads**: РќР° iOS 17.3.1 РїРѕ РЅРµРїРѕРЅСЏС‚РѕР№ РїСЂРёС‡РёРЅРµ forward
   walk allproc РґР°С‘С‚ С‚РѕР»СЊРєРѕ 11 kernel threads (PID=0), РїРѕСЃР»РµРґРЅРёР№ РёРјРµРµС‚ le_next=NULL.
   User procs РІРєР»СЋС‡Р°СЏ DarkSword (PID=449) РЅРµ РІ СЌС‚РѕР№ С†РµРїРѕС‡РєРµ.

2. **Zone scan anchor РЅРµРїСЂР°РІРёР»СЊРЅС‹Р№**: РЎСѓС‰РµСЃС‚РІСѓСЋС‰РёР№ coarse scan РёСЃРїРѕР»СЊР·СѓРµС‚
   [scan_min_seen, scan_max_seen]  РґРёР°РїР°Р·РѕРЅ РёР· 11 kernel thread proc Р°РґСЂРµСЃРѕРІ.
   Р­С‚Рё Р°РґСЂРµСЃР° РЅРµ РїРѕРєСЂС‹РІР°СЋС‚ Р·РѕРЅСѓ РіРґРµ Р°Р»Р»РѕС†РёСЂРѕРІР°РЅС‹ user procs.

3. **break РІРјРµСЃС‚Рѕ continue**: coarse scan РїСЂРё РѕС€РёР±РєРµ kread РґРµР»Р°РµС‚ reak, РѕСЃС‚Р°РЅР°РІР»РёРІР°СЏ
   РІРµСЃСЊ СЃРєР°РЅ. Stride  xD58 РЅРµ РІС‹СЂРѕРІРЅРµРЅ РїРѕ СЃС‚СЂР°РЅРёС†Р°Рј  СЃСЂР°Р·Сѓ РїРѕРїР°РґР°РµС‚ РЅР° unmapped page.
   РќСѓР¶РЅРѕ РґРµР»Р°С‚СЊ continue (РїСЂРѕРїСѓСЃС‚РёС‚СЊ unmapped СЃС‚СЂР°РЅРёС†Сѓ) Рё РїСЂРѕРґРѕР»Р¶Р°С‚СЊ.

**Р¤РёРєСЃ  Bug #296 full zone scan** (РґРѕР±Р°РІР»РµРЅ РІ ourproc() РїРµСЂРµРґ 
eturn 0):
- РСЃРїРѕР»СЊР·СѓРµС‚ ds_get_zone_map_min() / ds_get_zone_map_max()  СЂРµР°Р»СЊРЅС‹Рµ zone bounds
- Stride:  x1000 (page-aligned  РІСЃРµ observed proc Р°РґСЂРµСЃР° РєСЂР°С‚РЅС‹ 0x1000)
- РќР° РѕС€РёР±РєРµ kread: continue (РќР• break)
- Smart skip: 16 consecutive failures  РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅС‹Р№ jump 256 СЃС‚СЂР°РЅРёС† (1 MB) С‡РµСЂРµР· unmapped gap
- Max 3M РёС‚РµСЂР°С†РёР№ (~12 GB РїРѕРєСЂС‹С‚РёРµ)
- Р’Р°Р»РёРґР°С†РёСЏ PID match: РїСЂРѕРІРµСЂСЏРµС‚ p_list pointer sanity

**Р”Р°РЅРЅС‹Рµ РёР· syslog 15:56:**
- kbase= xfffffff00c7a4000, zone=[0xffffffdf2edc8000..0xffffffe52edc8000]
- allproc=kbase+0x3213678=0xfffffff00f9b7678
- proc0= xffffffe1482a3000 (le_prev=allproc )
- allproc chain: 11 procs, РІСЃРµ PID=0, proc[10].le_next=0x0
- coarse scan: step 2  kread failed at 0xffffffe22f3d0ab0  break
- fine scan: 40000 reads, not found

**Р¤Р°Р№Р»С‹:** darksword/utils.m
**Р’РµСЂСЃРёСЏ:** build 54
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™  Р±РµР· СЌС‚РѕРіРѕ ourproc РІСЃРµРіРґР° failing, jailbreak РЅРµ СЂР°Р±РѕС‚Р°РµС‚


---

### Bug #296: ourproc zone scan РЅРµ РЅР°С…РѕРґРёС‚ user procs (build 53->54)

**РЎРµСЃСЃРёСЏ:** 25e - syslog 2026-04-02 15:56

**РЎРёРјРїС‚РѕРј:** allproc РЅР°Р№РґРµРЅ (Bug #295), KERNPROC SUCCESS, РЅРѕ ourproc() РќР• РќРђРҐРћР”РРў DarkSword (PID=449): allproc chain = 11 kernel threads (PID=0), user procs РІ С†РµРїРё РЅРµС‚. Zone scan РѕСЃС‚Р°РЅР°РІР»РёРІР°РµС‚СЃСЏ РЅР° С€Р°РіРµ 2.

**Root cause (3 РєРѕРјРїРѕРЅРµРЅС‚Р°):**

1. allproc forward walk СЃРѕРґРµСЂР¶РёС‚ С‚РѕР»СЊРєРѕ 11 kernel threads, le_next РїРѕСЃР»РµРґРЅРµРіРѕ = NULL. User procs (PID=449) РІ РґР°РЅРЅРѕР№ С†РµРїРё РЅРµ РїСЂРёСЃСѓС‚СЃС‚РІСѓСЋС‚.
2. Coarse zone scan РёСЃРїРѕР»СЊР·СѓРµС‚ anchor [scan_min_seen, scan_max_seen] = РґРёР°РїР°Р·РѕРЅ 11 kernel proc Р°РґСЂРµСЃРѕРІ. User procs РІРЅРµ СЌС‚РѕРіРѕ РґРёР°РїР°Р·РѕРЅР°.
3. РџСЂРё РѕС€РёР±РєРµ kread coarse scan РґРµР»Р°РµС‚ break (СЃС‚РѕРї) РІРјРµСЃС‚Рѕ continue (РїСЂРѕРїСѓСЃС‚РёС‚СЊ unmapped page). Stride 0xD58 РЅРµ РІС‹СЂРѕРІРЅРµРЅ РїРѕ СЃС‚СЂР°РЅРёС†Р°Рј.

**Р¤РёРєСЃ - Bug #296 full zone_map scan** (РґРѕР±Р°РІР»РµРЅ РїРµСЂРµРґ return 0 РІ ourproc()):
- Bounds: ds_get_zone_map_min() / ds_get_zone_map_max() (СЂРµР°Р»СЊРЅС‹Рµ runtime zone bounds)
- Stride: 0x1000 (page-aligned, РІСЃРµ observed proc Р°РґСЂРµСЃР° РєСЂР°С‚РЅС‹ 0x1000)
- РќР° РѕС€РёР±РєРµ kread: continue, РќР• break
- Smart skip: 16 consecutive failures -> +256 СЃС‚СЂР°РЅРёС† (1 MB) РґР»СЏ РѕР±С…РѕРґР° unmapped gaps
- Max 3M РёС‚РµСЂР°С†РёР№ (~12 GB РїРѕРєСЂС‹С‚РёРµ)
- Р’Р°Р»РёРґР°С†РёСЏ: РїСЂРѕРІРµСЂСЏРµС‚ p_list pointer sanity РїСЂРё PID match

**Р”Р°РЅРЅС‹Рµ syslog 15:56:**
- kbase=0xfffffff00c7a4000, zone=[0xffffffdf2edc8000..0xffffffe52edc8000]
- allproc=kbase+0x3213678, proc0=0xffffffe1482a3000 (le_prev=allproc OK)
- 11 procs, proc[10].le_next=0x0
- coarse scan step 2: kread failed at 0xffffffe22f3d0ab0 -> break (BUG)
- fine scan: 40000 reads, not found

**Р¤Р°Р№Р»С‹:** darksword/utils.m
**Р’РµСЂСЃРёСЏ:** build 54
**РРјРїР°РєС‚:** РљР РРўРР§Р•РЎРљРР™

---

### Bug #297: Bug #296 zone скан стартует с zone_map_min  zone bounds check panic (build 5455)

**Симптом (build 54, syslog 16:26):**
`
panic: zone bound checks: buffer 0xffffffde5cad4060 of length 4 overflows object 0xffffffde5cad4060 of size 0 in zone [] @zalloc.c:1281
`
 xffffffde5cad4060 = zone_map_min + 0x60 = zmin + pid_off  первая итерация Bug #296 скана.

**Причина:** Bug #296 инициализировал p296 = zmin = zone_map_min. Начало zone_map  это VM zone (метаданные), первые объекты имеют размер 0. Чтение (ds_kread32 по zmin + pid_off) проходит через KRW-примитив который тригерит XNU zone bounds check  kernel panic.

**Zone map layout (из panic):**
- VM: zmin..zmin+3.1GB  метаданные (опасно!)
- RO: +0.5GB  read-only zone (опасно)
- GEN0:  xffffffdf8fe04000..0xffffffe076468000 (~3.8GB)  heap (безопасно)
- GEN1:  xffffffe076468000..zmax  heap (безопасно)  proc0 здесь

**Фикс Bug #297** (build 55): стартовать с kernproc  4GB вместо zmin:
`objc
const uint64_t scan_radius = 0x100000000ULL; /* 4 GB */
uint64_t p296 = (kernproc > scan_radius + zmin)
                    ? (kernproc - scan_radius)     /* kernproc-4GB = GEN0/GEN1 */
                    : (zmin + scan_radius);         /* floor: zmin+4GB */
uint64_t p296_end = (zmax > kernproc + scan_radius)
                        ? (kernproc + scan_radius)
                        : zmax;
// ZONE296_MAX уменьшен с 3M до 2.1M (8GB scan)
`
kernproc-4GB = 0xffffffe05cb0f000  в GEN0, далеко от VM zone метаданных. Proc structs (struct proc) живут в той же зоне что и proc0 (GEN1), scan window 4GB покрывает весь GEN1.

**Статус:** Build 55 скомпилирован и установлен.

---

### Bug #297: Bug #296 zone scan стартует с zone_map_min  zone bounds check panic (build 5455)

**Симптом (build 54, syslog 16:26):**
panic: zone bound checks: buffer 0xffffffde5cad4060 (length 4) overflows object of size 0 in zone [] @zalloc.c:1281
0xffffffde5cad4060 = zone_map_min + 0x60 = zmin + pid_off  первая итерация Bug #296.

**Причина:** p296 = zmin = zone_map_min. VM zone на начале zone_map имеет size=0 объекты. ds_kread32(zmin + pid_off)  XNU zone bounds check  kernel panic.

**Zone layout (из panic log):**
VM   : zmin..zmin+3.1GB  (метаданные, ОПАСНО)
RO   : +0.5GB            (ОПАСНО)
GEN0 : 0xffffffdf8fe04000..0xffffffe076468000 (БЕЗОПАСНО)
GEN1 : 0xffffffe076468000..zmax              (БЕЗОПАСНО, proc0 здесь)

**Фикс (build 55):** scan_radius = 4GB; p296_start = kernproc - 4GB (= GEN0/GEN1).
kernproc (proc0) = 0xffffffe15cb0f000. kernproc - 4GB = 0xffffffe05cb0f000 (GEN0/GEN1).
ZONE296_MAX снижен 3M2.1M (8GB окно). Proc structs в той же зоне что proc0.

**Статус:** Build 55 установлен.
---

### Bug #298#332: Серия исправлений zone scan / allproc (builds 4949)

**Краткое содержание:**
- Bug #298#319: Various zone_scan safety improvements, SMRQ allproc probing, kernproc chain detection
- Bug #320#324: Page-aligned proc scanning, pre_window=0 for forward-only safety
- Bug #325#328: Phased seed-local expansion (4 phases: 0x4000/0x40000/0x100000/0x400000)
- Bug #329: gap_limit per phase (4/16/64/128)
- Bug #330#331: kread_proc_name_bounded() safe name read within 4KB page boundary
- Bug #332: Added 5th phase (window=0x4000000 = 64MB, gap_limit=512) for distant proc

**Статус:** Build 49 скомпилирован и установлен.

---

### Bug #333: DATA-SMRQ allproc  sle_next at +0x08, не +0x00 (build 50)

**Симптом (build 49, panic 08:39:42):**
`
panic(cpu 6 caller 0xfffffff02a8de1f0): zone bound checks: buffer 0xffffffdd36b780d8
of length 4 overflows object 0xffffffdd36b780d8 of size 0 in zone [] @zalloc.c:1281
`
Phase 4 (64MB window) zone scan попал на незанятую/guard zone page  XNU zone bounds check  panic.

**Root cause:**
allproc (offset 0x31FFF30)  *(allproc) = 0xfffffff02c65ebd4 (kernel DATA, proc0 base).
- PID=0 at proc0+0x60  (confirmed)
- le_next read: *(proc0+0x00) = 0x0 (SMRQ sle_seq = 0 для статически аллоцированного proc0)
- SMRQ sle_next (*(proc0+0x08)) никогда не проверялся!
Код читал sle_seq (0x0) вместо sle_next (+0x08), считал le_next=NULL, падал на zone_scan.

**iOS 17.3.1 proc struct layout (SMRQ, list_off=0):**
- proc+0x00: smrq_slink.sle_seq = 0 (uint64, zero-init)
- proc+0x08: smrq_slink.sle_next  first_heap_proc_base
- proc+0x60: p_pid

**Фикс (utils.m, darksword/utils.m):**
В DATA-proc0 path добавлен fallback после le_next@+0x00=0:
`objc
// Bug #333: try sle_next at +0x08 (after 8-byte sle_seq)
uint64_t sle_next_raw = 0;
if (ds_kread64_checked(stripped + 0x08, &sle_next_raw)) {
    uint64_t sle_next = pac_strip(sle_next_raw);
    if (is_heap_ptr_relaxed(sle_next)) {
        uint32_t sn_pid = 0;
        if (ds_kread32_checked(sle_next + 0x60, &sn_pid) && sn_pid > 0 && is_plausible_pid(sn_pid)) {
            PROC_LIST_OFFSET = 0x00;
            PROC_NEXT_OFFSET = 0x08;
            PROC_PREV_OFFSET = 0x00;
            PROC_PID_OFFSET  = 0x60;
            g_direct_layout_set = true;
            g_kernproc_addr = candidate;
            g_kernproc_is_pid0 = false;
            return candidate;
        }
    }
}
`

**Результат:** allproc детектируется корректно через 0x31FFF30 с SMRQ layout (list_off=0, next_off=0x08, pid_off=0x60). Zone scan больше не нужен/не запускается. Устраняет zone bound check panic.

**Файлы:** darksword/utils.m
**Версия:** Build 50
**Импакт:** КРИТИЧЕСКИЙ  allproc detection теперь работает без zone scan

---

### Bug #334: PROC_PID_OFFSET=0x60 неверен для iOS 17; allproc — 0x31C3000 (Build 51)

**Проблема:** Build 50 паникует с `zone bound checks @zalloc.c:1281`. Анализ Build 50 показал:
1. GOT-кандидат `0x93B348` → `*(0xfffffff024666af8) = 0x52800020d503245f` = ARM64 инструкции (ISB SY), не proc ptr
2. PPLDATA `0x3198060` → значение 0xfffffff043846140 не является heap ptr
3. `0x3213678` принимался как kernproc [optimistic] через Bug #317 (обнаружен `pid_off=0xd8` ≠ `original_pid_off=0x60`)
4. Bug #319: `goto bug296_zone_scan` → 64MB сканирование → неаллоцированная GEN2 guard page → PANIC

**Коренная причина:** `PROC_PID_OFFSET=0x60` — неверное значение для iOS 17.3.1. PHASE2_SYMBOLS_REPORT.md явно указывает: "offset 0x60 ← proc->p_pid (iOS 18.4+)". На iOS 17.x `p_pid` находится на смещении `0xd8` (подтверждено динамическим обнаружением: kernel thread с PID=115 → +0xd8=115, kernel_task → +0xd8=0).

**Дополнительно:** Настоящий allproc — `kbase+0x31C3000` (__DATA.__common начало), 1211 xrefs (наибольшее среди всех DATA globals), но с `PROC_PID_OFFSET=0x60` validate_allproc его отвергал.

**Изменения:**

1. `init_offsets()`: `PROC_PID_OFFSET = 0xd8` для iOS 15..17, `0x60` для iOS 18+:
```objc
if (major >= 18) {
    PROC_PID_OFFSET = 0x60;  // iOS 18.4+
} else if (major >= 15) {
    PROC_PID_OFFSET = 0xd8;  // Bug #334: iOS 15-17
} else {
    PROC_PID_OFFSET = 0x10;
}
```

2. `build_pid_offset_candidates()`: возвращает {PROC_PID_OFFSET, alt} (оба 0xd8 и 0x60):
```objc
out[0] = PROC_PID_OFFSET;
out[1] = (PROC_PID_OFFSET == 0xd8) ? 0x60 : 0xd8;
return 2;
```

3. `builtin_xpf_offsets_for_os()` для 21D61: `0x31C3000` первым (был последним):
```
return "0x31C3000,0x31FFF30,0x3213678,0x3213680";
```

4. Bug #319: `goto bug296_zone_scan` → `return 0` (зональное сканирование из kernel thread anchor → panic):
```objc
filelog_write("[ourproc] Bug #334: ...aborting to prevent zone-scan panic");
return 0;
```

**Ожидаемый эффект:**
- `validate_allproc(kbase+0x31C3000)` проходит: `is_heap_ptr_relaxed(smrqh_first)=YES`, `*(smrqh_first+0xd8)=PID>0` → `direct_ok=TRUE`
- `discover_proc_list_layout` с pid_off=0xd8: scores ≈ 485 (все PID уникальны) >> 40 → fast accept
- `ourproc()` идёт по allproc → находит DarkSword
- Даже при сбое allproc: `return 0` вместо panic

**Дополнительный эффект:** С `original_pid_off=0xd8` и `discovered_pid_off=0xd8` у kernel thread chain — условие Bug #317 "optimistic" (`discovered_pid_off != original_pid_off`) теперь FALSE → 0x3213678 больше не принимается оптимистично → zone scan не инициируется.

**Файлы:** darksword/utils.m
**Версия:** Build 51
**Импакт:** КРИТИЧЕСКИЙ — корневое исправление неверного p_pid offset + правильный allproc + защита от zone-scan panic

---

### Bug #373/374: allproc validation falsely rejects iOS 17.3.1 direct offsets
**Проблема:** В iOS 17.3.1 первый тир кандидатов llproc (напр.  x31FFF30) содержит начальную цепь, полностью состоящую из потоков ядра (PID 0). alidate_direct_allproc_v2_with_layout отклонял их из-за нехватки уникальных пользовательских PID, что приводило к fallback и использованию неверных оффсетов.
**Решение:** Добавлена логика is_ios17_kernel_chain, которая разрешает использовать llproc, если начальная цепь состоит из PID 0 и не ломается (уникальных PID мало, но они стабильны).
**Файлы:** darksword/utils.m
**Версия:** Build 62/63
**Импакт:** КРИТИЧЕСКИЙ  восстанавливает привязку к Tier 0 оффсетам llproc на iOS 17.3.1.

---

### Bug #378: scan-discovered BSD allproc layout switched to `pid_off=0x60`, but follow-up validation still used stale `0xd8` and crashed before `kernprocaddress()` returned

**Симптом:** в run `syslog_2026-04-03_17-28-54.txt` ложные kernel-only direct/XPF-lite кандидаты `0x3213678` и `0x3213680` уже не принимались. После этого inner DATA scan нашёл новый BSD-style head:
`proc list layout: raw=0xffffffe2dfb2fe80 base=0xffffffe2dfb2fe80 list_off=0x0 pid_off=0x60 next_ff=0x8 ... -> FOUND!`
Сразу после этой строки syslog обрывался. В `panic-full-2026-04-03-172929.0002.ips` зафиксирован `Kernel data abort`, panicked task: `DarkSword` (pid 538). Строки `[ourproc] kernprocaddress() returned ...` уже не было, значит падение происходило ещё внутри `kernprocaddress()` / scan validation.

**Root cause:** `discover_proc_list_layout()` корректно находил layout scan-кандидата с `best_pid_off=0x60`, но коммитил только `PROC_LIST_OFFSET`, `PROC_NEXT_OFFSET` и `PROC_PREV_OFFSET`. Глобальный `PROC_PID_OFFSET` оставался на старом runtime-значении `0xd8`. Затем `validate_proc_chain_with_pid_off()` и follow-up link normalization снова шли через helper, завязанный на глобальный PID offset, и пере-декодировали уже найденную BSD цепочку как будто `p_pid` всё ещё лежит на `0xd8`. Это открывало crash window между `proc list layout ... -> FOUND!` и возвратом из `kernprocaddress()`.

**Фикс:**
1. `discover_proc_list_layout()` теперь коммитит `PROC_PID_OFFSET = best_pid_off` при принятии layout и отдельно логирует переключение PID offset.
2. `validate_proc_chain_with_pid_off()` теперь читает следующий proc через `proc_list_next_checked_pid(..., pid_off, ...)`, а не через helper с неявным использованием глобального `PROC_PID_OFFSET`.

**Ожидаемый эффект:** после scan-discovery реального BSD chain (`list_off=0x0`, `pid_off=0x60`) и validation, и последующий `ourproc()` walk будут декодировать один и тот же layout. Падение между `FOUND!` и `kernprocaddress()` return должно исчезнуть.

**Файлы:** darksword/utils.m
**Статус:** source patched; device retest required.

---

### Bug #373/374: allproc validation falsely rejects iOS 17.3.1 direct offsets
**Проблема:** В iOS 17.3.1 первый тир кандидатов llproc (напр.  x31FFF30) содержит начальную цепь, полностью состоящую из потоков ядра (PID 0). alidate_direct_allproc_v2_with_layout отклонял их из-за нехватки уникальных пользовательских PID, что приводило к fallback и использованию неверных оффсетов.
**Решение:** Добавлена логика is_ios17_kernel_chain, которая разрешает использовать llproc, если начальная цепь состоит из PID 0 и не ломается (уникальных PID мало, но они стабильны).
**Файлы:** darksword/utils.m
**Версия:** Build 62/63
**Импакт:** КРИТИЧЕСКИЙ  восстанавливает привязку к Tier 0 оффсетам llproc на iOS 17.3.1.
