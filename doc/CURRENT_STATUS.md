# ������� ������ DarkSword Jailbreak

> UPDATE 2026-04-04 (Bug #455): точный blocker для `iPad8,9 / 21D61` сместился в late-stage `ourproc()` recovery.
> Сейчас подтверждено следующее:
> - `kernproc` для 21D61 стабильно поднимается через curated/XPF shortlist;
> - `socket/tro` fast path всё ещё не возвращает validated `self proc`, даже после narrow nearby sweep;
> - `ourproc()` после list/backward fallbacks уходит в seed-local scan, но wide `64MB` phase 4 вызывала zone-bound panic (`page_base + 0x60` pattern);
> - поэтому phase 4 теперь отключена по умолчанию на exact `21D61`, а текущий статус проекта: **KRW OK, stable ourproc NOT OK**.
>
> Что сейчас НЕ работает в standalone runtime:
> - нет гарантированного получения `ourproc()` / `ourtask()` на exact `21D61`;
> - bootstrap chain не считается надёжно рабочим на этом устройстве;
> - текущая задача следующего цикла — либо дожать `socket/tro` self-proc path, либо безопасно восстановить user proc без panic через ограниченный fallback.

> ���������: 2026-04-04 (������ 2125i + offline_test_v6..v26 + runtime builds 42-64)
> 342 ����� �����������������; ������-������ ������������ (21/21 PASS, ������� custom training v24-v26).
> ������� ����: свежий runtime после Bug #381 уже panic-free, но новый blocker сместился раньше — DATA scan находит сильный proc-layout candidate (`score=25`, `pid_off=0x60`), а затем post-check `validate_proc_chain()` всё ещё выбивает его из-за loop/cycle до принятия как `allproc`.
> ��������� code-fix: Bug #382 в `utils.m`; revisit/cycle после достаточной PID-diversity теперь не делает мгновенный reject, а проходит через итоговую summary-валидацию, чтобы сильный DATA candidate мог быть принят как `allproc`.

> NOTE (2026-04-03): Bug #331 name-based fallback в seed-slot prepass откатан после `early_kread` regression. Текущий код: bounded `p_comm` helper сохранён, seed-slot prepass снова PID-only, активная device-validation цель — Bug #332 64MB forward scan.

## Update 2026-04-04  Bug #448 — disc_pl Phase2 пропускал list_off=0x00; выбирал wrong list (build 82)

**Симптомы (build 81, 3 прогона):** allproc SUCCESS (offset 0x321c480), disc_pl MATCH `list_off=0xb0 score=50`. ourproc() прошёл 227 proc (pid=320→94), `raw_next=0x0` (NULL). max_pid=320 < ourpid=466. `Bug #336: chain exhausted`.

**Root cause:** Phase 2 disc_pl: `for (list_off = 0x08; ...)` — скипал `list_off=0x00`. Реальный `p_list` iOS 17 TAILQ находится на `list_off=0x00` (подтверждено: `*(kernproc+0x08)=allproc` = le_prev → allproc). list_off=0xb0 = чужой структурный список (pid=320..94, 227 прокс, NULL). DarkSword(466) там нет. Bug #337 ходил только 10 шагов и не восстанавливал.

**Fix (Bug #448):**
1. Phase 2 `disc_pl`: `list_off=0x08` → `list_off=0x00`. score_proc_chain_ex с 0x00 скорит ~50 pid → MATCH с list_off=0x00.
2. Bug #337+448: 10→500 шагов; при нахождении ourpid — устанавливает PROC_LIST_OFFSET=0x00 и возвращает proc.

---

## Update 2026-04-04  Bug #447 — proc-scope anchor window ±12GB блокировал disc_pl → PANIC GUARD → abort (build 81)

**Симптом (build 80):**
allproc SUCCESS нашёл head=`0xfffffff010d40400` (kernproc, offset 0x321c400). `disc_pl` запустился с entry=`0xffffffe4668b3000`, но proc chain из kernproc содержал адреса `0xffffffe71936xxxx` (~14.3GB выше rw_socket_pcb=`0xffffffe380bb4400`). Каждое такое чтение через `set_target_kaddr` проверялось по anchor window `[rw-12GB, rw+12GB]=[0xffffffe2ccb98000, 0xffffffe680bb4400)` — адрес 14GB выше = BLOCKED. После 32 блокировок: `g_proc_scope_block_latched=true` → PANIC GUARD. `disc_pl` вернул `NO MATCH`. Попытка walk при step=0 сразу видит PANIC GUARD → abort.

**Root cause:** Bug #426 установил proc-scope anchor span=12GB. На 21D61 A12Z zone_map=24GB, rw_socket_pcb ~4.5GB выше zone_min → легитимные procs у конца zone_map находятся на ~14.5GB выше rw, что выходит за пределы ±12GB window.

**Fix (Bug #447):** В proc-scope (`g_proc_read_scope_depth > 0`): `anchor_max = zone_guard_max` (верхний предел zone_map) вместо `rw + 12GB`. Нижняя граница (rw - 12GB) сохранена для защиты от нижних false-ptrs.

**Файл:** `darksword/darksword_core.m`, `set_target_kaddr()`, блок anchor window (~строка 937)

**Build:** 81 (2026-04-04) — установлен

---

## Update 2026-04-05  Bug #445 + #446 — allproc head ниже safe_min отклонялся (build 80)

**Симптом (build 79):**  
`ourproc()` упал: socket/tro fast path не нашёл proc (tro_rejects=40 — все tro PAC-pointer-gated), затем allproc path — XPF offset 0x3213678 возвращает head=`0xffffffe299239000` (реальный allproc!), но прямой shortlist отклонял его строкой `"not even relaxed-heap"` — адрес ниже `zone_safe_min=0xffffffe2e5948000` на ~0.9GB, хотя входит в zone_map.

**Bug #445 — is_heap_ptr_relaxed в allproc validation:**
- Адрес `0xffffffe299239000` в zone_map (32% от zone_min), но ниже `zsafe = zone_min + 25%`
- 8 мест в `validate_direct_allproc_v2_with_layout`, `validate_allproc` и direct shortlist использовали `is_heap_ptr_relaxed` без fallback на `is_in_zone_map`
- Исправлено: добавлено `|| is_in_zone_map(...)` / `&& !is_in_zone_map(...)` во все критические проверки

**Bug #446 — val_ap Bug #398 3GB window:**
- kernproc head `0xffffffe465391000` IN zone_map но 7.2GB от rw_pcb (> 3GB лимита)
- Исправлено: если `is_in_zone_map(head_stripped)`, пропустить reject по 3GB proximity (allproc heads могут быть в любом месте zone_map)

**Ожидание (build 80):**  
Allproc head `0xffffffe299239000` принимается → `validate_direct_allproc_v2` с list_off=0xb0, pid_off=0x60 обходит SMRQ список → находит pid=479 → `ourproc()` SUCCESS.

---

## Update 2026-04-05  Bug #444 + возобновление socket/tro fast path (build 79)

**Суть изменения:**  
`find_self_proc_via_socket_tro()` использовал офсеты `tro_proc=0x18` / `tro_task=0x28`, что верно только для iOS 17.4+. На iOS 17.3.1 правильные значения: `0x10` / `0x20` (подтверждено из offsets.m wh1te4ever/darksword-kexploit-fun).

**Что читалісь в 0x18 вместо 0x10:** `tro_task` (kptr) → `proc_ok = false` → все попытки отклонялись → fast path возвращал 0 → Bug #433 отключил его.

**Исправление:**
- Константы заменены на массивы `{0x10, 0x18}` / `{0x20, 0x28}` + внутренний `for pc` цикл;
- Блокировка Bug #433 (`enable_socket_tro_fastpath = false` для 21D61) снята;
- Лог SUCCESS содержит поле `tro_proc_off=0x%x`.

**Ожидание:**  
`[ourproc] socket/tro fast path SUCCESS: ... tro_proc_off=0x10 ...` вместо вызова `kernprocaddress()`.

---

## Update 2026-04-04  Bug #387/#388 + build/install validation

## Update 2026-04-04  Bug #389 + fresh runtime root-cause

## Update 2026-04-04  Bug #390 + mixed-head legacy rejection

## Update 2026-04-04  Bug #391 + direct_v2 pid-off unhardcode

## Update 2026-04-04  Bug #392 + anti-false-FOUND gate в discover_proc_list_layout

## Update 2026-04-04  Bug #393 + отключение kernel-only direct_v2 shortcut

## Update 2026-04-04  Bug #394 + anti-partial-allproc gate в validate_allproc

## Update 2026-04-04  Bug #395 + расширение safe `__bss` scan window вниз

## Update 2026-04-04  Bug #396 + guard верхнего tail zone-map против per-cpu panic

## Update 2026-04-04  Bug #426 + scoped anchor-window widen (±12GB в proc/allproc scope)

## Update 2026-04-04  Bug #427 + scoped low-bound widen для guarded window (safe_min-4GB)

## Update 2026-04-04  Bug #428 + pre-zone-discovery anchor guard (anti-metadata panic before confirmed zone_info)

## Update 2026-04-04  Bug #429 + proc-scope fail-fast PANIC GUARD в `set_target_kaddr` (abort-after-block-storm)

## Update 2026-04-05  Bug #440 + PROC_BSD_BACKLINK_MAX_DIFF 8 GB → 20 GB (allproc head на 10.9 GB от rw_pcb)

## Update 2026-04-05  Bug #442 + сброс g_failed_allproc_heads при safe-shortlist fallback pass

## Update 2026-04-05  Bug #443 + замена is_heap_ptr_relaxed → is_proc_chain_ptr в chain-walk валидаторах (fix chain=11 cutoff ниже zone_safe_min)

## Update 2026-04-04  Bug #397 + metadata translation-fault guard в relaxed chain-walk

## Update 2026-04-04  Bug #414 + `Bug #268` next_ff dual-probe fix

## Update 2026-04-04  Bug #417 + hardening `set_target_kaddr` text/data gate (anti-copy_validate panic)

## Update 2026-04-04  Bug #418 + guarded zone-window в `set_target_kaddr` (anti-metadata data-abort)

## Update 2026-04-04  Bug #419 + `rw_socket_pcb` proximity-anchor в `set_target_kaddr` (anti-far-zone data-abort)

## Update 2026-04-04  Bug #420 + Mach-O allproc fallback enabled-by-default (post-419 functional unblock)

## Update 2026-04-04  Bug #424 + bypass false-positive mixed-head rejection (SMRQ allproc iOS 17.3.1)


## Update 2026-04-04  Bug #422 + disable direct `kernproc` path by default on 21D61

## Update 2026-04-04  Bug #423 + scoped widening of proc/allproc anchor-window

### Что показал свежий syslog (log/syslog_2026-04-04_12-04-00.txt) — Bug #423 analysis

**Новый статус после Bug #422:**
- crash-class действительно снят: новый run panic-free,
- direct `kernproc` path на `21D61` корректно skipped,
- но resolver по-прежнему не доходит до usable `allproc`: `XPF-lite` -> inner `__DATA` scan -> `Mach-O parse scan` -> `all strategies exhausted`.

**Свежий functional blocker:**
- лог показал правдоподобный proc candidate рядом с `rw_socket_pcb`,
- затем deep validation / traversal начал упираться в low-level guard:
    - `set_target_kaddr: BLOCKED zone addr outside rw_socket_pcb anchor window ...`
- то есть текущий blocker уже не structural panic-path, а слишком ранний low-level reject на реальных proc-chain deref.

**Что изменено (Bug #423):**
- в `darksword_core` добавлен scoped режим proc-read,
- в этом scope anchor-window вокруг `rw_socket_pcb` расширяется с `±4GB` до `±8GB`,
- scope включён только для validated proc/allproc paths в `validate_allproc()` и `ourproc()`,
- остальные crash guards (`zone_safe_min`, top-tail guard, text/data gating) не ослаблены.

**Ожидаемый маркер следующего run:**
- исчезновение или заметное уменьшение `BLOCKED zone addr outside rw_socket_pcb anchor window` на deep proc traversal,
- либо acceptance одного из сильных `XPF-lite` / `DATA` candidates,
- либо более глубокий panic-free walk с новыми telemetry, по которым уже можно править именно chain/layout acceptance, а не low-level anchor gate.

## Update 2026-04-04  Bug #416 + расширение `thread->tro` scan window в socket/TRO fast-path

## Update 2026-04-04  Bug #415 + hardening speculative kernproc chain walkers (anti-metadata-abort)

## Update 2026-04-04  Bug #413 + low-zone-map proc-chain scoring fix

## Update 2026-04-04  Bug #412 + post-KRW `kfs_init` anti-rediscovery fix

## Update 2026-04-04  Bug #398 + proximity-gate к rw_socket_pcb (anti-far-head)

## Update 2026-04-04  Bug #411 + bounded thread-TRO scan в socket/TRO fast-path

## Update 2026-04-04  Bug #410 + bounded socket-thread scan в socket/TRO fast-path

## Update 2026-04-04  Bug #409 + multi-offset socket selection в socket/TRO fast-path

## Update 2026-04-04  Bug #408 + rw_socket_pcb pre-gate fix в socket/TRO fast-path

## Update 2026-04-04  Bug #407 + thread gate relax в socket/TRO fast-path

## Update 2026-04-04  Bug #406 + stage-telemetry и relaxed `tro` gate в socket/TRO fast-path

## Update 2026-04-04  Bug #405 + socket/TRO fast-path ptr-gate fix

## Update 2026-04-04  Bug #404 + direct/probe chain ptr-check + depth 512 в `utils.m`

## Update 2026-04-04  Bug #403 + is_in_zone_map — chain-walk через ранние kthread proc structs ниже zone_safe_min

## Update 2026-04-04  Bug #402 + guarded far-head допуск по BSD-backlink в validate_allproc

## Update 2026-04-04  Bug #401 + BSD-head recovery fallback после partial allproc reject

## Update 2026-04-04  Bug #400 + расширение near-rw_pcb weak-score gate до score>=6

## Update 2026-04-04  Bug #399 + near-rw_pcb weak-score gate в `discover_proc_list_layout`

### Что показал свежий syslog (log/syslog_2026-04-04_10-54-11.txt) — Bug #414 analysis

### Что показал свежий syslog/panic (log/syslog_2026-04-04_10-58-47.txt + panic-full-2026-04-04-105954.0002.ips) — Bug #415 analysis

**Новый статус после Bug #414:**
- функционально run по-прежнему не доходит до `ourproc` success:
    - `socket/tro fast path ... tro_rejects=106`
    - fallback в `kernprocaddress/allproc`
    - повторяющиеся `Bug #268 ... len=11/1 ... found_ourpid=0`
    - `disc_layout FAILED`, затем `ourproc(): 0x0`.

**Новый риск, подтверждённый panic bundle:**
- зафиксирован `bug_type 210` (`Kernel data abort`) в процессе `DarkSword` (pid 440),
- FAR: `0xffffffe0af33b410` — low-zone metadata диапазон,
- это указывает, что в fallback chain traversal всё ещё возможны небезопасные спекулятивные переходы по «слишком широким» low-zone pointer.

**Что изменено (Bug #415):**
- `darksword/utils.m`:
    - `validate_kernproc_forward_chain()` — убран permissive переход по raw `is_in_zone_map` как самостоятельному next-gate,
    - `validate_kernproc_backward_chain()` — аналогично ужесточён prev/next gate,
    - `probe_kernproc_backward_pid_offset_for_ourpid()` — tightened acceptance для backward traversal.
- Во всех трёх путях оставлены только более строгие pointer criteria (heap-relaxed/direct-layout data pointer, с локальными стартовыми guard'ами), чтобы исключить blind walk по metadata region.

**Ожидаемый маркер следующего run:**
- снижение/исчезновение panic-сигнатуры `Kernel data abort` с FAR в metadata диапазоне при тех же fallback сценариях,
- если `disc_layout` всё ещё не принимается, run должен завершаться controlled abort без kernel panic,
- следующий функциональный цикл фокусируется уже на принятии layout (убрать `Bug #268`/`disc_layout FAILED` как финальный blocker).

### Что показал свежий syslog (log/syslog_2026-04-04_11-07-03.txt) — Bug #416 analysis

### Что показал свежий syslog/panic (log/syslog_2026-04-04_11-11-04.txt + panic-full-2026-04-04-111133.0002.ips) — Bug #417 analysis

### Что показал свежий syslog/panic (log/syslog_2026-04-04_11-16-04.txt + panic-full-2026-04-04-111655.0002.ips) — Bug #418 analysis

### Что показал свежий syslog/panic (log/syslog_2026-04-04_11-22-37.txt + panic-full-2026-04-04-112303.0002.ips) — Bug #419 analysis

### Что показал свежий syslog (log/syslog_2026-04-04_11-34-05.txt) — Bug #420 analysis

### Что изменено после Bug #420 в standalone app/runtime orchestration — Bug #421

### Что показал свежий syslog/panic (log/syslog_2026-04-04_11-51-51.txt + panic-full-2026-04-04-115222.0002.ips) — Bug #422 analysis

**Новый статус после Bug #421:**
- auto-run действительно стартует из standalone app и применяет `baseline-auto`,
- но до `safe-direct` / `full-direct` выполнение не доходит: panic возникает уже в первом профиле,
- panic сигнатура изменилась: это не прежний `Kernel data abort`, а `zone bound checks: address 0xffffffe0d4024ac0 is a per-cpu allocation`.

**Что изменено (Bug #422):**
- в `darksword/utils.m` direct `kernproc` path (`detect_kernproc_variable()`) отключён по умолчанию для build `21D61`,
- ручной opt-in оставлен через `DS_ENABLE_KERNPROC_DIRECT=1`,
- цель фикса — не допускать panic в `baseline-auto` и дать рантайму дойти до scan/Mach-O fallback путей.

**Ожидаемый маркер следующего run:**
- отсутствие нового panic `zone bound checks ... per-cpu allocation` в первом auto-profile,
- переход либо к scan/Mach-O fallback, либо к controlled abort без kernel panic,
- если functional blocker сохранится, следующий цикл будет уже про `allproc` recovery, а не про crash-класс.

**Новый engineering focus:**
- после стабилизации panic-класса основной bottleneck сместился в functional recovery / repeatability,
- для каждой новой проверки было нежелательно вручную переключать `DS_DIRECT_MODE` и смежные env-флаги.

**Что изменено (Bug #421):**
- `darksword/darksword_exploit.m`:
    - `jailbreak_full()` теперь сам перебирает профили `baseline-auto -> safe-direct -> full-direct`,
    - перед каждым `ds_run()` автоматически выставляются runtime env-флаги для allproc-стратегий,
    - panic-guard по-прежнему останавливает сессию немедленно.
- `app/main.m`:
    - UI показывает, что app работает в auto-mode,
    - стартовый лог и кнопка отражают авто-профильный запуск.

**Ожидаемый эффект:**
- меньше ручных действий между повторами run,
- более воспроизводимый standalone workflow,
- лучшая практическая вероятность успешного `allproc` discovery без ручного вмешательства.

**Новый фактический результат после Bug #419:**
- panic-класс снят: в текущем run нет `Kernel data abort` / `panicked task` сигнатур,
- exploit завершается контролируемо: `all strategies exhausted, allproc not found` -> `ourproc() failed (0x0)` -> `PANIC GUARD`.

**Почему это новый root-cause:**
- после стабилизации `set_target_kaddr` (Bug #418/#419) crash-risk в late-allproc путях снизился,
- но финальный `scan_for_allproc()` оставался opt-in (`DS_ENABLE_MACHO_SCAN=1`) и в обычном run не запускался,
- из-за этого часть сессий останавливалась раньше последнего резолвера allproc.

**Что изменено (Bug #420):**
- `darksword/utils.m`, `kernprocaddress()`:
    - Mach-O parse fallback включён по умолчанию,
    - добавлен явный opt-out: `DS_ENABLE_MACHO_SCAN=0`,
    - обновлён telemetry-лог для этого режима.

**Ожидаемый маркер следующего run:**
- при исчерпании direct/XPF-lite/DATA scan появится автоматический заход в `falling back to Mach-O parse scan (Bug #420: enabled by default)...`,
- снижение доли `allproc not found` abort-only сессий,
- сохранение panic-free поведения за счёт уже действующих guarded gates и panic guard.

**Новый фактический результат после Bug #418:**
- run стабильно проходит до `kernel r/w is ready!` и входа в `ourproc`,
- в этом же окне видны рабочие блоки `set_target_kaddr` по нескольким классам мусора (`misaligned`, `outside zone_map`, `outside kbase window`, `high non-kernel`),
- несмотря на это, panic сохраняется: `bug_type 210`, `Kernel data abort`, panicked task `DarkSword`, FAR `0xffffffe21d069fd0`.

**Почему это новый root-cause:**
- Bug #418 ограничил global zone-window (`safe_min .. zone_max-4MB`), но для спекулятивных `ourproc` traversal это всё ещё слишком широкий диапазон,
- часть дальних адресов остаётся «формально zone-valid» и может пройти в early kread path,
- без привязки к уже подтверждённому live-объекту (`rw_socket_pcb`) сохраняется риск попадания в нестабильные области и data-abort.

**Что изменено (Bug #419):**
- `darksword/darksword_core.m`, `set_target_kaddr()`:
    - в zone-ветке добавлен proximity-anchor window относительно `rw_socket_pcb` (`±4GB`),
    - anchor-window clamp'ится к существующему guarded window (`zone_safe_min .. zone_max-4MB`),
    - адреса вне anchor-window блокируются с telemetry `outside rw_socket_pcb anchor window`.

**Ожидаемый маркер следующего run:**
- исчезновение текущей panic-сигнатуры `Kernel data abort` после входа в `ourproc`,
- появление `BLOCKED ... anchor window` для дальних спекулятивных zone-кандидатов,
- при функциональном неуспехе — controlled abort без reboot/panic.

**Новый фактический результат после Bug #417:**
- старый high-kaddr вектор реально закрыт: в syslog есть только `set_target_kaddr: BLOCKED ... 0xfffffffd52800039` без повтора `copy_validate ... kaddr not in kernel`,
- однако появился новый panic (`bug_type 210`, `Kernel data abort`) в `DarkSword` pid 456,
- `FAR: 0xffffffe2035d0240` попадает в `Zone info -> Metadata` диапазон, то есть это metadata-path crash, а не text/data high-address crash.

**Почему это новый root-cause:**
- `set_target_kaddr()` после Bug #417 сузил только non-zone (kernel text/data) ветку,
- zone-ветка всё ещё принимала почти весь `[g_zone_map_min, g_zone_map_max)` для ранних kread/kwrite,
- такой диапазон включает sparse/tail участки, где kernel metadata validation для zone VA может упасть в неотмапленную metadata страницу и вызвать `Kernel data abort`.

**Что изменено (Bug #418):**
- `darksword/darksword_core.m`, `set_target_kaddr()`:
    - для zone-адресов добавлен guarded window вместо полного zone_map допуска,
    - `zone_guard_min = g_zone_safe_min` (fallback на `g_zone_map_min`),
    - `zone_guard_max = g_zone_map_max - 0x400000` (top 4MB guard),
    - вне окна адрес блокируется с telemetry `outside guarded window`.

**Ожидаемый маркер следующего run:**
- исчезновение panic-сигнатуры `Kernel data abort` с FAR в `Zone Metadata`,
- новые risky zone-адреса должны уходить в `set_target_kaddr: BLOCKED ... outside guarded window`,
- при сохранении функционального blocker run должен завершаться controlled abort без kernel panic.

**Новый фактический результат после Bug #416:**
- run уходит в panic раньше старого `disc_layout` blocker'а,
- exploit успевает дойти до:
    - `kernel r/w is ready!`
    - `about to call ourproc()`
    - `[ourproc] kread health check PASSED`
- затем panic bundle фиксирует:
    - `copy_validate(..., 0xfffffffd52800039, 8) - kaddr not in kernel @copyio.c:194`
    - panicked task: `DarkSword` pid 439 (bug_type 210).

**Почему это новый root-cause:**
- текущий guard в `set_target_kaddr()` для non-zone ветки (`where >= 0xfffffff000000000`) оставался слишком широким,
- из-за coarse допуска мусорные high-kaddr (`0xfffffffd...`) могли проходить как «kernel text/data candidate»,
- kernel-side `copy_validate` отбрасывал такой kaddr уже в copyout path и приводил к panic до пользовательского fallback.

**Что изменено (Bug #417):**
- `darksword/darksword_core.m`, `set_target_kaddr()`:
    - добавлен coarse верхний guard: блок `where >= 0xfffffff800000000`,
    - при известном `kernel_base` введён bounded text/data window (`kbase-0x02000000 .. kbase+0x80000000`, с clamp),
    - вне окна адрес теперь блокируется с явным telemetry-логом.

**Ожидаемый маркер следующего run:**
- исчезновение panic-сигнатуры `copy_validate ... kaddr not in kernel` на стадии `ourproc`/early-kread,
- проблемные `0xfffffffd...` адреса должны появляться только как `set_target_kaddr: BLOCKED ...` без kernel panic,
- после стабилизации run должен вернуться к функциональному blocker-анализу (`fast-path`/`disc_layout`) в следующем цикле.

**Фактический результат после Bug #415:**
- panic bundle в этой папке не появился, но run остаётся abort-only без `ourproc` успеха,
- fast-path снова не доходит до self-proc:
    - `socket/tro fast path stats ... tro_rejects=106 proc_rejects=1`
    - `rejected 106 tro pointers ... last tro_off=0x3b0 raw=0x121d0108b9424268 stripped=0x8b9424268`
    - затем `socket/tro fast path: no validated self proc found`.
- fallback повторяет прежний blocker: `Bug #268 (next_ff 0x0/0x8, len=11/1)`, `disc_layout FAILED`.

**Почему это новый root-cause:**
- telemetry указывает на упор в верхнюю границу текущего TRO scan окна (`0x3b0`),
- это соответствует boot-варианту, где реальный `thread->tro` лежит рядом, но за пределами диапазона `0x320..0x3b0`,
- из-за этого fast-path не переходит в устойчивую `proc/pid/task` верификацию и почти сразу деградирует в fallback loop.

**Что изменено (Bug #416):**
- `darksword/utils.m`, `find_self_proc_via_socket_tro()`:
    - `thread_tro_scan_start: 0x320 -> 0x300`
    - `thread_tro_scan_end:   0x3b0 -> 0x3f0`
    - шаг `0x8` и dedup логика сохранены.

**Ожидаемый маркер следующего run:**
- либо fast-path впервые проходит глубже в `proc/pid` стадии (изменение downstream counters),
- либо хотя бы меняется TRO telemetry (`last tro_off`/паттерн reject), подтверждая, что новый bounded диапазон реально задействован,
- целевая цель цикла: уменьшить fallback `enter kernprocaddress` и снять часть нагрузки с `disc_layout` path.

**Фактический результат после Bug #413:**
- run всё ещё падает на раннем `ourproc()` abort (`ourproc(): 0x0`, `PANIC GUARD`),
- panic bundle не появился, то есть сценарий остаётся panic-free abort, но blocker не снят.

**Новый подтверждённый bottleneck:**
- сильный xpf-lite candidate `0xfffffff016b9b678` снова детектится как `kernproc`-подобный:
    - `entry_ptr=0xffffffde289ab000`
    - `PROC_PID_OFFSET=0xd8 confirmed`
    - `proc0.le_prev == candidate` (`Bug #303` strong hint)
- но затем стабильно срабатывает reject-цепочка:
    - `Bug #268: kernproc chain validate: len=11 ... found_ourpid=0`
    - `disc_pl ... score=9`
    - `Bug #400 weak-score path enabled`
    - `REJECT: score=9 but full chain validation failed`
    - `disc_layout FAILED`.

**Почему это новый root-cause:**
- `validate_kernproc_forward_chain()` в этом пути читал `next` через helper, завязанный на глобальный `PROC_NEXT_OFFSET`,
- на ранней фазе candidate-validation global offset может быть stale для конкретного candidate,
- в результате forward-chain искусственно обрывается на коротком префиксе (`len=11`) и блокирует downstream acceptance независимо от реальной цепи.

**Что изменено (Bug #414):**
- `darksword/utils.m`, `validate_kernproc_forward_chain()`:
    - next-link probing теперь локальный и независимый от global state,
    - проверяются оба `next_ff` (`0x00`, `0x08`),
    - выбирается лучший outcome (`found_ourpid`/длина/разнообразие PID),
    - добавлена telemetry `next_ff=...` в Bug #268 log.

**Ожидаемый маркер следующего run:**
- вместо фиксированного `Bug #268 ... len=11` должен появиться более длинный/вариативный forward-chain telemetry с явным `next_ff`,
- либо candidate пойдёт в `FOUND` path, либо будет отклонён уже на другом, более узком критерии после корректного next-field probe.

### Что показал свежий syslog (log/syslog_2026-04-04_10-49-53.txt) — Bug #413 analysis

**Новый результат после Bug #412:**
- post-KRW panic path в этом run не активировался, потому что exploit вообще не дошёл до `Kernel R/W achieved!`.
- run снова оборвался раньше:
    - `socket/tro fast path ... no validated self proc found`
    - затем `ourproc()` ушёл в `kernprocaddress()`
    - и закончился `PANIC GUARD: ourproc() failed (0x0)`.

**Что важно в новом syslog:**
- fallback `allproc` не был пустым: он нашёл сильный xpf-lite candidate `0xfffffff012dd3678`.
- этот candidate прошёл далеко внутрь validation:
    - `Bug #402: allowing far head via BSD backlink`
    - `disc_pl` увидел plausible chain fragments,
    - но итоговый layout score остался только `9`, после чего было `disc_layout FAILED`.
- это сильно отличается от тупого false candidate: проблема не в полном отсутствии head, а в том, что layout-scoring всё ещё недооценивает реальную proc-chain на этом boot.

**Почему это считается root-cause:**
- строгие chain validators уже умеют ходить через low-zone-map proc pointers ниже `zone_safe_min` (`is_in_zone_map()` / `is_proc_chain_ptr()`),
- но scoring/pre-validation код (`score_proc_chain_ex`, `discover_proc_list_layout`, `walk_proc_chain_for_pid`) всё ещё держался за `is_heap_ptr_relaxed`,
- поэтому именно оценочная стадия преждевременно обрывала реальную цепь на ранних kernel-thread proc structs и не давала кандидату добрать score до acceptance threshold.

**Что изменено (Bug #413):**
- `darksword/utils.m`:
    - `score_proc_chain_ex()` переведён на `is_proc_chain_ptr()` для `cur/next`,
    - обе scoring phases в `discover_proc_list_layout()` теперь принимают `next` через `is_proc_chain_ptr()`,
    - `walk_proc_chain_for_pid()` также переведён на `is_proc_chain_ptr()`.

**Ожидаемый маркер следующего run:**
- candidate уровня `0xfffffff012dd3678` должен либо подняться выше score-порога и дать `proc list layout ... -> FOUND!`,
- либо пройти в strict full-chain validation и уже там показать более точный reject,
- главное ожидаемое изменение: исчезновение раннего `disc_pl ... best_score=9 ... NO MATCH` как финального blocker'а.

### Что показал свежий syslog (log/syslog_2026-04-04_10-39-48.txt) — Bug #412 analysis

**Ключевой сдвиг root-cause после Bug #411:**
- новый runtime уже проходит дальше исходного blocker'а:
    - `returned from ourproc(): 0xffffffde2218f1f8`
    - `returned from ourtask(): 0xffffffde2218f210`
    - `Kernel R/W achieved!`
- значит `socket/tro` widened scan больше не является главным blocker'ом этого run: fallback `ourproc()/ourtask()` реально сработал.
- затем сразу после старта `kfs_init` syslog повторно показывает:
    - `our proc: 0xffffffde2218f1f8`
    - `our proc (recovered): 0xffffffde2218f1f8`
    - `enter kernprocaddress: kbase=...`
- дальше по хвосту run появляются `getsockopt failed (early_kread)!`, а panic bundle фиксирует реальный kernel panic:
    - `zone bound checks ... buffer ... of length 32 ... zone [proc_task]`.

**Почему это теперь считается новым blocker'ом:**
- повторный `enter kernprocaddress` уже после `Kernel R/W achieved!` означает, что post-exploit код в `kfs` снова заходит в тяжёлый proc-discovery path,
- для `kfs` это не обязательно: self-proc уже известен, а `launchd` имеет стабильный `pid=1`, поэтому безопаснее идти PID-walk'ом от уже найденного `our_proc`,
- именно этот второй deep proc/allproc pass лучше всего совпадает по времени с началом post-success `early_kread` деградации.

**Что изменено (Bug #412):**
- `darksword/kfs.m`, `find_procs()`:
    - при валидном `g_our_proc` поиск `launchd` теперь сначала делает bounded PID-walk к `pid=1`,
    - `procbyname("launchd")` оставлен только как fallback, а не hot-path.
- `kfs_init()` теперь сразу сохраняет `g_our_proc = proc`, если exploit уже дал валидные `proc/task`.

**Ожидаемый маркер следующего run:**
- после `kfs_init starting...` на нормальном пути больше не должно быть немедленного `enter kernprocaddress` только ради поиска `launchd`,
- если panic исчезнет, следующий residual blocker сместится уже глубже в `rootvnode`/`ncache` path,
- если panic сохранится, то расследование надо будет переносить на конкретный post-success read-site внутри `find_rootvnode()`/`verify_ncache()`.

### Что показал свежий runtime (log/darksword_log.txt, Date 2026-04-04 10:37:05) — Bug #411 analysis

**Подтверждённый прогресс после Bug #410:**
- fast-path уже не застревает сразу на `thread=0x0/0x300` паттерне старого вида,
- новый telemetry показывает:
    - `socket_off=0x40`
    - `bg_candidates=29`
    - `thread_zero_reads=18`
    - `thread_rejects=3`
    - `tro_rejects=23`
- это означает, что widened `socket->thread` scan нашёл правдоподобные thread-кандидаты, но следующий bottleneck теперь на `tro`-стадии.

**Почему:**
- набор `thread_tro_offs` всё ещё был слишком узким (`0x360/0x368/0x370/0x378`),
- на текущем boot-layout реальный `tro` pointer, вероятно, лежит рядом, но вне этого фиксированного набора.

**Что изменено (Bug #411):**
- в `find_self_proc_via_socket_tro()` сохранены known `thread->tro` offsets и добавлен bounded fallback-scan:
    - `0x320..0x3b0`, шаг `0x8`, с dedup.
- TRO telemetry расширен:
    - `tro_candidates`, `tro_read_failures`, `tro_zero_reads`,
    - detail-log последнего rejected `tro` (`tro_off/raw/stripped`).

**Ожидаемый маркер следующего run:**
- либо fast-path впервые дойдёт до `proc/pid` (`proc_rejects`/`pid_misses` или `SUCCESS`),
- либо появится однозначный detail-лог по `tro` offsets, после которого можно будет таргетировать следующий фикс уже без догадок.

### Что показал свежий syslog (log/syslog_2026-04-04_10-29-33.txt) — Bug #410 analysis

**Подтверждение эффекта Bug #409 и новый blocker:**
- новый runtime уже содержит новый telemetry-format, значит Bug #409 реально установлен:
    - `socket/tro fast path stats: socket_off=0x38 socket_ptr_rejects=1 ...`
- ложный tiny-pattern `raw=0x300` исчез,
- но fast-path всё ещё не проходит thread-stage:
    - `thread_rejects=5`
    - `last raw=0x0 stripped=0x0`
- значит теперь upstream `socket` выглядит правдоподобно, а ошибка сместилась в слишком узкий набор `socket->thread` offset'ов.

**Почему:**
- список `so_bg_thread*` (`0x2a0..0x2c0`) оказался boot-specific и, судя по логам, не покрывает текущую layout-вариацию,
- в правильном `socket` читаются нули, то есть path смотрит не в тот field-slot внутри структуры.

**Что изменено (Bug #410):**
- в `find_self_proc_via_socket_tro()` сохранены known offsets и добавлен bounded fallback-scan:
    - `0x240..0x320`, шаг `0x8`, с dedup.
- telemetry расширен:
    - `bg_candidates`, `thread_read_failures`, `thread_zero_reads`, `last bg=...`.
- thread gate дополнен `is_kptr(thread)`.

**Ожидаемый маркер следующего run:**
- либо fast-path впервые дойдёт до `tro/proc/pid` стадии,
- либо появится сильный диагностический сигнал, что даже расширенное bounded scan-окно даёт только нули/ошибки чтения — тогда следующий фикс надо будет переносить с `socket->thread` на альтернативный path к `task/proc`.

### Что показал свежий syslog (log/syslog_2026-04-04_10-23-19.txt) — Bug #409 analysis

**Точный residual blocker после Bug #408:**
- fast-path доходит до thread-stage, но полностью отваливается на ptr gate:
    - `socket/tro fast path stats: thread_rejects=5 tro_rejects=0 proc_rejects=0 pid_misses=0 task_proof_misses=0`
    - `rejected 5 thread pointers ... last raw=0x300 stripped=0x300`
- это означает, что проблема не в thread-gate как таковом, а в upstream source (`socket`) — читается не та структура.

**Почему:**
- `find_self_proc_via_socket_tro()` использовал единственный `pcb_socket_offset=0x40`.
- на этом boot `pcb+0x40` может быть не реальным `struct socket`, поэтому `so_bg_thread*` возвращают tiny sentinel (`0x300`) вместо kernel pointer.

**Что изменено (Bug #409):**
- в `find_self_proc_via_socket_tro()` добавлен multi-offset подбор `socket` из `pcb`:
    - `0x40, 0x38, 0x30, 0x48, 0x50, 0x28`
- добавлен pre-probe для socket-кандидата:
    - если все ненулевые `so_bg_thread*` значения tiny (`<4GB`) и ни одно не pointer-like, кандидат отвергается.
- добавлена socket-stage telemetry:
    - `socket_off`, `socket_ptr_rejects`, `socket_read_failures`,
    - отдельный лог `no usable socket candidate ... last raw/stripped`.
- success-log дополнен `pcb_soff=...`.

**Ожидаемый маркер следующего run:**
- либо fast-path перейдёт в `tro/proc/pid` (ненулевые downstream counters),
- либо появится ранний и однозначный `no usable socket candidate` со stage-причинами,
- исчезнет повторяющийся thread-reject паттерн `raw=0x300` на всех bg-offset.

### Что показал свежий syslog (log/syslog_2026-04-04_10-18-33.txt) — Bug #408 analysis

**Новый blocker после Bug #407:**
- fast-path падал ещё до thread-стадии:
    - `[ourproc] socket/tro fast path: rw_socket_pcb unavailable (0xffffffdec49dc400)`
- при этом `rw_socket_pcb` не нулевой и выглядит как валидный kernel/zone адрес.

**Причина:**
- pre-gate для `rw_pcb` был на `is_heap_ptr_relaxed` only,
- на этом boot `rw_pcb` расположен ниже `zone_safe_min`, что даёт ложный reject.

**Что изменено (Bug #408):**
- `find_self_proc_via_socket_tro()`:
    - `rw_pcb_ok = rw_pcb && (is_heap_ptr_relaxed(rw_pcb) || is_in_zone_map(rw_pcb) || is_kptr(rw_pcb))`

**Ожидаемый маркер следующего run:**
- исчезает `rw_socket_pcb unavailable`,
- появляются downstream logs fast-path (`thread/tro/proc/pid stats`) или `socket/tro fast path SUCCESS`.

### Что показал свежий syslog (log/syslog_2026-04-04_10-14-35.txt) — Bug #407 analysis

**Новый точный сигнал из Bug #406 telemetry:**
- `socket/tro fast path stats: thread_rejects=5 tro_rejects=0 proc_rejects=0 pid_misses=0 task_proof_misses=0`
- то есть fast-path стопорился на первой стадии (`thread`), до `tro/proc/pid` вообще не доходил.

**Почему:**
- thread gate был всё ещё узкий (`is_heap_ptr_relaxed(thread)`),
- на этом boot `so_bg_thread*` указывает на объекты в валидном zone_map диапазоне, но ниже `zone_safe_min`.

**Что изменено (Bug #407):**
- `find_self_proc_via_socket_tro()`:
    - `thread_ok = is_heap_ptr_relaxed(thread) || is_in_zone_map(thread)`
    - добавлен detail-log по thread reject (`count + last raw/stripped`).

**Ожидаемый маркер следующего run:**
- `thread_rejects` должен уйти к 0 или заметно снизиться,
- должны появиться ненулевые downstream counters (`tro_rejects`/`pid_misses`) либо сразу `socket/tro fast path SUCCESS`.

### Что показал свежий syslog (log/syslog_2026-04-04_10-11-20.txt) — Bug #406 analysis

**Подтверждение после Bug #405:**
- fast-path снова не отработал: `socket/tro fast path: no validated self proc found`
- основной path без изменений:
    - `Bug #291 ... chain=11 ... found_ourpid=0`
    - `Bug #303: rejecting candidate 0xfffffff01ed7b678`
    - `ERROR: all strategies exhausted`
    - `PANIC GUARD: ourproc() failed (0x0)`

**Почему понадобился Bug #406:**
- в fast-path не хватало stage-telemetry: по старым логам нельзя было точно понять, где именно path отсекается (thread/tro/proc/pid/task-proof).
- `tro` gate был слишком узкий (`is_kptr` only), что могло пропускать мимо валидные указатели в zone_map.

**Что изменено (Bug #406):**
- `find_self_proc_via_socket_tro()`:
    - `tro_ok = is_kptr(tro) || is_in_zone_map(tro) || is_heap_ptr_relaxed(tro)`
    - добавлены счётчики и финальный stats-log:
        - `thread_rejects`, `tro_rejects`, `proc_rejects`, `pid_misses`, `task_proof_misses`
    - сохранён расширенный лог по `proc`-reject (последний raw/stripped).

**Ожидаемый маркер следующего run:**
- либо `socket/tro fast path SUCCESS ... proc=...`,
- либо детальный stats-log fast-path, который даст точный следующий таргет для Bug #407.

### Что показал свежий syslog (log/syslog_2026-04-04_10-06-35.txt) — Bug #405 analysis

**Результат после Bug #404:**
- run всё ещё завершился через fail-safe abort:
    - `Bug #291 ... chain=11 ... found_ourpid=0`
    - `Bug #303: rejecting candidate 0xfffffff01c72b678`
    - `ERROR: all strategies exhausted, allproc not found`
    - `PANIC GUARD: ourproc() failed (0x0)`
- до этого `ourproc` fast-path дал только
    - `socket/tro fast path: no validated self proc found`

**Новый корневой blocker:**
- в `find_self_proc_via_socket_tro()` ptr-gate для `proc` был уже/строже, чем на chain-path:
    - принимались только `is_heap_ptr_relaxed(proc)` или `is_kernel_data_ptr(proc)`
- валидные proc-указатели в lower zone_map (ниже `zone_safe_min`) отбрасывались молча, поэтому fast-path не проходил к PID-proof и не мог short-circuit'нуть `kernprocaddress()`.

**Что изменено (Bug #405):**
- `darksword/utils.m`, `find_self_proc_via_socket_tro()`:
    - `proc_ok` расширен до
        `is_heap_ptr_relaxed(proc) || is_in_zone_map(proc) || is_kernel_data_ptr(proc)`
- добавлена telemetry fast-path reject'ов:
    - `proc_ptr_rejects`
    - `last raw/stripped` rejected proc pointer.

**Ожидаемый маркер следующего run:**
- либо `socket/tro fast path SUCCESS ... proc=...` и ранний `ourproc` без allproc scan,
- либо новый диагностический лог по reject-count, который покажет следующую точку фильтрации.

### Что показал свежий syslog (log/darksword_log.txt, run 09:59:49) — Bug #404 analysis

**Подтверждённый residual blocker после Bug #403:**
- в live run всё ещё многократно `chain=11`:
    - `Bug #291: direct pid-off probe ... chain=11 ... found_ourpid=0`
    - `Bug #268: kernproc chain validate: len=11 ... found_ourpid=0`
- confirmed head `0xfffffff021683678` снова отклоняется по
    `Bug #303: rejecting candidate ... chain remained non-user-visible`

**Почему Bug #403 был недостаточен:**
- `validate_kernproc_forward_chain()` уже был расширен, но
    `validate_proc_chain_with_pid_off()` (используется direct/disc paths) оставался на строгом `is_heap_ptr_relaxed`
- `Bug #291` probe оставался с лимитом 64 узла (`chain_procs[64]`, `for i<64`), что не покрывает длинные allproc chains до user PID

**Что изменено (Bug #404):**
- добавлен `is_proc_chain_ptr()`:
    - `is_heap_ptr_relaxed || is_in_zone_map || (g_direct_layout_set && is_kernel_data_ptr)`
- `validate_proc_chain_with_pid_off()` переведён на `is_proc_chain_ptr` (и для `next` тоже)
- в Bug #291 probe:
    - массивы `chain_procs`/`probe_seen`: `64 -> 512`
    - depth loop: `i < 64 -> i < 512`
    - ptr-check: на `is_proc_chain_ptr`

**Ожидаемый маркер следующего run:**
- исчезает массовый `chain=11` в Bug #291
- появляется длинная цепочка с `found_ourpid=1`
- candidate `0xfffffff021683678` проходит Bug #303 и фиксируется как `g_kernproc_addr`

### Что показал свежий syslog (log/syslog_2026-04-04_09-30-28.txt) — Bug #403 analysis

**ROOT CAUSE подтверждён:**
- zone_map `[0xffffffdfe19bc000 – 0xffffffe5e19bc000]`, `safe_min=0xffffffe1619bc000`
- proc0 (`PID=0`) при `0xffffffe3c8632000` — выше safe_min ✓
- kthread proc #12 и далее при адресах ниже `zone_safe_min` → `is_heap_ptr_relaxed` возвращает false
- `validate_kernproc_forward_chain` прерывается на i=11 → `chain_len=11, found_ourpid=0`
- `Bug #268: len=11 unique_nonzero=2 found_ourpid=0` (pid 440 находится на позиции ~100+ в allproc)
- `Bug #303: rejecting candidate 0xfffffff02378f678` — несмотря на confirmed `proc0.le_prev == candidate`
- ourpid=440 при list=0x0, pid_off=0xd8 дальше entry #11 → никогда не достигается с chain-limit=11

**Что изменено — Bug #403:**
- добавлена `is_in_zone_map()`: raw `[zone_map_min, zone_map_max - 4MB)` без zone_safe_min, с ZONE_TOP_GUARD
- в `validate_kernproc_forward_chain`: `ptr_ok = is_in_zone_map(cur) || is_heap_ptr_relaxed(cur) || (i==0 && is_kptr(cur))`
- в `validate_kernproc_backward_chain`: аналогично ptr_ok + prev-check
- в `probe_kernproc_backward_pid_offset_for_ourpid`: аналогично ptr_ok + prev-check
- в `normalize_proc_link_target_with_pid`: `ptr_ok = is_heap_ptr_relaxed(cand) || is_in_zone_map(cand)` — kthread procs проходят нормализацию

**Почему безопасно:**
- `is_in_zone_map` используется ТОЛЬКО в функциях, которые вызываются от confirmed proc0 (backref доказан)
- все kreads: `kread*_checked_local` → нечитаемая страница = safe false return без паники
- `is_in_zone_map` по-прежнему применяет ZONE_TOP_GUARD (4MB) от per-CPU regexp

**Ожидаемый эффект следующего run:**
- `Bug #268: len=150+ unique_nonzero=20+ found_ourpid=1` — цепочка дойдёт до PID 440
- `Bug #303: KERNPROC detected at 0xfffffff02378f678`
- `Bug #372` больше не срабатывает ложно для confirmed le_prev candidates
- `ourproc()` возвращает ненулевой heap-адрес → exploit идёт дальше в post-exploit фазу

### Что показал свежий syslog (log/syslog_2026-04-04_09-30-28.txt)
- run остался panic-free, но часть XPF-lite кандидатов (`0x321c480/0x321c408/0x3213678/0x3213680`) отсекается на раннем `Bug #398` distance-gate как far-head.
- из-за раннего reject resolver не доходит до deep layout path для этих кандидатов и снова завершает run через `all strategies exhausted` + `PANIC GUARD`.

### Что изменено
- **Bug #402:** в `validate_allproc()` добавлен ограниченный bypass для far-head.
- теперь `diff > 3GB` всё так же reject по умолчанию, но допускается исключение только если:
    - `pac_strip(*(head+0x08)) == allproc_addr` (BSD-backlink сигнатура), и
    - `diff <= 8GB`.
- при этом сохраняются все дальнейшие структурные и chain-валидации.

### Ожидаемый эффект
- дать шанс обработать часть дальних, но структурно подтверждённых head-кандидатов,
- не возвращаясь к broad unsafe-допуску far-addresses.

### Статус
- code-fix и doc-sync выполнены.
- следующий шаг: build/sign/install и проверка свежего syslog на маркер `Bug #402: allowing far head via BSD backlink`.

### Что показал свежий syslog (log/syslog_2026-04-04_09-26-20.txt)
- Bug #400 telemetry сработал: near-rw_pcb path действительно активируется.
- run остался panic-free, но всё ещё safe-abort: `Bug #394` отвергает candidate `0x321c480` как partial (`max_pid=219 < ourpid=460`, `list_off=0xb0`).

### Что изменено
- **Bug #401:** в `validate_allproc()` добавлен recovery fallback на BSD-head геометрию.
- если после partial miss у `firstproc` есть backlink `firstproc+0x08 == allproc_addr`, запускается дополнительный walk с `list_off=0x0/next_off=0x0` (включая alternate `pid_off`).
- candidate принимается только при достижении `ourpid` и успешной `validate_proc_chain_with_pid_off(..., list_off=0x0, ...)`; при success коммитятся BSD offsets.

### Ожидаемый эффект
- снять часть false-negative, когда interior `list_off` даёт сильный score, но режется как partial, а корректный BSD-head path остаётся неиспользованным.
- сохранить panic-safe профиль, так как fallback не bypass'ит строгую chain-валидацию.

### Статус
- code-fix и doc-sync выполнены.
- следующий шаг: build/sign/install + новый runtime syslog с проверкой маркеров `Bug #401`.

### Что изменено
- в `discover_proc_list_layout()` порог near-ветки снижен с `9` до `6` (`PROC_NEAR_PCB_MIN_SCORE=6`),
- условия безопасности сохранены: candidate принимается только после `validate_proc_chain_with_pid_off(...)`.
- telemetry-маркер обновлён на `Bug #400` с печатью `score` и `min` порога.

### Зачем
- в свежем panic-free run Bug #399 path по логам не активировался; это признак, что порог `9` всё ещё отсекает часть близких кандидатов.

### Ожидаемый эффект
- дать шанс near-кандидатам со score `6..8` дойти до full-chain проверки,
- при этом сохранить текущий panic-safe профиль (без bypass строгой валидации).

### Статус
- code-fix внедрён.
- следующий шаг: build/sign/install и новый runtime syslog для проверки маркера `Bug #400` и результата `ourproc`.

### Что изменено
- в `discover_proc_list_layout()` добавлен управляемый weak-score path:
    - для кандидатов рядом с `rw_socket_pcb` (<=3GB) порог pre-filter снижен с `20` до `9`,
    - но финальное принятие всё равно только через `validate_proc_chain_with_pid_off()`.

### Зачем
- в свежем panic-free run были `disc_pl NO MATCH` случаи с невысоким score у близких кандидатов.
- прежний жёсткий pre-threshold отбрасывал их до строгой chain-проверки.

### Ожидаемый эффект
- увеличить шанс найти `allproc` после Bug #398 без роста panic-риска,
- потому что weak-score path не bypass'ит full-chain validation.

### Статус
- code-fix внедрён, compile diagnostics чистые.
- нужна следующая runtime-проверка (новый syslog) для подтверждения перехода от safe-abort к успешному `ourproc`.

### Что показал свежий syslog (log/syslog_2026-04-04_09-12-40.txt)
- exploit стабильно дошёл до `kernel r/w is ready` и `ourproc()`.
- panic в этом прогоне не зафиксирован: panic bundle не появился.
- run завершился штатным safe-abort: `allproc not found` -> `ourproc() returned 0x0` -> `PANIC GUARD`.

### Что подтвердилось по Bug #398
- в telemetry многократно видны срабатывания `Bug #398: rejecting far head=...`.
- это подтверждает, что новые proximity-фильтры реально отсекают дальние ложные head-кандидаты ещё до глубоких deref.

### Текущий blocker
- классический kernel panic ушёл из этого run, но `allproc` всё ещё не разрешается валидно на текущем boot.
- фактический статус: **panic-free fail-safe abort** вместо panic/crash.

### Следующий шаг
- точечно улучшить selection/acceptance для кандидатов рядом с рабочей зоной (`rw_socket_pcb`) в scan/direct fallback, чтобы перейти от safe-abort к успешному `ourproc` resolution.

### Что подтвердили panic + syslog
- новый panic не `per-cpu`, а `Kernel data abort`
- panicString содержит `esr: 0x96000007` (translation fault L3)
- `far=0xffffffdc13b4a280` попадает в Zone Metadata region
- panicked task: `DarkSword` pid 491; падение во время `Bug #372` forward-chain validation

### Root cause
- relaxed heap-check для proc-chain (`is_heap_ptr_relaxed`) принимал адреса по raw диапазону `[zone_map_min, zone_map_max)`
- адрес-кандидат мог быть численно валиден, но указывать на sparse/unallocated zone page
- при `kread/copyout` kernel обращался к metadata entry этой страницы и ловил translation fault

### Что изменено
- **Bug #397:** `is_heap_ptr_relaxed()` переведён на нижнюю границу `zone_safe_min` вместо raw `zone_map_min`
- relaxed acceptance теперь `[zone_safe_min, zone_map_max)`
- fallback к raw `zone_map_min` сохранён только для ранней фазы до вычисления zone-safe bounds

### Build/sign/install после фикса
- `build_sign_install.sh` выполнен успешно (compile + ldid + zsign + install)
- итоговый артефакт: [build_app/DarkSword_signed.ipa](build_app/DarkSword_signed.ipa)
- install step снова дал ожидаемый `ideviceinstaller exit code 1` с `Install: Complete` semantics в текущем workflow

### Ожидаемый эффект
- allproc/kernproc chain validation не должна больше дёргать sparse lower-GEN0 страницы
- цель следующего runtime: отсутствие panic с `ESR 0x96000007` и `FAR` в Zone Metadata

### Что подтвердили panic + syslog
- свежий panic: `zone bound checks: address ... is a per-cpu allocation`
- panicked task: `DarkSword` (pid 473)
- timestamp panic (`08:23:01`) совпадает с фазой `allproc` scan (`reading scan chunk`) в `__DATA.__bss_allproc`

### Root cause
- `is_heap_ptr()` всё ещё принимал адреса почти до `zone_map_max`.
- верхний хвост zone-map на этом boot может попадать в per-cpu-sensitive область; blind `kread` по таким адресам вызывает zone-bound panic.

### Что изменено
- **Bug #396:** в `is_heap_ptr()` добавлен верхний guard `ZONE_TOP_GUARD = 0x400000` (4MB).
- acceptance верхней границы теперь идёт по `zmax - 0x400000` вместо `zmax`.
- одинаковый guard применён и для strict zone bounds, и для fallback bounds.

### Ожидаемый эффект
- resolver должен перестать заходить в опасный верхний tail zone-map во время scan.
- цель следующего runtime: убрать повтор panic класса `per-cpu allocation` и сохранить прогресс поиска `allproc`.

### Build/sign validation после Bug #396
- `build_sign_install.sh` успешно собрал проект; `darksword/utils.m` компилируется без ошибок.
- подпись прошла (`ldid` + `zsign`), собран `build_app/DarkSword_signed.ipa`.
- install step вернул привычный `ideviceinstaller exit code 1` с `Install: Complete`, что в текущем workflow считается допустимым исходом.

### Что показал runtime после Bug #394
- run остался panic-free и честно abort'ится через panic guard.
- `Bug #393` продолжает работать: kernel-only chain явно отклоняется.
- новый blocker сместился ещё раньше: `kernprocaddress()` вернул `0`, потому что safe DATA scan ничего не нашёл.
- при этом XPF-lite telemetry показала полезные heap-like кандидаты около `kbase+0x3213678` / `+0x3213680`.

### Root cause
- стандартный `scan_allproc_known_range()` для `__DATA.__bss_allproc` начинал scan слишком поздно (`0x321c000`).
- нижняя область с новыми boot-specific кандидатами (`0x32136xx`) просто не попадала в scan window.

### Что изменено
- **Bug #395:** окно safe `__DATA.__bss_allproc` расширено вниз:
    - было: `0x321c000..0x322c000`
    - стало: `0x3213000..0x322b000`
- это по-прежнему ограниченный inner-`__bss` scan, без возврата к broad Mach-O parser.

### Ожидаемый эффект
- resolver должен снова подхватывать кандидаты из нижнего `__bss`, которые текущий boot уже показывает через XPF-lite,
- и при этом сохранить panic-free профиль после Bug #393/#394.

### Что показал свежий runtime после Bug #393
- panic-path исчез: `direct_v2 SUCCESS` больше нет, `kernprocaddress()` впервые стабильно вернул non-zero candidate `0xfffffff02381c500`.
- дальше выяснилось, что этот candidate всё ещё partial:
    - layout проходит (`list_off=0xb0`, `pid_off=0xd8`, score=50)
    - прямой walk в `ourproc()` доходит только до `max_pid_seen=368 < ourpid=479`
    - затем candidate blacklist'ится через `Bug #377` и только потом управление уходит в seed-local scan.

### Root cause
- `validate_allproc()` проверял structural/layout correctness, но не проверял reachability текущего процесса внутри уже принятой visible chain.
- из-за этого partial candidate мог считаться `allproc` слишком рано, хотя user-visible chain была усечена и обрывалась раньше `ourpid`.

### Что изменено
- **Bug #394:** после `validate_proc_chain()` добавлен visible-chain gate через `walk_proc_chain_for_pid()`.
- validator теперь требует одного из двух:
    - либо candidate реально достигает `ourpid`,
    - либо хотя бы не выглядит как partial chain с `max_pid_seen < ourpid`.
- дополнительно пробуется alternate `pid_off` (`0xd8` ↔ `0x60`) до окончательного reject.
- если alternate `pid_off` действительно находит `ourpid`, он принимается сразу в validator'е.

### Ожидаемый эффект
- candidate `0x321c500` и подобные partial allproc heads должны отбрасываться раньше — ещё в resolver path.
- `ourproc()` должен реже входить в blacklist/retry только ради того, чтобы понять, что candidate был неполным.

### Build/sign validation
- patched `darksword/utils.m` успешно собран без compile errors.
- `build_sign_install.sh` завершил build + ldid sign + zsign repack успешно.
- итоговый IPA: [build_app/DarkSword_signed.ipa](build_app/DarkSword_signed.ipa)
- install step снова дал известный `ideviceinstaller exit code 1`, который в этой ветке уже трактуется как допустимый post-install outcome.

### Что подтвердил panic/syslog
- panic timestamp `07:48:37` совпадает с run, где ранее в syslog был `direct_v2 SUCCESS: iOS 17 kernel chain detected (list=0x0 pid=0x60)`.
- panicked task: `DarkSword`; panic class: `zone bound checks`.
- по трассе перед срывом `ourproc()` шёл по цепочке с `pid=0`/zombie skip и не выходил в user-visible PID diversity.

### Root cause
- в `validate_direct_allproc_v2_with_layout()` оставался shortcut для kernel-only цепочки (PID=0-only) при `list_off=0x00`, `pid_off=0x60`.
- на `21D61` это оказалось ложным success-path: candidate принимался слишком рано, без реального userland-подтверждения.

### Что изменено
- **Bug #393:** kernel-only shortcut acceptance в `direct_v2` отключён.
- такие candidates теперь явно отклоняются (`Bug #393: kernel-only chain rejected ...`).
- direct_v2 acceptance оставлен только через:
    - достаточную PID-diversity в основном chain walk, или
    - явный `ourpid`/diversity через PID-probe path (`Bug #291`).

### Ожидаемый эффект
- исчезнет преждевременный lock-in на zero-only chain.
- resolver должен идти к более корректному head-кандидату вместо повтора crash-path после ложного direct_v2 success.

### ✅ Валидация (Build 49)
- **До фикса:** `direct_v2 SUCCESS` at 07:48:37 → zone panic (buffer overflow)
- **После фикса:** syslog_2026-04-04_08-00-46.txt (08:01:01-08:01:02)
  - ❌ NO `direct_v2 SUCCESS` entries → shortcut disabled ✓
  - ❌ NO `Bug #393` rejection logs → not even reaching validation ✓
  - ✅ Fallback to safe shortlist + seed[0-30] scanning started ✓
  - ✅ `kernprocaddress()` вернул: **0xfffffff02381c500** (non-zero!) ✓
  - ✅ Proc list layout: **FOUND** (score=50, `list_off=0xb0, pid_off=0xd8`) ✓
  - ✅ Начало traversal через процессы (pid=0, 228, 185, 248, 337...) ✓
  - ✅ NO zone panic, NO crash, app continues running ✓
  - ✅ NO new panic files after deployment ✓
- **Заключение:** Bug #393 работает идеально — kernel-only shortcut полностью исключён. Новый blocker: seed scan не находит self proc (pid=479) при traversal.

## Новый Blocker: `ourproc` не найден в kernel process list traversal
- **Симптом:** После успешного `kernprocaddress()` и layout discovery, traversal starts (pid=0,228,185,248,337...) но не достигает pid=479
- **Гипотеза:** Возможно, pid=479 находится вне основной цепочки, требуется дополнительный поиск или коррекция параметров traversal
- **Статус:** Требует анализа — next session

### Что показал свежий syslog перед фиксом
- в scan path появлялся промежуточный `proc list layout ... -> FOUND!` с `pid_off=0x60`
- сразу после этого тот же запуск всё равно заканчивался `all strategies exhausted` и `kernprocaddress() == 0`

### Root cause
- `discover_proc_list_layout()` коммитил `FOUND` по score-only (`best_score >= 20`) без обязательного полного chain-check.
- из-за этого возможен ложный `FOUND` + преждевременный `PID offset switch` на неподтверждённом кандидате.

### Что изменено
- добавлен жёсткий gate перед коммитом layout:
    `validate_proc_chain_with_pid_off(best_base, best_off, best_pid_off, 200)`
- при провале full-check кандидат отклоняется (`[disc_pl] REJECT ...`), глобальные offsets не меняются.
- `FOUND`/`switching PID offset` теперь логируются только после полного chain-validate.

### Ожидаемый эффект
- исчезнут ложные `layout FOUND` без реального принятия `allproc`.
- scan path станет стабильнее: без side-effect смены PID offset на слабых/частичных кандидатах.

### Что показал новый runtime после Bug #390
- Bug #390 сработал полезно: старый partial path с `0x321C480 -> list_off=0xb0 -> 176-step dead-end` больше не повторился.
- новый run panic-free, но `kernprocaddress()` теперь возвращает `0`, то есть resolver стал честнее, но пока слишком строг.
- ключевая новая улика: для direct candidate `0x321C480`
    - `detect_kernproc_variable()` видит `pid=0` по trusted `PROC_PID_OFFSET=0xD8`
    - а `direct_v2` не даёт success-path вовсе
    - в коде это объясняется тем, что `direct_v2` всё ещё читал `p_pid` только через `+0x60`

### Root cause
- `validate_direct_allproc_v2_with_layout()` был всё ещё привязан к старому `pid_off=0x60`.
- на build `21D61` это ломает раннюю валидацию реального head candidate: `+0x60` может быть мусором, хотя trusted `+0xD8` уже подтверждён runtime telemetry и Bug #388.

### Что изменено
- **Bug #391:** `direct_v2` теперь выбирает `pid_off` через `build_pid_offset_candidates()` вместо жёсткого `+0x60`.
- первый plausible PID offset используется и для first-proc validation, и для chain walk.
- при success-path выбранный offset пишется обратно в `PROC_PID_OFFSET`.

### Новый ожидаемый эффект
- direct candidate `0x321C480` больше не должен отваливаться только из-за hardcoded `+0x60`.
- следующий runtime должен либо показать `direct_v2 SUCCESS` для real head, либо как минимум дать более честную telemetry по chain уже под `pid_off=0xD8`.

### Что подтвердил следующий свежий runtime
- Bug #389 действительно убрал старый ложный lock-in на `0x321C400`.
- теперь новый ложный success-path сместился на `kbase+0x321C480`, но уже через legacy `validate_allproc()` / `disc_pl`, а не через `detect_kernproc_variable()`.
- runtime-след:
    - `disc_pl` выбирает `list_off=0xb0`, `score=50`
    - `ourproc()` делает 176-step walk только до `max_pid_seen=215 < ourpid=483`
    - тот же `proc0` показывает `first entry le_prev=0x10`, а в Bug #337 dump видно `proc0+0xb8 = 0x10`
    - одновременно `proc0+0x08 == allproc`, то есть candidate больше похож на mixed head с внутренним proc-sublist, чем на реальный user-visible `allproc`

### Root cause
- legacy path принимал candidate по сильному score/diversity на interior `list_off=0xb0`, но не проверял противоречие с BSD head signature самого `proc0`.
- если `proc0` уже выглядит как BSD head (`p_list.le_prev == allproc`), а выбранный interior-entry `prev` равен `0x10`, это сильный признак ложного mixed-head acceptance.

### Что изменено
- **Bug #390:** в `validate_allproc()` добавлен mixed-head guard.
- теперь candidate отклоняется, если:
    - `disc_pl` выбрал `PROC_LIST_OFFSET != 0`,
    - `proc0` имеет BSD head signature на `+0x00/+0x08`,
    - выбранный `prev` для interior-entry не является kernel pointer'ом,
    - и короткая BSD `p_list` chain тоже не выглядит как real user-visible `allproc`.

### Новый ожидаемый эффект
- `0x321C480` больше не должен проходить как partial legacy `allproc` с `list_off=0xb0`.
- следующий runtime должен либо найти более честный candidate, либо раньше перейти в retry / safe fallback без 176-step dead-end walk.

### Что подтвердил свежий syslog
- `Bug #388` реально активен в runtime: build `21D61` стартует с pinned `PROC_PID_OFFSET=0xD8`.
- текущий срыв больше не выглядит как проблема `p_pid` offset.
- найден новый ложный success-path: candidate `kbase+0x321C400` принимается как `kernproc`, но дальнейший walk идёт по heap-объектам с `pid=0` и заканчивается `max_pid_seen=0`.

### Root cause
- acceptance в `detect_kernproc_variable()` всё ещё допускал `PID-0-only` forward chain как достаточное доказательство.
- на свежем runtime это оказалось ложным: `le_prev` backlink есть, но список не user-visible и до `ourproc()` не доходит.

### Что изменено
- **Bug #389:** zero-only `kernproc` forward chain больше не принимается как валидный success-path.
- теперь для принятия нужны либо `ourpid`, либо достаточная nonzero PID-diversity.
- в direct shortlist дополнительно поднят runtime-подтверждённый offset `0x321C480`, чтобы resolver раньше пробовал сильный head-кандидат, а не застревал на более слабом `0x321C400`.

### Новый текущий blocker
- нужно подтвердить, что после Bug #389 `0x321C400` больше не lock-in'ится как ложный `kernproc`.
- следующий runtime должен либо принять более сильный `allproc`/`kernproc` candidate, либо дойти дальше в safe seed-local path без прежнего zero-only dead-end.

### Что изменено в коде
- **Bug #387:** для build `21D61` обновлён встроенный shortlist allproc offsets: первым идёт runtime-подтверждённый `0x321C480`, затем `0x321C408` и fallback-кандидаты.
- **Bug #387 (safety):** в `bug296_zone_scan` blind seed/page probes переведены на строгий heap-check (`is_heap_ptr`), чтобы отсечь per-cpu/unsafe подзоны до `kread`.
- **Bug #388:** добавлен build-profile pin для `21D61` в `init_offsets` — `PROC_PID_OFFSET` принудительно фиксируется на `0xD8` с отдельным telemetry-логом.

### Что подтверждено на практике
- Полный цикл `build_sign_install.sh` выполнен успешно.
- Подпись проходит (`ldid` + `zsign`), IPA собран и установлен на устройство.
- `ideviceinstaller -l` подтверждает установленный `soft.ru.app` (DarkSword, version 52).

### Текущий blocker в runtime-валидации
- Автозапуск через `idevicedebug` на данном хосте не работает без mounted DeveloperDiskImage (`Could not start com.apple.debugserver`).
- Из-за этого свежий автоматически снятый syslog не содержит `ourproc`-телеметрии и не позволяет подтвердить effect `Bug #387`/`Bug #388` только средствами host-side automation.

### Следующая обязательная проверка
1. Запустить DarkSword вручную на устройстве.
2. Параллельно снять `idevicesyslog` в новый файл.
3. Подтвердить в логах:
    - строку `Bug #388` (build-profile pin),
    - отсутствие прежнего per-cpu panic в seed-local path,
    - прогресс `ourproc` после safe-guard изменений Bug #387.

## Update 2026-04-03  ourproc()/seed-scan status после Bug #383/#384/#385

### Что уже подтверждено runtime-логами
- `kernel r/w is ready!` стабилен
- `kernprocaddress()` теперь регулярно возвращает ненулевой candidate
- новый fallback `Bug #383` реально исполняется на устройстве и пробует alternate `pid_off=0x60`
- старый broad scan больше не является главным blocker: runtime дошёл до page-local seed scan

### Что остаётся blocker'ом
- `socket/tro fast path` всё ещё не валидирует self `proc`
- direct walk от принятого `kernproc/allproc` по-прежнему даёт только частичный/ложный proc-chain
- `ourproc()` пока не находит `pid == getpid()` ни через `0xd8`, ни через `0x60`
- последний подтверждённый panic сместился внутрь safe seed-local path: zone-bound / zero-sized object при чтении `... + 0xd8`

### Что уже исправлено поверх этого
- **Bug #383:** alternate `pid_off` теперь пробуется не только на zero-only chain, но и на любом suspicious partial walk
- **Bug #384:** non-page-aligned anchors больше не роняют код в legacy broad zone scan; fallback принудительно переводится в page-aligned seed-local mode
- **Bug #385:** seed-local scan больше не использует synthetic `0x0/0x400/0x800/0xC00` как единственную геометрию; теперь он использует реальные intra-page offsets из observed `fwd_procs`
- дополнительно расширены seeds/slots, добавлены seeds из `proc0[+0x00]` chain, а точный `pid` теперь может приниматься по `proc_ro->task` и name proof

### Текущая ближайшая цель
Следующий runtime должен:
1. остаться panic-free дольше прежнего
2. показать новые логи `Bug #385` / expanded seed-page coverage
3. либо найти `ourproc()`, либо сузить blocker до конкретной safe-scan geometry без возврата к старым broad-scan panic paths

## Bug #332  panic-free seed scan ������� �����: user proc �� ��������� 4MB �� kernel-thread seeds (2026-04-03)

### ��������
Post-Bug #331 runtime panic-free, �� ourproc() �� ������:
- seeds = 11 kernel-thread procs (��� ��������: `0xffffffdf0ca8x`, `0xffffffde25a9x`)
- ��� 4 ����  11 seeds  12737 iters, DarkSword (PID=364) �� ������
- allproc `0x3213678` �������� ������ kernel threads (le_next=0 ����� ���� 10)

### �����������
-  ��������� 5-� ���� seed-local scan: `window=0x4000000` (64 MB)
-  `gap_limit=512` ��� ����� ����
-  scan forward-only (pre_window=0 per Bug #324), panic-safe (4-byte read ������ 1024-byte element)
-  ���-������ `Bug #332: extended local seed scan ...`  (5 phases, max_window=0x4000000)

### ��������� ������
��������� runtime ������ ��������� panic-free ��������� � ������� ������� �������� >4MB �� kernel-thread seeds, ������ DarkSword proc �� ��������� proc-cluster.
## Bug #331 � bounded name-fallback ��� `ourproc()` � seed-slot prepass

### ��������
���� ����� Bug #330 `ourproc()` ��� �� �������� ��� PID � safe seed-local scan, ���� panic ��� ��������� ������������.

### Root cause
Seed-slot prepass ��������� ������ �� `pid==ourpid`. �� �������� ��������� �������� PID-������������� ����� ���� ������, � ������� wide name-read � subslot path ��� ������������ ������ �� tail-slot.

### �����������
- ? �������� bounded helper ������ ����� �������� � �������� ����� 4KB ��������
- ? �������� name-based fallback �� ����� �������� �������� (`proc_name/getprogname/DarkSword`)
- ? �������� shortlist name offsets (������� `0x3E8`) � ��������������� `PROC_NAME_OFFSET`
- ? � seed-slot PID-hit path ������� ������������ wide name-read �� bounded �������

### ��������� ������
��������� runtime ������ ��������� panic-free ��������� � �������� ���� ����� `ourproc` � already-safe seed/subslot neighborhood, ���� ����� PID path �������� ����������.

## Bug #330 � �������� panic-free local seed scan (��������� ���� `0x400000`)

### ��������
������ runtime ����� Bug #328/329 ������� ���������� ���������� abort ��� panic, �� `ourproc()` �� ��� �� ������:
- `kernel r/w is ready!`
- `local page-seed scan done (2889 iters, not found)`
- `PANIC GUARD: ourproc() failed (0x0)`

### Root cause
���������� short-gap break �� Bug #329 ������� ������ ������, �� ������������ ���� �� ��� �������������� `0x100000`. ��� �������� boot ����� ��������� ������������, ����� ��������� �� ���������� proc-cluster ������������ observed seed pages.

### �����������
- ? ��������� 4-� phase local seed scan � `window=0x400000`
- ? ��� ����� ���� �������� `gap_limit=128`
- ? ���� ��� �������� �� ������������ `phase_count` �� ������� �������
- ? �������� ����� ��� `Bug #330: extended local seed scan ...`

### ��������� ������
��������� runtime ������ ��������� panic-free ��������� � ��������� ���������� seed-local �������� ��� �������� � broad contiguous sweep.

## Bug #329 � panic-free local seed scan �� ������ ��������� ����� ������ 4 ������ page-base probe

### ��������
������ post-`Bug #328` runtime ��� ������ ���������:
- ������ panic ���
- `Bug #327` subslot prepass ���� �� ������ ����������
- �� `Bug #325: local page-seed scan done (190 iters, not found)` �� ��� ������������� ������� ������

��� ����� `0x4000 / 0x40000 / 0x100000` ��������� `190` �������� ��� `11` seed pages ��������, ��� ����������� ��������� �������� ���������� ����� ����� ����� ������ ��������� gap-��.

### Root cause
����� Bug #325 scan ���� panic-free ������ ������, ��� �������� ������ ���� ������� contiguous sweep. �� ������� guard `cfails >= 4` �������� ������� �����������: ��� ������ ������ seed page ����������� ��������� ������ ������ page-base probe, ��������� ���� ��������� ������������ � �� ������� �� ���������� ���������� proc-cluster ������ ���� �� ����������� local range.

### �����������
- ? local seed scan ������ ���������� phase-aware gap tolerance
- ? phase 0 ��������� ������ ������ ����� `4`
- ? phase 1 �������� �� `16` ������ miss-��
- ? phase 2 �������� �� `64` ������ miss-��
- ? �������� ����� ��� `gap_limit=` ��� ������� phase

### ��������� ������
��������� runtime ������ ��������� panic-free ��������� Bug #325/328, �� ��� �� �������� local page-seed scan ����� ������ �������� ��� ����� ��������� proc-����������.

## Bug #328 � subslot prepass ������ ���� ������ pid-based, ��� 32-byte name-read �� tail slot

### ��������
������ post-`Bug #327` runtime ����� panic-���.

����� panic ����� ����������� �������:
- `buffer 0xffffffdf0f239fe8 of length 32 overflows object 0xffffffdf0f239000 of size 4096`
- syslog ����� ����� �� `Bug #327: seed-page subslot prepass ...`

�� ���� crash �������� �� �� ����� subslot pid probe, � �� ��������� ������� ������ ������ ���� ����� ����.

### Root cause
����������� name-guided fallback ����� `32` ����� ����� �������� �� ������������� subslot-���������. ��� ���������� slot (`+0xC00`) � �������� name offsets ����� read ��������� ������� ������� 4KB zone object � ����������� ����� `zone bound checks`.

### �����������
- ? name-guided fallback ����� �� subslot prepass
- ? subslot phase ��������� ������ ��� pid-based probe
- ? dangerous `32-byte` reads �� tail-slot ���������� ������ �� �����������

### ��������� ������
��������� runtime ������ ��������� �������������� intra-page coverage Bug #327, �� ��� ��� ������������ panic � ������ seed-page subslot prepass.

## Bug #327 � panic-free seed scan ������ ������ �� ������ page base, �� � intra-page proc slots

### ��������
������ post-`Bug #326` runtime ���������� ��� ����� ������������:
- panic ������ ���
- ���� � `pid_offs=2/0xd8 +0x60` local seed scan �� ��� �� ������� ��� `proc`

������ �������� ��� �� � scan geometry � �� ������ � `PID_OFFSET`, � � �������� ������ ����� seed pages.

### Root cause
������� safe page-seed scan ��������� ������ page-aligned base ������ candidate page. �� proc zone page ����� ��������� �� ������ ���������. ���� observed seed ����� �� ���� proc page, ��� app proc ����� ���� � �������� subslot ��� �� ��������, � ����� page-base-only probing ��� �������������� ���������.

### �����������
- ? �������� low-risk prepass ������ �� ��� observed `seed_pages`
- ? ����������� subslots `0x000/0x400/0x800/0xC00`
- ? ������������ dual-pid fallback (`active pid_off` + `0x60`)
- ? �������� name-guided fallback �� ����� `DarkSword` ��� �������������� `p_list`

### ��������� ������
��������� runtime ������ ��������� ������� panic-free ������������ � ������� ������� ����������� intra-page proc slots ����� � ��� �������������� proc neighborhoods.

## Bug #326 � panic-free seed-local scan ������ ������������� `0x60`, � �� ������ ��������� `0xd8`

### ��������
������ post-`Bug #325` runtime ��� ������ ����� ���������:
- panic �����
- `panics_*` ������ �� ��������
- `ourproc()` ����� �� `Bug #325: local page-seed scan done (178 iters, not found)`

������ ��������� scan ������ ���������, �� ������������� ��� `proc` �� ��� �� ���������.

### Root cause
����� ��� �������, ��� current success-path �� ��� ��� ����� short mixed fake chain � ���������� �������� �������� `PROC_PID_OFFSET=0xd8`. Safe zone scan ����� Bug #325 ��� ������ ������ ���������� proc-neighborhood pages, �� �� ��� �������� ����� offset �������. ���� �������� `p_pid` �� ����� proc pages ����� ����� �� ������������� `0x60`, scan ������ �������� ���� ������ PID ��� panic.

### �����������
- ? safe page-seed scan ������ ������� ������� `PROC_PID_OFFSET`
- ? ���� active offset �� `0x60`, scan ������������� ������ � `0x60`
- ? ��� �������� hit scan ����������� `PROC_PID_OFFSET` �� ����������� offset � ���������� proc
- ? ��� �� dual-pid fallback �������� � � non-page-aligned zone path

### ��������� ������
��������� runtime ������ ��������� ��� ����������� panic-free ��������� Bug #325, �� �������� �������������� ���� ����� ��� app `proc` ������ ��� �� ���������� seed-local clusters ��� �������� � ������� ������� scan-����������.

## Bug #325 � page-aligned `ourproc()` scan ������ ���� cluster-local, � �� contiguous

### ��������
������ runtime ����� Bug #324 �� ��� panic-���:
- `panic-full-2026-04-03-060638.0002.ips`
- `buffer 0xffffffe7e0dc40d8 of length 4 ... size 0`

��� ��� �� lower-bound crash. ������ unsafe �������� ��� ������� contiguous forward sweep ����� �������� ������������� gap.

### Root cause
�������� `proc` pages �� ���� boot ����� ����������. ����� scan ��� �������� ���������� ����� ����, �� ��������� ������� � non-proc pages, ������� �� ��� �������� ������ heap-range ������, �� ������ �� zone bound checks.

### �����������
- ? ������� seed pages �� ������� ��������� `fwd_procs`
- ? page scan ������ ��������� ������ seed pages
- ? ���� ��������� local window, � �� ���� ���������� span
- ? non-page-aligned fallback �� �������

### ��������� ������
��������� runtime ������ ����������� ������ ����� � ��� �������������� proc clusters � ������ �� panic-��� �� ������� contiguous ������� ����� zone holes.

## Bug #324 � page-aligned `ourproc()` scan ������ ���� ������ one-sided

### ��������
������ runtime ����� Bug #323 �� ����� panic-��� �� ������ �� ������ probe:
- `panic-full-2026-04-03-060125.0002.ips`
- `0xffffffe09c4fe0d8 = kernproc - 0x400000 + 0xd8`

������ unsafe �������� ��� �� ������ phase 1 lower bound, � ��� ������� ������ ���� �������� anchor.

### Root cause
�� ���� boot page-aligned lower neighborhood ��� anchor ������� toxic ���� ��� ����������� backward slack. ������� ��������� ����� `pre_window` ������ ���� ������.

### �����������
- ? `pre_window = 0` �� ���� ����� page-aligned scan
- ? scan �������� ����� � `anchor_min`
- ? ���������� ���������� ������� ������ forward/post
- ? cleanup / panic-guard path �� �������

### ��������� ������
��������� runtime ������ ����� ����� panic-free � ��������� ������ forward coverage ��� ���������� ����� � crashy lower region.

## Bug #323 � page-aligned `ourproc()` scan ����� ��������� ������ �����

### ��������
������ runtime ����� Bug #322 ����� ��� ����� fresh scan panic:
- `panic-full-2026-04-03-053459.0002.ips`
- `x0 = 0xffffffde25ea60d8`
- ����� ������ � ����� lower bound ������ ����: `0xffffffde25ea6000 + 0xd8`

�� ���� staged expansion �������� unsafe �� ��-�� stride, � ��-�� ���������� ����� �� ������������ anchor neighborhood.

### Root cause
��� ����� boot ������ ����� zone neighborhood ��� `anchor_min` ������� toxic ���� ��� page-aligned `0x1000` stride. Bug #322 �������� ���������� page geometry, �� �������� �������� ���� ����������� � ��� ����� ����� ����� � crashy lower region.

### �����������
- ? backward slack ������������ �� proven-safe `4MB`
- ? phase 1 / phase 2 ������ ��������� ������ forward/post coverage
- ? `0x1000` page-aligned stride ��������
- ? cleanup / panic-guard path �� ��������

### ��������� ������
��������� runtime ������ ����� ����� panic-free � ���������, ����� �� ��� `proc` ������ ����� �� ����������� anchor neighborhood.

## Bug #322 � ���������� page-aligned `ourproc()` scan ����� ��������� ������

### ��������
������ runtime 2026-04-03 ����� Bug #321 ���������� ������ ��������:
- ������� panic �����
- ���������� ����������� ������
- `Bug #296/320` page-aligned scan ������� ����������

�� ������� functional blocker �� ���������: `ourproc()` �� ��� �� ������� ��� PID ������ bounded ���� ������ short mixed `kernproc` chain.

### Root cause
���� Bug #320 ���� �������������� ��� panic-safety, � �� ��� coverage. ��� �������� boot page-aligned proc neighborhood �������� ����, ��� `anchor_min - 4MB .. anchor_max + 8MB`, ������� scan ������ �� ������, �� � �� ����� ��� app proc.

### �����������
- ? �������� staged expansion ��� page-aligned `Bug #296` scan
- ? �������� ���������� stride `0x1000`
- ? ��������� ����������� ���� `64MB/128MB` � `256MB/512MB`
- ? Non-page-aligned fallback �� �������

### ��������� ������
��������� runtime ������ �������� panic-free, �� ������� ������� ������� ������� proc zone �, ��������, ������� ����� `ourproc()`.

## Bug #321 � pre-hardened PANIC GUARD ������ ��������� ���������� �� rollback `icmp6filt`

### ��������
������ runtime 2026-04-03 ����� Bug #320 ��� ������������� �������� ����� neutralize-path:
- `abort-neutralize: parked corrupted filter target at self ... +0x148`
- ����� rollback/quarantine

�� ����� full panic �� ����� ������ ������, ��� ����� controlled abort, � ����� panic ����� ������ � `rw_socket_pcb + 0x150`.

### Root cause
����� ��� �������, ��� ��� pre-hardened failing session ���� best-effort rollback ��� ������: terminate-time teardown ������� �������������� � ����� post-abort ������ ������� � embedded `icmp6filt` slot. Neutralize stale target ��� �� ���� ������������, ���� ����� ���� ��� ����������� rollback qword0/qword1.

### �����������
- ? pre-hardened ����� `panic_guard_abort_cleanup()` ������ �� rollback-�� `icmp6filt`
- ? ����� ������ ������ park-�� target �� self-slot � quarantine-�� sockets/state
- ? generic early corruption cleanup ��� panic-guard success-path �� ����������

### ��������� ������
��������� runtime ������ ��-�������� ��������� ����������� �� `ourproc() == 0`, �� ��� ��� �������� panic �� `rw_socket_pcb + 0x150`.

## Bug #320 � pre-hardened PANIC GUARD abort ���� ������ neutralize-��� ��������� `target_kaddr` �� rollback

### ��������
������ runtime 2026-04-03 ����� ����������� ����������� page-aligned `Bug #296` zone scan ������� �������� panic-��� ������ ������ scan-path:
- `Bug #296/320: ... stride=0x1000 page_aligned=1`
- `Bug #296: scan done ... not found`
- `PANIC GUARD: ourproc() failed (0x0)`

�� ����� full panic �� ����� ��������� ��� ����� ���������� ����������, � ��� ����� ����� ������ � `rw_socket_pcb + 0x150`, �� ���� �� ������ qword embedded `icmp6filt` slot ������ `struct inpcb`.

### Root cause
Pre-hardened abort-path ����� rollback `icmp6filt` � quarantine fd-state, �� �� neutralize-�� ��������� speculative `target_kaddr`, ���������� ����� `set_target_kaddr()` probing. � ���������� terminate-time teardown �� ��� ��� ��������� �� stale embedded slot � ���������������� ��� ��� standalone small allocation.

### �����������
- ? � `fail_after_corruption_cleanup()` �������� ������ `park_corrupted_socket_filter_target_to_self()`
- ? Neutralize ������ ����������� � � pre-hardened PANIC GUARD �����, � �� ������ ����� leak-hardening
- ? rollback/quarantine policy ��������� ��� ���������� success-path

### ��������� ������
��������� runtime ������ ��������� controlled abort ��� `ourproc() == 0`, �� ��� ��� �������� terminate-time panic �� `rw_socket_pcb + 0x150`.

## Bug #319 � ����� ��������� `kernproc` accept ������ ����� � speculative alt-list probes, ���� short mixed chain ��� �������, ��� `ourproc()` �� � ���� �����

### ��������
������ runtime 2026-04-03 ����� Bug #318 ������� ��������� ���������� success-path ����� `0x3213678`:
- `KERNPROC detected ... [optimistic]`
- `ourproc()` ������� ����� �� ������
- �� forward walk ��� ������ 11 ����� � �� �������� ��� PID `471`

����� ����� ��� �� ��� �������� ������ `Bug #243B` / `alt next_off` speculative probes, � ����� ����� �� ���� ��� ������������ `getsockopt failed (early_kread)!` ��� �� ����������� `Bug #296` zone-scan fallback.

### Root cause
����� runtime ��� �� ����� �� ������ `PID=0-only` false chain. ������ � ��� short mixed chain � ��������� PID (`115`, `29542`), �� ��� ������ ��������. ��� ������ ������ alt-list detours �� ���� ����� �������� ����������, ���� ��������������� ������ KRW ������, ��� ����������� ���������� stride-based zone scan.

### �����������
- ? �������� ����� guard ��� short mixed `kernproc` chain (`count >= 8`, `max_pid_seen > 0`, `bwalk_count == 0`)
- ? � ���� ������ `ourproc()` ������ ���������� `alt-list`, `alt-next` � legacy intermediate scans
- ? ����������� ������ ������� � ���������� `Bug #296/299` zone-scan fallback �� `kernproc`

### ��������� ������
��������� runtime �� ������ ������ `early_kread()` �� speculative link probes � ������ ������� ������� �������� ��������� ����������� zone scan ��� ������ ������ `proc` ����� ��� ��������� `kernproc` acceptance.

## Bug #318 � strong `proc0.le_prev == candidate` path ������ ��������� `0x3213678` �����, � �� ������ ����� ��������� chain-validation

### ��������
������ runtime 2026-04-03 �������, ��� ���� ����� Bug #317 �������� `0x3213678` �� ��� ���������� ������ `kernprocaddress()`:
- `proc0.le_prev == candidate` ����
- `pid_off=0xd8` ����������
- �� ��� �� ����� ������� �� `Bug #315` � ����� �� reject

### Root cause
���������� optimistic-pass ���������� ������� ������. ��� success-first triage ����� ��������� ����� �������� ����� � ����� �������� backlink-�������, ���� �� ��� �� ������� ����� ������� �������������� ����������.

### �����������
- ? ��� `proc0.le_prev == candidate` � ��������� `pid_off` �������� ������ ����������� ����������
- ? `PROC_PID_OFFSET` ����� ������������� �� ��������� `0xd8`
- ? `g_direct_layout_set` / `g_kernproc_addr` / decode offsets ������������ ����� � ���� �����

### ��������� ������
��������� runtime ������ ������ ������ `kernprocaddress()` � ������� ��������, ��� ���������� ��� ������ ������ `ourproc()` ����� ��������� �������� `0x3213678`.

## Bug #317 � ��� success-path ��������� optimistic accept ��������� � `proc0.le_prev == candidate` � ��������� `pid_off`

### ��������
������ runtime ������� ����� �� ������������ `ourproc()`, �� `kernprocaddress()` �� ��� ��� �������� candidate `0x3213678`:
- `proc0.le_prev == candidate` ����������
- `pid_off=0xd8` ����������
- ����� Bug #303/315 �� ����� �������� path ����� reject

### Root cause
������� guard ��������� ������� ������� ��� success-first ���������: ���� ������� LIST_HEAD backlink � �������� ��������� `pid_off` �� ����������� �� ���������� �����, ��� ��� ��� `ourproc()` ����� ������ backward walk, alt-list probes � ������ ����� �������������� ��������.

### �����������
- ? �������� controlled optimistic accept ��� ������ `le_prev back-reference + discovered pid_off`
- ? ����� �������� ������ �� ������� �������������� ������ `kernprocaddress()`
- ? ��������� �������� ������ ������������� � ��� `ourproc()`, ��� ����������� ������ � �������� ��� ���������� success-path

### ��������� ������
����� runtime ������ ������ ������ ������� reject `0x3213678` � ��������, �������� �� `ourproc()` ��� ������� ����� user proc ��� ���� �� ������� ��������� ���������� blocker ����� �������� ����� ���������.

## Bug #316 � `ourproc()` �� ������ ��������� `ds_is_ready()` �� ����, ��� ��� exploit �������� bootstrap

### ��������
������ runtime ����� Bug #315 �� ��� ����� � `PANIC GUARD: ourproc() failed`, �� ��� ���� �� `ourproc()` ��������� ������� ��������� ���� `kread health check`, `calling kernprocaddress()` � `kernprocaddress() returned ...`.

### Root cause
� `darksword_core.m` ������� �����:
- ������ KRW ��� �����
- ����� ���������� `ourproc()`
- � ������ ����� �������� `ourproc()` � `ourtask()` ������������ `g_ds_ready = true`

�� � `utils.m` ��� `ourproc()` ������ ����� �������� `ds_is_ready()`. ��� ��������� self-blocking bootstrap loop: `ourproc()` ����������� ���������� �� ����, ��� ���������� `ourproc()`.

### �����������
- ? � `ourproc()` ����� ������ gate �� `ds_is_ready()`
- ? ������ ����� �������� bootstrap-path, ���� ��� �������� `kernel_base` �� ������� KRW
- ? ����� �� pre-ready gate �������� � `procbyname()` ��� ��������������� helper-path

### ��������� ������
����� runtime ������ ������� ������� ����� � ���� `ourproc()`, ���������� `kernprocaddress()` � ����� �� ���������� ���������� ������� success-path ������ ����������� self-abort.

## Bug #315 � ��������� ��������� `pid_off` ��� `le_prev` back-reference � ���������� ��� ������

### ��������
� ������ syslog `kernproc PID probe` ��������� �������� `pid_off=0xd8`, �� ������ ����� Bug #303 ������������� ������ rollback �� `0x60`:
- `Bug #267A: PID offset 0xd8 ACCEPTED`
- ����� `Bug #303: discarding probed pid_off=0xd8, keeping confirmed default 0x60`
- ����� ����� candidate `0x3213678` ���������� � `ourproc()` ������� `kernprocaddress() returned 0`.

### Root cause
Guard �� Bug #303 ����������������: � �������� `proc0.le_prev == candidate` �� ������ ���������� ��� ������������� probe-������, ������� chain validation ����������� �������� �������� `pid_off` ��� �������� ��������.

### �����������
- ? ������ �������������� `discarding probed pid_off` � back-reference �����
- ? ��������� ������� ������ ������� ��� � `discovered_pid_off`
- ? �������� ���������� fallback: ���� �������� � ��������� offset �� ��������, ����������� ������ � ��������� `0x60`

### ��������� ������
�������� `0x3213678` ������ �� ������ �������� ������ ��-�� ������� �������� � `pid_off=0x60`; ��� �������� ����������� ����� �� `allproc not found` � ������ � `ourproc/ourtask` success path.

## Bug #314 � leak-hardening ������ ���������� ������ ����� �������� `ourproc()` � `ourtask()`

### ��������
������ panic ����� Bug #313 �������, ��� neutralize stale target ������������:
- `abort-neutralize` ������� �������� � syslog
- �� ����� panic ��� �������� ����� �� `rw_socket_pcb + 0x148`
- panic string �������, ��� ����� ��������� � `kalloc.type1.1024 / struct inpcb`, � �� � ��������� `data.kalloc.32`

### Root cause
�� �������� `krw_sockets_leak_forever()` ������� ���� � ����� ����� ��������� ������� KRW. ���� ����� `ourproc()` ��� `ourtask()` �������������, ������ �� ����� ������� � terminate-time cleanup ��� � leak-hardened corrupted-socket ���������. ��� failing session ��� ��������� ����, ��� abort �� hardening.

### �����������
- ? `krw_sockets_leak_forever()` �������� �� success-only ����
- ? hardening ������ ����������� ������ ����� �������� `ourproc()` � `ourtask()`
- ? failing sessions ����� ���������� pre-hardened PANIC GUARD abort path

### ��������� ������
���� ������ �� ����� ����� `ourproc()`/`ourtask()`, ��� ������ �� ������ ������� � leak-hardened terminate path, ������� ������ � ��������� manual-close panic.

## Bug #313 � leak-hardened PANIC GUARD ������ neutralize-�� ��������� stale target ����� quarantine

### ��������
������ runtime ������� ����� �������:
- exploit session ������� �� `PANIC GUARD: ourproc() failed`
- ����� �������� `PANIC GUARD: leak-hardening already active � skipping icmp6filt rollback`
- ����� `abort-cleanup: quarantine sockets without close`
- panic ����������� �� �����, � ����� ���������� ����������� �������

### Root cause
� leak-hardened abort-path �� ��������� �� ������ rollback `icmp6filt`, �� ��� ���� ��������� � corrupted filter ��������� `target_kaddr`, ������� ��� ������� ��������� speculative probe ����� `set_target_kaddr()`. ��� ������ ���������� �������� kernel teardown �� ��� ��� ���������� ������ �� ���� stale target.

### �����������
- ? �������� helper park/neutralize corrupted filter target ������� �� self-slot `rw_socket_pcb + 0x148`
- ? � `panic_guard_abort_cleanup()` helper ���������� ������ � ����� `g_socket_teardown_hardened`
- ? �������� ��� rollback-��� `icmp6filt` ����� leak-hardening� ���������

### ��������� ������
����� PANIC GUARD + manual close teardown ������ �� ������ ����������� ��������� fake `allproc`/probe target, ��� ������ ������� ���� delayed panic ��� ��� �������� ����������.

## �������� ���������� ������������

- ����� ������� code-fix � ���� ����� ��������� � ��� �� �����: `doc/BUGS_AND_FIXES.md` � `doc/CURRENT_STATUS.md`.
- � `doc/BUGS_AND_FIXES.md` ��������� ����� bug-entry (�������, root cause, ����, ����, ��������� ������).
- � `doc/CURRENT_STATUS.md` ���������������� ����� ������� ����� � runtime-����.

## ���������� runtime-������ (2026-04-02, ������ 25e, syslog 15:42)

- ������: kbase=`0xfffffff01a124000`, kslide=`0x13120000`
- ����: `[0xffffffdc07934000..0xffffffe207934000]`
- **����� KRW**: �������� �������, `kernel r/w is ready!` ?
- **ALLPROC �� ��� �� ������** (�� Bug #295):
  - `0x31FFF30` > val=`0xfffffff01d33abd4` (DATA ptr, �� heap) > ��������
  - `0x3213678` > val=`0xffffffdd3b1b5000` (proc0, PID=0) ?; `proc0.le_prev=0xfffffff01d337678=candidate` ? (PERFECT PROOF)
    �� Bug #268 �������� ��-�� `pid_off=0xd8` (�������� probe) > `len=11 unique_nonzero=2 found_ourpid=0`
  - `0x3213680` > ����������, ��������
  - BSS scan ����� `score=22 FOUND!` �� `validate_proc_chain` ���������� (`seen<20` ��� `unique_pids<8`)
  - ���-O scan: ��� ������! Bug #294 �������� (0x63000 start), �� allproc �� 0x67F30 ����� �� ����� (scan ����������� �� ����������)
- **Bug #295 ��������** (build 54): `le_prev==candidate` � ���� chain validate, ����� ��������� pid_off
- **��������� ���**: ��������� syslog.bat, ��������� DarkSword, �������:
  ```
  [allproc] Bug #295: proc0.le_prev == candidate 0xfffffff01d337678 � definitive allproc proof, skipping chain validate
  [allproc] KERNPROC detected at 0xfffffff01d337678
  [ourproc] FOUND at step ...
  ```

## Bug #297 � XPF-lite env fallback ��� allproc ����� direct-shortlist

### ��������
����� ���������� `direct_offs_*` ��� ����� ��������� � scan-path. ��� ������� �������� �������-����������� patchfinder �� ���� ����������� runtime-������ ����������� �������� offset-��.

### �����������
- ? �������� `DS_XPF_OFFSETS` (������ ����� `,`/`;`/������): ��������� `offset` � `absolute kptr` (������������� � offset ������������ `kbase`)
- ? ����� fallback ����������� **�����** direct-shortlist � **��** scan fallback
- ? ��������� safety-�����������: �������� offset, ������� `validate_allproc()`, ��� ���������� deep scan

### ������
`DS_XPF_OFFSETS="0x31FFF30,0x3213678"`

## Bug #299 � ������� unsafe zone scan ��� PID=0-only kernproc chain

### ��������
������ device runtime ������� ������������������:
- `kernprocaddress()` ��������� candidate �� �������������� `proc0.le_prev == candidate`
- `ourproc()` �������� ������� ������ 11, �� ��� PID �������� `0`
- ����� ����� ��� �� ����� ��������� `Bug #296/299: zone scan ...`
- ���������� ������ � panic `zone bound checks`, panicked task = `DarkSword`

### Root cause
���� ����� ���� ��� runtime ��� �������, ��� ��������� ������� ������� � kernel-thread-only territory (`max_pid_seen=0`), ��� ��������� ������������ � blind zone scan fallback. �� iOS 17.3.1 ���� fallback ����������� ������ ��� ������ failure mode.

### �����������
- ? �������� ������ guard � `ourproc()`
- ? ���� walk ��� ���������� ������� �������, �� `max_pid_seen == 0`, ���������� zone scan fallback ������ �� �����������
- ? ������ panic-���� ������ controlled fail-fast � ����� �����

### ��������� ������
����� runtime ������ �� ������ ������� � panic ����� ����� `Bug #296/299: zone scan ...` � ����� ��������� kernproc, �� ������ PID 0 chain�.

## Bug #300 � ������� alt-list/alt-next probes ����� kernel-only PID=0 chain � ������� backward walk

### ��������
������ device runtime ����� Bug #299 ������� ����� path:
- `ourproc()` �������� ������ �� `PID 0` chain
- `Bug #243A` backward walk �� ������� �� ������ ��������� `proc`
- ����� ��� ��� � `Bug #243B` � `alt next_off`
- ����� ����� ����� ��� ������ � �������� `getsockopt failed (early_kread)!`
- ����� ���������� ����� ������ � `zone bound checks`

### Root cause
���� ��� �������� � explicit zone-scan fallback ��� ��������� ������ speculative alt-link probes �� ����������, ������� ��� �� ��������� ��� ���������������� proc list. �� ���� boot ����� ������ ��������������� ��� `early_kread` primitive ��� �� ��������� �������� ��������.

### �����������
- ? �������� ����� ������ guard ����� `Bug #243B` / `alt walk`
- ? ���� forward chain �������, `max_pid_seen == 0`, � backward walk ��� `0` proc, `ourproc()` ����� fail-fast
- ? Alt-list / alt-next probes ������ �� ����������� � ���� ���������� failure mode

### ��������� ������
����� runtime ������ �� ������ ������� � `getsockopt failed (early_kread)!` spam ����� `Bug #243A: backward walk checked 0 procs...` � ����� kernel-only `PID 0` chain.

## Bug #301 � ����� `krw_sockets_leak_forever()` panic-guard ������ �� ������ rollback-��� `icmp6filt`

### ��������
������ runtime � ��� �������� `Bug #300` ����� �� controlled abort, �� ���������� �� ����� ������� ������� `bug_type 210`:
- panicked task = `DarkSword`
- panic string �������� �� `rw_socket_pcb + 0x150`
- teardown ��� ���������� ����� `panic-guard abort`, � �� �� ������ alt-link ����.

### Root cause
� ������� abort ����� `krw_sockets_leak_forever()` ��� ���� ������� ���������. ��� ��������, ��� ������ ��� ���������� � leak/hardened �����. �������������� rollback `icmp6filt` � panic-guard path �������� ������ ���������� filter-slot ������ `inpcb` � �������� teardown � �������������� ���������.

### �����������
- ? �������� ���� ��������������� leak-hardening � `darksword_core.m`
- ? ����� ��������� `krw_sockets_leak_forever()` panic-guard abort ������ ���������� `restore_corrupted_socket_filter_best_effort()`
- ? Abort-path ��������� ������ quarantine ���������� fd/pcb ������ ��� ��������������� rollback `icmp6filt`

### ��������� ������
���� `ourproc()`/`ourtask()` ������ ��� ����� �������� KRW � leak-hardening, ���������� ������ ��������� ������ ��� �������� zone panic �� `rw_socket_pcb + 0x150`.

## Bug #302 � false-positive ����� `corruption stuck` �������� ����������� sprayed socket ��� rollback

### ��������
������ runtime � ��� �������� `Bug #301` �������� panic-��� ������ �� `rw_socket_pcb + 0x150`, �� ����� full panic �� ��� ���������:
- `panicked task = DarkSword`
- `expected zone data.kalloc.32 ... found in shared.kalloc.4096`
- panic-����� ��� �� �������� � ��������� `rw_socket_pcb`, �� ���� teardown ������� �� ������ `inpcb`.

### Root cause
� `find_and_corrupt_socket()` ��� false-positive path: corruption ��� "��������", �� marker-�������� ����������, ��� ��� �� ��� control-socket. ��� � ���� ����� ������ ����� `close(sock)` � ��� ������, �� �������������� ��� ����������� `icmp6filt`. ����� `sockets_release()` ���������� ����� sprayed socket, � kernel ������� ���������� embedded slot ������ `inpcb` ��� ��������� `data.kalloc.32` object.

### �����������
- ? � false-positive ����� ������ ������� ���������� `restore_corrupted_socket_filter_best_effort()`
- ? ����� rollback ��������� snapshot/pcb state �������� ���������
- ? ��������� fd ����������� ������ ����� rollback, � �� �� �� ��� ����������� ������

### ��������� ������
False-positive ��������� ������ �� ������ ��������� ����� ���� ������ ����������� sprayed sockets, ������� ����� ������ � zone free path ��� �� ������ `inpcb`.

## Bug #303 � `proc0.le_prev == candidate` ������ �� ��������� ����������� ��������������� real allproc

### ��������
������ runtime ����� Bug #302 ������������� �������� ������ � ������ `rw_socket_pcb + 0x150` path, �� ������� ����� ���������� ��������:
- `kernprocaddress()` ��������� `0x3213678`
- `KERNPROC detected ... kernel_task=0xffffffe304644000 decode_list_off=0x0 pid_off=0x60`
- `ourproc()` ����� ��� �� �������� heap-������� � ����� ������ `PID=0`
- ����� panic ��������� �� ����� `0xffffffe304644008`, �� ���� ����� `kernel_task + 0x8`

### Root cause
� `detect_kernproc_variable()` ������ Bug #295 ������� `proc0.le_prev == candidate` �������������� ��������������� real `allproc` � ��������� ���������� chain validation. �� ������� boot ����� ��������� ������������: ������ �������� ���� ����� ���������� back-reference, �� forward chain ���������� ��������� � kernel-only `PID=0` �������� ����� `kernel_task`.

### �����������
- ? `proc0.le_prev == candidate` ������ ���������� ������ ��� ������� structural hint
- ? ���� ��� ����� back-reference �������� �� ����� �������� `Bug #268` chain validation
- ? ��� head-backref validation ������������� ������������ ������������� `pid_off=0x60`, � �� tentative probe

### ��������� ������
������ `kernproc` candidates � ��������� ���������� `le_prev` back-reference, �� ��� ��������� ����������������� proc-chain, ������ �� ������ ����������� ��� valid `allproc`.

## Bug #304 � automatic Mach-O parse scan ������ �� ������ ����������� �� ��������� ����� ���������� shortlist/XPF-lite

### ��������
������ runtime ����� Bug #303 �������, ��� ������ ������ `kernproc` path ������������� ��������:
- `0x3213678` � `0x3213680` ������ ��������� �����������
- direct-��������� � builtin XPF-lite ��������� �������������
- ����� ��� ������������� ������ � `falling back to Mach-O parse scan...`
- ��������� ��� ����� ����� crash: `reading scan chunk at 0xfffffff022180000`
- ����� ����� ����� ���������� USB disconnect/reconnect, � `panic-full-2026-04-02-200839.0002.ips` ���������� `Panicked task: DarkSword`

### Root cause
���� � ��� �������� ����� `__DATA.__common` �������������� Mach-O scan ������� ������������ �� ������������ runtime-������ ����� exploit/KRW setup. � ������� boot �� ������ �� �������� ����� `allproc`, �� �� ��� �������� ��������� ������ �� controlled failure � `bug_type 210`.

### �����������
- ? Mach-O parse scan �������� � explicit opt-in
- ? �� ��������� ���� fallback ������ **�� �����������**
- ? ��� ������ ����������� path ����������� ����� `DS_ENABLE_MACHO_SCAN=1`

### ��������� ������
����� ���������� direct/XPF-lite ����� ���������� ������ ��������� `allproc`-resolve �������������� fail-fast, � �� ������� � ����� panic-path �� ����� speculative Mach-O scan.

## Bug #305 � `validate_allproc()` ������ ����������� ���� ��-proc head �� `disc_pl`

### ��������
������ runtime ����� Bug #304 ������� ��� clean abort �� `ourproc()==0`, �� ����� full panic �� ����� �������:
- panic string: `0xffffffe21ca1b748 not in the expected zone data.kalloc.32[41], but found in data.kalloc.16[40]`
- ���� ������ syslog ��������� false `allproc` head `0xffffffe21ca1b740`
- ��� �� ����� ����� ������� �� `val_ap` / `disc_layout FAILED`

### Root cause
`validate_allproc()` ���������� ������ ������ ������ head-� (`!is_heap_ptr_relaxed`). ����� ��������� ����: ������ �������� �� ��� �������� ��� heap pointer � ������� � `discover_proc_list_layout()`, ��� ���������� deeper structural reads (`raw+0x00`, `raw+0x08`, etc.) �� �������, ������� �� ��� �������� `proc` ��� `proc+list_off`.

### �����������
- ? �������� ������ preflight � `validate_allproc()`
- ? before `disc_pl` head ������ ��������� ��� `proc_base` **���** `proc_base+0xb0`
- ? ���� PID �� `head+0x60` � �� `(head-0xb0)+0x60` �� �������� plausibly, �������� ����������� �����

### ��������� ������
�������� ������ `allproc` head-� ����� `0xffffffe21ca1b740` ������ �� ������ �������� �� deep layout discovery. ��� ������ ������ late-panic path, ������� ������ � ������� `+0x8` � ������ �������.

## Bug #306 � preflight ��� `proc_base+0xb0` ������ ��������� ���� link-qword'� entry

### ��������
������ runtime ����� Bug #305 ������� ����� panic:
- panic string: `0xffffffe848901208 not in the expected zone data.kalloc.32[41], but found in data.kalloc.16[40]`
- ����� ���� `xpf-lite offset 0x3213ec8` ��� head `0xffffffe848901200`
- `disc_pl diag` ����� ������� �������� ���������: `pid=0x6c707041`, `[raw+0x00]=0x800000fa22000000`, `[raw+0x08]=0x0`

### Root cause
Bug #305 �������� ������ plausibility PID � `head+0x60` ��� `(head-0xb0)+0x60`. ��� `proc_base+0xb0` ����� ��������� ������������: ��������� small-value ���������� �� `(head-0xb0)+0x60` �� ��� ���������� ������������� zone object � `disc_pl`, ���� ���� ������ ��� qword � entry ��� �� ��������� ��� link pointers.

### �����������
- ? ��� ����� `proc_base+0xb0` ��������� ��������� structural-��������
- ? ������ ���� �� ���� �� `head+0x00` / `head+0x08` ������ ���� non-zero kernel pointer
- ? ���� PID ���������������, �� link qword'� �� ������ �� list entry, �������� ������� ��� �� `disc_pl`

### ��������� ������
������ SMRQ-like head-� ����� `0xffffffe848901200` ������ �� ������ �������� �� deep layout probing � �� ������ ����� ��������� � panic �� `+0x8` ���� �� �������.

## Bug #307 � direct `proc_base` preflight ������ ��������� real link-qword, � �� ������ ��������� `pid`

### ��������
������ runtime ����� Bug #306 ������� ��������� ��������:
- head `0xffffffe3fbe13340` ������ ������� ������ `Bug #306`
- �� ������ XPF-lite candidate `0xffffffe3fbe0b400` �� ��� ������� �� `disc_layout FAILED`
- ����� full panic ����� ������ � ��� �� ��������: `0xffffffe3fbe0b408 = head + 0x8`

### Root cause
Bug #305/306 ��� ���������� ����� `proc_base+0xb0`, �� direct-����� `proc_base` �� ��� ��������� �������� ������ �� `pid` �� `head + 0x60`. ��� `0xffffffe3fbe0b400` ��� ���� ������ `pid=0x6e65`, ���� ������ ��� qword ��� ��������� ��� �������� zone object: `[raw+0x00]=0x800000fa22000000`, `[raw+0x08]=0x0`.

### �����������
- ? ��� direct `proc_base` path ��������� ��������� structural-��������
- ? ������ ���� �� ���� �� `head+0x00` / `head+0x08` ������ ���� non-zero heap pointer ����� PAC stripping
- ? ���� ��������� `pid` ������ ��������, �� link qword'� �� ������ �� proc-list head, �������� ������� �� `disc_pl`

### ��������� ������
������ direct-head ��������� ����� `0xffffffe3fbe0b400` ������ �� ������ �������� � `discover_proc_list_layout()` � ��������� panic-path �� `head + 0x8`.

## Bug #308 � `detect_kernproc_variable()` �� ������ ������ `interp2` pid-probe �� fake SMRQ head

### ��������
������ runtime ����� Bug #307 �������, ��� ������ `disc_pl` path ������������� �������:
- head `0xffffffe3946518a0` ������ ������� Bug #307 ��� �� deep layout probing
- head `0xffffffe2613416a0` ����� ���� ����������� � `validate_allproc()`
- �� ����� full panic �� ����� ������ �� ������ `0xffffffe261341650`

### Root cause
���� ����� panic ��� �� ������ � `disc_pl` � �� ��� `head + 0x8`. Syslog ������� ����� ������ ���� � `detect_kernproc_variable()`: ��� direct candidate `0x3213ec8` ��� �������� `entry_ptr=0xffffffe2613416a0`, ����� ������ `interp2` ��� `maybe_base = entry_ptr - 0xb0 = 0xffffffe2613415f0` � �������� `maybe_base + 0x60 = 0xffffffe261341650` � ����� ����� panic-�����. �� ���� ������ head ��� ��� ���������� ����, ����� �� ������ SMRQ/direct pid-probe ������.

### �����������
- ? � `detect_kernproc_variable()` �������� ������ structural guard �� ������ ���� qword `entry_ptr`
- ? direct `interp1` ������ ����������� ������ ���� head ��� ����� �� �������� direct proc-head
- ? SMRQ `interp2` ������ ����������� ������ ���� entry ��� ����� �� �������� SMRQ/list entry

### ��������� ������
������ `kernproc detect` candidates ����� `entry_ptr=0xffffffe2613416a0` ������ �� ������ ��������� � ������ `(entry_ptr - 0xb0) + 0x60` � ��������� ����� panic-path �� `0xffffffe261341650`.

## Bug #309 � `validate_allproc()` ������ ��������� SMRQ link-qword �� ������ `(head - 0xb0) + pid_off`

### ��������
������ runtime ����� Bug #308 ������� ��������� ��������:
- `detect_kernproc_variable()` ������ �� ������� fake head-� `0xffffffe2003d46a0` � `0xffffffe2003d87d0`
- �� ����� full panic �� ����� ������ �� ������ `0xffffffe2003d8780`

### Root cause
���� ����� ��� �� ��������� � `kernproc detect`. �� ����� ������ � �������� SMRQ preflight � `validate_allproc()`:
`(head - 0xb0) + 0x60 = head - 0x50`.
��� fake head `0xffffffe2003d87d0` ��� ������� ����� `maybe_base + PROC_PID_OFFSET`, � ������ ����� ��������, ������ �� `q0/q8` � ������ head �� �������� SMRQ/list entry. �� ������� boot ����� ������� ��������� ����������, ����� ����� �������� zone panic �� reject path.

### �����������
- ? � SMRQ-����� `validate_allproc()` ������� �������� �����������
- ? ������ ������� ����������� `head+0x00` / `head+0x08`
- ? pid-read �� `(head - 0xb0) + PROC_PID_OFFSET` ����������� ������ ���� ��� head ��� structurally ����� �� �������� entry

### ��������� ������
������ SMRQ-head ��������� ����� `0xffffffe2003d87d0` ������ �� ������ ��������� � ������ `head - 0x50` � ��������� panic-path �� `0xffffffe2003d8780`.

## Bug #310 � staged qword-guard �� ������ ������ `head + 0x8`, ���� `head + 0x0` ��� ���������� fake head

### ��������
������ runtime ����� Bug #309 �������, ��� ������ `head - 0x50` path ������������� �����:
- fake candidate `0xffffffe200126680` ������ ������� ������� guard-���
- `PANIC GUARD` ����� ������� �� controlled abort
- �� ����� full panic �� ����� ������ �� ������ `0xffffffe0cce15ae8`

### Root cause
����� ����� ����� ��������� � `head + 0x8` ��� fake head `0xffffffe0cce15ae0`. ����� Bug #309 deeper SMRQ pid-probe ��� �� ��� �������; ���������� ���� ����� � ������ structural guard-��, ��� ��� �� ��� ���������� ����� ��� qword (`head+0x00` � `head+0x08`) ���� �����, ����� `q0` ��� ��� ���������� ��� reject.

### �����������
- ? ��������� staged helper-� ��� head-link validation
- ? ������ ������� �������� ������ `head+0x00`
- ? `head+0x08` �������� ������ ���� `q0 == 0` � ��� ������� qword ������ ���������������� head
- ? ������ ��������� � � `validate_allproc()`, � � `detect_kernproc_variable()`

### ��������� ������
������ head-� ����� `0xffffffe0cce15ae0` ������ ������������� �� ������ `q0`, ��� ������ `head + 0x8` � ��� ���������� panic-path �� `0xffffffe0cce15ae8`.

## Bug #311 � builtin XPF-lite ������ ��� `21D61` �� ������ ������������� ��������� known-bad offset `0x3213ec8`

### ��������
������ runtime ����� Bug #310 ���������� ��������� ��������:
- fake head `0xffffffe20a4ea200` ������ ������� ������ reject ��� ������ panic
- fake head `0xffffffe0d71da090` ���� ����������� ���������
- �� ����� full panic �� ����� ������ ����� �� ������ `0xffffffe0d71da090`

### Root cause
���� ����� ����� ������ � ����� head ��� builtin XPF-lite candidate `0x3213ec8` �� build `21D61`. ������, ���� ����� ����������� ������ guard-�� ��� ���� ��������������� ������� ����� candidate ������� ������� �����������. ��� ���� offset ��� ��������� �������� ������ �� ��� ��������� `allproc`-������� � ��������� �������� ��� ������ zone-object.

### �����������
- ? `0x3213ec8` ����� �� builtin XPF-lite ������ ��� `21D61`
- ? offset ������� ��������� ������ ����� ����� ������ `DS_XPF_OFFSETS`
- ? default runtime path ������ ������ �� ������� ���� known-bad candidate �������������

### ��������� ������
����� runtime ������ �� ������ panic-��� �� fake head `0xffffffe0d71da090`, ������ ��� builtin XPF-lite fallback ������ ������ �� ����� ��������� offset `0x3213ec8`.

## Bug #295 � Bug #268 chain validator �������� allproc `0x3213678` ��-�� ��������� `pid_off=0xd8` ( param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } , syslog 15:42)
`0x3213678` = allproc (proc0.le_prev ��������� �� candidate). �� PID probe ������ `pid_off=0xd8` (2-� proc � allproc � kernel thread, PID=0 �� +0x60). Bug #268: `len=11 unique_nonzero=2 found_ourpid=0` > REJECTED.

### �����������
- ? **#295**: ���� `le_prev == candidate && !is_heap(le_prev) && is_kptr(le_prev)` > `skip_chain_validate = true`
- ? ����� `discovered_pid_off` ��� `skip_chain_validate` � ����� default 0x60


## Bug #294 � Mach-O scan COMMON_START=0x27000 ���������� Metadata zone pointers > kernel panic ( param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value }  pre-fix)
Mach-O scan `scan_for_allproc()` ������� � `outer_DATA+0x27000`, ����� 21 ������� ����� Metadata zone pointer > Translation fault level 3. `far: 0xffffffe39af8cdf0` �� `zone_map_max=0xffffffe39398c000`. Kernel panic: panicked task pid 486: DarkSword.

### �����������
- ? `COMMON_START`: `0x27000` > `0x63000` (����� � allproc `outer_DATA+0x67F30`)
- ? `COMMON_END`: `0x83000` > `0x70000` (����� 28KB ����, ��� ������� ������ �������)

## Bug #293 � shortlist �� �������� ������������� allproc offset 0x31FFF30 ��� iOS 17.3.1 / 21D61 / A12Z ( param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value }  pre-fix, syslog 15:00)
��� shortlist ������ (`0x3213678`, `0x3213680` � ���������) ���� VALUE=0 ��� proc0 chain=1. �������� allproc ��������� � `outer_DATA+0x67F30 = kbase+0x31FFF30`, �� ���� offset �� ��� � shortlist � ��� ��� ������� �� ��������.

### �����������
- ? `0x31FFF30ULL` �������� ������ ��������� � `direct_offs_minimal[]`, `direct_offs_safe[]`, `direct_offs_full[]`

## Bug #266 � PID offset ����� ��������� ��� 0x90 (v1.0.50,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )
Bug #265 ����� �������� detect_kernproc � kernproc ��������� ? �� kbase+0x3213680.
�� PID probe ����� *(next_proc+0x90) = 9984 � ����� ��� PID offset = 0x90.
�����������: kernel_task+0x90 = 0x07732835 ? 0 > ��� �� PID.
���� proc0 �������: +0x60 � TAILQ_HEAD self-pointer, �� PID.
ourproc() �� ����� PID 521 �� � offset 0x90, �� � 0x60.

### �����������
- ? **#266A**: PID probe verification � reject ���� kernel_task+offset ? 0
- ? **#266B**: �������� `0x3213678` (allproc) ��� ������ �������� (forward walk)
- ? **#266C**: Brute-force PID search: scan 0x00..0x300 �� backward-walked procs

## Bug #265 � detect_kernproc_variable() ���� ��������� kernproc (v1.0.49,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )
kernproc �� kbase+0x3213680 > PID=0 ?, �� proc_ro check (proc_base+0x18) � silent failure.
Fallback � 0x321C240 > 762 DATA entries, ��� PID=0 > watchdog timeout.

### �����������
- ? **#265A**: proc_ro check non-fatal (�����������, �� �����)
- ? **#265B**: Blacklist ��� invalidated ���������� ��� retry
- ? **#265C**: ���� proc0 ����� ����������

## Bug #264 � krw_sockets_leak_forever() ��������� > panic ��� ������ (v1.0.48,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime builds 42-47)
���������� ���������� ����� ������� �������. �������: � Bug #234 (������ 21)
������� `krw_sockets_leak_forever()` ���� ��������� (hardcoded skip � darksword_core.m).
��� ��: ��� ���������� ���������� ���� ��������� ~22528 corrupted ������� > data abort.

������������ ������ ������ 21 ����� ������ ������� (Bugs #221-223: wrong so_count offset,
8-byte write corrupting adjacent field). ��� ��� ���� ����� ����������, �� skip �������.

### �����������
- ? ����� hardcoded skip, ������������ ����� `krw_sockets_leak_forever()`
- ? ������� ����� zone bounds ��������, 32-bit aligned R/W, sanity checks
- ? ���������� `so_count` offset 0x24c ��� iOS 17

## Bug #263 � ������������ allproc 0x321C240 (v1.0.47,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )
����� �������� 762 ������ � ��� � kernel DATA, ��� PID=0. PID=437 �� ������.
����� kbase+0x321C240 � ��� ������ ������ ������������ (~0x80 ���� ������), �� allproc.

### �����������
- ? **#263A**: SMRQ discovery ��������� PID ������� ���� (>0, <65536)
- ? **#263B**: Shortlist �������������� � 0x3213680 (heap kernproc) ������
- ? **#263C**: proc0 memory dump (0x100 ����) ��� �����������
- ? **#263D**: PID offset auto-probing (0x40..0xA8)
- ? **#263E**: Cache invalidation ��� false allproc
- ? **#263F**: Retry walk ����� false-allproc detection

## Bug #262 � Kernel panic ��� ������ �� DATA-proc0 (v1.0.46,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )
���������� ������ � ������� �������������� ����� ����� SMRQ discovery.
��� ���������, ������ �� �����.

### Root cause
1. **#262A**: `le_prev mismatch` ���� (Bug #238) ������������� PPLDATA-����� ����� le_prev proc0 > **kernel panic**
2. **#262B**: `is_plausible_pid(0)` = false > break �� step 0 (proc0/kernel_task)
3. **#262C**: unchecked `ds_kread64` ��� next_raw > ������ �� ���������� ������

### �����������
- ? **#262A**: le_prev check ������������ ��� DATA-proc0 (safe)
- ? **#262B**: PID=0 ����������� ��� step 0 ��� DATA-�������� proc0
- ? **#262C**: `ds_kread64` > `ds_kread64_checked` � graceful break
- ? **�����**: usleep(50ms) �������� ����� �������� �����; heap=/data= � first 5 hops
- ?? **��������**:  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value }  ������ ������ ��� ������ � �������� walk ��������

## Bug #261 � normalize_proc_link ��������� DATA ptrs (v1.0.45,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (������  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )
`normalize_proc_link_target_with_pid()` ����� `is_heap_ptr_relaxed(cand)` check �
��������� ��� DATA-���������. proc1 � DATA > normalize ���������� 0 > walk ��������.

### �����������
- ? **#261A**: `is_kernel_data_ptr(cand)` ��� g_direct_layout_set � normalize
- ? **#261B**: SMRQ discovery don't require PID validation on next (proc0 PID=0 already confirmed)
- ? **#261C**: proc0 entry dump (le_next/le_prev), heap/data status in first 8 hops

## Bug #260 � DATA-resident proc chain (v1.0.44,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )
SMRQ next_proc ����� proc0 **���� � kernel DATA** (�� heap).
��� �������� DATA ������ ��� proc0.

### �����������
- ? helper `is_kernel_data_ptr()`: kptr && kbase..kbase+0x4000000
- ? ��� walk paths ���������: validator, SMRQ discovery, ourproc, procbyname

## Bug #259 � Cache + procbyname + PAC le_prev (v1.0.42,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (����� ����)
- **#259A**: Cache validation � kernprocaddress() �������� `validate_allproc()`, ������� ������� heap-head. ��� DATA-proc0 ��� ���������� > ������ ����� ��������� ������ ���� (������� ������ kread)
- **#259B**: `procbyname()` �������� `discover_proc_list_layout()` (������� heap head) � `is_heap_ptr(kernproc)` � ��� fail ��� DATA-proc0. Walk loop �� ������������ DATA entry, ��� circular sentinel detection
- **#259C**: `first_leprev != kernprocaddr` ���������� RAW pointer (� PAC bits) vs clean address. �� arm64e ����� ���� ������ mismatch > �������� ��������� head

### �����������
- ? **#259A**: ��� `g_direct_layout_set` � lightweight check: `*(allproc)` > heap OR kernel DATA > cache valid. ������ `validate_allproc()` ������ ��� fallback
- ? **#259B**: `procbyname()` ������ ���������� `g_direct_layout_set` path (��� ourproc): �������� PROC_LIST_OFFSET, ��������� DATA proc0 at HEAD, sentinel detection, relaxed heap for next
- ? **#259C**: `pac_strip(first_leprev)` ��� ��������� � kernprocaddr

## Bug #258 � Circular list support (v1.0.42,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

### �������� (offline_test_v22)
- allproc 0x321C240 � **circular doubly-linked list** (�� BSD LIST � �� SMRQ)
- Init: `STP X9,X9,[X9,#0]` > self-pointer sentinel, entry at proc+0xb0
- BSD evidence=6, SMRQ evidence=0 (entry: le_next at +0, le_prev at +8)

### ����������� (4 �������)
- ? **#258A**: `validate_direct_allproc_v2` � `entry==candidate` = empty circular list; `next_entry==candidate` = ����� walk
- ? **#258B**: v2 validator DATA entry support � skip proc0, relax first_pid, handle kptr entries
- ? **#258C**: relaxed heap � confirmed walks � `g_direct_layout_set > is_heap_ptr_relaxed` ��� ptr_ok � next check
- ? **#258D**: sentinel detection � ourproc � `raw_stripped == kernprocaddr > break` ����� heap check

### �������� ( param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value }  runtime)
- `0x321C240` > val = kbase+0x321c400 (DATA ptr) > ��������� ��������� ?
- PID at val+0x60 = 44392616 (�� 0) > BSD ������������� fail
- SMRQ interp: base = val-0xb0, PID at base+0x60 = **0** > kernel_task ?
- ��: ��� ����� SMRQ le_next �� `proc+0x00` (BSD) > **heap=0** > FAIL!
- allproc ������ `&proc0->p_smrq_list` = proc0+0xb0, �� proc0+0x00

### �����������
- ? SMRQ next: ������ �� `stripped` (= proc+0xb0), �� `d_base2+0x00` (= proc+0x00)
- ? next_proc = smrq_next - 0xb0, ��������� heap + PID plausible
- ? PROC_LIST_OFFSET = 0xb0 > ourproc() �������� 0xb0 ��� proc base
- ? TAILQ fallback: ���� smrq_next=0 (kernel_task � tail), ������� candidate-8 ��� tqh_first
- ?? **��������**: (A) ���� proc0=HEAD > smrq_next > heap procs > forward walk > PID; (B) ���� proc0=TAIL > TAILQ fallback > tqh_first > newest procs > walk > PID
- `is_heap_ptr_relaxed()` ��������� >= `0xfffffff000000000` > allproc �� �������� ���������
- `0x3213680` (kernproc) > val = `0xffffffe4399a5000` > relaxed-heap, �� `detect_kernproc_variable()` ����� ���������� (0 �����)

### ����������� (Bug #256A + #256B)
- ? **#256A**: ������ diagnostic logging � `detect_kernproc_variable()` � ��� kread, PID, ��� ������������� (SMRQ ptr-0xb0, BSD direct), p_proc_ro
- ? **#256B**: DATA-resident proc0 path � direct shortlist loop:
  - ���� val � kptr � ��������� [kbase..kbase+0x10000000]: PID check at val+0x60
  - ���� PID=0 > proc0 � DATA; ������ le_next at val+0x00 > ������ ���� heap ptr
  - ���� le_next is_heap_ptr_relaxed > allproc ������ � DATA-resident head
- ? **ourproc() forward walk**: count==0 + g_direct_layout_set + is_kptr(proc) > ��������� ������ proc � DATA
- ? **heap_ok fallback**: g_direct_layout_set + is_kptr(proc) > �� ��������� DATA pointers
- ? **Bug #238 le_prev fix**: `is_heap_ptr(kernproc) || (g_direct_layout_set && is_kptr(kernproc))` ��� DATA entries
- ?? **��������**: runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value }  �������, �������� �� allproc `0x321C240` > DATA proc0 > le_next > forward walk > ��� PID

### offline_test_v21 (kernproc vs allproc hypothesis)
- `0x3213680` (4 xrefs): **KERNPROC** score 5 � HEAD_MUTATION + DEREF, ��� list traversal
- `0x321C240` (5 xrefs): **ALLPROC** score 6 � 3? LIST_TRAVERSAL, HEAD_MUTATION � insertion > ��� ��������� allproc
- `0x31C3000` (2727 xrefs): �� proc list, �����-�� ������ ������
- `0x3198060` (2 xrefs): PPLDATA allproc, PPL-protected �� A12+

## Bug #255 � kernproc detection + backward walk (v1.0.39,  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } )

- ? runtime  param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } : `0x321C240` > kernel data pointer (not heap), `0x3213680` > chain=1 PID=0
- ? `0x3213680` ������ SMRQ entry pointer �� kernel_task (PID 0 �� `entry_ptr-0xb0+0x60`)
- ? kernel_task � ����� allproc BSD LIST; forward walk ��� chain=1 > direct_v2 ��������� ���������
- ? **����� ����**: `detect_kernproc_variable()` ���������� PID 0, ������������ p_proc_ro, le_prev
- ? **backward walk**: ourproc() ��� `g_kernproc_is_pid0` ���������� BSD LIST offsets (`list=0x00, prev=0x08`) ������ SMRQ (`list=0xb0`)
- ? relaxed heap checks ��� kernproc path (kernel_task ����� ���� ���� safe_min)
- ? zone_map bounds ���������� ��� ����������� le_prev validity
- ?? **��������**: backward walk �� kernel_task ����� le_prev ������ ������ ���� procs �� ������ PID; runtime �������, �������� �� BSD le_prev ��������� �� iOS 17

## Runtime screenshots � direct_v2 ��� �����������, �� �� ������ ����������

- ? ����� Bug #253 shortlist ������ �� ����� relaxed-heap ��������� ������� ����
- ? �� ����� ���� `direct_v2` ������� ������� �� `SUCCESS` � `ourproc()` ���������� direct layout
- ? ������ ���������� walk ���������� ������ ������ PID (`0`, `13`, `15`, `16`, ...), � �� ��� ���������������� PID range
- ? ��� ������, ��� ������� �������� �� ��� �� ��������� `allproc`, � �����-�� proc-���������� / ��������������� ������
- ? ����� ����: `direct_v2` ������ ������� �� ������ chain/unique PID, �� �:
    - `first_pid != 0`
    - `max_pid_seen >= getpid()`
    - ����� ������� ����� `chain_len/unique_pids`

## Runtime screenshot � ����� blocker � direct-path

- ? �� ��������� exploit ����� ��������� ������� �� `kernel r/w is ready`
- ? `ourproc()` �������� `kernprocaddress()` � ������� �� direct shortlist
- ? ��������� ����� direct offsets ���������� ��� `val=... not heap` ��� �� ������� `direct_v2`
- ? ��� ��������, ������ ��� `direct_v2` ���������� ����� ��������� `entry_ptr = proc + list_off` ����� `is_heap_ptr_relaxed(...)`
- ? ������ ������� direct prefilter ��� ������� �������: �� ���������� `LIST_ENTRY`/SMRQ head pointers �� ����, ��� `direct_v2` ��� �� ������������� � `proc_base`
- ? ����: direct-path ������ ������� ������ `relaxed-heap` ��� ����� � `direct_v2`; strict-heap ����� ������ ��� ������� legacy validator

## Offline Test v20 � LIST_HEAD vs paired-head / anchor semantics

- ? `offline_test_v20.py` ������� shape-�������� ��� `0x31C30B0`, `0x321C220`, `0x3214850`
- ? `0x31C30B0` �� ���� �������� ����� ������ ������������� `LDR [head,#0]` + `LDR [head,#0x8]` � compare/branch, ��� head->node traversal
- ? ��� �������� ��� paired queue-head / state struct, � �� `LIST_HEAD.lh_first` ��� `allproc`
- ? `0x321C220` ���� � exact-referenced, �� ������������ ��� address/offset anchor (`ADD`/arithmetics), � �� ��� head pointer � ������� ������
- ?? `0x3214850` ������� ������, �� �� ������� ���� ����� � head/object probe, ��� paired-head `0x31C30B0` ��� anchor `0x321C220`
- ? direct-path reordered �����: `0x31C30B0` � `0x321C220` ������� ���� `0x3214850` � `0x3213EC8`

## Offline Test v19 � runtime-cluster exact-reference audit

- ? `offline_test_v19.py` ������������ cluster: `0x321C220/240/248/3F8/400/408/480`
- ? `0x321C240` ������� strongest runtime-cluster candidate: exact-ref + doubly-linked `prev/next` + `store [node,#0x8]`
- ? `0x321C220` ���� ����� exact refs, �� ��� ������� proc-list semantics � �������� ��� ������ weak neighbor
- ?? `0x321C248` � head-load audit �� ��� exact windows, �������� �� ������� �������� � runtime area
- ? `0x321C3F8`, `0x321C400`, `0x321C408`, `0x321C480` ����� �������� `0 exact refs / 0 semantic windows`
- ? direct-path reordered: zero-xref session-artifact offsets ���� � ����� ����� ����� `0x3214850` � `0x3213EC8`

## Offline Test v18 � ������ fallback-��������� ������ shortlist

- ? `offline_test_v18.py` ������� �������� evidence windows ��� `0x31C3000`, `0x31C30B0`, `0x3214850`, `0x3213EC8`
- ? `0x31C3000` �������� ������������, �� �������� �������: `PID@+0x60`, ��������� `store [head]`, ������ `next/prev`
- ? `0x31C30B0` �� ��� proc-hop ���������, �� ��������� ���������� paired-head reads `LDR [head,#0]` � `LDR [head,#0x8]`
- ?? `0x3214850` ����� �������� ������ `next`-like: ��� `prev`, ��� `PID@+0x60`, ��� ������������ doubly-linked ���������
- ? `0x3213EC8` ������������ ������� noisy next-only object-list head
- ? direct-path reordered ��� ���: `0x31C30B0` � runtime-cluster neighbors ������ ���� ������ `0x3214850`

## Offline Test v16/v17 � ��������� doubly-linked head �� next-only noise

- ? `offline_test_v16.py` �������, ��� `0x3213EC8` �������� �������� score ������ �� �������� `next`-chain ��������, ��� `prev`, `PID` � head-mutation ���������
- ? ��� �� `v16` �������� � `0x31C3000` ���� ������������ �������� (`PID@+0x60`, `store [head]`), �� �� ��������� ������������, ��� � runtime doubly-linked ����������
- ? `offline_test_v17.py` ������� next-only ��� � ����� ����� ���:
    - `0x321C240` � strongest runtime doubly-linked head
    - `0x3213680` � strongest `__common` doubly-linked fallback
    - `0x323C058/0x323C068` ������ ��-�� `+0x50/+0x54` object-like �����
- ? direct-path reordered: `0x3213680` ������ ���� `0x31C3000`, � `0x3213EC8` ������ � ����� ����� ��� last-resort probe

## Offline Test v15 � ������������� strongest runtime head

- ? `offline_test_v15.py` ��� ����������� �������� ��� `0x321C240`, `0x3213680`, `0x323C058`, `0x323C068`
- ? � `0x321C240` ����� ����� strongest pattern: `head -> prev -> next` � ������ `STR ... [node,#0x8]` � `STR ... [head]`
- ?? `0x3213680` ������� �������� doubly-linked ����������, �� ��� �������� ����� ���� proc-like
- ? `0x323C058/0x323C068` ���������� ���� ���� `+0x50/+0x54`, ��� ������ ������ �� ����� ��������� ������, � �� `proc`
- ? `kernprocaddress()` ������ ������� `kbase+0x321C240` ������ `0x31C3000` � ��������� shortlist-����������

## Offline Test v6 � ����������� �������

### �������� ���������� `offline_test_v6.py` (������ kernelcache.macho):
- ? **kbase+0x321C480**: ���� code xrefs � kernelcache > runtime-var � `__DATA.__bss`, �� allproc!
- ? **Bug #241 nearby-head scan (�0x90)**: �� ����� ������� �� ������ ���������. ��������� 23 ��, PPLDATA 529 ��.
- ?? **list_off=0xb0**: ����� ���� `p_pglist` (198 procs = ���� process group), �� `p_list` (allproc)
- ?? **PPLDATA allproc (kbase+0x3198060)**: ������ 2 code xrefs �� `__PPLTEXT` > PPL-protected, kread �� ����� ������
- ? **��� allproc ��������**: kbase+0x31C3000 (2727 xrefs, __DATA.__common, LDR[0] pattern) � � scan range
- ? **pid_off=0x60**: ���������� (2 getter ������� � kernelcache)

### ����� ����� (Bug #243, �������� Bug #241):
- **Bug #243A**: Backward walk via le_prev � ������� ������ � �������� �����������
- **Bug #243B**: �������������� list offsets (0x00, 0x08, 0x10, 0x18, 0xa8) � ���� 0xb0 ��� p_pglist
- **Bug #242**: Zone scan �������� ��� last resort

## Offline Test v10 � focused proc-related search

- ? `offline_test_v10.py` ����� ����� �� proc-related code windows (`kernproc` string xrefs + nearby globals)
- ? ������ focused candidate ������� `kbase+0x31C3000`

## Offline Test v11/v12/v13/v14 � ��������� list-head ����������

- ? `offline_test_v11` �������, ��� `0x3243920` ������ ��������� global, � �� proc-list head (`+0x10/+0x18`, ��� PID/next/prev ������)
- ? `offline_test_v12` ���������� � `0x321C240` ����� ������� `head -> node -> prev/next`
- ? `offline_test_v13` �� ����� `__common/__bss` ������� ����� `next-only` �����, �� ��� � �������� �� ������ �� proc-list
- ? `offline_test_v14` ������������ doubly-linked heads; ����� runtime-������� ����� ������������ `0x321C240`
- ? � direct-path ��������� ��� ��� ������-���������: `0x3213680` � `0x3214850`
- ? companion candidate � ������ �������� `__common`: `kbase+0x31C30B0`
- ? strongest non-page-boundary candidate: `kbase+0x3213EC8`
- ? ��� ��������� ��������� � `kernprocaddress()` direct path �� �������� range-scan

## Offline Test v11/v12 � proc-list-like usage scoring

- ? `offline_test_v11.py` ������ ��������� �� ��������� proc-list-like �������������, � �� �� ����� xref counts
- ? `kbase+0x321C240` ��� ������ ����� `next/prev`-������� ����� � runtime-cluster
- ? `offline_test_v12.py` ���������� ��������:
    - `ADRP X8, 0xfffffff00a220000`
    - `ADD X8, X8, #0x240`
    - `LDR X0, [X8, #0x0]`
    - ������ ���� `LDR X9, [X0, #0x8]` � `LDR X9, [X0, #0x0]`
- ? runtime-cluster `0x321C220/240/248` �������� � ������ direct-path

## Offline Test v7/v8/v9 � ���������� ������

- ? `kbase+0x321C480` � `kbase+0x321C400` ��-�������� ����� **0 exact xrefs** > �� �������� ��� �������� ����������� `allproc` globals
- ? ����� ������ ��������� runtime-cluster � `__DATA.__bss`: `kbase+0x321C220`, `kbase+0x321C240`, `kbase+0x321C248`
- ? ��������� exact-referenced global � `0x321C480` � `0x321C248` (��������� `0x238`)
- ? � `__PPLTEXT` ������������ 2 ������ `__PPLDATA+0x60` (`0x84b1278`, `0x84b1450`) > �������� ��� PPL-managed allproc �����������
- ?? refined runtime fallback ������ ������� `list_off=0xa8`, ��� ��� ���� offset ��� ����������� � `direct_v2`, �� ������������ � `ourproc()`

## ������ 25c � allproc ������ (score=49!), �� `ourproc()` �� ������� ��� PID

### ��� ���������� `syslog_session25c.txt` (3-� ������, PID 362):
- ? exploit ��������� ������� �� kernel r/w
- ? `kernprocaddress()` ����� `kbase+0x321C480` ����� `__DATA.__bss` scan (score=49, 198 procs!)
- ? layout ����������: `list_off=0xb0, pid_off=0x60, next_off=0x0, prev_off=0x8`
- ? `le_prev` ������� entry == `allproc` addr (backlink ����������)
- ? kread health check PASSED �� ���� 4 ������� `ourproc()`
- ? walk �������� 198 ��������� (PID 0>0>262>261>...>225>...>NULL) �� PID 362 �� ������
- ? ������������ PID � ������ = 262, ��� PID = 362 (����!)
- ? alt walk � `next_off=0x8` ���������� ���������� (raw == allproc addr)
- ? zone scan fallback (Bug #240) �� ���������� � IPA �������������� �� ������� ����

### �������� ������� (Bug #241):
`kbase+0x321C480` � ��� �� `allproc.lh_first`, � ������ `kernproc` (����������� ��������� �� `kernel_task`). ��������������:
- `*(0x321C480)` = `0xffffffe094bca100` = kernel_task entry (pid=0, ALWAYS)
- ����� ��� �� kernel_task (����� ������) � pid=262, �� ��� pid=362 ����
- � XNU `LIST_INSERT_HEAD` ��������� ����� �������� � ������ > head ������ ���� PID 362, � �� 0
- ������ �� ��� �� ������ ������, � �� �� ������

### �������������� blocker (Bug #242):
���� ���� zone scan ����������, ����� `scan_max_seen` �������� kernel_task (`0xffffffe0...`), � ���������������� �������� � `0xffffffdf...` � ������ ~3.7 ��, scan ������� ������ ~267 ��.

### ����� ��� session 26:
- **Bug #241**: �������� nearby-head scan � ������� `kernprocaddr � {0x80,0x78,0x88,...}` ��� �������������� allproc HEAD
- **Bug #242**: Zone scan ������ ����������� user proc range �������� �� kernel_task; SCAN_STEPS �������� �� 2000, fine-grained range �� �1��
- �����: ������� ��� (� Bug #240 zone scan) ����� ������� ������������� � ����� IPA

## ������ 24 � ����� �� `ourproc()`, �� legacy curated candidates �� ��� ������

### ��� ���������� `syslog_session24.txt`:
- ? ����� ���� ���������� � ������� �������
- ? exploit ��������� ������� �� `kernel r/w is ready!`
- ? bypass `krw_sockets_leak_forever()` ��-�������� ��������� ����� �� `about to call ourproc()`
- ? `ourproc()` ������� ������ � `kernprocaddress()` ��� ����� ����� Bug #236
- ? ����� GOT � `PPLDATA_allproc` ��� �� ��� ������� legacy candidate `DATA_0x31FFF30`
- ? � ���� ������ ��� ���������� ��:
    - `[val_ap] addr=0x...0bbf30 raw_head=0x...0d2bd4 heap=0`
    - `[disc_pl] entry: raw=0x...0d2bd4 ... heap=0 relaxed=0`
    - ����� `[disconnected]`

### ����� blocker:
- Bug #236 ��� �������� ������ pre-range read ����� `__bss` scan
- �� �� ������ scan ��� �� ��� �� �������, ������ ��� ����� ���� ���������� ������ curated offsets `0x31FFF30/0x31FFB50/0x31FFC68`
- session 24 ��������, ��� �� ������� ���� `0x31FFF30` �� ������� boot ��� `raw_head`, ������� ����� �� �������� heap `proc` pointer
- ������ ��� legacy candidates ��� �� ������ ������������������, � ������ ����� �� ����� ����������� aligned runtime scan

### ����� ���� ����� session 24:
- `validate_allproc()` ������ ����� ��������� candidate, ���� `*(allproc)` �� �������� heap `proc` pointer
- legacy curated `DATA_0x31FFF30/0x31FFB50/0x31FFC68` ���������
- `kernprocaddress()` ������ ����� GOT/PPLDATA ����� ��������� � ����� aligned scan windows

## ������ 23 � ������� validator ����� false positive, �� ������ ����� scan bug

### ��� ���������� `syslog_session23.txt`:
- ? Bug #235 ������� ��������: ������ ������ curated candidates (`0x31FFF30`, `0x31FFB50`, `0x31FFC68`) ������ �� �����������
- ? `discover_proc_list_layout()` ������ ��������� ������� proc-like ������ � `best_score=2`, ������ ������� `FOUND`
- ? ���������� ������� �� `starting inner-kernel DATA range scan...`
- ? �� ����� �������� � `__DATA.__bss` ��� ���������� ��:
    - `scan __DATA.__bss: 0x...6f000..0x...9f000`
    - `reading scan chunk at 0x...6c000`
    - ����� `[disconnected]`

### ����� blocker:
- helper `scan_range_for_allproc()` ���������� `range_start` ���� �� 16KB
- ��-�� ����� �������� scan `__DATA.__bss` ��������� �� `0x3000` ������ ��������� ����
- session 23 �������� ������ ����� ������: requested start ��� `0x...6f000`, � ������ ������ ���� � `0x...6c000`
- ��� ��������, ��� panic/disconnect ������ ���������� �� ��-�� false-positive layout, � ��-�� ������ pre-range chunk ����� ������� `__bss` �����

### ����� ���� ����� session 23:
- `scan_range_for_allproc()` ������ �� ������ ������ �� `range_start`; ����� ������ align-up, � �� align-down
- narrow scan windows ���������� �� 16KB-aligned offsets
- broad `__DATA.__bss` fallback �������� ������� �� ����� ���� ������ �������� runtime hit `kbase + 0x321c260`

## ������ 22 � panic �����, `ourproc()` ����� �����������

### ��� ���������� `syslog_session22.txt`:
- ? panic �� session 21 ������ �� ����������� ����� ���������� bypass `krw_sockets_leak_forever()`
- ? `ourproc()` ����� ������� ����������
- ? `PROC_PID_OFFSET` ������ �� ����������� � `0x10`; ������������ ������ `0x60`
- ? `kernprocaddress()` ������� �� runtime scan � ������� candidate � `__DATA.__bss`:
    - `allproc = kbase + 0x321c260`
- ? `discover_proc_list_layout()` ������ ���������� ������ `pid_off = 0x60`

### ����� blocker:
- ? `discover_proc_list_layout()` / `validate_allproc()` �� ��� ��������� ������ proc-like ������
- � ���� ����� false positives � layout'��� �����:
    - `list_off = 0xf0, next_ff = 0x0, score = 1002`
    - `list_off = 0x0, next_ff = 0x8, score = 22`
- ����� `ourproc()` ��� �� ������� � ���� ������������ PID-��������������:
    - `pid = 0, 5, 5, 5, 0, 0, 9, ...`
    - walk ���������� ��� ����� 20 ����� � `our pid=397` �� ���������

### ������������� root cause:
- ������ scoring �� ��� �������� false positive ����� ������ PID-diversity
- ���� ��� cycle loop ��������� ������ ������ ���� 20+ ���������� �������, �� ����� �� ���� ���������� PID
- persisted cache ��������� ��������, �������� ������ runtime candidate

### ����� ���� ����� session 22:
- scoring �������� �� **PID diversity**, � �� �� ����� hop'� / pid1 bonus
- `validate_proc_chain()` ������ �������:
    - ������� 20 �����
    - ������� 8 ���������� PID
    - �� ����� 2 ��������� `pid=0`
- ���������� persisted `kernproc` offset �������� ���������
- scan ������ �� ��������� runtime candidate �� ������ ������������ ���������

## ������ 21 � ��������� �������� panic ������

### ��� ���������� `syslog_session21.txt`:
- ? exploit ��������� ������� �� `kernel r/w is ready`
- ? crash ���������� **��** ����� ����� `ourproc()` / `allproc()`
- ? ��������� ������ ���������� ����� reboot:
    - `krw leak: refcount patch applied successfully`
- ? ������
    - `returned from krw_sockets_leak_forever()`
  �����������

### Root cause:
- kernel panic ������� �� proc-walk, � ������ `krw_sockets_leak_forever()`
- ������� ��� ���������� ������ �� `ourproc()` �� session 21 ���� ������������ � ��� �� ���� ������ �� �������

### �������� ����:
- `krw_sockets_leak_forever()` �������� bypass'���, ����� �������������� ������������ ��������� `allproc`/`ourproc`
- ��� �� ������������� �������, � ��������������� bypass ��� �������� �������� blocker'�

## ������ 17 � ����� ��������

### ��� ���������� `syslog_session17.txt`:
- ? exploit ����� ��������� ��������� ������� �� `kernel r/w is ready`
- ? `kernprocaddress()` ������ ������� ������� `allproc`
- ? ������ ����� runtime offset: `allproc = kbase + 0x321b080`
- ? `scan __DATA.__bss` ��� �������� proc-list layout:
    - `list_off = 0xb0`
    - `pid_off = 0x60`
    - ������� `pid0 -> pid0 -> pid1` ����������

### ����� blocker:
- ? `ourproc()` �� ��� ��������� `0x0`
- ��� ������� �������:
    - step 0: `pid=0`
    - step 1: `pid=0`
    - step 2: `pid=1`
    - ����� `raw_next=0x0`
- ��� ��������, ��� ����� ��������������� `le_next/le_prev` ��� ������ ��������� �� base `proc`,
  ���� �� ���� layout link ����� ��������� ������ `LIST_ENTRY` ������ `proc`

### �������� ����:
- ��������� ������������ proc-link target:
    - ������� ��������� raw pointer ��� base `proc`
    - ����� raw pointer ��� `proc + list_off`
    - ���������� ������� � ��������/plausible `pid`
- `discover_proc_list_layout()` ������ ����������� `next`/`nextnext` � ������ �������� `pid_off`
- `ourproc()` � fallback traversal ������ ������ ���� �� base `proc`, � �� �� ����������� `LIST_ENTRY`

## ������ 18 � ����������� ��������� �����

### ��� ���������� `syslog_session18.txt`:
- ? `kernel r/w is ready`
- ? `kernprocaddress()` ������ ��������� ������� ������ runtime candidate `kbase + 0x31FFC68`
- ? runtime layout ��� �� `0xb0`, � �����:
    - `list_off = 0x158`
    - `pid_off = 0x60`
- ? ������ ���������� ���� �������� ��������: `allproc` ������ �� ��������

### ����� blocker:
- ? `ourproc()` �� ��� ������ � ������������ `next`
- � ���� �����:
    - step 0: `pid=0`
    - step 1: `pid=6`
    - step 2: `pid=2869045281` < ����� �����
- ����� `raw_next=0x0` � `ourproc()` ������ � `NOT FOUND`

### ����� ����:
- ��������� ������� �������� `pid` � `ourproc()` � reversed traversal
- ���� `pid` �� �������� `is_plausible_pid()`, ����� ������ ���������� ��� invalid hop,
  ������ ����������� �� ������� `proc`
- next hop ������ � `ourproc()` ������ ������ ����� `proc_list_next_checked_pid(...)`, � �� ����� ������� `pac_strip(raw_next)`

## ������ 15�16 � ������� ��������� allproc

### ��� ���������� syslog_session15.txt:
- ? exploit, `kernel_base`, `zone_info`, `refcount patch` ��-�������� ��������
- ? ������ panic �� �������� `__DATA.__common` scan �����
- ? strongest candidate ������ ��������� ���������������: `kbase + 0x31FFB50`
- ? � ��������� �������� �������� proc-like ������:
    - `pid=0`
    - `le_next=0xffffffdcf911a500`
    - `nextpid=0`

### ����� ��������:
- ? `discover_proc_list_layout()` �� ��� �������� ������� ��������
- ������ ������ ������� ����� ��������� ������� `kernel_task(pid 0) -> launchd(pid 1)`
- �� �������� ���������� ����������� ����� ������� ������� `pid0 -> pid0 -> ...`
- ��-�� ����� `kernprocaddress()` �� ��������� ������� �������� � ����� ������ � scan

### �������� ����:
- �������� `is_heap_ptr_relaxed()` ��� ��������� proc-chain ��� `safe_min`
- �������� fallback-�������� `0x31FFB50` � nearby-�������� `0x31FFC68`
- �������� ������������ ������� `PROC_PID_OFFSET`: `0x60`, `0x28`, `0x10`
- ��������� �������������� �������� ��� �������� `pid0 -> pid0 -> nextnext`
- ������� ������������ ��������� ����������� ��������������
- ������ ���������� ������� �� `1.0.16` / build `16`

## ������ 13 � ��������� ����� Bug #225 + ���� Bug #226b

### ��� �������� (������������ syslog_session13.txt):
- ? VFS race + Physical OOB + ICMPv6 corruption
- ? Kernel R/W (kread health check PASSED: magic=0x100000cfeedfacf)
- ? Zone discovery: zone_map [0xffffffdd9faf0000 - 0xffffffe39faf0000], safe_min=0xffffffdf1faf0000
- ? Kernel base: 0xfffffff025408000, slide: 0x1e404000 (via protosw->pr_input)
- ? Socket refcount: so_usecount ctrl=1 rw=2 � CORRECT! refcount bumped OK
- ? Bug #225 fix ��������: per-CPU zone panic ������ �� ���������

### ����� �������� (Bug #226b):
- ? allproc scan: Kernel data abort ��� ������ chunk 2 (0xfffffff0285d0000)
- **Root cause**: �������� ������ offset 0x93B348 + ������������ � ������ __DATA.__common
  �������� �� heap-��������� � unmapped zone pages > kernel panic � copyout()
- **����**: ���������� offset 0x31FFF30 + scan ���������� � ������ ���� ������ allproc

## ������: kernel r/w + kernel_base + refcount patch!

�������� ������ 12 ����������, ��� exploit ������� ��:
```
rw_socket_pcb validated: 0xffffffe17b8e4400
zone bounds primed from rw_socket_pcb: [0xffffffdf... - 0xffffffe3...]
kernel-base fallback: success via protosw->pr_input
kernel_base: 0xfffffff012c38000
kernel_slide: 0xbc34000
krw_sockets_leak_forever()
krw leak: so_count control=0x1a800000000 rw=0x1a800000000  < WRONG OFFSET!
krw leak: refcount patch applied successfully
> kernel panic (so_count offset 0x228 �������� socket struct)
```

Bug #221 ���������: `so_count` offset = `0x24c` ��� iOS 17+ (������������ ����� �� 29 �����).
��������� ���������� �������� � ���� refcount ��������������, bump ������������.

## ���������� � ����
- **iPad8,9** (iPad Pro 11" 2G, A12Z Bionic, arm64e)
- **iOS 17.3.1** ( param($m) if ($m.Value -match '\d+') { "build 54" } else { $m.Value } D61), xnu-10002.82.4~3
- **Kernelcache UUID:** D1B6EFB84A11AE7DCDF3BC591F014E72
- **Kernel unslid base:** `0xfffffff007004000`

---

## ��������� ��������: ������ 6�7

- **#211:** `set_target_kaddr()` ������ �� ��������� A12Z PCBs � ��������� `0xffffffdd...`
- **#212:** fallback/emergency zone bounds ������ �� clamp'���� � `0xffffffe000000000`
- **#213:** ������������� ����������������� ������ original exploit ��� VFS race:
    - `target_object_size` �� `mach_make_memory_entry_64()` ������ �����������
    - `target_object_offset` ������ page-aligned � clamp'���� � ������� memory object
    - `free_thread()` ������ �� 5 retry `mach_vm_map()` ������ single-shot fail
    - ��� `mach_vm_map failed in free_thread` rate-limited (1 ��� �� 128 fail'��)

**������:** ������ ������ `set_target_kaddr` ��������; ������� ������ �������� ����� ���� race-map path � ������ � ���������� ����� �� ����������.

---

## ��������� ��������: ������ 8

- ���������� ������ ����� panic/reboot �� flush ����, ������� �������� �������������� ������-����� � [ipsw_analysis/offline_analysis_v5.py](../ipsw_analysis/offline_analysis_v5.py)
- **#214:** ��������� original fallback ���� ��� `kernel_base`:
    - `control_socket_pcb + 0x40 -> socket`
    - `socket + 0x18 -> so_proto`
    - `protosw + 0x28 -> pr_input`
    - `pr_input` ������ ���� ptr � `__TEXT_EXEC`, ������� ��� ������� ��� ������ kbase ������ ����� `zv_name`
- ��������� ��������� `zv_name` ��� printable ASCII cstring (`icmp6` / `ripcb` / `inpcb` / `raw6` family)
- ���� `zv_name` ���������, `discover_zone_boundaries_raw()` ������ ���������� � emergency path ������ ����� �� ������������ ��������� `ipi_zone`

**��������� ������:** ���� ������� panic ���������� ��-�� ���������, �� canonical-looking `ipi_zone/zv_name`, ����� ���� ������ �������� ������������ kernel panic � ���� �� ������ �� flush ����.

---

## ��������� ��������: ������ 9

- ����� screenshot �������, ��� ������ ��� ������� ��:
    - `found control_socket`
    - `rw_socket_pcb validated`
    - `control_socket_pcb`
    - `pcbinfo_pointer`
    - `ipi_zone`
    - `zv_name`
    - `discovering zone boundaries...`
- �� ������ ����� `zone name: site.struct inpcb`
- �������������� workspace-������ �������: `site.struct inpcb` ���������� � kernelcache ��� debug/assert-style string � **�� ������ ��������� �������� zalloc-zone ������** ��� `ipi_zone`
- **#215:** ��������� `zv_name` ����������: ������ ����������� ������ ������ ����� `icmp6`, `ripcb`, `inpcb`, `inp6`, `in6pcb`, `raw6`, `icmp6pcb`

**��������� ������:** ���� ������ `discover_zone_boundaries_raw()` ��������� �� ��������� `ipi_zone` ��-�� ������������������� `zv_name`, ������ �� ���� � emergency path ������ �������� memory scan �� ��������� ������.

---

## ��������� ��������: ������ 10 � KERNEL R/W ���������!

- �������� ����������: **��� ���� #211-#215 ���������**, exploit ������� ������ ������ ���� �� `kernel r/w is ready!`
- Runtime ��������: `kernel_base=0xfffffff022378000`, `kernel_slide=0x1b374000`
- Crash ������ � `ourproc()` � **post-exploit**, � �� exploit
- **#216:** `kernprocaddress()` �� �������� �� ������ known-good offset allproc (��� ������� � #205/#206). ������������ ��������� � `scan_for_allproc()`, ������� ��������� 512KB __DATA � ������ heap-reads ����� emergency bounds �8GB. ��������� heap-like ������ ����������� zone metadata (unmapped) > kernel panic.
  - �������� ADRP-derived offset `kbase+0x31FFF30` (`__DATA.__common`+0x3CF30) ��� ������ �������� (389 ADRP refs, PHASE2 ������)
  - Scan range ����� �� `__DATA.__common` only (0x27000�0x83000 �� outer __DATA)
  - Pre-filter: heap pointer �2GB �� rw_socket_pcb (�������� zone metadata)
  - Health check kread (magic `0xFEEDFACF`) ����� allproc scan

**��������� ������:** `ourproc()` ������ ����� allproc �� known offset �� 1-2 kernel reads ������ �������� scan.

---

## ��������� ��������: ������ 11 � allproc scan range

- **#217�#219:** ������-������ ������ 3 �������� � `kernprocaddress()`:
  - 8 ADRP-���������� ������� PAC-signed function pointers, � �� proc pointers > ��� �������
  - `scan_allproc_known_range()` ���������: ��������� `__DATA.__common` (kbase+0x31c3000..0x321b000) � `__DATA.__bss` (kbase+0x321b000..0x324b000)
  - ������ ADRP+LDR[#0] ��������: kbase+0x3216000 � ���������� � �������� scan range
  - ������-����������� �����������: scan range ��������� ��������� `__DATA.__common`, overlap � PPL �����������

**��������� ������:** allproc scan ������ ��������� ��������� ���������� ������� kernel data.

---

## ��������� ��������: ������ 12 � zone bounds + so_count

### Bug #220: zone bounds not primed (�������������� � ��������)
- �������� �������: exploit �������������� �� `rw_socket_pcb validated` � �� ����� PCB reads
- ���: `set_target_kaddr: BLOCKED addr ... (no zone bounds, static_max=...)` > `getsockopt failed` > panic
- **�������:** `g_zone_map_min/max = 0` ��� ������ heap read; `set_target_kaddr()` ���������� ��� ������
- **�����������:** `prime_zone_bounds_from_rw_pcb()` � emergency �8GB ���� �� validated PCB
- **���������:** ��������� �������� ���������� ������ ����� ��� ������ reads!

### Bug #221: so_count offset 0x228 > 0x24c (����������, ������� ����)
- ������ �������� � ����� ������ �������� �� ��� �������:
  - `kernel_base: 0xfffffff012c38000`, `kernel_slide: 0xbc34000`
  - `zone name: site.struct inpcb` > ��������� ���������
  - `EMERGENCY bounds` �����������
  - `krw_sockets_leak_forever()` �����
  - `so_count control=0x1a800000000 rw=0x1a800000000` � **�����** (������ � ��������� offset)
  - `refcount patch applied successfully` > kernel panic
- **�������:** `so_count` offset `0x228` = iOS 16 (xnu-8792). iOS 17 (xnu-10002) ���������� �� `0x24c` (+36 ����)
- **��������������:** `darksword_live2.txt` (29 �����) � `0x24c` ������� `raw=0x1` � `raw=0x2` � �������� refcount
- **�����������:** ������������ offset (`0x24c` ��� iOS 17+, `0x228` ��� ?16) + ���������� �������� (<0x10000)
- **����������� ���������:** �������� zone scan ������ 256KB, ����������� ��� ����� ������� kernel read

**IPA SHA1:** `5221E39661E50E82D5CDD7839A9B43044E902213`

---

## ��������� ��������: ������ 12b � Bug #222�#225

### Bug #222: `set_target_kaddr()` ���������� 4-byte-aligned ������
- �������: ������ �������� `where & 7` ������ ������/������ 32-bit ����� � `struct socket`
- �����������: ��������� `kread32_aligned()` � `kwrite32_aligned()` � �������/������ ��������� 8-byte qword

### Bug #223: 32-bit write corruption � `struct socket`
- �������: refcount/readcount ��������� ��� ����� ����� patch-�
- �������: 32-bit ������ �� `0x24c` ����� ������� �������� ���� ��� ������ 8-byte write
- �����������: patch ������ ��� ����� `kread32_aligned()` / `kwrite32_aligned()` ��� ������� 32-bit ���� ��������

### Bug #224: `site.struct inpcb` + ������� ����� emergency bounds
- �������: `is_expected_ipi_zone_name()` �������� ������ ������ �������� �����, � emergency/fallback ���� `ZONE_MAP_SPAN/3` �� ��������� �������� ����� `inpcb - socket`
- �����������:
    - zone name validation ���������� �� substring match �� `inpcb`
    - emergency/primed bounds ��������� �� ������� `ZONE_MAP_SPAN` (24 GB)
- ������������ syslog-��:
    - `zone name: site.struct inpcb` > ACCEPTED
    - `zone_info FOUND ... zone_map [0xffffffdcc181c000 - 0xffffffe2c181c000]`
    - `refcount bumped OK`

### Bug #225: panic `address X is a per-cpu allocation` �� ����� allproc scan
- Panic log: `panic-full-2026-03-31-184806.000.ips`
- �������:
    - `is_heap_ptr()` ������ �������� ����� ����� ������ ������� `zone_map`
    - � scan-� `allproc` ���������� ��������� �� VM-submap
    - VM-submap �������� per-CPU allocations; ������ �� ����� corrupted socket primitive �������� panic � `zalloc.c`
- �����������:
    - �������� `g_zone_safe_min`
    - `g_zone_safe_min = zone_map_min + ZONE_MAP_SPAN / 4`
    - `is_heap_ptr()` ������ ���������� safe lower bound � �� ������� VM/RO submaps heap-���������
- ��������� ������: `scan_range_for_allproc()` ����� skip-��� per-CPU ������ �� `ds_kread32_checked(first_q + PROC_PID_OFFSET)` � �� ������ ���������� �� `zone bound checks`

---

## ������ �������

| ������ | ���� | ������ | ������ |
|--------|------|--------|--------|
| **VFS race exploit** | darksword_core.m | ? ���������� (#213) | ������������� `target_object_size`, in-range offset clamp, retry `mach_vm_map` � `free_thread()` |
| **Kernel R/W** | darksword_core.m | ? ���������� | ICMPv6 socket corruption, 32-byte R/W |
| **Zone Discovery** | darksword_core.m | ? ���������� (#201/#211/#212/#214/#220/#224/#225) | �4MB scan, A12Z-aware floor, `zv_name` validation, emergency fallback, full 24GB bounds, safe heap lower bound ������ per-CPU zone allocs |
| **Kernel base discovery** | darksword_core.m | ? ���������� (#214) | primary fallback ����� `protosw->pr_input` �� original exploit |
| **Socket refcount leak** | darksword_core.m | ? ���������� (#221/#222/#223) | `so_count`/refcount: offset `0x24c` ��� iOS 17, 32-bit aligned read/write helpers, ��� ����� ��������� ���� |
| **set_target_kaddr log** | darksword_core.m | ? ���������� (#203) | BLOCKED misaligned: rate-limit 5 ������� (����: ������ �����, ���������) |
| **Process utilities** | utils.m | ? ���������� (#205/#206/#207/#216/#217-219/#225) | allproc: `scan_allproc_known_range()` �� `__DATA.__common`+`__DATA.__bss`; PAC-signed function ptr ��������� �������; kread health check; VM/per-CPU zone ptrs ������������� |
| **Kernel filesystem** | kfs.m | ? ���������� (#208) | 13 PAC ������, auto-detect layout, overwrite API guards, build-fixed; #208: find_rootvnode() ��������� NULL v_name (root vnode � XNU ������ v_name=NULL) |
| **Post-exploitation** | postexploit.m | ? ���������� (#209) | PPL-aware + AMFI global bypass + retry state reset; #209: ����� ��������� KC 32KB>256KB � ������ AMFI kext LC_FILESET_ENTRY ��������� � ������� fileset KC |
| **Trust cache** | trustcache.m | ? ���������� (#204/#210) | xref-����: ����� 300 kr64, ���� 256KB; #210: find_tc_head_by_scan() ��������� __PPLDATA + PPL skip 0x8000 ��� __DATA > panic �������� |
| **Bootstrap** | bootstrap.m | ? ���������� | tar.xz, disk check, uicache, SSH, cleanup, retry fixes, safe child-exit handling, honest sshd/Sileo/summary status, stale-download cleanup, honest prepare/extract/source status, verified OpenSSH apt fallback, shared SSH launch checks, env restore hygiene, directory-type validation, checked sources writes, honest partial trust status, required uicache trust, checked env restore, guarded config overrides, URL validation |
| **App UI** | app/main.m | ? ���������� | bgTask, signal safety, O(1) log, live runtime log bridge |

---

## ��� ������������ ���� (����������)

### 2026-03-31 (������ 2): ���� #202�204 � allproc + log spam + trustcache hang

| # | ��� | ���� | ������ | ����������� |
|---|-----|------|--------|-------------|
| 202 | allproc offset 0x93B348 �������� ������� ��� �bad� � allproc �� ��������� ������� | utils.m | ��������: post-exploit root=NO, unsandbox=NO, AMFI=NO | �������� ��� primary candidate � kernprocaddress(); ���� __DATA 16KB>256KB |
| 203 | `set_target_kaddr` BLOCKED misaligned ����������� ��� ������ | darksword_core.m | �������: ��� 829KB, ���������� ����� ������ �� ����� tc_init | static rate-limit: ������ 5 �������, ��������� ����� ����������� |
| 204 | `find_tc_head_by_string_xref` ����������� 4MB ��� ������ kr64-������� + �� ���������� __PPLDATA | trustcache.m | �������: ��������� ����� log-spam + PPL panic ���� | ����� 300 kr64, ���� 256KB, __PPLDATA ������������ |

### 2026-03-31 (������ 3): ���� #205�207 � ������-������ kernelcache 21D61

| # | ��� | ���� | ������ | ����������� |
|---|-----|------|--------|-------------|
| 205 | kbase+0x93B348 (`__DATA_CONST`, READ-ONLY) � �� allproc, PAC auth_rebase ptr � __TEXT_EXEC | utils.m | �������: 200 kr64 �������, ���������� | ����� ��� �������� |
| 206 | kbase+0x3198060 = `__PPLDATA`+0x60 (PPL-protected) > kernel panic ��� ������ | utils.m | ��������: panic ��� ������ ������� | ����� ��� �������� |
| 207 | `scan_for_allproc` �������� ���� � vmaddr=`__PPLDATA` + ������ 256KB �� �������� `__DATA.__common` | utils.m | ��������: panic ��� allproc �� ������ | PPL skip 0x8000 + scan_size `0x40000>0x80000` |

**������-������ (ipsw_analysis/offline_analysis_v2.py + v3.py):**
- kernelcache.macho, 53MB, arm64e fileset, iPad8,9 iOS 17.3.1 21D61
- Outer `__DATA` (kbase+0x3198000): ������ 0x8000 = `__PPLDATA`+`__KLDDATA` (PPL-protected!)
- Top candidates � `__DATA.__common`: `kbase+0x31fff30` (389 refs), `kbase+0x31f4188` (154 refs)
- PROC_PID_OFFSET = 0x60 ? ���������� �������-��������

---

### 2026-03-31 (������ 2): ���� #202�204 � allproc + log spam + trustcache hang
- `kernel_base: 0xfffffff028b9c000`, slide=`0x21b98000`
- `zone_map: 0xffffffdf2e7b4000�0xffffffe52e7b4000` (���������� ���������)
- `allproc NOT FOUND` > ���� post-exploit ���������� (4 errors)
- `trust cache initialized` � �� ���������� (���������� ��������� �� ���������� xref-�����)

---

### 2026-03-31: ��� #201 � Zone Metadata Kernel Panic (CRITICAL)

| # | ��� | ���� | ������ | ����������� |
|---|-----|------|--------|-------------|
| 201 | fallback zone bounds ���� ������ ������� 0xffffffd..., ������� Zone Metadata (0xffffffdd...) | darksword_core.m | ��������: kernel data abort ESR=0x96000007, FAR=0xffffffdd8e93dec0, panic ��� ������ ������� | ������ ������� �� ���� 4 ������: 0xffffffd... > 0xffffffe0... |

**������:** Zone map �� ���� ����: `0xffffffe2f7470000�0xffffffe8f7470000`. Zone Metadata: `0xffffffdd8d9fc...`.
fallback �������� `min = rw_pcb - 8GB ? 0xffffffdd...` ������ `? 0xffffffe2...`. ������ ������ ������ `0xffffffe0...`.

### ��������� ������-������ (80 ����� ������)

| # | ��� | ���� | ������ | ����������� |
|---|-----|------|--------|-------------|
| 84 | `is_kptr()` �������� canonical kernel ptr | kfs.m | rootvnode/ncache false negative | canonical top-16-bit check |
| 85 | typo � `is_heap_ptr()` range | trustcache.m | ����� heap-���������� �������� | fixed upper bound |
| 86 | `kfs_overwrite_file_bytes()` ����������� `MAP_PRIVATE` | kfs.m | ������ �� �������� � ���� | `MAP_SHARED` |
| 87 | `g_running` �� ����������� | bootstrap.m | bootstrap "already running" �������� | reset on early returns |
| 88 | `.zst` path ������� ����� retry | bootstrap.m | .xz ��� �������������� ��� .zst | reset preferred tar path |
| 89 | NSURLSession false-success | bootstrap.m | download �������� �������� ��� timeout/write fail | explicit timeout + write check |
| 90 | stale kfs state on retry | kfs.m | ������ rootvnode/ncache reused | reset cached state in `kfs_init()` |
| 91 | stale postexploit flags | postexploit.m | ������� sandbox step on retry | reset all `g_is_*` flags |
| 92 | stale trustcache state | trustcache.m | stale `g_tc_head` false success | reset scan state in `tc_init()` |
| 93 | stale `g_installed` status | bootstrap.m | UI ��� ����� ���������� installed | clear status at install start |
| 94 | auto-flush ����� CDHashes ��� failed inject | trustcache.m | pending trust entries silently lost | return `-1`, �� ������� ����� silently |
| 95 | trust path ������� ��� `tc_init()` | trustcache.m | ������ success ��� ��������� trust | early fail when `g_ready=false` |
| 96 | final directory flush ����������� result | trustcache.m | `trusted X files` even on failed inject | propagate `inject_entries()` failure |
| 97 | `procbyname()` ����������� `is_kptr` ��� proc walk | utils.m | false-positive proc ptr / launchd lookup instability | switch to `is_heap_ptr` |
| 98 | phys-map init failure �� ���������� | darksword_core.m | possible userspace crash/null write | bool return + caller guard |
| 99 | `IOSurfacePrefetchPages(NULL)` | darksword_core.m | crash on IOSurface alloc failure | null guard + safe release |
| 100 | `pe_v1/pe_v2` ������������ fail init | darksword_core.m | exploit path continued with invalid `pc_*` | early bail in callers |
| 101 | underflow �� `socket_ports_count - 1` | darksword_core.m | OOB read when spray failed early | zero-count guards + retry |
| 102 | zero-spray retry leak | darksword_core.m | userspace VM leak on repeated retries | deallocate mappings before continue |
| 103 | temp race fds ����� �������� `-1` | darksword_core.m | invalid `preadv/pwritev` path | fail fast in `init_target_file()` |
| 104 | `pe_init()` ����������� alloc/thread fail | darksword_core.m | exploit could run with no race thread | bool return + clean abort |
| 105 | invalid socket spray entries | darksword_core.m | poisoned spray set / bogus gencnt | validate port creation + syscall + gencnt |
| 106 | unchecked calloc in exploit paths | darksword_core.m | null deref under memory pressure | validate core buffers and arrays |
| 107 | unchecked `default_file_content` alloc | darksword_core.m | null write before exploit start | fail fast in `ds_run()` |
| 108 | infinite loops in A18 wired allocation | darksword_core.m | exploit hang under allocation failure | bound retries + clean abort |
| 109 | unchecked CF allocations in IOSurface helper | darksword_core.m | NULL CF object misuse | validate dictionary/number creation |
| 110 | invalid control/rw fds from `fileport_makefd` | darksword_core.m | exploit proceeded with fd < 0 | explicit fd checks |
| 111 | A18 search mapping leak on memory-entry fail | darksword_core.m | userspace VM leak on retry | deallocate mapping before break |
| 112 | deadlock on `pthread_join` after early return | darksword_core.m | exploit hang forever | abortable free-thread waits + signaled join |
| 113 | stale spray/IOSurface state across retries | darksword_core.m | gradual exhaustion of `MAX_GENCNT` / `MAX_MLOCK` | reset and release transient state in `ds_run()` |
| 114 | missing rw-socket partner bounds check | darksword_core.m | OOB read on `socket_ports[control+1]` | explicit index validation |
| 115 | unchecked temp dir path from `confstr` | darksword_core.m | UB in path construction | validate failure/truncation before `strcat` |
| 116 | ignored short write for race files | darksword_core.m | malformed exploit backing files | `create_target_file()` now returns success |
| 117 | pe_init path/buffer hygiene issues | darksword_core.m | stale/leaked thread buffer, weak path handling | resize `_NSGetExecutablePath`, tracked free |
| 118 | unbounded corruption retry loop | darksword_core.m | potential infinite hang | bound overwrite retries to 256 |
| 119 | unbounded OOB read retry helper | darksword_core.m | exploit could hang forever on persistent read failure | bound retries + bool result |
| 120 | leaked candidate control socket fd | darksword_core.m | FD exhaustion across repeated corruption retries | close all failed candidate fds |
| 121 | partial search-mapping allocation continued into exploit | darksword_core.m | invalid memory-entry setup on zero mapping slots | abort attempt and free partial mappings |
| 122 | race file descriptors leaked on init fail/reset | darksword_core.m | retry path could exhaust fd table | shared `close_target_fds()` cleanup |
| 123 | unbounded top-level retry loop in `pe_v1()` | darksword_core.m | app could hang forever on persistent exploit failure | bounded attempt budget |
| 124 | unbounded top-level retry loop in `pe_v2()` | darksword_core.m | A18 path could hang forever on persistent failure | bounded attempt budget |
| 125 | fallback name-offset probe accepted prefix match | utils.m | wrong `PROC_NAME_OFFSET` could poison proc name lookups | require exact nul-terminated match |
| 126 | `procbyname()` guessed hardcoded `PROC_NAME_OFFSET` | utils.m | false process-name matches/misses on discovery failure | fail cleanly instead of guessing |
| 127 | failed name-offset discovery poisoned global state | utils.m | later proc-name lookups could use unverified offset | no fallback guess on discovery fail |
| 128 | `procbyname()` did not self-recover `our_proc`/name offset | utils.m | false failure before proc cache was populated | call `ourproc()` and guard unknown name offset |
| 129 | `kfs` overwrite path could not recover task after proc-only fallback | kfs.m | file overwrite could stay broken after successful proc scan | fallback via `g_our_proc` / `ourtask()` |
| 130 | `postexploit` accepted broad canonical proc pointers | postexploit.m | stale/non-heap proc pointer could enter patch paths | validate proc with heap-range checks |
| 131 | `postexploit` accepted broad `ucred` candidates | postexploit.m | wrong heap object could be patched as credentials | validate `ucred` with heap-range checks |
| 132 | `kfs` accepted broad canonical vnode/ubc pointers | kfs.m | path/file-size logic could walk non-heap kernel objects | validate vnode/ubc with `is_heap_ptr()` |
| 133 | `kfs` lacked PID fallback for locating `launchd` | kfs.m | rootvnode discovery could fail when name offset discovery was unavailable | walk proc list for PID 1 |
| 134 | `postexploit` matched `ucred` on `uid` alone | postexploit.m | retry/root states could patch wrong heap object | validate full uid/gid identity + ngroups + label |
| 135 | `postexploit` accepted broad sandbox label pointers | postexploit.m | unsandbox path could write NULL into wrong kernel object | validate MAC label with `is_heap_ptr()` |
| 136 | `trustcache` inject path accepted broad canonical node/module pointers | trustcache.m | wrong kernel object could be treated as trust cache | validate node/module with `is_heap_ptr()` |
| 137 | `tc_trust_directory()` masked recursive/file trust failures | trustcache.m | false success count despite failed trust operations | propagate nested/file errors |
| 138 | `trustcache` used static heap ranges instead of runtime zone bounds | trustcache.m | false positives/negatives on different zone KASLR layouts | use `ds_get_zone_map_min/max()` |
| 139 | `tc_trust_directory()` followed symlink recursion | trustcache.m | recursive trust scan could loop forever | use `lstat()` and skip symlinks |
| 140 | `kfs_listdir()` did not validate outputs/allocation | kfs.m | userspace crash on NULL outputs or OOM | validate args and `calloc()` |
| 141 | `trustcache` silently truncated paths/commands | trustcache.m | wrong file/dir trust or broken deb extract/cleanup on long paths | check `snprintf()` truncation |
| 142 | `kfs resolve_path()` silently truncated long paths | kfs.m | wrong vnode resolution on long absolute paths | reject oversized path before copy |
| 143 | `kfs_listdir()` could return non-NUL-terminated names | kfs.m | callers could read past end of filename buffer | force `name[255] = 0` |
| 144 | critical bootstrap fail reduced global error count | darksword_exploit.m | final jailbreak summary could look healthier than reality | normalize negative bootstrap return to one failure |
| 145 | `run_cmd()` trusted unchecked `waitpid()` status | bootstrap.m | bootstrap commands could be reported with bogus success/exit state | retry/check `waitpid()`, log abnormal exits |
| 146 | `bootstrap_install_openssh()` reported false SSH success | bootstrap.m | UI/logs could claim SSH is ready when no host keys or failed `sshd` launch existed | verify keys and `sshd` exit status |
| 147 | OpenSSH step failure was excluded from bootstrap error count | bootstrap.m | `/var/jb` could be marked complete without working SSH | count Step 6 failure in `errors` |
| 148 | `dpkg --configure -a` failure did not affect final install status | bootstrap.m | package database could remain broken while bootstrap showed complete | count Step 7 failure in `errors` |
| 149 | `bootstrap_setup_sources()` result was ignored | bootstrap.m | apt repo configuration could be missing while bootstrap showed complete | count Step 8 failure in `errors` |
| 150 | `bootstrap_install_sileo()` did not verify `Sileo.app` exists after install | bootstrap.m | UI/logs could claim Sileo is installed with missing app bundle | verify app path after `dpkg -i` |
| 151 | Sileo trust failures were ignored | bootstrap.m | app could remain unlaunchable while bootstrap reported success | require at least one successful trust path |
| 152 | `uicache` failure was logged as success | bootstrap.m | Home Screen registration could silently fail while logs claimed completion | check `uicache` exit status |
| 153 | failed downloads left stale partial destination files | bootstrap.m | next retry could reuse truncated payloads as if fully downloaded | unlink destination before/after failed download |
| 154 | bootstrap archive cache accepted any existing file | bootstrap.m | partial `.tar.xz/.tar.zst` could skip re-download and fail extraction repeatedly | require regular file + minimum size |
| 155 | `Sileo.deb` cache accepted any existing file | bootstrap.m | partial package could be reused on next install attempt | require minimum size before reusing |
| 156 | rootless subdirectory creation failures were masked | bootstrap.m | later bootstrap steps could fail far away from real mkdir root cause | fail if any required subdir creation fails |
| 157 | temp bootstrap directory creation result was ignored | bootstrap.m | download/extract path could continue without usable temp dir | check `mkdir(g_jb_tmp)` result |
| 158 | extraction succeeded without verified `dpkg` | bootstrap.m | broken bootstrap contents could pass Step 3 and fail later | require executable `dpkg` after extract |
| 159 | `bootstrap_setup_sources()` ignored failed `havoc.sources` write | bootstrap.m | Step 8 could report success with incomplete repo config | fail when second sources file cannot be written |
| 160 | `tc_trust_deb()` trusted unchecked raw `waitpid()` status | trustcache.m | deb extract/cleanup could misreport child failure or signal exit | use checked `EINTR`-safe child wait helper |
| 161 | OpenSSH apt fallback masked failed install | bootstrap.m | Step 6 could report success even when `apt install` failed | return error on non-zero `apt` exit |
| 162 | OpenSSH apt fallback did not verify `sshd` and trust results | bootstrap.m | SSH could still be unusable after reported apt success | require executable `sshd` and successful trust |
| 163 | `tc_trust_deb()` accepted invalid NULL/empty path | trustcache.m | API could hit UB or meaningless shell invocation | reject invalid deb path early |
| 164 | `tc_trust_deb()` used unquoted shell paths | trustcache.m | paths with spaces/metacharacters could fail extraction | shell-quote temp/deb paths |
| 165 | OpenSSH apt fallback skipped keygen/daemon launch | bootstrap.m | SSH could be reported installed but not actually running | reuse shared post-install SSH launch path |
| 166 | `bootstrap_install_openssh()` ignored failed trust of `sshd` | bootstrap.m | daemon launch path could continue with untrusted binary | require successful `tc_trust_file(sshd)` |
| 167 | `bootstrap_install_openssh()` ignored failed trust of `ssh-keygen` | bootstrap.m | host-key generation could continue after trust failure with misleading logs | require successful `tc_trust_file(keygen)` |
| 168 | creation of `/var/jb/etc/ssh` result was ignored | bootstrap.m | keygen could fail later on missing directory while root cause stayed hidden | check `mkdir(ssh_dir)` result |
| 169 | bootstrap mutated env before re-entrancy guard | bootstrap.m | skipped bootstrap call could still poison process environment | move guard before `setenv()` |
| 170 | bootstrap env setup ignored PATH truncation / `setenv()` failures | bootstrap.m | child tools could run with broken env and fail indirectly | validate `snprintf()` and `setenv()` |
| 171 | bootstrap did not restore `PATH/DPKG_ROOT` on exit | bootstrap.m | retries/later phases could inherit stale jailbreak env | save and restore env on all exits |
| 172 | concurrent bootstrap call returned false success | bootstrap.m | caller could mark skipped re-entrant invocation as successful install | return error when `g_running=true` |
| 173 | `/var/jb` accepted non-directory `EEXIST` as success | bootstrap.m | bootstrap could continue with root path blocked by regular file | verify existing path is directory |
| 174 | required subdirs/temp dir accepted non-directory `EEXIST` | bootstrap.m | later failures could occur far from actual path collision | require directory type for all mandatory dirs |
| 175 | `/var/jb/etc/ssh` accepted non-directory `EEXIST` | bootstrap.m | OpenSSH setup could fail later with hidden root cause | validate `ssh_dir` as directory |
| 176 | `procursus.sources` write/flush result was ignored | bootstrap.m | Step 8 could report success with incomplete main repo file | validate `fprintf()` and `fclose()` |
| 177 | `havoc.sources` write/flush result was ignored | bootstrap.m | Step 8 could report success with incomplete secondary repo file | validate `fprintf()` and `fclose()` |
| 178 | `bootstrap_trust_binaries()` masked partial trust failures | bootstrap.m | Step 4 could report success despite failed directory trust | fail if any trust directory returns error |
| 179 | `tc_trust_file()` accepted invalid NULL/empty path | trustcache.m | public API could continue with meaningless invalid input | reject invalid file path early |
| 180 | `tc_trust_directory()` accepted invalid NULL/empty path | trustcache.m | recursive trust API could start from invalid input | reject invalid directory path early |
| 181 | `kfs_overwrite_file()` accepted invalid NULL/empty source/target paths | kfs.m | overwrite API could continue with meaningless input and unclear root cause | reject invalid paths early |
| 182 | KFS overwrite paths ignored `lseek()` failures | kfs.m | invalid file sizes could reach `mmap()` and later overwrite logic | fail on size-query errors before mapping |
| 183 | `kfs_overwrite_file_bytes()` accepted negative offsets / NULL data and used overflow-prone bounds math | kfs.m | byte overwrite API could write before mapping or crash on invalid input | validate offset/data and use overflow-safe bounds check |
| 184 | `tc_trust_deb()` reused stale temporary extraction directory | trustcache.m | repeated `.deb` trust in same process could mix old extracted contents into new result | pre-clean temp dir before extraction |
| 185 | `tc_trust_deb()` masked failed temp-dir cleanup | trustcache.m | stale extracted files could poison later trust calls despite reported success | make cleanup mandatory on success/failure paths |
| 186 | `bootstrap_install_sileo()` ignored failed trust of `uicache` | bootstrap.m | Sileo registration step could continue on untrusted helper binary with false success logs | require successful `tc_trust_file(uicache)` |
| 187 | `bootstrap_install()` ignored failed restore of `PATH/DPKG_ROOT` and could log false `COMPLETE` | bootstrap.m | poisoned process environment could survive a supposedly successful bootstrap run | check restore calls and compute final summary after restore |
| 188 | `bootstrap_set_procursus_url()` accepted invalid NULL/empty override | bootstrap.m | bootstrap download config could be poisoned before next retry/install | restore default Procursus URL on invalid input |
| 189 | `bootstrap_set_sileo_url()` accepted invalid NULL/empty override | bootstrap.m | Sileo download config could remain broken across retries | restore default Sileo URL on invalid input |
| 190 | `tc_trust_deb()` accepted non-regular path input | trustcache.m | shell extraction could run on invalid filesystem object and hide the real root cause | require regular file before extraction |
| 191 | `tc_trust_deb()` accepted obviously undersized `.deb` files | trustcache.m | truncated package input reached late extract failure instead of early API reject | reject too-small `.deb` before extraction |
| 192 | `tc_add_cdhash()` accepted calls before trustcache was ready | trustcache.m | caller could believe cdhash was queued despite uninitialized trustcache state | reject add requests when `g_ready=false` |
| 193 | `tc_add_cdhash()` accepted NULL cdhash input | trustcache.m | public API could crash on `memcpy()` with invalid caller input | reject NULL cdhash early |
| 194 | `tc_init()` left stale pending CDHashes in `g_nentries` across retries | trustcache.m | next trustcache session could inject old buffered hashes alongside new ones | reset pending entry count on every init |
| 195 | `bootstrap_set_procursus_url()` accepted malformed non-HTTP override | bootstrap.m | download config could fail late on invalid scheme/path string | require `http(s)` URL or restore default |
| 196 | `bootstrap_set_sileo_url()` accepted malformed non-HTTP override | bootstrap.m | Sileo retry/install config could stay poisoned by invalid URL string | require `http(s)` URL or restore default |
| 197 | `download_file()` accepted malformed URL into `NSURLSession` fallback | bootstrap.m | fallback networking path could continue with invalid URL state instead of failing early | validate URL/destination and `NSURL` conversion |
| 198 | app UI did not receive full runtime log stream | app/main.m, darksword_exploit.m | user could not see live exploit/bootstrap progress in the app | add frontend log bridge and forward module logs into `UITextView` |
| 199 | `kfs.m` failed to compile due to global declaration order | kfs.m | full IPA rebuild was blocked by `g_our_proc` undeclared at first use | move cached proc globals above `get_our_task()` |
| 200 | `bootstrap.m` failed to compile after URL validation helper was added | bootstrap.m | IPA rebuild was blocked by implicit declaration of `is_http_url_string()` | add forward declaration before config setters |
| 201 | `spray_socket()` broke self `proc_pidfdinfo` lookup during socket spray | darksword_core.m | exploit retried forever with `proc_info syscall failed` and zero sprayed sockets | query `proc_info` on live fd, require `ret >= 0`, validate short result, then convert fd to fileport |
| 202 | `spray_socket()` still used `PROC_INFO_CALL_PIDFILEPORTINFO` after switching to live fd | darksword_core.m | fresh runs still failed with `errno=22 (Invalid argument)` on the first sprayed socket | switch syscall selector from pidfileportinfo (`6`) to pidfdinfo (`3`) for live fd queries |

### ������ 1: Kernel panics (5 ����)

| # | ������ | �������� | ����������� |
|---|--------|----------|-------------|
| 1 | Boot A: copy_validate | Userspace addr � OOB write | Bounds check |
| 2 | Boot B: zone meta ���� | FAR � metadata ���� zone_map | Zone discovery �4MB |
| 3 | Boot C: zone meta ���� | FAR � metadata ���� zone_map | Fallback SPAN/3 (~8GB) |
| 4 | Boot D: zone meta ���� | ������ boot layout | set_target_kaddr bounds |
| 5 | Boot E: zone meta ���� | ourproc() is_kptr vs metadata | is_heap_ptr ������ (5 ����) |

### ������ 2: Kernelcache analysis

| # | ��� | ���� | ���� | ����� |
|---|-----|------|------|-------|
| 6 | vmaddr KASLR slide | utils.m | Unslid vmaddr � scan | 2-pass � slide |
| 7 | PROC_PID_OFFSET | utils.m | 0x28 | 0x60 (XNU struct proc) |
| 8 | PROC_UID_OFFSET | utils.m | 0x30 | 0x2C (XNU struct proc) |
| 9 | PROC_GID_OFFSET | utils.m | 0x34 | 0x30 (XNU struct proc) |
| 10 | 4 wrong allproc offsets | utils.m | Hardcoded | �������, kernprocaddress() rewrite |

### ������ 3: XNU source deep verification (�������)

| # | ��� | ���� | ���� | ����� | ������ |
|---|-----|------|------|-------|--------|
| 11 | **OV_TYPE** | kfs.m | 0x71 | **0x70** | rootvnode ������� �� ��������� |
| 12 | **ONC_NEXT** | kfs.m | 0x00 | **0x10** (nc_child) | ����� �� ������ linked list |
| 13 | **ONC_VP** | kfs.m | static 0x50 | dynamic auto-detect | smrq_link size varies |
| 14 | **ONC_NAME** | kfs.m | static 0x60 | dynamic auto-detect | �� �� |

### ������ 3: ����� features

| # | ���� | ���� | ��� ������ |
|---|------|------|-----------|
| 15 | Trust cache scanning | trustcache.m | ����� return -1 ���� + string xref fallback |
| 16 | AMFI global bypass | postexploit.m | amfi_get_out_of_my_way + cs_enforcement_disable + proc_enforce + vnode_enforce |
| 17 | PPL-aware platformize | postexploit.m | Scan proc/task struct �� shadow csflags |
| 18 | CS_DEBUGGED by default | postexploit.m | �������� �� ���� csflags patches |

---

## ���������������� kernel offsets (XNU xnu-10002.1.13)

### struct proc (utils.m)
| ���� | Offset | �������� | ������ |
|------|--------|----------|--------|
| p_list.le_next | +0x08 | scan | ? |
| p_pid | +0x60 | XNU source | ? FIXED (���� 0x28) |
| p_uid | +0x2C | XNU source | ? FIXED (���� 0x30) |
| p_gid | +0x30 | XNU source | ? FIXED (���� 0x34) |
| proc_ro | +0x18 | XNU source | ? |
| p_textvp | scan 0x80-0x800 | dynamic | ? safe |

### struct inpcb (darksword_core.m) � ��� �����
| ���� | Offset | ������ |
|------|--------|--------|
| inp_list.le_next | +0x20 | ? |
| inp_list.le_prev | +0x28 | ? |
| inp_pcbinfo | +0x38 | ? |
| inp_socket | +0x40 | ? |
| inp_gencnt | +0x78 | ? |
| icmp6filt | +0x148 | ? empirically |
| ipi_zone | pcbinfo+0x68 | ? |

### struct socket (darksword_core.m)
| ���� | Offset | ������ |
|------|--------|--------|
| so_count | +0x24c (iOS 17+) / +0x228 (iOS ?16) | ? FIXED (#221, ���� 0x228 only) |
| so_proto | +0x18 | ? |

### struct vnode (kfs.m) � 1 ���������
| ���� | Offset | ������ |
|------|--------|--------|
| v_type (uint16_t) | +0x70 | ? FIXED (���� 0x71) |
| v_ncchildren | +0x50 | ? |
| v_name | +0xB8 | ? |
| v_parent | +0xC0 | ? |
| v_mount | +0xD0 | ? |

### struct namecache (kfs.m) � 3 ����������
| ���� | Offset | ������ |
|------|--------|--------|
| nc_child.tqe_next | +0x10 | ? FIXED (���� 0x00 = nc_entry) |
| nc_vp | auto 0x48/0x50 | ? FIXED (���� static 0x50) |
| nc_name | auto 0x58/0x60 | ? FIXED (���� static 0x60) |

### vm_map_entry (kfs.m) � ��� �����
| ���� | Offset | ������ |
|------|--------|--------|
| links.next | +0x08 | ? |
| links.start | +0x10 | ? |
| links.end | +0x18 | ? |
| flags | +0x48 | ? |

### ucred (postexploit.m) � ��� �����
| ���� | Offset | ������ |
|------|--------|--------|
| cr_uid | +0x18 | ? |
| cr_ruid | +0x1C | ? |
| cr_svuid | +0x20 | ? |
| cr_groups[0] | +0x28 | ? |
| cr_rgid | +0x68 | ? |
| cr_svgid | +0x6C | ? |
| cr_label | +0x78 | ? |

---

## ������� ����������� (jailbreak_full)

```
Phase 1: ds_run()
    +-- IOSurface physical mapping
    +-- VFS race (pwritev vs mach_vm_map)
    +-- Socket spray (22K ICMPv6)
    +-- PCB corruption > KRW
    +-- Zone discovery �4MB
    +-- kernel_base scan (0xFEEDFACF)
    L-- Socket refcount leak

Phase 2: init_offsets()
    L-- Dynamic proc offset discovery

Phase 3: kfs_init()
    +-- find_rootvnode() < ������ �������� (OV_TYPE fixed)
    +-- verify_ncache() + auto-detect nc_vp/nc_name
    L-- Path resolution via ncache

Phase 4: postexploit_run()
    +-- [1/4] Credentials: ucred>uid=0, gid=0
    +-- [2/4] Sandbox: label>slot[0] = NULL
    +-- [3/4] Platformize: csflags |= CS_PLATFORM_BINARY | CS_DEBUGGED
    L-- [4/4] AMFI:
        +-- amfi_get_out_of_my_way = 1
        +-- cs_enforcement_disable = 1
        +-- proc_enforce = 0
        L-- vnode_enforce = 0

Phase 5: tc_init()
    +-- Segment scan for TC head
    +-- String xref fallback
    L-- CDHash injection into existing module

Phase 6: bootstrap_install()
    +-- /var/jb directory creation
    +-- Procursus bootstrap download + extract
    +-- Trust all binaries via TC
    +-- Sileo + OpenSSH install
    L-- apt sources config
```

---

## Build + Install

```bash
# ������ + �������:
wsl -d Ubuntu -e bash -c "cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword && bash build_sign_install.sh"

# ���������:
.\ideviceinstaller.exe -i Dopamine_darksword\build_app\DarkSword.ipa

# ���� � �������� �������:
.\idevicesyslog.exe --quiet

# Crash reports:
.\idevicecrashreport.exe -k -e Dopamine_darksword\doc\crashes_next
```

---

## ��� ��������� ��� ��������� ������� (����� Bug #221 fix)

1. **Exploit** > kernel R/W ? (������������ ������ 12)
2. **Zone bounds** > primed �8GB ? (������������ ������ 12, Bug #220)
3. **kernel_base** > via protosw>pr_input ? (������������ ������ 12)
4. **Socket refcount** > `so_count` offset 0x24c ?? **(������� ������ ����!)**
5. **ourproc() / allproc** > `scan_allproc_known_range()` ?? **(��� �� �����������)**
6. **rootvnode** > OV_TYPE=0x70, nc_child=0x10 (��� ����������, �� ����������)
7. **root** > ucred patching (writable ����� kwrite)
8. **sandbox** > label NULL
9. **AMFI** > ���������� bypass ����� kernel variables
10. **Trust cache** > scan + injection
11. **Bootstrap** > ������� �� root + unsandbox + TC

### ������������� ��������:
- **so_count 0x24c �� ���������� runtime ��� �������� boot** > ���������� �������� fallback
- **allproc scan �� ���������� ����� refactor** > `scan_allproc_known_range()` ����� ����������� debug
- **PPL ��������� proc_ro csflags** > AMFI global bypass ������� �������������
- **Trust cache head �� ������** > string xref fallback + AMFI global = CS off
- **ucred � PPL ����** > scan �� writable uid location
- **Kernel vars � __DATA_CONST** > ���� PPL ��������, TC + root minimum

---

## ����� �������

| ���� | ����� | �������� |
|------|-------|----------|
| darksword_core.m | ~2031 | VFS race exploit, KRW, zone discovery, protosw fallback, zone priming, dynamic so_count |
| darksword_exploit.m | ~298 | Entry point (jailbreak_full + Dopamine plugin) |
| utils.m | ~1017 | proc utilities, offset discovery, scan_allproc_known_range (__DATA.__common + __bss) |
| kfs.m | ~701 | Kernel FS: rootvnode, ncache, vm_map, dir listing |
| postexploit.m | ~952 | root, unsandbox, platformize, AMFI global bypass (KASLR slide fixed) |
| trustcache.m | ~883 | TC scan + CDHash injection + retry-safe init + no false success |
| bootstrap.m | ~698 | Procursus + Sileo + SSH + retry-safe download/install |
| filelog.m | ~100 | File-based logging for crash analysis |
| app/main.m | ~260 | UIKit app: bgTask, signal-safe, O(1) log |

## Build

| �������� | �������� |
|----------|---------|
| IPA | DarkSword_signed.ipa (build_app.sh + zsign_ipa.sh) |
| ������ | ~693 KB |
| Arch | arm64 (��������� � arm64e) |
| BundleID | soft.ru.app |
| TeamId | V945SAD4LF |
| Cert | Apple Development: Vladimir Polevoy (NN49GWDWRL) |
| Build | Build 62 hotfix source state (Bug #298-#334 + #378, retest pending) |
| �������� | KRW  kbase  allproc (Bug #334: PROC_PID_OFFSET=0xd8 + 0x31C3000 first)  ourproc walk  DarkSword expected |

## ���������� known issues (������ ���������)

- `is_kptr()` ����� `0xffff000000000000` ������� ������� (������ ���� `0xfffffff000000000`)
- 16KB �������� ����� `page[0x4000]` � `scan_range_for_allproc` � �������� �� ���� (������ ��������� �� 256KB)
- allproc ADRP offset `0x31FFF30` �������� �� iOS 17.3.1 21D61 A12Z � ��� ������ build-��������� nearby scan �0x1000 + fallback __DATA.__common scan
- ��� ��������������� ����������� �������� allproc ��� ������ iOS/kernelcache
- ��� SHA256 ����������� ���������� bootstrap
- `/var/jb` � ������� ����������, �� symlink (������������ �� Dopamine)
- `filelog_close()` �� ���������� � ���������� ������ (������ terminate/crash)
- Procursus URL `/bootstraps/2000/` ID ����� ����������� ����������
- `kreadbuf`/`kwritebuf` wrappers ������ ���������� 0 (Dopamine integration only)
- `create_physically_contiguous_mapping` �� ��������� ��������� � caller
- ��� cycle detection >1 � allproc traversal

## Session Update (2026-04-03 17:29)

- False direct heads `0x3213678` / `0x3213680` больше не принимаются. Эта часть hotfix сработала.
- KRW поднимается, и inner DATA scan находит новый BSD-style candidate `0xffffffe2dfb2fe80` с `list_off=0x0`, `pid_off=0x60`, `next_ff=0x8`, `score=23`.
- Новый crash происходит раньше старого zone-scan path: syslog обрывается сразу после `proc list layout ... -> FOUND!`, ещё до `[ourproc] kernprocaddress() returned ...`.
- Panic log `panic-full-2026-04-03-172929.0002.ips` показывает `Kernel data abort`; panicked task: `DarkSword` (pid 538).
- Root cause: layout discovery уже выбрал `pid_off=0x60`, но глобальный `PROC_PID_OFFSET` оставался `0xd8`, и follow-up validation пере-декодировала найденную цепочку неверно.
- Source fix applied in `darksword/utils.m`: accepted layout now commits `best_pid_off`, and proc-chain validation uses the explicit `pid_off` it is validating.
- Rebuild/retest from this terminal session was not re-run because the current VS Code shell does not expose a configured WSL distro; source patch is ready for the next device retest.

