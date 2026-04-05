# Файлы  Подробное описание каждого исходника

> Для ИИ: при редактировании любого файла — сверяйся с этим описанием
> Обновлено: 2026-03-31 (сессия 12: Bug #220–#221, 221 баг исправлен)

## darksword/darksword_core.m (~2031 строк) — ЯДРО ЭКСПЛОЙТА

**Описание:** VFS race condition exploit → физический OOB → ICMPv6 corruption → kernel R/W → Zone Discovery → Zone Priming → Dynamic so_count.

**Глобальные переменные:**
- `our_proc` (~L125)  наш proc в ядре (пока 0x0)
- `kernproc_addr` (~L126)  адрес kernproc
- `rw_socket_pcb` (~L127)  PCB corrupted сокета (R/W primitive)
- `control_socket_pcb` (~L128)  PCB control сокета (для поиска kernel structures)
- `kernel_base` (~L130)  найденный kbase (с KASLR slide)
- `kernel_slide` (~L131)  KASLR slide
- `g_zone_map_min`  нижняя граница zone map (от discover_zone_boundaries_raw)
- `g_zone_map_max`  верхняя граница zone map

**Ключевые функции:**

### Exploit primitives:
- `pe_init()`  инициализация VFS race
- `free_thread()`  background thread для race condition
- `pe_v1()`  основной exploit: socket spray + VFS race + ICMPv6 corruption
- `find_and_corrupt_socket()`  поиск corrupted PCB через physical OOB read

### Kernel R/W:
- `set_target_kaddr(uint64_t addr)` -> **bool**  устанавливает целевой kernel адрес для R/W. Возвращает `false` если адрес заблокирован (вне zone map и не kernel text). Проверяет зону динамически если g_zone_map_min/max установлены.
- `early_kread(uint64_t kaddr, void *buf, size_t len)`  чтение kernel memory через getsockopt
- `early_kread_checked(uint64_t kaddr, void *buf, size_t len)` -> **bool**  как early_kread, но проверяет return set_target_kaddr. При блокировке обнуляет буфер и возвращает false.
- `early_kwrite32bytes(uint64_t kaddr, void *buf)`  запись 32 байт через setsockopt. Проверяет set_target_kaddr return.
- `early_kread64(uint64_t kaddr)` -> uint64_t  helper: читает 8 байт
- `early_kwrite64(uint64_t kaddr, uint64_t value)`  helper: пишет 8 байт

### Zone Discovery:
- `discover_zone_boundaries_raw(uint64_t ipi_zone_addr)` — сканирует **±4MB** вокруг ipi_zone в __DATA_CONST ядра. Ищет {min, max} где max-min == 0x600000000 (24GB). При неудаче: fallback bounds pcb ± ZONE_MAP_SPAN/3 (~8 GB). EMERGENCY bounds при отсутствии ipi_zone.
- `ds_get_zone_map_min()` → uint64_t — API для других модулей (utils.m, kfs.m)
- `ds_get_zone_map_max()` → uint64_t — API для других модулей

> **Kernelcache verified:** ±4MB = 8 MB total window vs kernel __DATA_CONST 1 MB = **8× safety margin** ✓

### Socket management:
- `krw_sockets_leak_forever()` — намеренный leak сокетов. `so_count` offset динамический: `0x24c` (iOS 17+), `0x228` (≤16). Санитарная проверка refcount перед bump. Zone bounds валидация.

### Kernel discovery:
- Поиск kernel_base через ipi_zone -> vz_name -> backward scan для 0xFEEDFACF

**Вызов zone discovery:** ПЕРЕД `krw_sockets_leak_forever()`, сразу после чтения ipi_zone.

---

## darksword/darksword_core.h  Header

**Публичный API:**
- `void pe_init()`, `void pe_v1()`
- `bool set_target_kaddr(uint64_t addr)`  BOOL return!
- `void early_kread(...)`, `bool early_kread_checked(...)`, `uint64_t early_kread64(...)`
- `void early_kwrite32bytes(...)`, `void early_kwrite64(...)`
- `uint64_t ds_get_zone_map_min(void)`  NEW
- `uint64_t ds_get_zone_map_max(void)`  NEW

---

## darksword/utils.m (~1017 строк) — УТИЛИТЫ ЯДРА

**Описание:** Поиск процессов, PAC strip, scan_allproc_known_range.

**Ключевые функции:**
- `is_heap_ptr(uint64_t addr)` → bool — ДИНАМИЧЕСКИЙ! Использует ds_get_zone_map_min/max(). Fallback: `>= 0xffffffd000000000 && < 0xfffffff000000000`.
- `pac_strip(uint64_t ptr)` → uint64_t — убирает PAC tag (T1SZ_BOOT=0x19, arm64e A12+)
- `kernprocaddress()` → uint64_t — текущая безопасная цепочка: runtime cache → persisted cache → `scan_allproc_known_range()` (`__DATA.__common` + `__DATA.__bss`)
- `scan_allproc_known_range(kbase)` → uint64_t — сканирует `__DATA.__common` (kbase+0x31c3000..0x321b000) и `__DATA.__bss` (kbase+0x321b000..0x324b000), офлайн-верифицировано, нет PPL overlap
- `ourproc()` → uint64_t — ищет наш proc по pid в allproc linked list. Все 5 pointer проверок через `is_heap_ptr()` (не `is_kptr`!). Предварительный **kread health check** (magic `0xFEEDFACF`).

---

## darksword/postexploit.m (~408 строк)  POST-EXPLOITATION

**Описание:** Root, sandbox escape, platformize, AMFI bypass.

**Ключевые функции:**
- `postexploit(uint64_t our_proc)`  главная: root + sandbox + platformize + AMFI
- Читает proc -> proc_ro -> ucred, записывает uid=0, gid=0
- Патчит cr_label для sandbox escape
- Устанавливает CS_PLATFORM_BINARY | CS_DEBUGGED | CS_GET_TASK_ALLOW

---

## darksword/kfs.m (~628 строк)  KERNEL FILE SYSTEM

**Описание:** Файловые операции через kernel r/w (чтение/запись файлов в sandbox escape).

**Ключевые функции:**
- `is_heap_ptr(uint64_t addr)` -> bool  ДИНАМИЧЕСКИЙ! Использует ds_get_zone_map_min/max(). Fallback: is_pac_tagged + `< 0xfffffff000000000`.
- `kfs_init()`  инициализация: находит vnode нашего процесса
- `kfs_read_file(...)`  чтение файла через kernel vnode ops
- `kfs_write_file(...)`  запись файла через kernel vnode ops
- `kfs_overwrite_file(...)`  перезапись файла

---

## darksword/trustcache.m (~390 строк)  TRUST CACHE

**Описание:** Инъекция CDHash в ядерный trust cache для подписи бинарников.

**Ключевые функции:**
- `trustcache_inject()`  главная: находит trust cache module в __DATA_CONST, добавляет CDHash
- Парсит CodeDirectory из LC_CODE_SIGNATURE
- SHA-256 хеш -> 20 байт CDHash

---

## darksword/bootstrap.m (~320 строк)  BOOTSTRAP

**Описание:** Скачивание и установка jailbreak environment (Procursus, Sileo, SSH).

**Ключевые функции:**
- `bootstrap_install()`  скачивает .tar.zst, распаковывает в /var/jb/
- `install_deb(path)`  устанавливает .deb через dpkg
- `setup_repos()`  настраивает apt sources

---

## darksword/filelog.m (~50 строк)  ФАЙЛОВЫЙ ЛОГ

**Описание:** Пишет лог в Documents/darksword_log.txt.

**Функции:**
- `filelog(NSString *fmt, ...)`  printf-like запись в файл
- `filelog_init()`  очистка/создание лог-файла

---

## darksword/main.m (~60 строк)  ENTRY POINT

**Описание:** Entry point iOS приложения (UIApplicationMain).
Вызывает pe_init -> pe_v1 при lifecycle events.

---

## build_sign_install.sh  СКРИПТ СБОРКИ

**Описание:** Компилирует, подписывает (zsign), создаёт .ipa.

**Команды:**
1. `clang` с iPhoneOS16.5 SDK, `-arch arm64`, `-mios-version-min=16.0`
2. `zsign` с сертификатом и provisioning profile
3. Создаёт `build_app/DarkSword_signed.ipa`

---

## doc/  ДОКУМЕНТАЦИЯ

| Файл | Содержание |
|------|------------|
| CURRENT_STATUS.md | Текущий статус, блокирующий баг, zone layouts, что работает/нет |
| BUGS_AND_FIXES.md | 26 багов с историей, причинами и исправлениями |
| EXPLOIT_FLOW.md | Детальное описание 7 фаз exploit chain |
| FILES_REFERENCE.md | Этот файл  описание каждого исходника |
| PROJECT_MAP.md | Карта проекта, устройство, offsets, сборка |
| BUILD_SIGN_INSTALL.md | Инструкция сборки |
| crashes3-8/ | Краш-репорты с устройства (5 паник A-E, FIXED) |
| syslog_live.txt | Последний syslog |

---

## ipsw_analysis/ — ОФФЛАЙН АНАЛИЗ KERNELCACHE (NEW)

**Описание:** Результаты оффлайн-анализа kernelcache скачанного из IPSW (2026-03-30).

| Файл | Описание |
|------|----------|
| kernelcache.macho | Декомпрессированный Mach-O fileset (54,870,016 bytes / 52.33 MB) |
| kernelcache.release.ipad8b | IM4P-wrapped kernelcache (17,057,597 bytes) |
| __DATA_CONST.bin | Raw __DATA_CONST segment (4,964,352 bytes / 4.73 MB) |
| OFFSET_ANALYSIS.md | Верификация оффсетов из DarkSword |

**UUID:** D1B6EFB8-4A11-AE7D-CDF3-BC591F014E72 — совпадает с panic logs ✓

**Memory Layout (unslid):**
| Segment | Start | End | Size |
|---------|-------|-----|------|
| __TEXT | `0xfffffff007004000` | `0xfffffff00700c000` | 32 KB |
| __PRELINK_TEXT | `0xfffffff00700c000` | `0xfffffff007890000` | 8.52 MB |
| __DATA_CONST | `0xfffffff007890000` | `0xfffffff007d4c000` | 4.73 MB |
| __TEXT_EXEC | `0xfffffff007d4c000` | `0xfffffff00a008000` | 34.73 MB |
| __DATA | `0xfffffff00a19c000` | `0xfffffff00a3dc000` | 2.25 MB |
