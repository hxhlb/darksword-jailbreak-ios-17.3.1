# DarkSword Jailbreak — iOS 17.3.1 / iPad8,9

## Описание

Standalone jailbreak для iPad Pro 11" (A12Z Bionic, arm64e) на базе
VFS race + ICMPv6 socket corruption exploit (CVE-2025-43520).
Основан на [rooootdev/lara](https://github.com/rooootdev/lara) — полностью
портированный + **сотни задокументированных исправлений/багов** + **4 новых модуля**.

## Целевое устройство
- **iPad8,9** (iPad Pro 11" 2nd gen, A12Z Bionic, arm64e)
- **iOS 17.3.1** (build 21D61)

## Текущий статус

Проект активно отлаживается именно под **iPad8,9 / iOS 17.3.1 / 21D61**.

На текущем этапе:
- ✅ ранний exploit и kernel R/W поднимаются;
- ✅ `kernproc` для 21D61 стабильно находится через curated/XPF path;
- ✅ собран воспроизводимый patch-diff bootstrap для пары `21D61 -> 21E219`;
- ✅ side-by-side socket diff снял ложный `connectx` secondary hit и сузил 21D61 default shortlist;
- ⚠️ standalone flow **ещё не доведён до рабочего конца**;
- ⚠️ главный blocker сейчас — надёжно получить **наш `proc` / `ourproc()`** без panic и без ложного fallback в kernel-only PID=0 chain;
- ⚠️ свежий `14:58` run сузил точку отказа: `socket/tro` path теперь чаще доходит до `tro`, но всё ещё ломается до `proc/pid` proof, а panic остаётся в том же `struct inpcb` family.

### Что сейчас не получается

Для точного target `21D61` пока **не решён финальный functional blocker**:

- `socket/tro` fast path пока не даёт validated `self proc`; текущий sub-blocker — `tro` pointer/read gate до `proc/pid` proof;
- fallback через `allproc` / `ourproc()` всё ещё может застревать в kernel-only PID=0 chain;
- старый wide seed-scan (`64MB`, phase 4) на этом build вызывал zone-bound panic, поэтому теперь отключён по умолчанию;
- из-за этого standalone app пока **не гарантирует успешный выход к root/unsandbox/bootstrap** на данном устройстве.

Итого: проект находится в состоянии **"KRW есть, но стабильного `ourproc()` для 21D61 ещё нет"**.

## Что работает (после последних исправлений)

| Фаза | Статус | Детали |
|------|--------|--------|
| Kernel R/W | ✅ | VFS race → socket corruption → 32-byte R/W |
| Zone Discovery | ✅ | Runtime bounds, ±4MB scan, 8× safety margin |
| Process Utils | ✅ | allproc scan, PID/UID/GID verified via XNU source |
| Kernel FS | ✅ | rootvnode (fixed!), ncache auto-calibration |
| Root + Unsandbox | ✅ | ucred zeroing + sandbox label NULL |
| AMFI Bypass | ✅ | 4 kernel variables: amfi, cs_enforce, proc/vnode_enforce |
| Trust Cache | ✅ | Scan + string xref fallback + CDHash injection |
| Bootstrap | ⏳ | Procursus + Sileo + SSH (упирается в unresolved `ourproc()` на 21D61) |

## Цепочка эксплойта

```
ds_run() → IOSurface phys mapping → VFS race → OOB R/W
  → ICMPv6 spray (22K) → PCB corruption → KRW
  → Zone discovery → kernel_base (0xFEEDFACF)
  → Socket refcount leak

init_offsets() → Dynamic proc offset discovery

kfs_init() → find_rootvnode() → verify_ncache() → ready

postexploit_run()
  → [1] ucred: uid=0, gid=0, rgid=0, svgid=0
  → [2] sandbox: cr_label slot[0] = NULL
  → [3] platformize: CS_PLATFORM_BINARY | CS_DEBUGGED
  → [4] AMFI global: amfi_get_out_of_my_way=1, cs_enforcement_disable=1

tc_init() → TC head scan → CDHash injection

bootstrap_install() → /var/jb → Procursus → Sileo → SSH
```

## Файлы

| Файл | Строк | Описание |
|------|-------|----------|
| darksword_core.m | ~1357 | VFS race, KRW, zone discovery |
| darksword_exploit.m | ~298 | Entry point, Dopamine plugin API |
| utils.m | ~882 | proc utilities, allproc scan, offset discovery |
| kfs.m | ~701 | rootvnode, ncache, vm_map, dir listing |
| postexploit.m | ~785 | root, unsandbox, AMFI global bypass, PPL-aware |
| trustcache.m | ~810 | TC scan + CDHash injection |
| bootstrap.m | ~502 | Procursus + Sileo + SSH pipeline |
| filelog.m | ~100 | File logging for crash analysis |

## API

```c
void ds_run(void);                         // VFS race → KRW
bool ds_is_ready(void);                    // KRW ready?
uint64_t ds_kread64(uint64_t addr);
void ds_kwrite64(uint64_t addr, uint64_t val);
void ds_kread(uint64_t addr, void *buf, size_t len);
void ds_kwrite(uint64_t addr, const void *buf, size_t len);
```

## Исправленные баги

Полный и актуальный список с root cause analysis: **doc/BUGS_AND_FIXES.md** (**479 багов** на 2026-04-05).

Текущий runtime-статус и этап валидации: **doc/CURRENT_STATUS.md**.

Правило проекта: после каждого code-fix сразу обновлять оба документа выше в том же рабочем цикле.

## Сборка (Windows + WSL)

```bash
# Полная сборка + подпись + установка на устройство:
wsl -d Ubuntu -e bash -c "cd /mnt/c/Users/.../Dopamine_darksword && bash build_sign_install.sh"

# Только установка:
.\ideviceinstaller.exe -i Dopamine_darksword\build_app\DarkSword.ipa

# Логи:
.\idevicesyslog.exe --quiet
```

## Standalone режим

Установка через TrollStore / SideStore. При запуске:
1. Нажать "Jailbreak" → exploit chain → root → AMFI → TC → bootstrap
2. Respiring не нужен (userland jailbreak)

## Документация

- **doc/CURRENT_STATUS.md** — текущий статус всех модулей + offset таблицы
- **doc/BUGS_AND_FIXES.md** — полный журнал (479+ багов) + features с подробным анализом
- **doc/EXPLOIT_FLOW.md** — пошаговый flow эксплойта
- **doc/BUILD_SIGN_INSTALL.md** — инструкции сборки
- **doc/PROJECT_MAP.md** — карта файлов проекта
- **doc/KERNELCACHE_MACHO_DEEP_DIVE_21D61.md** — полный разбор `kernelcache.macho`: outer fileset, inner `com.apple.kernel`, PPL/normal data границы, syscall и mach anchors
- **doc/PATCH_DIFF_21D61_21E219.md** — первый воспроизводимый `21D61 -> 21E219` patch diff: extraction pair, kext delta, anchor-driven `__DATA.__common` comparison
