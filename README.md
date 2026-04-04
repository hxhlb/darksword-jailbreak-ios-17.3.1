# DarkSword Jailbreak — iOS 17.3.1 / iPad8,9

## Описание

Standalone jailbreak для iPad Pro 11" (A12Z Bionic, arm64e) на базе
VFS race + ICMPv6 socket corruption exploit (CVE-2025-43520).
Основан на [rooootdev/lara](https://github.com/rooootdev/lara) — полностью
портированный + **284 задокументированных исправлений/багов** + **4 новых модуля**.

## Целевое устройство
- **iPad8,9** (iPad Pro 11" 2nd gen, A12Z Bionic, arm64e)
- **iOS 17.3.1** (build 21D61)

## Что работает (после всех исправлений)

| Фаза | Статус | Детали |
|------|--------|--------|
| Kernel R/W | ✅ | VFS race → socket corruption → 32-byte R/W |
| Zone Discovery | ✅ | Runtime bounds, ±4MB scan, 8× safety margin |
| Process Utils | ✅ | allproc scan, PID/UID/GID verified via XNU source |
| Kernel FS | ✅ | rootvnode (fixed!), ncache auto-calibration |
| Root + Unsandbox | ✅ | ucred zeroing + sandbox label NULL |
| AMFI Bypass | ✅ | 4 kernel variables: amfi, cs_enforce, proc/vnode_enforce |
| Trust Cache | ✅ | Scan + string xref fallback + CDHash injection |
| Bootstrap | ⏳ | Procursus + Sileo + SSH (depends on TC) |

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

Полный и актуальный список с root cause analysis: **doc/BUGS_AND_FIXES.md** (**284 бага** на 2026-04-02).

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
- **doc/BUGS_AND_FIXES.md** — полный журнал (282 бага) + features с подробным анализом
- **doc/EXPLOIT_FLOW.md** — пошаговый flow эксплойта
- **doc/BUILD_SIGN_INSTALL.md** — инструкции сборки
- **doc/PROJECT_MAP.md** — карта файлов проекта
