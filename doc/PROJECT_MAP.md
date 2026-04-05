# DarkSword Jailbreak  Полная карта проекта

> Этот документ — основной справочник для ИИ-ассистентов.
> Последнее обновление: 2026-04-01 (Bug #260–#262, build 46, 262 бага исправлено)

## Цель проекта

Полноценный jailbreak iPad8,9 (A12Z Bionic, arm64e) на iOS 17.3.1 (build 21D61):
- **root** (uid=0, gid=0)
- **sandbox escape**
- **CS_PLATFORM_BINARY** + AMFI bypass
- **Trust cache injection** (произвольные бинарники)
- **Bootstrap**  Procursus + Sileo + SSH

## Устройство

| Параметр | Значение |
|----------|----------|
| Модель | iPad8,9 |
| SoC | A12Z Bionic (arm64e) |
| iOS | 17.3.1 (21D61) |
| Kernel | xnu-10002.82.4~3 |
| PAC | Да (arm64e)  нужен pac_strip |
| PPL | Да  нельзя писать в __PPLDATA, __LASTDATA |

## Структура проекта

```
Dopamine_darksword/
  darksword/
    darksword_core.m    VFS race + kernel R/W + Zone Discovery + protosw fallback + zone priming + dynamic so_count (~2031 строк)
    darksword_core.h    Public API (set_target_kaddr->bool, ds_get_zone_map_*)
    utils.m             Kernel utils, PAC strip, allproc walk, DATA-chain support, is_kernel_data_ptr (~2664 строк)
    kfs.m               Kernel file system ops (~628 строк)
    postexploit.m       Root, sandbox, platformize (~408 строк)
    trustcache.m        Trust cache injection (~390 строк)
    bootstrap.m         Procursus + Sileo + SSH (~320 строк)
    filelog.m           File logging (~100 строк)
    main.m              Entry point (~60 строк)
  build_app.sh           Standalone build pipeline (compile + link + sign + IPA)
  zsign_ipa.sh           Re-sign IPA with developer cert
  build_app/
    DarkSword_signed.ipa   Signed IPA (~693 KB, build 46)
  doc/
    CURRENT_STATUS.md      Текущий статус + kernelcache analysis
    BUGS_AND_FIXES.md      История всех багов и исправлений
    EXPLOIT_FLOW.md        7 фаз exploit chain
    FILES_REFERENCE.md     Описание каждого файла
    PROJECT_MAP.md         Этот файл
    BUILD_SIGN_INSTALL.md  Инструкция сборки
    crashes3-8/            Краш-репорты с устройства (5 паник A-E)
  ipsw_analysis/           Оффлайн анализ kernelcache из IPSW
    kernelcache.macho      Декомпрессированный kernelcache (52.33 MB)
    __DATA_CONST.bin       Raw __DATA_CONST segment (4.73 MB)
    OFFSET_ANALYSIS.md     Результаты верификации оффсетов
```

## Kernel offsets (iOS 17.3.1, build 21D61, iPad8,9)

| Offset | Значение | Сегмент | Описание |
|--------|----------|---------|----------|
| unslid base | `0xfffffff007004000` | __TEXT | Kernel base без KASLR slide |
| `_kernproc` | kbase + `0x19FBE8` | __PRELINK_TEXT | ⚠️ НЕ allproc — в static binary value=0x5458 |
| `_allproc` | kbase + `0x93B348` | __DATA_CONST | ⚠️ Read-only data, не allproc |
| **legacy allproc** | kbase + `0x3198060` | **__DATA + 0x60** | ⚠️ `__PPLDATA+0x60` — PPL-protected, PANIC при чтении (Bug #206, УДАЛЁН) |
| **ADRP allproc** | kbase + `0x31FFF30` | **__DATA.__common** | **✅ Основной кандидат: 389 ADRP refs, mutable, безопасный (Bug #216)** |
| PROC_PID_OFFSET | `0x28` | — | Offset pid в struct proc (iOS 17.x) |
| PROC_NEXT | `0x08` | — | Offset p_list.le_next в struct proc |
| ipi_zone offset | PCB + `0x38` → `+0x68` | __DATA_CONST | pcbinfo → ipi_zone |
| Zone map span | `0x600000000` (24 GB) | — | XNU constant ZONE_MAP_VIRTUAL_SIZE_LP64 |
| KASLR slide | `0x6dd4000` | — | Наблюдённый slide (Boot E) |

> **ВАЖНО:** Верификация через IPSW kernelcache (UUID D1B6EFB84A11AE7DCDF3BC591F014E72):
> - `0x19FBE8` → `__PRELINK_TEXT` — safe (validate отбракует), но НЕ allproc
> - `0x93B348` → `__DATA_CONST` — safe, но read-only данные
> - `0x3198060` → `__DATA + 0x60` = `__PPLDATA+0x60` — **PPL-protected, PANIC** (Bug #206, УДАЛЁН)
> - **`0x31FFF30`** → `__DATA.__common + 0x3CF30` — **389 ADRP refs, mutable, основной кандидат** (Bug #216)
>
> **Runtime finding (2026-03-30, panic #3):** первый чанк скана начинался с `0xfffffff01ca40000`, а panic FAR был `0xfffffff01ca44000` — это ровно вторая 16 KB страница `__DATA`. Поэтому broad scan по `__DATA` больше не считается safe; fallback ограничен первой страницей `__DATA`.

## Zone Map  ключевая информация

Zone map  виртуальная область ядра размером ровно 24 GB, где живут все zone allocations (сокеты, процессы, vnodes и т.д.). Адреса zone map **рандомизируются** при каждой загрузке.

**Zone Metadata/Bitmaps**  служебные структуры, которые живут ВОВНЕ zone map. Их расположение непредсказуемо:
- Могут быть НИЖЕ zone map
- Могут быть ВЫШЕ zone map
- Чтение metadata через наш R/W primitive = kernel panic (translation fault)

**Решение:** Runtime Zone Discovery  ищем zone_info global в __DATA_CONST ядра, определяем [min, max) и блокируем все адреса вне этого диапазона.

## Наблюдённые zone layouts (5 загрузок / паник)

| Boot | Panic | Zone min | Zone max | FAR (crash) | Metadata |
|------|-------|----------|----------|-------------|----------|
| A (210919) | copy_validate | `0xffffffdc..0xffffffe2` | — | userspace | ВЫШЕ |
| B (215013) | zone meta | `0xffffffde..0xffffffe4` | — | `0xffffffdc1b3a7170` | НИЖЕ |
| C (221644) | zone meta | `0xffffffdc..0xffffffe2` | — | `0xffffffe8f4ccd9f0` | ВЫШЕ |
| D (223121) | zone meta | `0xffffffdd..0xffffffe3` | — | `0xffffffec35648ee0` | ВЫШЕ |
| **E (070246)** | **zone meta** | **`0xffffffde57f78000`** | **`0xffffffe457f78000`** | **`0xffffffdc0673a9a0`** | **НИЖЕ** |

## Jailbreak Chain (порядок выполнения)

```
1. pe_init()                         VFS race setup
2. pe_v1()                           Socket spray + VFS race + ICMPv6 corruption
   -> kernel R/W ready!
3. Kernel base discovery             ipi_zone -> vz_name -> backward scan
4. discover_zone_boundaries_raw()    Zone map [min, max) discovery   NEW
5. krw_sockets_leak_forever()        Leak sockets (with zone bounds check)
6. kernprocaddress()                 GOT → PPLDATA → direct scan → DATA-proc0 SMRQ discovery
7. ourproc()                         kread health + DATA-chain walk + find our PID in allproc
8. postexploit(our_proc)             Root + sandbox + platformize + AMFI
9. trustcache_inject()               CDHash injection
10. bootstrap_install()              Procursus + Sileo + SSH
```

## Build

```bash
# WSL Ubuntu:
cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword
bash build_app.sh      # compile + IPA
bash zsign_ipa.sh      # re-sign with cert

# Windows install:
.\ideviceinstaller.exe -i Dopamine_darksword\build_app\DarkSword_signed.ipa
```

## Текущее состояние (2026-04-01, build 46)

**262 бага исправлено.**

**Последние фиксы:**
- Bug #260: DATA-resident proc chain (proc0 + proc1 в __DATA ядра)
- Bug #261: normalize_proc_link_target_with_pid DATA ptr support
- Bug #262: Kernel panic prevention (le_prev PPLDATA, PID=0, unchecked kread)

**Прогресс эксплойта:**
- ✅ VFS race + Physical OOB + ICMPv6 corruption + Kernel R/W
- ✅ Zone bounds priming + zone discovery + kernel_base
- ✅ Socket refcount leak (so_count fixed)
- ✅ allproc discovery: `kbase+0x321C240` → DATA-proc0 SMRQ → confirmed
- ⚠️ ourproc() walk — build 46 с защитой от паники, ожидает runtime тест
- ⬜ postexploit / trustcache / bootstrap
