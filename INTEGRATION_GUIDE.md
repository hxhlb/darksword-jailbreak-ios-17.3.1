# DarkSword → Dopamine Integration Guide

## Архитектура

```
Dopamine.app
├── Frameworks/
│   ├── kfd.framework          ← существующий exploit (iOS 15-16)
│   ├── weightBufs.framework   ← существующий exploit (iOS 15-16)
│   └── darksword.framework    ← НОВЫЙ exploit (iOS 17-18)
│       ├── darksword          ← Mach-O arm64e
│       └── Info.plist         ← DPExploitType=Kernel, iOS 17.0-18.7
├── BaseBin/                   ← post-exploitation (нужна адаптация для iOS 17+)
└── Dopamine                   ← основное приложение
```

## Что делает darksword.framework

### `exploit_init("default")`
1. **Запуск эксплойта** — VFS race condition (CVE-2025-43520)
   - IOSurface physical mapping (16 MB)
   - Spray 22528 ICMPv6 сокетов
   - pwritev/mach_vm_map race → physical OOB
   - Corruption → kernel R/W через ICMP6_FILTER
2. **Установка Dopamine примитивов**
   - `gPrimitives.kreadbuf = darksword_kreadbuf`
   - `gPrimitives.kwritebuf = darksword_kwritebuf` 
   - `gSystemInfo.kernelConstant.slide = kernel_slide`
3. **Динамическое обнаружение оффсетов** (фиксы багов iPad8,9)
   - Автоматический поиск `proc_name_offset` (вместо захардкоженного 0x56c)
   - Автоматический поиск `task→vm_map` (вместо task+0x28)
   - Автоматический путь `proc→proc_ro→task` (вместо proc+0x740)

### `exploit_deinit()`
- Очистка gPrimitives
- Закрытие сокетов, освобождение IOSurface

## Исправленные баги (из анализа iPad8,9)

| # | Баг | Причина | Исправление |
|---|-----|---------|-------------|
| 1 | `procbyname("launchd") failed` | `PROC_NAME_OFFSET=0x56c` неверен для iOS 17.x | Сканирование proc struct для имени процесса |
| 2 | `vm_map_entry not found` | `vm_map = task+0x28` дает мусор | Перебор task+0x20..0x300, проверка nentries |
| 3 | `ourtask()` неверный | `proc+0x740` неверен | Путь proc→proc_ro→task с валидацией |

## Сборка

### На macOS:
```bash
# Клонируйте Dopamine для заголовков libjailbreak
git clone --recursive https://github.com/opa334/Dopamine ../Dopamine

# Соберите фреймворк
make all

# Внедрите в IPA
./build_and_inject.sh /path/to/Dopamine.ipa
```

### GitHub Actions:
Пуш на GitHub → CI автоматически собирает → артефакт `darksword-framework`

## Установка IPA

1. **TrollStore** (рекомендуется если доступен):
   - Откройте `Dopamine_DarkSword.ipa` через TrollStore
   
2. **Sideloadly**:
   - Подключите iPad к ПК
   - Sideloadly → выберите IPA → Install
   - Может потребоваться Apple ID (бесплатный)

3. **AltStore**:
   - AltStore → My Apps → Install → выберите IPA

## ⚠️ ВАЖНЫЕ ОГРАНИЧЕНИЯ

### Dopamine 2.x поддерживает только iOS 15.0-16.6.1

DarkSword эксплойт работает на iOS 17-18, но **полный джейлбрейк** через Dopamine на iOS 17+
требует адаптации:

1. **BaseBin** — systemhook, launchdhook, bootstrap installer спроектированы для iOS 15/16
2. **XPF patchfinding** — автоматический поиск оффсетов ядра для iOS 15/16
3. **PAC/PPL bypass** — байпасы PAC и PPL специфичны для iOS 15/16
4. **Bootstrap (Procursus)** — пакеты собраны для iOS 15/16

### Что работает на iOS 17+:
- ✅ Kernel exploit (получение kernel R/W)
- ✅ Чтение/запись памяти ядра
- ✅ Обнаружение оффсетов
- ⚠️ Повышение привилегий (частично — нужны правильные оффсеты)
- ❌ Полный jailbreak (injection, bootstrap, tweak loading)

### Для полного джейлбрейка iOS 17+:
Рассмотрите: **Dopamine 3.x** (если/когда выйдет) или другие инструменты.
Либо используйте darksword kernel R/W для кастомных задач (remount, файловый доступ и т.д.).

## Структура файлов

```
Dopamine_darksword/
├── README.md                         # Обзор проекта
├── INTEGRATION_GUIDE.md              # Этот файл
├── Makefile                          # Система сборки
├── build_and_inject.sh               # Скрипт сборки + внедрения
├── .github/workflows/build.yml       # GitHub Actions CI
└── darksword/
    ├── darksword_exploit.m           # exploit_init / exploit_deinit (Dopamine API)
    ├── darksword_core.h              # Заголовок ядра эксплойта
    ├── darksword_core.m              # Реализация VFS race exploit  
    ├── darksword_offsets.h           # Заголовок обнаружения оффсетов
    ├── darksword_offsets.m           # Динамическое обнаружение (фиксы 3 багов)
    └── Info.plist                    # Дескриптор фреймворка для Dopamine
```
