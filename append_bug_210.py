#!/usr/bin/env python3
"""Appends Bug #210 to BUGS_AND_FIXES.md"""
import os

doc_path = os.path.join(os.path.dirname(__file__), "doc", "BUGS_AND_FIXES.md")

text = r"""

---

## Bug #210 — trustcache.m: find_tc_head_by_scan() читает PPL-protected память → panic

**Сессия:** 5
**Файл:** `darksword/trustcache.m`, функции `find_tc_head_by_scan()` и `scan_segment_for_tc()`
**Статус:** ИСПРАВЛЕН

**Симптом:** Kernel panic при вызове `tc_init()` после успешного kernel R/W.
Лог обрывается на "tc_init: looking for trust cache..." без дальнейшего вывода.

**Root cause:**
`find_tc_head_by_scan()` явно добавлял `__PPLDATA` сегменты в список для скана:
```c
if (strncmp(seg->segname, "__DATA", 6) == 0 ||
    strncmp(seg->segname, "__PPLDATA", 9) == 0 ||    // ← PPL-protected → panic!
    strncmp(seg->segname, "__LASTDATA", 10) == 0) {
    segs[nsegs].addr = seg->vmaddr + kslide;
```
Затем `scan_segment_for_tc()` начинала сканировать с `off=0` (начало сегмента):
```c
krd(seg_addr + off, page, 0x1000);  // ← __PPLDATA = PPL-protected → PANIC
```

Дополнительно: для outer `__DATA` сегмент начинается с vmaddr = начала `__PPLDATA`
(первые 0x8000 = `__PPLDATA` + `__KLDDATA`, PPL-protected). Скан без skip = panic.

Для сравнения: `find_tc_head_by_string_xref()` уже имела корректный skip:
```c
if (strncmp(data_segs[d].name, "__PPLDATA", 9) == 0) {
    tlog("string xref: skipping %s (PPL-protected)", data_segs[d].name);
    continue;
}
```
...но `find_tc_head_by_scan()` — НЕ имела.

**Файл:** `darksword/trustcache.m`, `find_tc_head_by_scan()` + `scan_segment_for_tc()`
**Импакт:** КРИТИЧНО — panic на tc_init() = trust cache всегда недоступен = bootstrap binaries не доверены = dpkg/apt/Sileo не запускаются

**Фикс:**
1. `scan_segment_for_tc()` получила параметр `start_skip` — читает с `seg_addr + start_skip + off`
2. `find_tc_head_by_scan()`:
   - Убрана из списка: `__PPLDATA` (skip entirely — trust cache head никогда не в PPL)
   - Убрана из списка: `__LASTDATA` (unknown, may be PPL-protected)
   - Для `__DATA` сегмента: `skip = PPL_SKIP = 0x8000` (пропускает __PPLDATA+__KLDDATA prefix)
   - Для остальных (`__DATA_CONST` и подобных): `skip = 0`
"""

with open(doc_path, "a", encoding="utf-8") as f:
    f.write(text)

print("Done: appended Bug #210 to BUGS_AND_FIXES.md")
