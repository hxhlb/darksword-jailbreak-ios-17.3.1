#!/usr/bin/env python3
"""Appends Bug #208 and #209 to BUGS_AND_FIXES.md"""
import os

doc_path = os.path.join(os.path.dirname(__file__), "doc", "BUGS_AND_FIXES.md")

text = r"""

---

## Bug #208 — kfs.m: find_rootvnode() всегда пропускает root vnode (v_name == NULL)

**Сессия:** 4
**Файл:** `darksword/kfs.m`, функция `find_rootvnode()`
**Статус:** ИСПРАВЛЕН

**Симптом:** `kfs_init()` → `find_rootvnode()` возвращает -1 → `g_rootvnode = 0`
→ `kfs_listdir()` всегда возвращает -1 → файловая система недоступна.

**Root cause (XNU source xnu-10002.1.13):**
В XNU `struct vnode.v_name` для root vnode ВСЕГДА NULL.
Root-vnode создаётся в `vfs_mountroot()` без родительского имени.
Старый код: `if (!is_kptr(root_name)) continue;` — пропускал реальный root vnode каждый раз.

**Файл:** `darksword/kfs.m`, `find_rootvnode()`
**Импакт:** КРИТИЧНО — kfs не работает, rootvnode не найден

**Фикс:** Убрана проверка `is_kptr(root_name)` для root vnode.
NULL v_name принимается как валидный (нормальный случай XNU).
Оставлена только проверка `v_type == VDIR (2)`.

---

## Bug #209 — postexploit.m: заголовок KC 32KB — AMFI kext не найден в iOS 17 fileset

**Сессия:** 4
**Файл:** `darksword/postexploit.m`, функция `postexploit_patch_amfi()`
**Статус:** ИСПРАВЛЕН

**Симптом:** "amfi_get_out_of_my_way string not found in kernel" в логах. AMFI не отключается.

**Root cause:**
Буфер заголовка kernelcache был ограничен 32KB (8 × 0x1000).
На iOS 17.3.1 fileset KC sizeofcmds > 32KB (200+ LC_FILESET_ENTRY, по одному на kext).
AMFI kext (com.apple.driver.AppleMobileFileIntegrity) находится за пределами
первых 32KB load commands → amfi_kext_vmaddr = 0 → строка не найдена.

**Файл:** `darksword/postexploit.m`, `postexploit_patch_amfi()`
**Импакт:** КРИТИЧНО — AMFI отключение всегда проваливается

**Фикс:** Увеличен буфер с 32KB до 256KB (64 страниц × 0x1000),
hdr_limit clamped с 0x8000 до 0x40000.
"""

with open(doc_path, "a", encoding="utf-8") as f:
    f.write(text)

print("Done: appended Bug #208 and #209 to BUGS_AND_FIXES.md")
