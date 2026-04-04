# Как собрать, подписать и установить DarkSword

> Обновлено: 2026-04-01 (сессия 12, обновлено сессия 25d)
> Для ИИ-ассистентов и человека: пошаговая инструкция сборки и деплоя

## Требования

### На Windows:
- WSL2 с Ubuntu (дистрибутив `Ubuntu`, НЕ `docker-desktop`)
- `ideviceinstaller.exe` в `C:\Users\smolk\Documents\palera1n-windows\`
- iPad подключён USB кабелем и доверяет компьютеру

### В WSL Ubuntu:
- Theos toolchain: `/opt/theos/toolchain/linux/iphone/bin/clang`
- iPhone SDK: `/opt/theos/sdks/iPhoneOS16.5.sdk`
- ldid: `/opt/theos/bin/ldid` (v2.1.5-procursus7, поддерживает -K p12)
- **zsign 0.9.8:** `/mnt/c/Users/smolk/Documents/palera1n-windows/zsign_build/bin/zsign`
- Пакеты: `g++ libssl-dev libminizip-dev zlib1g-dev pkg-config`

### Сертификаты:
- P12: `Dopamine_darksword/Сертификатыnew2 (3).p12` (пароль: `1984`)
- Provision: `Dopamine_darksword/ios (2) (2).mobileprovision`
- Subject: `Apple Development: Vladimir Polevoy (NN49GWDWRL)`
- Team ID: `V945SAD4LF`
- Bundle ID: `soft.ru.app`
- Срок: до 2026-05-24

## Шаг 1: Компиляция + ldid signing

```bash
# ВАЖНО: запускать через WSL Ubuntu, НЕ docker-desktop
wsl -d Ubuntu bash -c "cd '/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword' && bash build_sign_install.sh 2>&1"
```

Скрипт `build_sign_install.sh` делает:
1. Компилирует 9 .m файлов → arm64 Mach-O
2. Создаёт .app bundle с Info.plist
3. Встраивает mobileprovision
4. Извлекает entitlements из provision profile
5. Создаёт _CodeSignature/CodeResources (Python)
6. Подписывает ldid с P12 сертификатом

Результат: `build_app/DarkSword.ipa` (~60KB)

## Шаг 2: Переподписать zsign

ldid создаёт рабочую подпись для бинарника, но **не включает промежуточные Apple-сертификаты** в CMS-блоке. iOS отказывает с `0xe8008001`. zsign решает эту проблему.

**Самый простой способ — готовый скрипт:**
```bash
wsl -d Ubuntu bash /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/zsign_ipa.sh
```

Или вручную:
```bash
wsl -d Ubuntu /mnt/c/Users/smolk/Documents/palera1n-windows/zsign_build/bin/zsign \
  -k '/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/Сертификатыnew2 (3).p12' \
  -p 1984 \
  -m '/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/ios (2) (2).mobileprovision' \
  -b 'soft.ru.app' \
  -o '/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/build_app/DarkSword_signed.ipa' \
  '/mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/build_app/DarkSword.ipa'
```

Результат: `build_app/DarkSword_signed.ipa` (~240KB) — это файл для установки.

## Шаг 3: Установка на iPad

```powershell
cd C:\Users\smolk\Documents\palera1n-windows
.\ideviceinstaller.exe -i "Dopamine_darksword\build_app\DarkSword_signed.ipa"
```

Ожидаемый выход:
```
Install: InstallComplete (100%)
Install: Complete
```

Exit code 1 — нормально (из-за WARNING о iTunesMetadata.plist). Главное — видеть `Install: Complete`.

## Чтение логов

Лог сохраняется в Documents приложения. Два способа:

### Через 3uTools:
1. Приложения → DarkSword → Файлы
2. Documents → darksword_log.txt → Экспорт
3. Сохранить в `Dopamine_darksword/log/darksword_log.txt`

### Через idevicesyslog (в реальном времени + в файл):
```powershell
# Запустить ДО запуска приложения!
cd C:\Users\smolk\Documents\palera1n-windows
.\idevicesyslog.exe --match DarkSword 2>&1 | Tee-Object -FilePath "Dopamine_darksword\log\syslog_session.txt"
```
Логи пишутся в `Dopamine_darksword\log\syslog_session.txt` и одновременно показываются в консоли.

### Через idevicecrashreport (после паники):
```powershell
cd C:\Users\smolk\Documents\palera1n-windows
.\idevicecrashreport.exe -k -e Dopamine_darksword\doc\crashes_next
```

---

## Где что лежит (справочник путей)

| Что | Путь (Windows) |
|-----|---|
| **Исходники** | `C:\Users\smolk\Documents\palera1n-windows\Dopamine_darksword\darksword\` |
| **Скрипт сборки** | `Dopamine_darksword\build_sign_install.sh` |
| **Скрипт подписи** | `Dopamine_darksword\zsign_ipa.sh` |
| **zsign бинарник** | `zsign_build\bin\zsign` (v0.9.8) |
| **P12 сертификат** | `Dopamine_darksword\Сертификатыnew2 (3).p12` (пароль: `1984`) |
| **Provisioning profile** | `Dopamine_darksword\ios (2) (2).mobileprovision` (до 2026-05-24) |
| **IPA после сборки** | `Dopamine_darksword\build_app\DarkSword.ipa` (не для установки!) |
| **IPA после zsign** | `Dopamine_darksword\build_app\DarkSword_signed.ipa` (✅ для установки) |
| **ideviceinstaller** | `C:\Users\smolk\Documents\palera1n-windows\ideviceinstaller.exe` |
| **idevicesyslog** | `C:\Users\smolk\Documents\palera1n-windows\idevicesyslog.exe` |
| **Логи syslog** | `Dopamine_darksword\log\` |
| **Документация** | `Dopamine_darksword\doc\` |

Все пути относительны от `C:\Users\smolk\Documents\palera1n-windows\`.

---

## Пересборка zsign (если утерян)

```bash
wsl -d Ubuntu bash -c "
cd /mnt/c/Users/smolk/Documents/palera1n-windows && rm -rf zsign_build &&
git clone https://github.com/nicedayzhu/zsign.git zsign_build &&
cd zsign_build &&
g++ *.cpp common/*.cpp -o bin/zsign -lcrypto -lssl -lz -lpthread -std=c++11 2>&1
"
```

Бинарник: `zsign_build/bin/zsign`

---

## Быстрая итерация (3 команды)

```powershell
# 1. Компиляция + ldid
wsl -d Ubuntu bash -c "cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword && bash build_sign_install.sh 2>&1"

# 2. Подпись zsign (ОБЯЗАТЕЛЬНО!)
wsl -d Ubuntu bash /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/zsign_ipa.sh

# 3. Установка на iPad
cd C:\Users\smolk\Documents\palera1n-windows
.\ideviceinstaller.exe -i "Dopamine_darksword\build_app\DarkSword_signed.ipa"
```

## Быстрая итерация (одна команда для AI)

```powershell
# Всё в одну команду: компиляция + zsign + установка
wsl -d Ubuntu bash -c "cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword && bash build_app.sh 2>&1" ; wsl -d Ubuntu bash /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword/zsign_ipa.sh ; cd C:\Users\smolk\Documents\palera1n-windows ; .\ideviceinstaller.exe -i Dopamine_darksword\build_app\DarkSword_signed.ipa
```

## Полный build_sign_install.sh (одна команда)

Включает фазы 1-4 (компиляция + ldid + zsign + install):
```powershell
wsl -d Ubuntu bash -c "cd /mnt/c/Users/smolk/Documents/palera1n-windows/Dopamine_darksword && bash build_sign_install.sh 2>&1"
```
