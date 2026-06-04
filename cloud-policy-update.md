# Cloud Policy Update для AWG/OpenCCK

## Что это решает

Локальный ручной `20_update_opencck.bat` больше не должен быть единственным способом поддерживать свежие YouTube/AI/Telegram/Meta CDN-адреса. Cloud Update разделяет работу:

- GitHub Actions/Windows PowerShell собирает тяжелые `.rsc`-артефакты.
- MikroTik только скачивает готовые файлы по HTTPS и импортирует их.
- Ежедневно обновляется легкий force/CDN слой.
- Полный OpenCCK импорт выполняется на роутере раз в 3 дня и чанками, чтобы не кормить RouterOS одним файлом на 16 MiB.

## Файлы

- `_settings.bat` - настройки cloud update и timeout policy.
- `tools/build-cloud-policy.ps1` - сборщик cloud artifacts.
- `60_build_cloud_policy.bat` - ручной запуск сборщика.
- `.github/workflows/awg-policy-cloud.yml` - публикация полного набора artifacts через GitHub Pages.
- `awg-cloud-policy-installer.rsc` - RouterOS installer wrapper/watchdog scripts.
- `70_install_cloud_policy.bat` - подстановка URL, SCP и `/import` installer на роутере.
- `cloud-artifacts/` - локально сгенерированный набор для проверки.

## Сборка локально

```bat
60_build_cloud_policy.bat all
```

Ожидаемый результат:

- `force-update.rsc`
- `force-manifest.txt`
- `full-policy-001.rsc` ... `full-policy-NNN.rsc`
- `full-policy-manifest.txt`

Селективные режимы `force` и `full` оставлены только для локальной отладки. Для публикации каталога используем `all`, чтобы GitHub Pages всегда содержал и force, и full artifacts.

## Публикация

В GitHub нужно включить Pages для workflow artifact deployment. Workflow `AWG Policy Cloud Build` всегда собирает полный каталог artifacts. Роутер импортирует daily force каждый день, а full chunks только раз в 3 дня.

После публикации взять base URL каталога, например:

```text
https://<user>.github.io/<repo>/
```

и прописать в `_settings.bat`:

```bat
set "CLOUD_ARTIFACT_BASE_URL=https://<user>.github.io/<repo>"
```

URL должен указывать на каталог, где лежат `force-manifest.txt` и `full-policy-manifest.txt`.

## Установка на RouterOS

Пока `CLOUD_ARTIFACT_BASE_URL` равен placeholder, установщик специально отказывается работать.

После настройки URL:

```bat
70_install_cloud_policy.bat
```

Установщик создаст на роутере:

- `awg-cloud-config`
- `awg-cloud-lib`
- `awg-cloud-force-update`
- `awg-cloud-full-update`
- `awg-policy-watchdog`
- scheduler `awg-cloud-force-update-daily`
- scheduler `awg-cloud-full-update-every-3d`
- scheduler `awg-policy-watchdog-every-1h`

## Логика отказоустойчивости

- Force layer использует два слота: `awg_force_ip4_a` и `awg_force_ip4_b`.
- Daily wrapper очищает только inactive force slot, импортирует новый список, проверяет marker/count/size и только потом переключает `awg-force-mark-connection`.
- Full OpenCCK использует существующие `awg_vpn_ip4_a` и `awg_vpn_ip4_b`.
- Full wrapper чистит target slot, импортирует chunks по очереди, проверяет marker каждого chunk и переключает active slot только после последнего успешного chunk.
- При runtime error target slot очищается, active slot не меняется.
- Если питание пропало во время full import, watchdog после загрузки увидит state `RUNNING_FULL target=...` и очистит только stale target slot.
- Watchdog пишет локальный state в `awg-usb/awg-policy-state.txt`, системный log и пытается отправить Telegram через существующий SHC `ShcSendTg`.

## Проверки

На Windows:

```bat
60_build_cloud_policy.bat all
```

Проверено локально на 2026-06-04:

- force: 69 записей;
- full: 152389 записей;
- chunks: 31;
- размер chunk примерно 0.26-0.56 MiB;
- manifest sizes совпадают с фактическими файлами;
- `.rsc` и manifest пишутся UTF-8 без BOM.

На роутере после установки:

```rsc
/system/scheduler/print where name~"awg-cloud|awg-policy"
/system/script/run awg-cloud-force-update
/file/print where name="awg-usb/awg-policy-state.txt"
/log/print where message~"AWG_CLOUD|POLICY_"
```

Полный import вручную запускать только ночью:

```rsc
/system/script/run awg-cloud-full-update
```

## Ограничение текущей итерации

Installer пишет policy state и уведомляет через Telegram, но не переписывает текущий source `shc-bot-poll`. Поэтому отображение `policy=STALE` прямо в `/status` требует отдельного аккуратного patch для Telegram bot source после публикации cloud URL. Локальная аварийная фиксация уже есть: `awg-usb/awg-policy-state.txt` и `/log`.
