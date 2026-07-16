<h1 align="center">Proxy Networks</h1>

<p align="center">
  <img src="icons/logo-brand-128.png" width="128" height="128" alt="Proxy Networks logo">
</p>

<div align="center">

![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Chrome](https://img.shields.io/badge/Google_Chrome-108%2B-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white)
![Manifest](https://img.shields.io/badge/Manifest-V3-34A853?style=for-the-badge&logo=googlechrome&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Updated](https://img.shields.io/badge/Updated-16.07.2026-lightgrey?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/thekhabaroff/ProxyNetworks?style=for-the-badge)
![Last Commit](https://img.shields.io/github/last-commit/thekhabaroff/ProxyNetworks?style=for-the-badge)
![Issues](https://img.shields.io/github/issues/thekhabaroff/ProxyNetworks?style=for-the-badge)

[Возможности](#возможности) • [Требования](#требования) • [Установка](#установка-из-исходников) • [Использование](#использование) • [Поддержать проект](#поддержать-проект)

</div>

Proxy Networks — расширение для Google Chrome на Manifest V3, которое хранит несколько прокси-профилей и позволяет быстро переключать HTTP, HTTPS и SOCKS5-прокси. Проект не требует сборки и не содержит сторонних runtime-зависимостей.

## Возможности

- несколько локальных прокси-профилей;
- отдельные эндпоинты HTTP, HTTPS и SOCKS5;
- автоматическая маршрутизация по типу запроса или принудительный выбор одного протокола;
- прокси-авторизация по логину и паролю;
- список адресов-исключений;
- проверка каждого прокси с цветным индикатором;
- отображение текущего публичного IP;
- импорт и экспорт профилей в JSON;
- динамическая иконка состояния: белая — выключено, зелёная — работает, красная — обнаружена ошибка.

## Требования

- Google Chrome 108 или новее;
- Node.js 18 или новее — только для запуска проверок проекта.

## Установка из исходников

1. Скачайте репозиторий или клонируйте его.
2. Откройте `chrome://extensions`.
3. Включите «Режим разработчика».
4. Нажмите «Загрузить распакованное расширение».
5. Выберите корневую папку проекта, содержащую `manifest.json`.

После изменения исходников нажимайте «Обновить» на карточке расширения.

## Использование

1. Откройте настройки расширения и создайте профиль.
2. Заполните хотя бы один прокси-эндпоинт и при необходимости укажите авторизацию и исключения.
3. Сохраните профиль.
4. В миниатюре выберите профиль и режим протокола.
5. Включите прокси переключателем.

Режим «Авто» формирует правила Chrome для каждого заполненного эндпоинта: HTTP используется для HTTP-запросов, HTTPS — для HTTPS-запросов, а SOCKS5 — для остальных типов трафика или когда для типа запроса не настроен отдельный сервер. При ручном выборе один прокси применяется ко всем запросам.

## Проверка прокси

Кнопка «Проверить» временно применяет выбранный эндпоинт, запрашивает публичный IP через `api.ipify.org`, а затем восстанавливает предыдущую конфигурацию. Во время проверки сетевые запросы других вкладок могут на несколько секунд пройти через проверяемый прокси.

Зелёный индикатор означает успешный запрос, красный — ошибку, жёлтый — выполняющуюся проверку. Индикатор сбрасывается после изменения адреса, порта или учётных данных.

## Разрешения

| Разрешение | Назначение |
| --- | --- |
| `proxy` | Применение конфигурации через `chrome.proxy.settings` |
| `storage` | Локальное хранение профилей и состояния |
| `webRequest` | Получение событий прокси-аутентификации и завершения запросов |
| `webRequestAuthProvider` | Передача логина и пароля в proxy-auth challenge |
| `<all_urls>` | Работа прокси и авторизации для любых открываемых адресов |

## Данные и безопасность

Все профили хранятся в `chrome.storage.local`. Пароль шифруется AES-GCM, однако ключ находится в том же локальном хранилище. Это защита от случайного просмотра, а не от пользователя или программы с полным доступом к профилю Chrome.

Экспорт без паролей используется по умолчанию. Не публикуйте экспортированные профили и не добавляйте реальные учётные данные в Git.

## Ограничения

- прокси применяется ко всему обычному профилю Chrome, а не к отдельной вкладке;
- поддерживаются только фиксированные серверы HTTP, HTTPS и SOCKS5; PAC и SOCKS4 не поддерживаются;
- SOCKS5 работает без авторизации: Chrome не поддерживает логин и пароль для SOCKS5-прокси;
- расширение не управляет отдельной конфигурацией прокси для инкогнито;
- доступность прокси определяется HTTPS-запросом к `api.ipify.org`, поэтому сбой этого сервиса или блокировка домена также даст отрицательный результат;
- Chrome или другое расширение с разрешением `proxy` может переопределить текущую конфигурацию.

## Разработка и проверка

```bash
npm run check
```

`npm run check` проверяет синтаксис всех JavaScript-файлов проекта.

## Структура проекта

```text
.
├── manifest.json         # Manifest V3
├── background.js         # service worker, авторизация и проверки
├── config.js             # построение правил chrome.proxy
├── storage.js            # хранение профилей и шифрование паролей
├── popup.*               # миниатюра расширения
├── options.*             # редактор профилей
└── icons/                # брендовые и статусные PNG
```

## Диагностика

Если Chrome сообщает `ERR_TUNNEL_CONNECTION_FAILED`, проверьте адрес, порт и авторизацию нужного протокола. Низкоуровневую информацию о прокси можно посмотреть на `chrome://net-internals/#proxy`, а ошибки service worker — на карточке расширения в `chrome://extensions`.

## Поддержать проект

Если расширение сэкономило тебе время — можешь поддержать разработку криптовалютой:

<details>
<summary><b>🟠 BTC</b></summary>

```
1CAWPNFJMAWxCany1A317yqHoZz4mq9MTE
```

</details>

<details>
<summary><b>🟣 EVM</b></summary>

```
0xbdfa3a427e457a99d7254af04b44fe76c347bd10
```

</details>

<details>
<summary><b>🔴 TRC</b></summary>

```
TFGa8KRdcyCv3gk6khGU8NQvR8ot5UtiP5
```

</details>

<details>
<summary><b>🔵 TON</b></summary>

```
UQCacF30U98zSCbzd1NM5qMjjdkTygJwMjgDURobdXTIDN4-
```

</details>

<details>
<summary><b>🟢 SOL</b></summary>

```
ETdRsuSYgpijG4RFckEQUoLfQ4CctibcoshTKyk1sCoW
```

</details>

<details>
<summary><b>🟡 APT</b></summary>

```
0x82b02deef3c3d8d21a665c53d9ea2e046813b6a92085efbc241b8acf69dc3af5
```

</details>

> Каждый донат мотивирует развивать проект дальше 🙏

---

## Лицензия

[MIT](LICENSE) — используйте свободно, упоминание автора приветствуется.

---

<div align="center">⭐ Поставь звезду, если проект оказался полезным!</div>
