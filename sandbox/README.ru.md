# Стенд Kannel — реальный SMPP-окружение для отладки и доказательства корректности

> **Статус:** оригинал написан в рамках задач T1–T5 Story 6.3; русский перевод следует за
> оригиналом, нормативен [английский оригинал](README.md) — при расхождении истина в оригинале,
> автоматической сверки нет, согласованность «перевод ↔ оригинал» — обязанность ревью; T1 — сам
> Kannel-стенд (2026-09-17), T2 — сервис Keycloak в compose (ROPC-адъюдикация, которую требует
> reverse-ячейка, AD-17 fail-closed — обхода аутентификации не существует) и рецепт запуска прокси
> на хосте (§5, машинно исполнен с этой страницы), T3 — сценарии проверки корректности с ожидаемыми
> наблюдениями на каждом плече (§6) и гид по отладке (§7), оба исполнены вживую с этой страницы на
> стенде 2026-09-17. T4 (того же числа) — закрытие: инертность к Gradle проверена живым прогоном
> (`./gradlew clean build --console=plain` GREEN, 521 тестов, ни одного изменения в
> Gradle-файлах), сценарии внесены в тест-каталог как датированные строки manual-rig/Ops-tier
> (E2E-002..005), `epic-6-context.md` регенерирован по факту. T5 (2026-09-18, добавлено
> владельцем): три руководства по docker-упакованным вариантам в `runbooks/` (§5.6) —
> reverse.mode-b, forward+reverse mode A, forward+reverse mode C; каждый контейнер прокси —
> `network_mode: host` со собранным на хосте jar'ем, bind-mounted поверх копии образа; каждое
> руководство пройдено дословно до `bind_accept coupled` на живом стенде, рядом RU-переводы.
> Рецепт `java -jar` на хосте (§5) ОСТАЁТСЯ позой отладки · **Аудитория:**
> разработчики, отлаживающие релей/адъюдикацию прокси против реального стороннего SMPP-стека ·
> **Оракул:** сам стенд — `docker compose up` в `sandbox/` плюс спецификация
> `_bmad-output/implementation-artifacts/6-3-kannel-sandbox.md`.

Стенд — это инструмент разработчика, а не поставляемый продукт: он не меняет ни одной строки
main-кода, инертен к Gradle (`./gradlew clean build` не затрагивается), не подключается к CI и не
публикует показателей производительности (измерениями владеет Epic 7).

## 1. Что это за стенд

Цепочка docker-compose из **Kannel 1.5.0** по обе стороны прокси. До сих пор доказательства
interop-совместимости прокси опирались на внутрирепозиторные моки (`MockSmsc` на собственном
кодеке репозитория) плюс jSMPP 3.0.2 как независимый оракул; этот стенд добавляет недостающий
уровень — РЕАЛЬНЫЙ, немодифицированный сторонний SMPP 3.4-стек (контекст COMP-1). Он
**дополняет, но не заменяет** автоматические оракулы: внутрирепозиторные наборы тестов остаются
машинно-проверяемой поверхностью конформности; Kannel — уровень ручной отладки и проверки
корректности на реальном стеке.

Цепочка с прокси в середине (SMPP-клиент фронтового bearerbox звонит на host-ingress прокси,
а не напрямую в opensmppbox — ЕДИНСТВЕННЫЙ перепрошитый порт от портированного источника;
вторая и последняя конфиг-дельта — MO-маршрутизация `smsbox-route`, потребовавшаяся сценарию
§6.2, — в списке честности §10), а
compose-Keycloak адъюдирует каждый bind по ROPC:

```mermaid
flowchart TD
    subgraph front["FRONT — сторона compose"]
        smsbox["smsbox :8080<br/>sendsms HTTP"]
        sqlbox["sqlbox :13002"]
        fbearer["фронтовый bearerbox :13001<br/>SMPP-клиент"]
    end

    proxy["ПРОКСИ — на хосте, собранный jar<br/>ingress :2775 · egress :14567"]

    subgraph smsc["SMSC — сторона compose"]
        osmpp["opensmppbox :14567<br/>SMPP 3.4-сервер"]
        sbearer["SMSC bearerbox :14001"]
        fake["fakesmsc FAKE1 :10004<br/>инъекция через stdin (tty)"]
    end

    keycloak["Keycloak :8443<br/>realm smpp-companions<br/>ROPC-адъюдикация"]
    pg[("pg :5432<br/>хранилище DLR")]

    smsbox <--> sqlbox
    sqlbox <--> fbearer
    fbearer -- "bind_transceiver usr1/pwd1 (SMPP 3.4)" --> proxy
    proxy -- "ROPC usr1/pwd1 (TLS, каждый bind)" --> keycloak
    proxy -- "SMPP 3.4" --> osmpp
    osmpp <--> sbearer
    sbearer <--> fake
    fbearer -.-> pg
    osmpp -.-> pg
    sbearer -.-> pg
```

Всё compose-стороны говорит через `host.docker.internal`, и каждый межсервисный переход
«шпилькой» проходит через опубликованные порты хоста — портированный паттерн, позволяющий
запущенному на хосте прокси встать в цепочку единственной правкой конфигурации. Сам прокси
работает на **хосте** как собранный jar (`java -jar` под ЕДИНСТВЕННЫМ набором операторских
флагов, reverse.mode-b — plaintext-поза топологии [B], принятый риск, чей WARN-баннер — часть
документированного запуска; рецепт — §5). Прокси на хосте — и есть смысл стенда:
доступ к отладчику и флагам.

**Почему прокси работает на хосте (`java -jar`), а не как docker-упакованный сервис.** Стенд
существует, чтобы ОТЛАЖИВАТЬ прокси против реального SMPP-стека — исследуемый компонент работает
там, где его можно инструментировать. Запуск на хосте даёт подключение отладчика IDE, полный
набор инструментов JDK (`jcmd`, JFR, дампы кучи) и мгновенное изменение операторских флагов на том
самом `java -jar`-контракте запуска (идиома `PackagedBootSmokeTest`); distroless-образ Epic-5
намеренно минимален — без оболочки и без JDK-инструментария, — а отладка внутри него означала бы
дрейф JDWP/entrypoint от поставляемой формы развёртывания. Всё остальное в цепочке (Kannel, pg,
Keycloak) — фиксированная инфраструктура, для которой compose и предназначен. Docker-упакованный
прокси не отвергнут — E2E Story 6.2 уже доказал двухконтейнерную форму end-to-end (allow +
auth-DENY) — и §5.5 документирует её как опциональный вариант для однокомандного all-compose
запуска (решение владельца ратифицировано 2026-09-17: хост остаётся умолчанием).

## 2. Состав

| Файл | Что это |
|------|---------|
| `compose.yml` | Цепочка из 8 сервисов: портированные 7 — `pg`, фронтовая сторона (`front-bearer-box`, `front-sql-box`, `front-sms-box`), сторона SMSC (`smsc-bearer-box`, `smsc-opensmpp-box`, `smsc-fake-smsc`) — плюс `keycloak` (T2); healthcheck на `pg` + обоих bearerbox + TCP-проба `keycloak`, `smsc-fake-smsc` подключён к tty для инъекций `deliver_sm`. |
| `kannel/Dockerfile` | Сборка Kannel 1.5.0 из зафиксированного исходника, портирована байт-в-байт из предпроектного окружения (gateway-1.5.0.tar.gz, `--with-pgsql`, `test/fakesmsc`, аддоны opensmppbox + sqlbox; UBI10 builder / UBI10-minimal runtime, включая quirk с симлинками automake-1.11). Без дрейфа версий, без смены дистрибутива. |
| `conf/front-kannel.conf` | Фронтовый bearerbox + smsbox: SMPP-**transceiver** `group = smsc` (`usr1`/`pwd1`, `interface-version = 34`), звонящий прокси на `host.docker.internal:2775`, и HTTP-пользователь `sendsms` (`user`/`password`). |
| `conf/front-sqlbox.conf` | Фронтовый sqlbox (плечо маршрутизации smsbox → sqlbox → bearerbox). |
| `conf/smsc-kannel.conf` | Bearerbox стороны SMSC: admin 14000, fake-SMSC `FAKE1` на 10004, pgsql-DLR (`smsc_bearer_dlr`) и группа `smsbox-route` (MO-маршрутизационная дельта T3, §10 — маршрутизирует MO от FAKE1 на соединение opensmppbox, без которой сценарий инъекции §6.2 не работает). |
| `conf/smsc-opensmppbox.conf` | opensmppbox на 14567: `smpp-logins` из `smsc-users.txt`, `route-to-smsc = FAKE1`, pgsql-DLR (`smsc_smpp_dlr`). Этот бокс — реальный SMSC, на который звонит egress прокси. |
| `conf/smsc-users.txt` | Список SMPP-учётных данных opensmppbox (`usr1 pwd1 smsc1 *.*.*.*`) — авторитет стороны SMSC, который прокачивают сценарии отказа (AD-32 случай 4). |
| `conf/db.conf` | Общее pgsql-соединение (через `host.docker.internal`). |
| `init.sql` | Таблицы pgsql-DLR (`front_bearer_dlr`, `smsc_bearer_dlr`, `smsc_smpp_dlr`), применяются postgres-entrypoint при каждом свежем старте контейнера (время жизни анонимного тома — §9). |
| `keycloak/realm-smpp-companions.json` | Realm-экспорт, который сервис `keycloak` импортирует при старте (T2): зеркалирует форму realm'а тестового `KeycloakFixture` — realm `smpp-companions`, конфиденциальный клиент `smpp-client-confidential` с ВКЛЮЧЁННЫМ Direct Access Grants (per-client, выключен по умолчанию с KC 26.2), ROPC-пользователи (§5.1). Намеренно НЕ содержит секрета клиента: Keycloak генерирует его при импорте — ЕДИНСТВЕННЫЙ секрет AD-18 в стенде, забираемый в `secrets/` (§5.1). |
| `keycloak/certs/` | TLS-материал Keycloak, скопированный байт-в-байт из зафиксированных тестовых фикстур (`proxy/src/test/resources/keycloak/certs/`): `server.pem`/`server-key.pem` (SAN `localhost`, `keycloak`, `127.0.0.1` — запущенный на хосте прокси звонит на `localhost:8443`, опциональный docker-вариант — на `keycloak:8443`), `truststore.p12` (пароль `smpp-test` — trust-якорь прокси для IdP), `ca.pem` (для проверки `curl --cacert` с хоста). Фикстурный тестовый PKI, а НЕ продакшн-секреты — тот же класс материала, который коммитит тестовый уровень; единственный настоящий секрет-по-пути стенда — секрет клиента. |
| `certs/` | TLS-материал SMPP-плеч для docker-руководств T5 (§5.6), байт-в-байт копии тех же зафиксированных тестовых фикстур: `smpp-reverse-server.pem`/`-key.pem` (SAN `localhost`/`127.0.0.1` — сертификат слушателя составного reverse; forward соединяется к `localhost` с включённой проверкой имени хоста, AD-20), `smpp-forward-client.pem`/`-key.pem` (персональный mTLS-сертификат клиента forward), `smpp-truststore.p12` (пароль `smpp-test`, якорит `CN=smpp-test-ca` — и сторона соединения, и сторона REQUIRE). Тот же фикстурный класс, что `keycloak/certs/`; держите файлы читаемыми всеми (`0644`), чтобы UID 65532 образа читал монтирования. |
| `runbooks/` | Три руководства T5 по docker-упакованным вариантам (§5.6), EN нормативен + RU-переводы: [`reverse-mode-b.md`](runbooks/reverse-mode-b.md), [`forward-reverse-mode-a.md`](runbooks/forward-reverse-mode-a.md), [`forward-reverse-mode-c.md`](runbooks/forward-reverse-mode-c.md) — по одному на вариант развёртывания; каждый инстанс прокси — distroless-образ Epic-5 на `network_mode: host` со собранным на хосте jar'ем, bind-mounted поверх копии образа. |
| `secrets/` | Создаётся оператором (gitignored, AD-18): `oidc-client-secret` — сгенерированный секрет клиента Keycloak, записывается бутстрапом §5.1. Сюда не попадает ничего коммитимого. |

### 2.1 Почему opensmppbox необходим — fakesmsc не является SMPP-конечной точкой

Egress прокси говорит на SMPP 3.4 и должен звонить SMPP-**серверу**. fakesmsc не может быть этим
сервером ни на каком порту: он — *клиент*, подключающийся К bearerbox на его порт `smsc = fake` и
говорящий на внутреннем box-протоколе Kannel — он никогда не слушает SMPP и не разбирает PDU.
Указать egress прокси на что-либо «в сторону fakesmsc» — категориальная ошибка, а не вариант
конфигурации.

opensmppbox — единственный SMPP 3.4-listener в стенде, и он несёт три работы, которые больше
никто не может выполнить:

1. **Принимает исходящий звонок egress прокси** — лицо реального SMPP-сервера: отвечает на
   `bind_transceiver`, аутентифицирует по `smpp-logins` (`conf/smsc-users.txt`) и является
   авторитетом учётных данных стороны SMSC, который прокачивает сценарий отказа при неверном
   пароле (AD-32 случай 4: его non-ROK `bind_resp` должен пройти через прокси дословно).
2. **Трансслирует SMPP ↔ box-протокол Kannel** — `submit_sm`, пришедший от прокси,
   маршрутизируется (`route-to-smsc = FAKE1`) через SMSC-bearerbox в fakesmsc, а MO-сообщение,
   введённое в stdin fakesmsc, возвращается настоящим `deliver_sm` в сторону ESME через прокси
   (свойство A-1 — привязка к соединению — на реальном стеке).
3. **Владеет своим плечом DLR** — `smsc_smpp_dlr` в pg — одно из наблюдаемых плеч DLR-кругооборота
   (именно под эту pgsql-проводку и существует зафиксированный Dockerfile).

Разделение труда, итого: **opensmppbox — SMPP-лицо стороны SMSC; fakesmsc — терминальный
фейковый центр за bearerbox** (инъекция MO через stdin, печать принятых MT в свой tty). Убрать
opensmppbox — и у прокси не останется SMPP-пира: сценарии отказа, привязки и DLR станут
недоказуемы, а fakesmsc в одиночку не может обслужить ни один из них.

## 3. Предусловия

- Docker Engine с плагином compose (проверено на Docker 29.6.1 / compose v5.3.1).
- Эти **порты хоста свободны** (стенд их публикует; паттерн «шпилька» зависит от них):

| Порт | Кто использует | Роль |
|------|----------------|------|
| 5432 | `pg` | Хранилище DLR (также доступно с хоста для наблюдений DLR-сценария) |
| 8080 | `front-sms-box` | HTTP-вход `sendsms` — точка входа сценария |
| 13000 | `front-bearer-box` | Фронтовая admin-страница статуса |
| 13001 | `front-bearer-box` | Порт фронтового бокса (sqlbox звонит на него через хост) |
| 13002 | `front-sql-box` | Порт sqlbox (smsbox звонит на него через хост) |
| 10004 | `smsc-bearer-box` | Порт fake-SMSC, к которому подключается fakesmsc |
| 14000 | `smsc-bearer-box` | Admin-страница статуса стороны SMSC |
| 14001 | `smsc-bearer-box` | Порт бокса стороны SMSC (opensmppbox звонит на него через хост) |
| 14567 | `smsc-opensmpp-box` | РЕАЛЬНЫЙ SMSC-listener — цель egress прокси |
| 8443 | `keycloak` | HTTPS-порт realm'а ROPC-адъюдикатора (запущенный на хосте прокси звонит на него как `localhost:8443`; фиксированный бинд держит issuer детерминированным, зеркалируя координаты тестовой фикстуры) |
| 2775 | — | Должен оставаться свободным: SMPP-ingress прокси (стандартный порт SMPP) — либо запущенный на хосте прокси из §5.2, либо слушатель docker-варианта из §5.6 (одинокий reverse или FORWARD составных пар — фронтовый conf в обоих случаях один и тот же `host.docker.internal:2775`) |
| 2776 | — (docker-варианты, составные) | Должен оставаться свободным для руководств mode A/C из §5.6: слушатель reverse составных вариантов (reverse уходит с 2775, чтобы его занял forward — план портов в каждом руководстве) |
| 9090 | — (прокси) | Read-only `/metrics` прокси, биндится на литерал `127.0.0.1` внутри собственного процесса прокси — занят только пока прокси работает (точка наблюдения §5.3; compose ничего здесь не публикует). Прокси из §5.2 на хосте и ПЕРВЫЙ инстанс каждого варианта §5.6 используют его |
| 9091 | — (docker-варианты, составный reverse) | `/metrics` reverse в составных вариантах §5.6 — второй процесс прокси в host network не может делить loopback-bind 9090 с первым, поэтому его руководство сдвигает порт (план портов: задокументировано, а не обнаружено на месте) |

У строки 8443 есть одно столкновение, о котором надо знать: `KeycloakContainer` тестового уровня
биндит ТОТ ЖЕ фиксированный `localhost:8443` — Keycloak стенда и одновременно идущий `:proxy:test`
live-набор соревнуются за него. Гасите одно перед другим (тестовый контейнер ждёт до своего
startup-timeout и затем валит свой тест-кейс — громко, не молча).

## 4. Подъём (ноль → здоровый стенд)

Из `sandbox/`:

```bash
docker compose up -d --build   # первый запуск компилирует Kannel из зафиксированного исходника —
                               # запаситесь терпением; последующие попадают в кэш сборки и быстры
docker compose ps              # дождитесь (healthy) у pg, front-bearer-box, smsc-bearer-box
```

Готовность по сервисам:

| Сервис | Как понять, что он поднялся |
|--------|------------------------------|
| `pg` | compose-healthcheck (`pg_isready`) зелёный. |
| `front-bearer-box` | compose-healthcheck зелёный — отвечает `curl "http://127.0.0.1:13000/status.txt?password=test"`; его список `Box connections:` содержит `smsbox:sqlbox1` и `smsbox:smsbox1` on-line. |
| `smsc-bearer-box` | compose-healthcheck зелёный — отвечает `curl "http://127.0.0.1:14000/status.txt?password=test"`, а список `SMSC connections:` содержит `FAKE1 ... (online ...)`. |
| `front-sql-box` | Admin-страницы нет (у sqlbox её не существует); зависит от `front-bearer-box: healthy`. Подключён, как только фронтовая страница статуса показывает `smsbox:sqlbox1`; его таблицы (`front_sms_log`, `front_sms_insert`) есть в `pg`. |
| `front-sms-box` | Без healthcheck (зависит от `front-sql-box`); отвечает по HTTP на 8080 — curl `sendsms` получает ответ smsbox (202 Accepted/поставлено в очередь, пока плечо SMSC недоступно — Kannel копит в очередь; connection-refused означал бы, что он не поднялся). |
| `smsc-opensmpp-box` | Admin-страницы нет; слушает 14567 (порт, на который будет звонить egress прокси); `docker compose logs smsc-opensmpp-box` показывает `Connected to bearerbox at host.docker.internal port 14001`. |
| `smsc-fake-smsc` | Остаётся подключённым (tty) к 10004; `docker compose logs smsc-fake-smsc` показывает `Entering interactive mode`, а `FAKE1` появляется online на странице статуса SMSC. |
| `keycloak` | Compose-healthcheck зелёный — TCP-подключение к HTTPS-listener'у (Keycloak стенда работает только по HTTPS, а в образе нет TLS-способного клиента, поэтому healthcheck утверждает listener; см. комментарий к сервису в `compose.yml`). ГОТОВНОСТЬ realm'а доказывается discovery-curl'ом из §5.1, который бутстрап секрета и так выполняет. |

Healthcheck в compose несут только сервисы с admin-страницами статуса (это портированный
паттерн: `pg` + два bearerbox; `keycloak` присоединяется к ним со своей TCP-пробой — сильнейший
проб, который допускает его HTTPS-only образ без клиента); остальные упорядочены `depends_on`
и проверяются своей функцией, по таблице выше.

Экспресс-проверка (всё наблюдено на проверенном подъёме):

```bash
curl "http://127.0.0.1:13000/status.txt?password=test"   # фронт: боксы on-line, DLR через pgsql
curl "http://127.0.0.1:14000/status.txt?password=test"   # SMSC: FAKE1 online
curl "http://127.0.0.1:8080/cgi-bin/sendsms?user=user&pass=password&from=79876543210&coding=0&to=79033374423&text=hello"   # -> 202
docker compose exec pg psql -U postgres -d postgres -c '\dt'   # таблицы DLR + sqlbox
curl --cacert keycloak/certs/ca.pem https://localhost:8443/realms/smpp-companions/.well-known/openid-configuration   # -> JSON, "password" в grant_types_supported
```

**Ожидаемое состояние после §4 — фронтовый SMSC недоступен, пока не запущен прокси.** Фронтовый
bearerbox звонит на `host.docker.internal:2775`, а прокси не входит в compose-файл (он работает
на хосте; рецепт запуска — §5). До этого bearerbox повторяет попытку каждые 10 с —
журнал называет это дословно:

```text
ERROR: error connecting to server `host.docker.internal' at port `2775'
ERROR: SMPP[smsc1]: Couldn't connect to SMS center (retrying in 10 seconds).
```

Это стенд, честно сообщающий состояние, а не поломка, и `front-bearer-box` остаётся healthy
(его healthcheck — admin-страница, а не SMPP-линк). Сопряжение происходит, когда прокси запущен
по рецепту §5; фронтовый bearerbox переподключится сам, по своему циклу повторных попыток выше.

## 5. Рецепт запуска прокси (Keycloak + собранный jar)

Поставка T2, машинно исполнена с этой страницы на проверенном подъёме (каждое наблюдение ниже
наблюдалось вживую; таблица мутаций в §5.4 прогнана так же). Рецепт запускает РЕАЛЬНЫЙ артефакт —
собранный boot-jar под ЕДИНСТВЕННЫМ набором операторских флагов, `reverse.mode-b` (в точности
plaintext-поза топологии [B]) — с ingress 2775 для фронтового bearerbox, egress на
опубликованный opensmppbox 14567 и OIDC на compose-Keycloak. WARN-баннер Mode B — часть
документированного запуска с принятым риском, а не шум, который надо заглушить.

### 5.1 Сервис Keycloak и однократный бутстрап секрета (AD-18)

Compose-сервис `keycloak` (T2) зеркалирует форму realm'а тестового `KeycloakFixture`, чтобы IdP
стенда совпадал с тем, против которого прокси уже доказан: зафиксированный
`quay.io/keycloak/keycloak:26.7.0` (пол ≥26.7.0 из вердикта жизнеспособности 3.1), проверенный
запуск `start --import-realm --hostname-strict=false` с серверным сертификатом фикстуры (SAN
`localhost`/`keycloak`/`127.0.0.1`), только-HTTPS (`KC_HTTP_ENABLED=false` — линк к провайдеру
обязан быть TLS, SEC-053) и фиксированный бинд `8443:8443`, держащий issuer детерминированным
(`https://localhost:8443/realms/smpp-companions`). Две намеренные позы, отличные от тестового
контейнера, обе прокомментированы в `compose.yml`: SSLContext продакшн-прокси к IdP —
только-trust (без клиентского сертификата к провайдеру — клиентской аутентификацией является
ROPC `client_secret`), поэтому `KC_HTTPS_CLIENT_AUTH` не задаётся; и admin-окружение использует
bootstrap-написание KC 26 (`KC_BOOTSTRAP_ADMIN_*`), чтобы не получать deprecation-предупреждение
устаревшего `KEYCLOAK_ADMIN`.

Принципалы realm'а (в `keycloak/realm-smpp-companions.json`, зеркалирует realm фикстуры с
собственными пользователями стенда):

| Принципал | Значение | Роль в стенде |
|-----------|----------|---------------|
| Клиент | `smpp-client-confidential` — конфиденциальный, DAG **включён** (`directAccessGrantsEnabled: true` — per-client и ВЫКЛЮЧЕН по умолчанию с KC 26.2; без него каждый bind отказывает на первом же bind) | ROPC-клиент прокси; его секрет — ЕДИНСТВЕННЫЙ секрет AD-18 в стенде |
| Пользователь | `usr1` / `pwd1` | Счастливый путь — в точности `smsc-username/-password` фронтового bearerbox (`conf/front-kannel.conf`), поэтому ОБА авторитета принимают: ROPC разрешает, а `smsc-users.txt` opensmppbox (`usr1 pwd1 …`) отвечает ROK → bind сопрягается |
| Пользователь | `usr2` / `pwd2` | Сценарий отказа при неверном SMSC-креде (T3): валиден в realm (ROPC разрешает), ОТСУТСТВУЕТ в `smsc-users.txt` (opensmppbox отвечает non-ROK → проходит дословно, AD-32 случай 4). Положен сейчас, потому что правка realm'а запускает цикл перезапроса секрета ниже |

**Единственный секрет — по пути (AD-18).** Realm-экспорт намеренно НЕ содержит секрета клиента:
Keycloak ГЕНЕРИРУЕТ его при импорте, а оператор забирает его в gitignored
`sandbox/secrets/oidc-client-secret` (каталог игнорируется через `.gitignore`; `git status`
никогда не видит файл). Стенд — отладочная реплика deploy-контракта, а не место, где значение
секрета — «просто песочные данные». Бутстрап (из `sandbox/`, один раз на свежий контейнер
Keycloak):

```bash
# (a) готовность realm'а, авторитетно — discovery-документ по TLS, заякорен коммитнутым CA:
curl --cacert keycloak/certs/ca.pem \
     https://localhost:8443/realms/smpp-companions/.well-known/openid-configuration
# -> JSON с "issuer":"https://localhost:8443/realms/smpp-companions" и "password" в grant_types_supported

# (b) вход kcadm (коммитнутый truststore заякоривает self-signed сертификат сервера внутри контейнера):
docker compose exec keycloak /opt/keycloak/bin/kcadm.sh config truststore \
     /opt/keycloak/conf/truststore.p12 --trustpass smpp-test
docker compose exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
     --server https://localhost:8443 --realm master --user admin --password admin

# (c) забрать СГЕНЕРИРОВАННЫЙ секрет и записать в gitignored-файл (AD-18):
CID=$(docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh get clients -r smpp-companions \
      -q clientId=smpp-client-confidential --fields id --format csv --noquotes)
docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh get "clients/$CID/client-secret" -r smpp-companions
#   -> {"type":"secret","value":"<сгенерирован>"} — затем:
mkdir -p secrets && printf '%s\n' '<сгенерирован>' > secrets/oidc-client-secret && chmod 0600 secrets/oidc-client-secret
```

Семантика регенерации (та же форма, что у pg, §7): `stop`/`start` сохраняет импортированный realm
и его секрет; пересоздание (`down` и затем `up`) переимпортирует коммитнутый realm и
РЕГЕНЕРИРУЕТ секрет — прокси после этого отказывает каждому bind (401 `invalid_client`), пока вы
не повторите (b)+(c). Конфиг `kcadm` (truststore + сессия) тоже живёт внутри контейнера и умирает
вместе с ним — повторяйте оба шага после любого пересоздания. Альтернатива (c) без инструментария:
admin-консоль `https://localhost:8443/admin` (admin/admin) → Clients → `smpp-client-confidential`
→ Credentials → скопировать секрет в файл.

### 5.2 Сборка и запуск

Из **корня репозитория** (путь к jar и пути секретов ниже — от корня):

```bash
./gradlew :proxy:bootJar
java --enable-preview -XX:+UseZGC -XX:MaxDirectMemorySize=6442450944 -Djava.net.preferIPv4Stack=true \
     -jar proxy/build/libs/proxy.jar \
     --companion.bind.host=0.0.0.0 \
     --companion.bind.port=2775 \
     --companion.reverse.mode-b.smsc.host=127.0.0.1 \
     --companion.reverse.mode-b.smsc.port=14567 \
     --companion.reverse.mode-b.acknowledged=true \
     --companion.reverse.mode-b.oidc.provider-url=https://localhost:8443/realms/smpp-companions \
     --companion.reverse.mode-b.oidc.client-id=smpp-client-confidential \
     --companion.reverse.mode-b.oidc.client-secret-path=sandbox/secrets/oidc-client-secret \
     --companion.reverse.mode-b.oidc.trust-store.path=sandbox/keycloak/certs/truststore.p12 \
     --companion.reverse.mode-b.oidc.trust-store.password=smpp-test \
     --companion.reverse.mode-b.oidc.timeout=4s \
     --companion.reverse.mode-b.oidc.max-in-flight=64
```

Четыре JVM-флага — ЕДИНСТВЕННЫЙ операторский набор: эта страница ссылается на
[`docs/operator-jvm-flag-contract.md`](../docs/operator-jvm-flag-contract.md) и никогда не
дублирует его обоснование (смена флага — это история, затрагивающая страницу контракта, константу
smoke-теста, ENTRYPOINT Docker-образа — и, по обязанности ревью, этот рецепт). Gradle-задача
`bootJar` отслеживает свои входы, поэтому обычный путь никогда не подаёт устаревший jar
(проводка `PackagedBootSmokeTest` — второе плечо §5.4 потому достижимо только если намеренно
указать путь `-jar` куда-то устаревшее).

Почему именно эти параметры ячейки (каждый отражает факт проводки стенда):

| Параметр | Почему |
|----------|--------|
| `bind.host=0.0.0.0` | Фронтовый bearerbox достигает прокси через `host.docker.internal` → адрес шлюза хоста — listener не должен быть ограничен loopback. Это plaintext-плечо Mode B, биндящее все интерфейсы: поза стенда (совет deployment guide по ограничению области применим к реальным развёртываниям). |
| `bind.port=2775` | Контракт проводки стенда (`conf/front-kannel.conf` звонит на `host.docker.internal:2775`). Это же умолчание yml — указано для самодокументирования. |
| `smsc.host=127.0.0.1`, `smsc.port=14567` | Прокси звонит на compose-опубликованный opensmppbox по loopback хоста — реальный SMPP 3.4-сервер стороны SMSC (§2.1). |
| `acknowledged=true` | Opt-in Mode B (SEC-052) — без него загрузка отказывает; с ним — WARN-баннер ниже. |
| `provider-url=https://localhost:8443/realms/smpp-companions` | База realm'а compose-Keycloak (именно БАЗА REALM, а не корень хоста — token-endpoint выводится как `<provider-url>/protocol/openid-connect/token`). SAN `localhost` серверного сертификата удовлетворяет hostname-верификации JDK HttpClient против выделенного trust-store. |
| `client-secret-path` | Файл из §5.1 — канал AD-18 deploy-контракта, в стенде без изменений. |
| `trust-store.path`/`password` | Коммитнутый фикстурный PKI (`keycloak/certs/truststore.p12`, пароль `smpp-test`), заякоривающий CA стенда — никогда JDK `cacerts` (AD-13). |
| `timeout=4s`, `max-in-flight=64` | Документированные умолчания адаптера, указаны явно (должны укладываться в бюджет adjudication-deadline). |

Всё остальное едет на умолчаниях `application.yml` jar'а (`companion.metrics.port=9090`,
`companion.shutdown.drain-timeout=10s`, тройка memory с `budget-check: fail`, списки TLS) — те же
умолчания, на которые опирается каждый документированный запуск.

### 5.3 Ожидаемые наблюдения (по порядку — доказательство рецепта)

На stdout прокси (чистый поток JSON-lines):

1. **Баннер Mode B** — ОДНА WARN-строка JSON с дословным текстом `MODE B (plaintext) is ACTIVE on
   a REVERSE instance` (`CompanionModeBWarning`) — поза принятого риска, часть запуска.
2. **Строка готовности** — `"event":"startup_summary"` с `"role":"reverse"`, `"mode":"b"`,
   `"smpp_bind_host":"0.0.0.0"`, `"smpp_bind_port":2775`, `"metrics_port":9090`,
   `"routing_system_ids":[]` и интерлок AD-30 `"memory_budget_bytes":6442450944` ==
   `"direct_memory_ceiling_bytes":6442450944` (вывод умолчаний yml 65536 × 64 × 1024 × 1.5 против
   флага контракта — сам факт достижения ready ЕСТЬ прохождение `budget-check: fail`).
3. **Сопряжение, в пределах ~10 с** (интервал повторных попыток фронтового bearerbox):
   `"event":"bind_accept"`, `"system_id":"usr1"`, `"outcome":"coupled"` — bind фронта пересёк
   прокси, ROPC-успех против compose-Keycloak (секрет из §5.1 делает реальную работу), дозвон до
   opensmppbox и сопряжение по его ROK.

Затем тот же факт с двух других точек наблюдения:

4. **`/metrics`** (loopback, read-only): `relay_binds_unknown_total 1.0`. Заметка честности:
   I/O-матрица спецификации формулирует это как "`relay_binds_accepted_total` в `/metrics`" — на
   REVERSE-ячейке у счётчика accepted нет предрегистрированного ряда, потому что reverse-ячейки не
   несут таблицы маршрутизации, а AD-19 запрещает свободные метки `system_id`; сопряжение поэтому
   попадает в немаркированный счётчик вне таблицы (`relay.binds.unknown` →
   `relay_binds_unknown_total`). Маркированный ряд `relay_binds_accepted_total{system_id=…}`
   существует только на forward-ячейках с таблицами маршрутизации. После первого интервала
   keepalive подрастают `relay_pdus_total{direction="INGRESS"}` и `{direction="EGRESS"}` —
   `enquire_link` Kannel проходит сопряжённую пару в обе стороны (keepalive-сценарий T3, здесь
   уже виден).
5. **Страница статуса фронта** — `curl "http://127.0.0.1:13000/status.txt?password=test"` теперь
   показывает `smsc1[smsc1]    SMPP:host.docker.internal:2775/2775:usr1:smsc1 (online …)` —
   взгляд самого Kannel на сопряжение. ERROR-строки переподключения из §4 прекращаются.
6. **Журнал opensmppbox** — ответ реального SMSC на relayed-bind:
   `docker compose logs smsc-opensmpp-box` показывает дамп PDU `bind_transceiver_resp` с
   `command_id: 2147483657 = 0x80000009`, `command_status: 0 = 0x00000000` — ROK, пересёкший
   прокси обратно к фронту.

Демонтаж (проход AD-22, здесь повторно наблюдаемый как часть рецепта): `kill -TERM <pid>` →
WARN-drain — `shutdown drain deadline (PT10S) expired — force-closed 1 live pair(s) as
SHUTDOWN_DRAIN (OBS-020: …)` (Kannel никогда не полузакрывает свою сторону, поэтому проход всегда
форс-закрывает на дедлайне — здесь это ожидаемо, а не поломка) → процесс завершается с кодом
**143** (JVM-конвенция hook-completed-SIGTERM; крэш — 1, форс-килл — 137). Фронтовый bearerbox
возвращается к циклу повторных попыток из §4 и переподключится при следующем запуске.

### 5.4 Когда рецепт падает громко (проверено вживую — мутационный прогон T2 и прогоны отказов)

Шаги ожидаемых наблюдений рецепта и есть детектор отказа — запуск, который не сопрягается,
громко отсутствует везде, где должен присутствовать. Плечи неверного порта, неверного секрета и
лежачего Keycloak прогнаны вживую на этом стенде; последние две строки опираются на
машинно-закреплённые внутрирепозиторные доказательства (проводка no-stale-jar из
`PackagedBootSmokeTest`; живые тексты отказов DEPLOY-009):

| Сломанный вход | Что наблюдается (все три точки наблюдения) |
|----------------|---------------------------------------------|
| **Неверный порт egress** (живой прогон: `smsc.port=14568` — никто не слушает) | Stdout прокси: `startup_summary` появляется, затем ТИШИНА — `bind_accept` нет никогда (и нет `bind_reject`: вердикт был Allow, сбой — послевердиктный дозвон — закреплённые триггеры AD-27 логируют только вердикты верификатора). Журнал фронта, каждые 10 с: `ERROR: SMPP[smsc1]: SMSC rejected login to transmit, code 0x0000000d (Bind Failed).` — коллапсированный генерический код AD-33 на проводе. `/metrics`: `relay_connections_closed_total{direction="INGRESS",reason="EGRESS_CONNECT_FAILED"}` растёт на 1 за попытку; `relay_binds_*` остаются 0. |
| **Устаревший jar** (путь `-jar` указан на старую сборку) | Структурно предотвращено на обычном пути — `./gradlew :proxy:bootJar` отслеживает входы и пересобирает при любом изменении исходников (проводка no-stale-jar из `PackagedBootSmokeTest`). Если намеренно указать путь на устаревшее, сопряжение падает ровно как плечо неверного порта выше (факты проводки jar'а больше не соответствуют стенду). |
| **Несовпадение секрета** (живой прогон: запуск указан на файл с неверным значением — случай устаревания после пересоздания из §5.1) | ROPC 401 `invalid_client` → JSON-строки `bind_reject` на каждую попытку фронта: `verdict":"DenyInvalid"` + `bind_resp_command_status":"0x0000000D"`; `relay_binds_rejected_total` растёт. Строка фронта на проводе — ТОТ ЖЕ `code 0x0000000d (Bind Failed)`, что и у плеча неверного порта — отказ богат только в журналах прокси. |
| **Keycloak лежит / недостижим** (живой прогон: `docker compose stop keycloak`, секрет верный) | Сетевая ошибка ROPC → `bind_reject` (`verdict":"DenyIndeterminate"`) на каждую попытку, на проводе `0x0000000D` — НА ПРОВОДЕ неотличимо от плеча 401 (AD-33; нет перечисления доступности IdP); два плеча различаются ТОЛЬКО полем вердикта в журнальных строках прокси. |
| **Отсутствует/нечитаем файл секрета** | Сама загрузка отказывает до бинда любого listener'а — exit 1 с отказом SEC-060/AD-18, называющим путь (таблица §8). |

### 5.5 Опциональный вариант — прокси в compose (docker)

Ратифицированное умолчание — запуск на хосте выше. Для однокомандного all-compose запуска
distroless-образ Epic-5 может занять место прокси в той же цепочке (форму, которую E2E Story 6.2
уже доказал end-to-end — allow + auth-DENY + drain; этот вариант документирован, а не
перепроверен здесь, и отличия проводки — ровно эти):

```bash
./gradlew :proxy:dockerImage        # собирает и тегирует smpp-proxy:local (те же байты jar'а)
docker run -d --name smpp-proxy \
      --network smpp-bmad-sandbox_default \
      -p 2775:2775 \
      -v "$(pwd)/sandbox/secrets/oidc-client-secret:/run/secrets/oidc-client-secret:ro" \
      -v "$(pwd)/sandbox/keycloak/certs/truststore.p12:/run/secrets/idp-truststore.p12:ro" \
      smpp-proxy:local \
      --companion.bind.host=0.0.0.0 \
      --companion.reverse.mode-b.smsc.host=smsc-opensmpp-box \
      --companion.reverse.mode-b.smsc.port=14567 \
      --companion.reverse.mode-b.acknowledged=true \
      --companion.reverse.mode-b.oidc.provider-url=https://keycloak:8443/realms/smpp-companions \
      --companion.reverse.mode-b.oidc.client-id=smpp-client-confidential \
      --companion.reverse.mode-b.oidc.client-secret-path=/run/secrets/oidc-client-secret \
      --companion.reverse.mode-b.oidc.trust-store.path=/run/secrets/idp-truststore.p12 \
      --companion.reverse.mode-b.oidc.trust-store.password=smpp-test \
      --companion.reverse.mode-b.oidc.timeout=4s \
      --companion.reverse.mode-b.oidc.max-in-flight=64
```

Отличия от рецепта на хосте, каждое несущее нагрузку: контейнер присоединяется к compose-сети
стенда (явное имя проекта → `smpp-bmad-sandbox_default`), поэтому резолвит `keycloak` и
`smsc-opensmpp-box` ПО ИМЕНАМ СЕРВИСОВ — SAN `keycloak` серверного сертификата существует ровно
для этого, а дозвон к SMSC минует «шпильку» через хост; `-p 2775:2775` перепубликует ingress для
`host.docker.internal:2775` фронтового bearerbox (conf без изменений); два файла секретов
монтируются read-only по конвенционным путям `/run/secrets` (режим `0444` на файлах хоста, чтобы
UID 65532 мог их читать — правила монтирования deployment guide также запрещают JVM-флаги через
env и ограничения памяти ниже бюджета AD-30). Наблюдения — список §5.3, где stdout — это
`docker logs smpp-proxy`, а демонтаж — `docker stop --timeout 30 smpp-proxy` (exit 143). Что
ТЕРЯЕТСЯ — и есть смысл §1: ни отладчика, ни набора инструментов JDK, ни правок флагов — поэтому
умолчанием остаётся запуск на хосте.

**T5 повысил docker-упакованный прокси до полноценных руководств (владелец, 2026-09-17):** три
руководства по вариантам в `runbooks/` (§5.6 ниже) — теперь каноническая docker-документация:
по одному на вариант развёртывания, каждый контейнер прокси — `network_mode: host` со собранным
на хосте jar'ем, bind-mounted поверх копии образа. Этот §5.5 остаётся тем, чем был: вариантом на
BRIDGE-СЕТИ (compose-сеть, dial по именам сервисов, `-p 2775:2775`) — снимок однокомандного
all-compose запуска; форма host-network из руководств — та, за которой нужно идти.

### 5.6 Руководства по docker-упакованным вариантам (T5)

По одному руководству на вариант развёртывания; все три делят ОДНУ docker-форму: distroless-образ
Epic-5 (`./gradlew :proxy:dockerImage` → `smpp-proxy:local`), контейнер на **`network_mode: host`**
(прокси встаёт в сетевой namespace хоста — его dial на `127.0.0.1` достигает compose-опубликованных
14567/8443, его слушатель 2775 — это 2775 самого хоста, а `/metrics` читается с loopback хоста) и
**собранный на хосте jar, bind-mounted поверх `/opt/proxy.jar` образа** — история отладки, которую
docker-форма сохраняет: пересборка `./gradlew :proxy:bootJar` + `docker restart` подменяет jar
(РАБОТАЮЩИЙ контейнер держит старый inode; перезапуск заново разрешает путь — механика проверена
вживую, 2026-09-18), пересборка образа в цикле не нужна.

| Руководство | Вариант | Наблюдаемое сопряжение |
|-------------|---------|------------------------|
| [`runbooks/reverse-mode-b.md`](runbooks/reverse-mode-b.md) (+ [RU](runbooks/reverse-mode-b.ru.md)) | Одиночный reverse, legacy-клиенты напрямую — вариант §5 в docker-форме; без сертификатов, баннер Mode B как контракт | `bind_accept … coupled` на единственном инстансе; `relay_binds_unknown_total` |
| [`runbooks/forward-reverse-mode-a.md`](runbooks/forward-reverse-mode-a.md) (+ [RU](runbooks/forward-reverse-mode-a.ru.md)) | Два инстанса: forward с plaintext-плечом доверенной сети + соединение one-way TLS; баннер Mode A и его смягчение ACL-isolate вживую (reverse ограничен loopback) | `bind_accept` на ОБОИХ инстансах; маркированный `relay_binds_accepted_total{system_id="usr1"}` у forward |
| [`runbooks/forward-reverse-mode-c.md`](runbooks/forward-reverse-mode-c.md) (+ [RU](runbooks/forward-reverse-mode-c.ru.md)) | Два инстанса, mTLS-соединение (топология `DockerRig.launchComposedModeCChain` против реальной цепочки Kannel); без баннера — затвор и есть рукопожатие REQUIRE | `bind_accept` на ОБОИХ; проба затвора mTLS (dial без сертификата никогда не достигает SMPP) |

Общий план портов всех трёх (каждое руководство несёт свою таблицу): одиночный reverse и FORWARD
составных пар держат **2775** — фронтовый conf (`host.docker.internal:2775`) не меняется между
вариантами, — **reverse составных уходит на 2776**, а `/metrics` второго процесса прокси уходит на
**9091** (два процесса в host network не делят loopback-bind 9090). Все три руководства пройдены
дословно до `bind_accept coupled` на живом стенде (2026-09-18), с отправками; их таблицы отказов
несут живые плечи (лежачий reverse в составной цепочке; отказы монтирования UID 65532; коллизия
metrics-порта). На составных вариантах вживую прошли сценарий отправки §6.1 (байт-в-байт до
fakesmsc через оба плеча) и keepalive §6.3 — отправки выше прогнаны через каждый. Сценарий отказа
§6.4 **D1** в составной форме НЕ проходит без изменений: `usr2` нет в таблице маршрутизации
forward (её единственная запись — `usr1`), и FORWARD сам отказывает бину — генерический 0x0d
AD-33 на проводе, log-only WARN `routing miss: system_id not in the routing table — AD-33 deny
(AD-29/AD-11)`, БЕЗ соединения (opensmppbox не видит bind, поэтому дословный non-ROK-проброс
AD-32 случай 4 в этой форме недостижим — D1 принадлежит одно-проксивым позам: запуску на хосте из
§5 и руководству mode B). **D2** (неверный пароль у маршрутного `usr1`) доходит до reverse и
отказывает там — форма D2 из §6.4 без изменений; эту строку routing-miss содержат таблицы отказов
составных руководств.

## 6. Сценарии проверки корректности (T3)

Доказательный артефакт, ради которого стенд существует. Каждый сценарий — процедура против
сопряжённой по §5 цепочки с ЗАРАНЕЕ НАЗВАННЫМ ожидаемым наблюдением на каждом плече —
Ops-tier-форма плана A-1 в миниатюре (оракул, предусловия, как выглядит PASS). Always-правило,
которым управлялось написание: сценарий с неназванным или ненаблюдаемым ожиданием не поставляется.
Каждое наблюдение ниже исполнено вживую на этом стенде (2026-09-17); где значение зависит от
прогона, таблицы называют ДЕЛЬТУ для наблюдения, а не абсолют.

Предусловия всех четырёх: стенд здоров по §4, прокси запущен по §5.2, сопряжение наблюдено по §5.3
(`bind_accept … coupled`; страница статуса фронта показывает `smsc1 … (online`).

### 6.1 Счастливая отправка — `submit_sm` через релей + кругооборот DLR

```bash
curl "http://127.0.0.1:8080/cgi-bin/sendsms?user=user&pass=password&dlr-mask=31&from=79876543210&coding=0&to=79033374423&text=hello"
```

| Плечо | Ожидаемое наблюдение (куда смотреть) |
|-------|--------------------------------------|
| smsbox принимает | HTTP `202`, тело `0: Accepted for delivery`. |
| sqlbox журналирует MT | В pg `front_sms_log` появляется строка `momt=MT`: `msgdata=hello`, `dlr_mask=31`, `boxc_id=smsbox1`. |
| резервирования DLR | В pg `front_bearer_dlr` появляется строка (`mask=31`, `status=0`, пустой `url` — `dlr-url` не запрашивался); в `smsc_bearer_dlr` — своя (`mask=19` — SMSC-сторонняя реинтерпретация Kannel); `smsc_smpp_dlr` в этом потоке остаётся пустой. |
| submit пересекает релей | `/metrics`: `relay_pdus_total{direction="INGRESS"}` +1 (`submit_sm`) и `{direction="EGRESS"}` +1 мгновениями позже (`submit_sm_resp`). |
| реальный SMSC отвечает | `docker compose logs smsc-opensmpp-box`: дамп `Got PDU:` с `type_name: submit_sm`, затем `Sending PDU:` `type_name: submit_sm_resp` (`command_id: 2147483652 = 0x80000004`, `command_status: 0`) с `message_id: "<ваш>"`. |
| фейковый центр квитует | `docker compose logs smsc-fake-smsc`: `DEBUG: Got message 1: <79876543210 79033374423 text hello>` — текст не повреждён сквозь прокси + opensmppbox + bearerbox. |
| DLR возвращается ЧЕРЕЗ прокси | opensmppbox: `Sending PDU:` `type_name: deliver_sm` (short_message `id:<mid> sub:001 dlvrd:001 submit date:… done date:… stat:DELIVRD err:000`, `message_state: 2`, `receipted_message_id: "<mid>"`), затем `Got PDU:` `type_name: deliver_sm_resp` (`command_status: 0` — ответ ФРОНТА, прошедший обратно). `/metrics`: +1 `EGRESS` (DLR) +1 `INGRESS` (его resp). |
| фронт завершает DLR | `docker compose logs front-bearer-box`: `DEBUG: removing DLR from database`; в pg `front_sms_log` добавляются две строки `momt=DLR` — `ACK/` (`dlr_mask=8`, sme-ack, который Kannel выводит сам из ROK `submit_sm_resp`) и текст `id:…stat:DELIVRD…` (`dlr_mask=1`); smsbox пишет `Starting delivery report <user> from <79876543210>` и безобидную пару без url: `ERROR: URL <> doesn't start with 'http://' nor 'https://'` / `Couldn't send request to <>`. |
| страницы статуса считают | фронт 13000: у строки `smsc1` `sent: sms` +1, после DLR-ов `rcvd: dlr` +2; SMSC 14000: FAKE1 `sent: sms 1 / dlr 0`, `rcvd: dlr 1`. |

Чтение целостности транзита: текст, покинувший smsbox, — тот же, что напечатал fakesmsc, а
`receipted_message_id` DLR — тот же `message_id`, что выдал opensmppbox: сквозной проход через
релей без потерь, дублей и переписывания (строки резервирования в этом стенде без `dlr-url`
остаются с `status=0` — завершение DLR видно по строкам `front_sms_log` и строке журнала
`removing DLR from database`). Для ПОБАЙТОВОГО взгляда на пересечение релея перезапустите прокси
с TRACE-плечом из §7: submit появится как
`relayed pdu: direction=INGRESS command_id=0x4 length=66 body=0x00000042…`, текст читается в hex.
Submit, потерянный/удвоенный/искажённый на любом плече, — дефект REL-1 → дисциплина находок §11,
никакой подгонки.

### 6.2 `deliver_sm` в сторону ESME — инъекция MO на стороне SMSC

Свойство A-1 (привязка к соединению) на реальном стеке: MO, введённый в фейковый центр,
возвращается настоящим `deliver_sm` по ТОМУ ЖЕ сопряжённому плечу, что отправляло MT.

Предусловие — конфиг-дельта T3: `conf/smsc-kannel.conf` несёт `group = smsbox-route`,
маршрутизирующий трафик `FAKE1` на `usr1` (соединение opensmppbox). Bearerbox Kannel раздаёт MO
боксам только БЕЗ boxc-id; opensmppbox регистрируется как `usr1`
(`use-systemid-as-smsboxid = true`), поэтому без маршрута каждая инъекция умирает в очереди с
`WARNING: smsbox_list empty!` — наблюдено вживую; потому дельта и существует (§10).

Инъекция (сервис подключён к tty; `docker attach` требует терминал на ВАШЕЙ стороне):

```bash
docker compose attach smsc-fake-smsc     # интерактивно: вводите строку, отсоединение Ctrl-p Ctrl-q
79033374423 79876543210 text hello from the mobile
```

Синтаксис строки: `<отправитель> <получатель> text <сообщение>` — первым отправитель (мобильный),
затем получатель (короткий номер), затем ОБЯТЕЛЬНОЕ кодовое слово `text`, затем тело. Скриптовая
подача без терминала: держать fifo через `script -qec "docker attach --sig-proxy=false <контейнер>"
/dev/null` (простой канал отклоняется с `cannot attach stdin to a TTY-enabled container because
stdin is not a terminal`).

| Плечо | Ожидаемое наблюдение |
|-------|----------------------|
| fakesmsc принимает | его tty печатает `DEBUG: fakesmsc: sent message N`. ЗАМЕТКА: он печатает это и для кривой строки — синтаксис оценивает BEARERBOX: `docker compose logs smsc-bearer-box` показывает `WARNING: smsc_fake: invalid message syntax from client, ignored` для плохой строки, `DEBUG: smsc_fake: new message received` для хорошей. |
| MO становится `deliver_sm` | opensmppbox: `Sending PDU:` `type_name: deliver_sm` с `source_addr: "79033374423"`, `destination_addr: "79876543210"`. |
| пересекает релей | `/metrics`: +1 `{direction="EGRESS"}` (`deliver_sm`), затем +1 `{direction="INGRESS"}` (`deliver_sm_resp`). |
| фронт принимает | `docker compose logs front-bearer-box`: дамп `SMPP[smsc1]: Got PDU:` показывает ТЕ ЖЕ октеты `short_message` (`data: … hello from the m…obile`); на странице статуса фронта `rcvd: sms` +1. |
| ESME отвечает | opensmppbox: `Got PDU:` `type_name: deliver_sm_resp`, `command_status: 0`. |

Доставка не на то плечо — `deliver_sm`, пришедший куда угодно, кроме породившей пары, — класс
дефекта привязки → bounce (§11). (Стенд с одной парой демонстрирует свойство; фальсификация на
нескольких парах — дело плана A-1, который этот стенд дополняет, но не заменяет.)

### 6.3 `enquire_link` — keepalive Kannel через сопряжённую пару

Пассивный сценарий: запустить, сопрячь, наблюдать. SMPP-клиент Kannel опрашивает каждые
`enquire-link-interval` — по умолчанию 30 с (conf его не задаёт; наблюдено: первый `enquire_link`
на сопряжение + 30 с, затем по одному за ~30 с).

| Наблюдение | Где |
|------------|-----|
| `relay_pdus_total{direction="INGRESS"}` и `{direction="EGRESS"}` — КАЖДЫЙ +1 за интервал: `enquire_link` туда, его resp обратно, никогда не расходясь | `/metrics` |
| сами PDU | журнал opensmppbox: `Got PDU:` `type_name: enquire_link` (`command_id: 21 = 0x00000015`), ответ `Sending PDU:` `type_name: enquire_link_resp`; журнал фронтового bearerbox — зеркальная пара (`SMPP[smsc1]: Sending enquire link:`). |
| сессия живёт сквозь окна простоя | страница статуса фронта: `smsc1 … (online Ns` — N растёт неограниченно, пока живы оба конца. |

**Заметка keepalive-против-`pre-couple-idle-timeout` (ограничение принятого риска, сформулировано
для этого стенда).** После сопряжения `enquire_link` — ОПАКОВЫЙ релей в обе стороны (AD-3/AD-32):
прокси никогда не отвечает на него и никогда не синтезирует `enquire_link_resp` — отвечает
opensmppbox; keepalive-трафик стоит прокси один релей и ничего о нём не сообщает. До сопряжения —
наоборот: любой не-bind PDU, включая `enquire_link`, закрывается молча, без ответа (равномерное
правило AD-32; окна до сопряжения — `companion.bind.adjudication-deadline` 4 с и
`companion.bind.pre-couple-idle-timeout` 30 с по умолчанию). Ограничение: интервал keepalive
клиента должен превышать его задержку bind — здесь окно до сопряжения ограничено дедлайном 4 с
(внутри него сидит `oidc.timeout=4s` из §5.2) — на порядок меньше 30-секундного интервала Kannel, —
и Kannel опрашивает только УЖЕ сопряжённую сессию, так что фронт этого стенда правило не нарушает.
Клиент, чей keepalive срабатывает внутри окна адъюдикации, увидел бы попытку bind, молча закрытую
как keepalive-разрыв: поведение by-design, а не дефект прокси (interop-заметка реестра принятых
рисков; carrier-сторонняя проверка — в плане A-1).

### 6.4 Сценарии отказа — где какой отказ всплывает (провод против журнала против метрики)

Два сценария и один операционный навык: чтение отказа bind по его ПОВЕРХНОСТИ. Все плечи отказов
коллапсируют к ОДНОМУ коду на проводе — различие живёт в журналах/метриках прокси и в том, видел
ли bind вообще SMSC. (§5.4 уже прогоняет вживую плечи OIDC-стороны — неверный секрет клиента и
лежачий Keycloak; эти два дополняют набор кредом, которым владеет ФРОНТ.)

**D1 — неверный кред SMSC (AD-32 случай 4: SMSC — единственный авторитет учётных данных).**
`smsc-username/-password` фронтового conf валидны в Keycloak и отсутствуют в `smsc-users.txt`:

```bash
# conf/front-kannel.conf: smsc-username = usr2 / smsc-password = pwd2 (пользователь realm, существующий ровно для этого)
docker compose restart front-bearer-box && docker compose up -d     # зависимые следуют за bearerbox
```

**D2 — неверный кред OIDC (AD-33: собственный отказ прокси коллапсирует на проводе).** Валиден
везде, кроме Keycloak:

```bash
# conf/front-kannel.conf: smsc-password = что-угодно-кроме-pwd1 (username остаётся usr1)
docker compose restart front-bearer-box && docker compose up -d
```

Восстановление в обоих случаях — вернуть conf и перезапустить так же: сопряжение возвращается в
пределах одного 10-секундного повтора (наблюдено дважды).

| Поверхность | D1 (SMSC отказывает) | D2 (Keycloak отказывает) |
|-------------|----------------------|--------------------------|
| Провод (журнал фронта, каждые 10 с) | `ERROR: SMPP[smsc1]: SMSC rejected login to transmit, code 0x0000000d (Bind Failed).` | ИДЕНТИЧНАЯ строка |
| Stdout прокси | ТИШИНА — ни `bind_accept`, ни `bind_reject`, ни WARN: вердикта не было, ответ SMSC и есть ответ (закреплённые триггеры AD-27) | по строке `bind_reject` на повтор: `"verdict":"DenyInvalid"`, `"bind_resp_command_status":"0x0000000D"` — богатая причина живёт ТОЛЬКО здесь |
| `/metrics` | `relay_connections_closed_total{direction="INGRESS",reason="BIND_FAILED_NON_ROK"}` И `{direction="EGRESS",…}` +1 за повтор на ОБОИХ плечах; `relay_binds_rejected_total` не растёт; `relay_binds_unknown_total` не растёт | `relay_binds_rejected_total` +1 за повтор И `relay_binds_unknown_total` +1 (reverse-ячейка считает каждый отказ в обоих); `relay_connections_closed_total{direction="INGRESS",reason="BIND_REJECTED"}` +1; НА EGRESS-плече активности нет |
| Взгляд SMSC | журнал opensmppbox: `Got PDU:` `type_name: bind_transceiver` с `system_id: "usr2"`, ответ — ЕГО СОБСТВЕННЫЙ `bind_transceiver_resp`: `command_status: 13 = 0x0000000d`, `system_id: NULL` — и ИМЕННО эти байты доходят до фронта неизменными (дословный проброс, AD-32 случай 4) | opensmppbox НЕ ВИДИТ ничего (ноль дампов `bind_transceiver`) — отказ сработал до проброса |

Заметка к D1, которую стоит усвоить: opensmppbox сам отвечает `0x0000000d`, поэтому в ЭТОМ стенде
оба плеча неотличимы на проводе вплоть до кода; свойство дословного проброса всё равно видно
напрямую в дампе opensmppbox (его собственный ответ, неколлапсированный, с `system_id: NULL`) и в
форме метрик (`BIND_FAILED_NON_ROK` на обоих плечах = ответил SMSC; `BIND_REJECTED` только на
ingress = ответил прокси). Коллапсированный или синтезированный ответ на проводе D1 — например,
код фронта, не совпадающий с дампом opensmppbox — нарушил бы контракт дословности → дефект, bounce
(§11).

## 7. Гид по отладке — точки входа

Куда смотреть, примерно в порядке доступности. Поверхности прокси — ШТАТНЫЕ (ради стенда не
добавлено ни логирования, ни метрик — JSON-поток и `/metrics` в поставляемом виде и есть
доказываемая поверхность отладки); их полный справочник —
[`docs/runbooks.md`](../docs/runbooks.md) (таблица поверхностей отказа, справочник журнальных
событий, справочник `/metrics`).

| Точка входа | Как | Что даёт |
|-------------|-----|----------|
| JSON-stdout прокси | терминал из §5.2 (или его перенаправление) | стержень событий: `startup_summary` (готовность), `bind_accept` / `bind_reject` (сопряжение и вердикт), WARN-каталог (дедлайн drain, idle-watchdog, исчерпание капа). Grep `"event":`. |
| `/metrics` прокси | `curl -s http://127.0.0.1:9090/metrics` | различающие счётчики: `relay_pdus_total{direction}` (течёт ли данные), `relay_binds_unknown_total` / `relay_binds_rejected_total`, полная сетка `relay_connections_closed_total{direction,reason}` — таблица §6.4 читается ровно с них. |
| TRACE-плечо прокси (тела PDU) | перезапуск §5.2 с ЕЩЁ ОДНИМ аргументом запуска: `--logging.level.smpp.companion.proxy.relay.pdu=TRACE` | по строке на каждый relayed PDU — `relayed pdu: direction=INGRESS command_id=0x4 length=66 body=0x00000042…` — точные байты кадра, пересекающего релей, текст сообщения читается в hex (наблюдено вживую, §6.1). Семейство bind вымарывается на ЛЮБОМ уровне (пароль не проходит никогда); по умолчанию выключено. |
| Страница статуса фронта Kannel | `curl "http://127.0.0.1:13000/status.txt?password=test"` | мир фронта: соединения боксов, строка `smsc1` (online против переподключения), счётчики на SMSC (`rcvd: sms / dlr, sent: sms / dlr`), глубина очереди, хранилище DLR. |
| Страница статуса SMSC Kannel | `curl "http://127.0.0.1:14000/status.txt?password=test"` | здоровье FAKE1, SMSC-сторонние счётчики DLR, список box-соединений (плечо opensmppbox как `smsbox:usr1`). |
| Журналы боксов Kannel — байтовый взгляд | `docker compose logs front-bearer-box` / `smsc-opensmpp-box` / `smsc-bearer-box` / `front-sms-box` | каждый бокс несёт `log-level = 4` — самый подробный, с полными дампами SMPP PDU. Дампы фронта `Sending PDU:` / `Got PDU:` против дампов opensmppbox — прослушка провода С ДВУХ КОНЦОВ вокруг прокси: что ушло от фронта и что получил SMSC — проверка дословного проброса, не трогая прокси. (Регулятора уровня на лету нет — смена уровня это правка conf + перезапуск.) |
| pg — хранилища DLR | `docker compose exec pg psql -U postgres -d postgres -c 'SELECT * FROM front_bearer_dlr;'` (аналогично `smsc_bearer_dlr`, `smsc_smpp_dlr`) | резервирования DLR и их колонки `status`/`mask` — строки плеча из §6.1. |
| pg — журнал sqlbox | `… -c 'SELECT sql_id,momt,sender,receiver,msgdata,dlr_mask,boxc_id FROM front_sms_log;'` | каждый MT и каждый завершившийся DLR-текст (`momt` = `MT` / `DLR`) — долговременная расшифровка отправок. |
| tty fakesmsc | `docker compose attach smsc-fake-smsc` (требуется терминал — §6.2) | инъекции MO (синтаксис строки из §6.2) и печать квитанций MT (`Got message N: <…>`). |

Эвристики отладки — навык §6.4 в общем виде:

- **Bind не сопрягается** → сначала stdout прокси. Строки `bind_reject`: плечо OIDC (читайте
  `verdict`; подвиды — в §5.4). Тишина + закрытия `BIND_FAILED_NON_ROK`: SMSC отказал — сверьте
  `conf/smsc-users.txt` с `smsc-username/-password` фронта. Тишина + закрытия
  `EGRESS_CONNECT_FAILED`: дозвон egress — поднят ли opensmppbox, верен ли порт из §5.2?
- **Сообщение исчезло** → пройдите таблицу плеч §6.1 сверху вниз; первое плечо без ожидаемого
  наблюдения — место остановки. Счётчики прокси скажут, пересёк ли релей (`relay_pdus_total`);
  TRACE-плечо покажет байты; дампы Kannel покажут, что видел каждый конец.

## 8. Устранение неполадок подъёма — сбои называются, не прячутся

| Симптом | Что сломалось | Куда смотреть / что делать |
|---------|---------------|----------------------------|
| `docker compose up` падает с `bind: address already in use` по порту из §3 | Порт занят процессом хоста (чаще всего локальным postgres на 5432) | Освободите порт или перемапьте публикацию — НЕ удаляйте её: в паттерне «шпилька» непубликуемый порт молча ломает бокс, звонящий на него через хост (строка ниже) |
| Журнал бокса показывает неудачу подключения к `host.docker.internal:<порт>` | Соответствующая публикация удалена/изменена либо целевой сервис лежит | Каждый conf называет свои цели (§2); верните публикацию или целевой сервис — conf-файлы являются источником истины карты портов |
| `pg` не становится healthy | Postgres не принимает соединения (неудачная инициализация тома, мало места) | `docker compose logs pg` — учтите: `init.sql` выполняется при каждом СВЕЖЕМ старте контейнера (анонимный том, §7): цикл `down`/`up` пересоздаёт таблицы пустыми; строки сохраняет только `stop`/`start` |
| `front-bearer-box` / `smsc-bearer-box` висит в `starting`, потом `unhealthy` или `exited` | Bearerbox отверг conf (синтаксис, нечитаемое монтирование) или упал после старта — healthcheck опрашивает curl-ом admin-страницу, нет страницы — нет здоровья | `docker compose logs <сервис>` — Kannel называет виновную группу, файл и строку перед выходом (`Group '...' is no valid group identifier. Error found on line N of file '/etc/kannel/front-kannel.conf'`, exit 1; проверено мутационным прогоном T1). Без restart-политики контейнер остаётся exited, пока вы не поправите conf и не выполните `docker compose up -d` |
| `front-sql-box` / `front-sms-box` `exited (0)` | Боксы Kannel корректно завершаются, потеряв bearerbox — если `front-bearer-box` exited (строка выше), зависимые уходят с ним | Сначала верните bearerbox, затем `docker compose up -d` восстанавливает зависимых (проверено: оба перерегистрировались как box-соединения за секунды) |
| `front-sql-box` / `front-sms-box` падает циклически | Тот же класс отвержения conf (монтируется тот же `./conf`) либо недостижим порт вышел стоящего бокса | `docker compose logs <сервис>`; затем строки о портах боксов выше |
| `smsc-opensmpp-box` завершается | `smpp-users.txt` отсутствует/нечитаем в монтируемом conf либо недостижим 14001 | `docker compose logs smsc-opensmpp-box`; файл logins и порт bearerbox названы в `conf/smsc-opensmppbox.conf` |
| `smsc-fake-smsc` завершается сразу | Недостижим 10004 (smsc-bearer-box лежит) — fakesmsc быстро умирает при неудачном подключении; ПЕРЕЗАПУСК работающего `smsc-bearer-box` тоже может уронить его glibc-крэшем (`free(): double free detected in tcache 2` в его tty — наблюдено, quirk Kannel 1.5.0; interop-заметка в духе COMP-1) | Сначала поднимите `smsc-bearer-box` в healthy (порядок compose это делает; после крэша переподключает `docker compose up -d`). Для инъекции MO (§6.2) бокс должен быть подключён — переподключайтесь после каждого рестарта SMSC-стороны |
| Инъектированный MO не приходит (§6.2), а `docker compose logs smsc-bearer-box` показывает `WARNING: smsbox_list empty!` | Отсутствует дельта `group = smsbox-route` в `conf/smsc-kannel.conf` (у MO нет маршрута к соединению opensmppbox) | Верните группу (`smsbox-id = usr1`, `smsc-id = FAKE1`) и перезапустите `smsc-bearer-box` — bearerbox раздаёт MO только боксам БЕЗ boxc-id, а у opensmppbox он есть (примечание предусловия в §6.2) |
| fakesmsc напечатал `sent message N`, но bearerbox залогировал `smsc_fake: invalid message syntax from client, ignored` | Синтаксис введённой строки неверен — fakesmsc принимает и пересылает что угодно; парсер, который отвергает, — BEARERBOX | Используйте синтаксис строки из §6.2: `<отправитель> <получатель> text <сообщение>` — кодовое слово (`text`) обязательно |
| Фронтовая страница статуса вечно показывает переподключение `smsc1` | ОЖИДАЕТСЯ, пока прокси не поднят (см. §4) — либо прокси поднят, но не слушает 2775 | Это предусловие §5, а не баг стенда: сопряжение наблюдается в журналах прокси + `/metrics` после запуска. Если прокси ПОДНЯТ, таблица §5.4 называет сигнатуры сломанного входа |
| Журнал `smsc-opensmpp-box` показывает `ERROR: Invalid SMPP PDU received` | В 14567 ткнули нульбайтовым/слепым TCP-пробом (порт-сканер или ваш собственный `nc`/TCP-тест живости) — opensmppbox трактует мгновенное закрытие как PDU нулевой длины и пишет это в нити соединений | Артефакт проба, не поломка стенда; бокс продолжает обслуживать (его собственное соединение с bearerbox не затронуто). Interop-заметка (в духе COMP-1): ждите эти строки всегда, когда что-то опрашивает 14567, не говоря на SMPP |
| `sendsms`-curl отвечает 403 Authorization failed | Неверные учётные данные sendsms | `sendsms-user` — `user`/`password` (`conf/front-kannel.conf`) |
| `keycloak` никогда не становится healthy | HTTPS-listener так и не поднялся — нечитаемое монтирование сертификата/ключа, порт 8443 занят на хосте или контейнер упал при старте | `docker compose logs keycloak` (отказы называют файл/опцию); проверьте строку 8443 в §3 — включая одновременно идущий набор `:proxy:test`, чей `KeycloakContainer` биндит тот же фиксированный порт |
| Discovery-curl из §5.1 падает (404 / TLS-ошибка / connection refused) | 404: realm не импортировался (плохой JSON — при успехе журнал содержит `Realm 'smpp-companions' imported`); TLS-ошибка: несовпадение hostname/сертификата (используйте `--cacert keycloak/certs/ca.pem` против `localhost`, а не IP или другого имени); refused: контейнер лежит | `docker compose logs keycloak`; curl — авторитетная проба готовности realm'а (compose-healthcheck утверждает только listener — см. комментарий к сервису в `compose.yml`) |
| Прокси отказывает при загрузке: `…client-secret-path=… does not exist (OIDC client secret file missing) — refusing to start (SEC-060/AD-18)` | Бутстрап §5.1 пропущен (или файл переехал) — AD-18 делает путь необязательным к отсутствию | Выполните шаги §5.1; отказ срабатывает ДО бинда любого listener'а (exit 1, без `startup_summary` — никакого частичного старта) |
| Прокси поднят, но каждый bind отказывает: строки `bind_reject`, вердикт `DenyInvalid`, код на проводе 0x0d | Секрет клиента Keycloak в `sandbox/secrets/oidc-client-secret` устарел — пересоздание контейнера регенерировало его (семантика регенерации §5.1) | Повторите забор из §5.1 и перезапишите файл; следующая попытка фронта сопряжётся |
| Контейнер варианта §5.6 отказывает при загрузке, exit 1, называя путь `cert-path`/`key-path`/секрета (SEC-060), без `startup_summary` | Смонтированный файл нечитаем для UID 65532 образа — копия `0600` (KEY-файлы тестовых ресурсов при наивном копировании получаются `0600`; `cp` сохраняет режим) либо секрет из §5.1 ещё в `0600` | `chmod 0644 sandbox/certs/*` (включая ключи — фикстурный PKI) и `chmod 0444 sandbox/secrets/oidc-client-secret`; перезапустите контейнер |
| `docker run` из руководства сообщает при загрузке `is a directory, not a file (OIDC client secret)` (или сертификат) | Опечатка в ИСТОЧНИКЕ `-v` — Docker молча создаёт КАТАЛОГ по несуществующему пути-источнику, и прокси называет его (SEC-060) вместо ошибки монтирования | Исправьте путь `-v` (пути в руководствах относительны корня — запускайте их из корня репозитория); удалите случайно созданный каталог |
| ВТОРОЙ контейнер составного варианта §5.6 отказывает при загрузке с отказом bind-in-use, называющим `metrics.port` | Оба контейнера прокси оставлены на умолчании 9090 — промах плана портов | Сдвиньте metrics у reverse: `--companion.metrics.port=9091` (запуск в руководстве уже так делает) |
| Составная цепочка §5.6 не сопрягается: stdout forward молчит, его `relay_connections_closed_total{INGRESS,EGRESS_CONNECT_FAILED}` растёт, на проводе фронта привычный 0x0d | Контейнер REVERSE лежит (или неверен его порт/сертификат) — egress-dial forward и есть TLS-плечо | `docker ps` на контейнер reverse; `docker start` его (пересопряжение в пределах одного повтора — наблюдено) либо сверьте план портов руководства и SAN сертификата с `routing[0].host` |
| Контейнер варианта §5.6 отказывает при загрузке с ошибкой bind-in-use на 2775 (или на loopback `/metrics` 9090/9091) | Порт держит оставленный прокси — всё ещё работающий прокси §5.2 с хоста либо неостановленный контейнер предыдущего варианта (один фронтовый conf означает ОДНОГО слушателя 2775; loopback-порты метрик тоже в одиночном владении) | Одна поза прокси за раз: `kill -TERM <pid>` прокси на хосте (`pgrep -f proxy/build/libs/proxy.jar`) либо `docker stop --timeout 30 <имя>` контейнерам предыдущего варианта (exit 143 у каждого), затем запуск — отказ называет порт и срабатывает до того, как что-то начнёт обслуживаться |

## 9. Демонтаж

Портированный compose не даёт `pg` именованного тома (паттерн окружения-источника, сохранён
как есть), поэтому данные postgres живут в анонимном томе, чьё время жизни — КОНТЕЙНЕР, а не
проект. Проверенное поведение (подъём T1, пробные строки вставлены и наблюдены):

```bash
docker compose stop        # пауза: контейнеры сохранены — хранилище DLR ПЕРЕЖИВАЕТ stop/start
docker compose start       # продолжение с целыми данными

docker compose down        # контейнеры + сеть удалены; анонимный том pg остаётся осиротевшим,
                           # а свежий `up` стартует НОВОЕ ПУСТОЕ хранилище (init.sql выполняется
                           # заново) — на практике `down` СТИРАЕТ наблюдения DLR, что заодно и
                           # поза воспроизводимости-с-чистого-листа для стенда проверки
                           # корректности
docker compose down -v     # дополнительно удаляет анонимный том — без сирот
```

Состояние Keycloak следует той же форме: его хранилище H2 живёт в контейнере (без тома), поэтому
`stop`/`start` сохраняет импортированный realm И сгенерированный секрет клиента, а любое
пересоздание (`down` и затем `up`) переимпортирует коммитнутый realm с РЕГЕНЕРИРОВАННЫМ секретом —
применяются семантика регенерации и шаги перезапроса из §5.1 после каждого пересоздания.

Запущенный на хосте прокси (по рецепту §5.2) демонтируется отдельно по SIGTERM — graceful-drain
AD-22, доказанный в Story 5.1 и повторно наблюдаемый как часть доказательства рецепта §5.3:
WARN-drain, форс-закрывающий живую пару на дедлайне PT10S (Kannel никогда не полузакрывает —
ожидаемо), затем exit 143.

Контейнеры docker-вариантов §5.6 демонтируются командой `docker stop --timeout 30 <имя>` (exit 143
у каждого — java является PID 1 благодаря exec-form ENTRYPOINT; ожидание 30 с покрывает 10-секундный
дедлайн дрейна, по правилу останова deployment guide) и `docker rm <имя>`. В составных вариантах
останавливайте сначала FORWARD (он держит живую пару — его stdout несёт упорядоченный поток
summary → couple → WARN дрейна); собственный WARN reverse затем зависит от того, была ли его пара
ещё в дрейне на дедлайне — наблюдали оба исхода, оба корректны (это указано в руководствах).

## 10. Отличия от портированного источника (список честности)

Источник портирования — проверенная цепочка предпроектного окружения; вот ВСЕ отличия, чтобы
стенд не дрейфовал молча:

1. **`conf/front-kannel.conf`, ЕДИНСТВЕННЫЙ перепрошитый порт:** порт фронтового `group = smsc`
   перепрошит `14567 → 2775` (`host` остаётся `host.docker.internal`) — фронтовый bearerbox
   сопрягается ЧЕРЕЗ запущенного на хосте прокси вместо прямого захода в opensmppbox. Стенд с
   двумя перепрошитыми портами — другой стенд; перепрошит ровно один.
2. **Идентичность `compose.yml`:** явное имя проекта `name: smpp-bmad-sandbox` (дефолт compose —
   имя каталога чекаута — пересеклось бы с compose-проектом самого окружения-источника на этой
   машине) и `build: ./kannel` (самодостаточная раскладка `sandbox/`; сам Dockerfile портирован
   байт-в-байт).
3. **Сервис Keycloak + рецепт запуска прокси (T2, как записано):** compose-сервис `keycloak`,
   зеркалирующий запуск/realm тестового `KeycloakFixture` (с двумя позами, прокомментированными
   в `compose.yml`), коммитнутый материал `keycloak/` (realm-экспорт + фикстурный PKI,
   скопированный байт-в-байт из `proxy/src/test/resources/keycloak/certs/`), gitignored
   `sandbox/secrets/oidc-client-secret` (AD-18 — стенд есть отладочная реплика deploy-контракта,
   а не место, где значение секрета — «просто песочные данные»), запись `.gitignore`, его
   покрывающая, и рецепт §5. Keycloak никогда не был частью источника портирования — это
   недостающий адъюдикатор reverse-ячейки, а не порт.
4. **`conf/smsc-kannel.conf`, MO-маршрутизационная добавка (T3, как записано):** группа
   `group = smsbox-route` (`smsbox-id = usr1`, `smsc-id = FAKE1`), которой не было в источнике
   портирования — окружение никогда не маршрутизировало MO. Bearerbox Kannel раздаёт MO только
   боксам БЕЗ boxc-id, а opensmppbox регистрируется как `usr1`; без маршрута каждая инъекция
   fakesmsc умирает в очереди с `WARNING: smsbox_list empty!` (наблюдено вживую). Найдено
   исполнением сценария §6.2; для него требуется — и здесь документировано.
5. **Сценарии проверки + гид по отладке (T3, как записано):** четыре сценария §6 и таблица точек
   входа §7; все наблюдения исполнены вживую на стенде в тот же день; их единственное
   конфиг-требование — дельта 4 выше.
6. **Русский перевод этого README** (`README.ru.md`) и mermaid-схема цепочки — владелец,
   2026-09-17; нормативен английский оригинал.
7. **Руководства по docker-вариантам + `certs/` (T5, как записано 2026-09-18):** три руководства
   по вариантам в `runbooks/` (§5.6, EN + RU) — добавления только на стороне docker; compose-файл,
   conf Kannel и всё портированное не получают ничего (dial `2775` фронтового conf обслуживает
   любой вариант без изменений). ЕДИНСТВЕННЫЙ новый материал — `sandbox/certs/`: фикстурный PKI
   SMPP-плеч, байт-в-байт копии (`cmp`-проверены) зафиксированных тестовых ресурсов — прецедент
   T2 `keycloak/certs/`, применённый к плечам mTLS/one-way TLS. Ни одного Gradle-файла, ни одного
   build-файла, ни одной строки main-кода в T5 нет.

## 11. Дисциплина находок

- Дефект прокси, всплывший через Kannel, возвращается (bounce) во владеющий эпик — паттерн
  честного исключения — и записывается в deferred-work: он никогда не чинится внутри стенда и
  никогда не подстраивается под желаемый результат.
- Подлинный quirk Kannel становится interop-заметкой в этом README (контекст COMP-1).
- Потерянный/удвоенный/искажённый в транзите Submit — дефект REL-1: возвращается (bounce) во
  владеющий эпик, не подстраивается.
