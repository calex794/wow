# WOW-CUSTODIAN-05 P0-7 — W7 AUDIT между отдельными узлами приватной сети

**Статус:** испытательный контур, НЕ производственная служба. Источник: [WOW-CUSTODIAN-05](https://app.notion.com/p/40232a84beec81ddbc82c9748d7c704a) и [P0-6: preflight](W7-TWO-HOST-PREFLIGHT-P06.md). Реальная проверка двух независимых хостов должна выполняться отдельно от CI и пока **NOT TESTED**.

## Границы безопасности

Исполняемый файл \`w7_interhost_lab\` (собирается только с \`--features iroh-transport\`) реализует **только** синтетический W7 AUDIT. Он **не** поддерживает STORE/FETCH, реальные пользовательские письма, Vault, W4, K3, публичные репутационные записи или санкции. Отдельный ALPN: \`akula-wow/w7-private-overlay-audit-lab/1\`, не боевой W6/Node.

Сервер может слушать \`127.0.0.1\` / \`::1\` без особого флага; для частного интерфейса IPv4 RFC1918, 100.64/10 или IPv6 ULA **требуется явное \`--private-overlay-opt-in\`**. Адреса \`0.0.0.0\`, \`::\`, публичные IP и multicast запрещены даже с флагом. На хостах обеспечить приватный WireGuard/Tailscale overlay и отдельный firewall, допускающий UDP только от ожидаемого аудитора. Нельзя пробрасывать порт напрямую в интернет. Входящий TLS EndpointId и подпись связываются с закреплённым Ed25519 ключом службы.

Все файлы ключей — 32 **сырых** байта. Команда \`generate\` создаёт новый файл и отказывается перезаписывать существующий. На Unix права не шире 0600; \`public\` показывает только открытые ключи, не секрет. Не передавать seed, Vault, Notion или приватные гранты в GitHub Actions/логах. Сервисный ключ, TLS-ключ, ключ оператора и issuer — разные, хранятся на соответствующих участниках, не копируются между C1/C2.

## Сборка

На лабораторных хостах и проверяющем из доверенного зафиксированного коммита PR #97:

\`\`\`sh
cargo build --features iroh-transport --bin w7_interhost_lab
cargo test --features iroh-transport --test custodian_p07_overlay
cargo test --features iroh-transport --test custodian_p07_interhost_process
\`\`\`

Путь до бинарника далее обозначен \`./target/debug/w7_interhost_lab\`.

## Подготовка

1. Проверяющий генерирует **свой** TLS-ключ и независимый issuer генерирует ключ подписи разрешений. C1 и C2 создают **каждый на своём сервере** отдельные TLS- и service-ключи. Для примера:
   \`\`\`sh
   w7_interhost_lab generate ./tls.key
   w7_interhost_lab generate ./service.key
   w7_interhost_lab public ./tls.key
   w7_interhost_lab public ./service.key
   \`\`\`
   Команда \`public\` выводит \`ED25519 ...\` и \`QUIC ...\`; использовать TLS-ключ как service-ключ нельзя. Все пути должны быть в защищённом локальном каталоге.
2. Выбираются два оператора **с доказуемо разным управлением**, независимые площадки и два доступных VPN UDP-адреса. Проверяющий **отдельно** закрепляет публичные service/issuer/operator ключи и фактические QUIC EndpointId. IP/ASN и отдельные ключи сами по себе не доказывают независимость.
3. Проверяющий и операторы выполняют криптографический preflight P0-6 с неповторяющимся \`RunChallenge::generate\`, собирают ручное подтверждение владельцев и сверяют **фактический** TLS EndpointId при последующем сетевом подключении. CLI P0-7 **не проводит P0-6 вместо людей**.
4. На всех сторонах используется **только синтетический** файл \`synthetic.w3\` из доверенной тестовой генерации W3. Он не должен быть копией пользовательского файла. Входящий W3 хешируется и сверяется по exact BLAKE3+длине. Не выводить содержимое в stdout.

## Сервер C1 / C2

После выдачи проверяющему его собственного \`QUIC\` EndpointId запускать на каждом сервере с **его собственными** \`SERVICE_ID\`, \`EPOCH\`, \`SERVICE_KEY\`, \`TLS_KEY\`, \`VPN_IP\` (не использовать секреты другого C):

\`\`\`sh
w7_interhost_lab serve \
  VPN_IP:UDP_PORT SERVICE_ID_HEX EPOCH SERVICE_KEY_FILE TLS_KEY_FILE \
  ISSUER_ID_HEX ISSUER_EPOCH ISSUER_ED25519_PUB_HEX \
  AUDITOR_QUIC_ID ROUTE_TOKEN_HEX MESSAGE_ID_HEX synthetic.w3 \
  honest --private-overlay-opt-in
\`\`\`

Строка \`READY TLS_ENDPOINT_ID SOCKET SIGNED_BINDING_HEX\` содержит **только публичные** данные, которые следует сверить по независимому каналу перед выпуском гранта. \`READY\` не удостоверяет физическую независимость.

## Выпуск отдельного AUDIT-гранта

Лицо с полномочием issuer **отдельно** от кастодиана подписывает грант на конкретные W3, сервис/epoch, два QUIC EndpointId, маршрут и сообщение. Действие допускает TTL не больше 120 секунд. Поле \`NONCE_HEX\` — свежие 16 байт, полученные через CSPRNG. Секрет issuer не передаётся на C1/C2.

\`\`\`sh
w7_interhost_lab issue \
  ISSUER_KEY_FILE ISSUER_ID_HEX ISSUER_EPOCH \
  SERVICE_ID_HEX SERVICE_EPOCH SERVICE_QUIC_ID AUDITOR_QUIC_ID \
  ROUTE_TOKEN_HEX MESSAGE_ID_HEX synthetic.w3 \
  EXPIRES_UNIX_MS NONCE_HEX ./audit.grant
\`\`\`

Выпускается отдельный файл \`audit.grant\` для C1 и C2. Это **не W5/W6 WRITE RelayGrant** и не разрешение обычного FETCH. Для проверки подлинности issuer ключ и роль должны быть закреплены и согласованы вне протокола.

## Пробный аудит с проверяющего узла

\`\`\`sh
w7_interhost_lab probe \
  AUDITOR_PRIVATE_VPN_IP:0 AUDITOR_TLS_KEY_FILE \
  C1_PRIVATE_VPN_IP:UDP_PORT C1_QUIC_ID C1_SIGNED_BINDING_HEX \
  C1_SERVICE_ID_HEX C1_SERVICE_EPOCH C1_SERVICE_ED25519_PUB_HEX \
  ISSUER_ID_HEX ISSUER_EPOCH ISSUER_ED25519_PUB_HEX \
  ROUTE_TOKEN_HEX MESSAGE_ID_HEX ./c1.audit.grant synthetic.w3 \
  ./local-private-observations.sqlite --private-overlay-opt-in
\`\`\`

Повторить отдельно для C2. \`RESULT status=...\` содержит локальный \`rtt_ms\`, **число байт полезной нагрузки запроса** (не полные сетевые/UDP/IP байты), локальную численность exact-W3 проверок и **\`domain_independence=UNVERIFIED auto_sanction=false\`**. Сами W3, private keys, route/message ID и секреты grant не выводятся. Не считать W7 доказательством W4, устойчивого хранения или независимости.

## Отрицательные сценарии

В лаборатории можно запускать сервер с \`honest\`, \`missing\`, \`corrupt\`, \`reject\` или \`delay\` в качестве параметра fault. Только \`honest\` может давать \`EXACT_W3_LOCAL_E1\`. \`missing\` → \`UNKNOWN_UNAVAILABLE\`; \`corrupt\` → \`UNATTRIBUTED_MISMATCH\`; \`reject\` → \`DENIED\`; \`delay\` → \`UNKNOWN_TRANSPORT\`. Никакой из этих результатов автоматически не подтверждает мошенничество C.

Обязательны дополнительное тестирование реального NAT/partition, перезапуска, неточного времени, недействительного и отозванного issuer, неверного TLS EndpointId, подменённого \`SIGNED_BINDING_HEX\`, похищенного AUDIT-гранта с чужим TLS-ключом, неверного exact-W3 хеша, долгой паузы и пропажи UDP. Отсутствующий W3 или истёкший grant не должны приводить к раскрытию наличия другой записи.

## Протокол результатов

Для каждого физического теста зафиксировать без секретов: время и класс источника часов, фактические IP-транспорты без публичного каталогизирования, доверенно закреплённые ключи/epochs/операторов, результат P0-6 внеполосной проверки, digest приватного транскрипта, реальные rtt/app bytes и сетевые ошибки, повторный W7-аудит и, **отдельно**, настоящие recipient-signed W4. Рассчитать W4/байт и влияние на false positive только после измерений на разных операторах.

**Граница приёмки:** GitHub CI может подтвердить настоящие QUIC-соединения **двух отдельных процессов на одном runner**, но не два независимых хоста. Производственный W6 READ, автоматический выбор маршрутов, санкции, K3 и W4 остаются выключенными. До реальных независимых серверов статус **PHYSICAL P0-7 NOT TESTED**.
