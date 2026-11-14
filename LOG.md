# LOG.md — журнал проекта Oko

Формат записи: **дата — этап — что сделано — на чём одобрено**.

---

## 2026-11-14 — Этап 1 — каркас + базовые пробы (DNS, TCP)

**Одобрение:** бриф «Oko — детектор блокировок и доступности сервисов», этап 1.

**Сделано.**
- `git init` (ветка `main`), автор `Dmitry Etherhaus <lehzenblad@proton.me>`, MIT.
- `Cargo.toml`: пакет `oko-detector`, бинарь `oko`, edition 2024, зависимости clap 4.6, tokio 1.54, ureq 3.5 (rustls, без gzip).
- `src/target.rs` — 6 сервисов (youtube.com, discord.com, github.com, x.com, facebook.com, wikipedia.org) + 3 контрольных (yandex.ru, vk.com, mail.ru), записанные IP от 2026-11-14 как фолбэк.
- `src/probes/dns/wire.rs` — DNS-wire-кодек: сборка запроса, разбор ответа с компрессией имён, A/AAAA, rcode. 14 юнит-тестов без сети.
- `src/probes/dns.rs` — системный резолвер vs три DoH-эталона (dns.google, cloudflare-dns.com, dns.sb), структуры `ResolveOutcome`/`ResolveFailure`/`Comparison`, фолбэк на записанные IP.
- `src/probes/tcp.rs` — connect с таймаутом, тайминг, исходы Connected/Refused/Timeout/NoRoute/Failed, до 4 адресов на цель параллельно.
- `src/report.rs` — текстовый отчёт: DNS по каждому резолверу, сравнение наборов, TCP, контроль, честные примечания. Форматирование UTC без внешних крейтов.
- `src/main.rs` — CLI `oko probe <домен>` и `oko probe --all`.
- `AGENTS.md` (раздел «Рабочий контекст»), `LOG.md`, `LICENSE`, `.gitignore`, `rustfmt.toml`.

**Проверено.**
- `cargo fmt --check` — чисто.
- `cargo clippy --all-targets -- -D warnings` — чисто.
- `cargo test` — 50 тестов, все зелёные.
- Живой прогон `oko probe github.com` и `oko probe --all` (6 целей, 6.2 с) — отчёт печатается, DoH-эталоны отвечают, контроль доступен.

**Найдено по ходу.**
- `dns.quad9.net` отдаёт HTTP 505 на HTTP/1.1 (нужен HTTP/2) — заменён на `dns.sb`.
- IPv6-адреса на машине без IPv6-маршрута дают ENETUNREACH — вынесено в отдельный исход `NoRoute`, чтобы не выглядело блокировкой.

**Не сделано (по брифу — следующие этапы).** Вердикты, TLS/HTTP-пробы, JSON, l4-25, QUIC, туннель, GUI, README, CI, SECURITY.md.

---

## 2026-11-14 — Этап 2 — TLS + HTTP-пробы, движок вердиктов, `--json`

**Одобрение:** бриф «Oko — детектор блокировок и доступности сервисов», этап 2 (с правками: коммит-правило, три эталона, NoRoute, правила вердиктов).

**Сделано.**
- `src/probes/tls.rs` — rustls-рукопожатие с настоящим SNI; при неудаче — повтор с контрольным SNI на том же IP. Исходы `Ok` / `ServerResponded{cert_mismatch}` / `RstAfterClientHello` / `Timeout` / `TlsAlert{code}` / `Failed`; `reached_server()` — сигнал «DPI не вмешался».
- `src/probes/http.rs` — plain HTTP/1.1 GET на порт 80 с настоящим `Host`, при неудаче — с контрольным; исходы `Response{status}` / `Reset` / `Timeout` / `Failed`, разбор статус-строки покрыт тестами.
- `src/verdict.rs` — `VerdictKind` (ok / dns_spoof / dpi_sni / ip_block / host_filter / unknown), `Level` (ok / warn / bad / undetermined), `Verdict{kind, level, reason, facts, address_source}`, `classify()`, `pick_address()`. 16 юнит-тестов на моках, по одному на каждое правило плюс `unknown`.
- `src/report.rs` — сводный вердикт, секции DNS/TCP/TLS/HTTP, список фактов для не-`ok`, JSON-отчёт.
- `src/format.rs`, `src/json.rs` — форматирование длительностей и адресов, сериализация `Duration` в миллисекундах.
- `src/main.rs` — флаг `--json`, оркестрация: контроль → DNS по всем целям → TCP/TLS/HTTP по цели → вердикт.
- `AGENTS.md` — структура, статус этапа 2, грабли этапа 2.

**Проверено.**
- `cargo fmt --check` — чисто.
- `cargo clippy --all-targets -- -D warnings` — чисто.
- `cargo test` — 94 теста, все зелёные.
- `oko probe github.com` → `ok` (TLS завершён, HTTP 301), `oko probe github.com --json` — валидный JSON.
- `oko probe --all` (33.6 с): youtube.com, discord.com, x.com, facebook.com → `dpi_sni`; github.com, wikipedia.org → `ok`.
- Вердикты `dpi_sni` сверены вручную через `openssl s_client`: настоящий SNI молчит, контрольный `yandex.ru` на том же IP получает ответ (Google — cert `*.google.com`, Cloudflare — alert 40). Ложное срабатывание исключено.

**Найдено по ходу.**
- Баг в TLS-пробе: `rustls::Connection::read_tls` читает во внутренний буфер ограниченного размера и может взять меньше предложенного; остаток терялся, полёт сервера обрывался, рукопожатие висело до дедлайна (контрольный SNI на youtube.com: то 150 мс, то 5 с). Исправлено — чанк скармливается до конца с дренажом между вызовами; добавлены 4 теста на `stalled`/`closed`.
- На ТСПУ настоящий SNI уходит в тишину (timeout), а не в RST — оба исхода трактуются как «сервер не ответил».

**Не сделано (по брифу — следующие этапы).** l4-25, QUIC/UDP, туннель-дифф и `--socks5` (этап 3), GUI (этап 4), README/CI/SECURITY.md (этап 5).

---

## 2026-11-14 — Этап 3 — l4-25, QUIC/UDP, туннель-дифф, `--timeout`

**Одобрение:** бриф «Oko — детектор блокировок и доступности сервисов», этап 3 (с попутными пунктами из разбора этапа 2: `--timeout`, перенос факта «разные адреса» из сводки в детали).

**Сделано.**
- `src/route.rs` — транспорт пробы: `Route::Direct` / `Route::Socks5(SocketAddr)`, `connect()` с таймаутом, SOCKS5 no-auth handshake и CONNECT, парсеры method/connect-ответов, `reply_description()`. 12 юнит-тестов без сети.
- `src/probes/payload.rs` — после рукопожатия GET `/`, чтение до 64 КБ; исходы `Complete` / `KbDrop{range}` / `Ended` / `Truncated` / `Stalled` / `NotAttempted` / `Failed`. Обрыв в 16–20 КБ или ~25 КБ считается и по телу, и по телу+рукопожатию, и только при неполном ответе (`Content-Length` / chunked-терминатор). На dpi_sni-целях — `NotAttempted` («рукопожатие не завершилось»), не таймаут.
- `src/probes/quic.rs` — 1200-байтный Initial с grease-версией `0x1a2a3a4a`, varint-кодировщик, разбор Version Negotiation; исходы `Answered` / `Silent` / `Failed`; тишина — `unknown`.
- `src/probes/tls.rs` — принимает `Route`, новый `handshake()` отдаёт живой поток и счётчик байт сервера; дренаж rustls после каждого `read_tls` (баг этапа 2 не вернулся).
- `src/probes/http.rs`, `src/probes/tcp.rs` — принимают `Route`.
- `src/verdict.rs` — вердикты `l4_drop`, `geo_block_by_service`; `DiffKind` (both_ok / path_block / service_block / unknown), `diff()`, `apply_diff()`; правило payload после HTTP; сравнение DNS убрано из `facts()`.
- `src/report.rs` — секции payload, QUIC, туннель и дифф-таблица; `RunReport.tunnel`; новые примечания.
- `src/main.rs` — `--timeout <сек>` (дефолт 5, 1..=120), `--socks5 <addr>`, payload и QUIC в прямом прогоне, `run_tunnel()` на адресах прямого прогона, дифф после туннельного прогона.
- `AGENTS.md` — структура, статус этапа 3, грабли этапа 3.

**Проверено.**
- `cargo fmt --check` — чисто; `cargo clippy --all-targets -- -D warnings` — чисто; `cargo test` — 143 теста, все зелёные.
- `oko probe --all` (49 с): youtube/discord/x/facebook → `dpi_sni`, github/wikipedia → `ok`; payload на dpi_sni-целях — честная N/A, на github — 69.7 КБ полностью.
- `oko probe --all --socks5 127.0.0.1:10808` (60 с, живой туннель xray): youtube/discord/x/facebook — direct `dpi_sni`, tunnel `ok` → `path_block`; github/wikipedia — `both_ok`. Дифф-таблица честная.
- `oko probe --all --timeout 2` — 25 с вместо 49 с.
- `--json` несёт `payload`, `quic`, `tunnel`, `diff`; `note` у `Ended` сериализуется только когда есть.
- QUIC: youtube/discord/x отвечают Version Negotiation (67/49/68 мс), github/facebook/wikipedia молчат 5 с → `unknown`.

**Найдено по ходу.**
- Баг payload-пробы: `read_tls` отказывается принимать записи, когда буфер plaintext держит больше 16 КБ, а 16-КБ чанк расшифровывается в чуть больше — github.com через туннель обрывался на 53.7 КБ с «received plaintext buffer full». Исправлено: `feed()` дренирует plaintext после каждой записи.
- youtube.com через туннель отдаёт 301 и следом 19-байтную TLS-запись, которую не расшифровывает ни rustls, ни OpenSSL (`openssl s_client -msg`, Python `ssl` — оба `bad_record_mac`). Это внешняя особенность пути, не наш баг; теперь такой обрыв после полного ответа — `Ended` с пометкой, а не `Failed`, и дифф youtube даёт `path_block`, а не «не сравнимо».

**Не сделано (по брифу — следующие этапы).** GUI на Slint (этап 4), README/CI/SECURITY.md (этап 5). Отдельного `tunnel.rs` нет: SOCKS5-транспорт — в `route.rs`, прогон — `run_tunnel()` в `main.rs`, дифф — в `verdict.rs`.

---

## 2026-11-14 — Этап 4 — GUI на Slint: темы, RU/EN, экспорт, туннель из окна

**Одобрение:** бриф «Oko — детектор блокировок и доступности сервисов», этап 4 (список целей с чекбоксами, «Проверить», прогресс, таблица вердиктов с цветом, панель деталей, экспорт текст/JSON, EtherOS-стиль, обе темы, RU/EN, прогон в tokio-задаче через канал событий, настройки таймаута и SOCKS5).

**Сделано.**
- `src/run.rs` — оркестрация одного прогона, общая для CLI и GUI: `run(targets, Options, progress) -> RunReport`, `Options { timeout, socks5 }`, `Progress` (Control / Started / Target / Tunnel / Diff). `main.rs` больше не держит логику прогона.
- `src/gui.rs` — окно: состояние `App`, движок в отдельном потоке со своим tokio-рантаймом, `mpsc` в обе стороны, UI-поток дренирует события таймером Slint раз в 50 мс. Таблица целей с чекбоксами, «Все»/«Ничего», прогресс, статус, панель деталей (текст CLI в моноширинном `Text` внутри `Flickable`), экспорт текст/JSON через `rfd` (xdg-portal, без GTK), настройки: таймаут 1..=120 (дефолт 5) и поле SOCKS5.
- `src/i18n.rs` — строки интерфейса RU/EN (`Lang`, `Strings`, `apply`), определение языка из `LC_ALL`/`LC_MESSAGES`/`LANG`. Текст отчётов остаётся английским, как в CLI и JSON; в подписи строки — локализованное слово уровня.
- `ui/app.slint` — `TargetRow`, `Labels`, `Theme`, компоненты Card / Pill / GhostButton / PrimaryButton / Segment / Segmented / StepButton / Stepper / Field / Check / TargetItem, окно `AppWindow`.
- `build.rs` — `slint_build::compile("ui/app.slint")`; в `Cargo.toml` — `slint 1.18`, `slint-build 1.18`, `rfd 0.18`.
- `src/main.rs` — без подкоманды открывает окно, `oko probe …` остаётся CLI; `main()` не `#[tokio::main]`.
- `src/report.rs` — `render_target(target, tunnel)` и `render_sections()`: панель деталей показывает то же, что CLI, включая туннель и дифф.
- `src/verdict.rs` — `DiffKind::as_str()` (канонические имена для подписи строки) + тест.
- `AGENTS.md` — структура, команды, статус этапа 4, грабли этапа 4, палитра.

**Проверено.**
- `cargo fmt --check` — чисто; `cargo clippy --all-targets -- -D warnings` — чисто; `cargo test` — 154 теста, все зелёные.
- Живой прогон из окна на 6 целях (тёмная тема, RU): youtube/discord/x/facebook → `dpi_sni` (красный), github/wikipedia → `ok` (зелёный); прогресс идёт 0/6 → 6/6, кнопка гаснет на время прогона, окно не замерзает.
- Живой прогон с туннелем `127.0.0.1:10808` (xray) из окна: tunnel `ok` у всех шести, дифф `path_block` у четырёх и `both_ok` у двух — совпадает с CLI. В подписи строки — `блокировка · path_block` / `ok · both_ok`.
- Светлая тема + EN: переключаются, подписи и статусы на английском, отчёты остаются английскими.
- Экспорт из окна: `oko-2026-11-14T17-24-45Z.txt` (15818 Б) и `.json` (56352 Б), в JSON — `tunnel` и `diff` по каждой цели.
- CLI не сломан: `oko probe github.com --timeout 3` печатает те же секции и вердикт `ok`.

**Найдено по ходу.**
- Поле SOCKS5 было мертво: `TextInput` не был связан с `app.socks5`, поэтому туннель нельзя было включить из окна — таблица оставалась `dpi_sni` при заполненном поле. Исправлено (`edited` → `app.socks5`), проверено живым прогоном.
- Один прогон из окна завис на 5/6 и не завершился за 2+ минуты; повторить не удалось (6+ прогонов после этого — 44–75 с), ptrace заблокирован (yama), бэктрейса нет. Честно: не воспроизведено, не исправлено; подозрение на пробуждение таймера в QUIC-пробе.
- Инъекции ввода на машине нет (нет xdotool/wtype/ydotool, корень XWayland закрыт полноэкранным окном игры, `XSendEvent` winit игнорирует), поэтому добавлены отладочные переменные `OKO_AUTOSTART`, `OKO_THEME`, `OKO_LANG`, `OKO_SELECT`, `OKO_SOCKS5`, `OKO_EXPORT_DIR` — каждая дёргает тот же колбэк, что и кнопка.

**Не сделано (по брифу — следующий этап).** README EN/RU, CI, SECURITY.md, упаковка (этап 5). Релиз и публикация — за Дмитрием.
