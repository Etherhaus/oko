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
