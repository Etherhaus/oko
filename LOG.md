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
