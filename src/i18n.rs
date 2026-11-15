//! Every user-visible string, in English and Russian.
//!
//! The table below is the single place where the window's text lives: adding a
//! language means adding a column, and nothing else in the app changes. The
//! Slint side reads the strings from the `Labels` global, which [`apply`] fills
//! in.
//!
//! The probe report itself stays in English: it is the same text the CLI and
//! the JSON carry, and the README documents it. The window's chrome is what
//! this table translates.

use slint::{ComponentHandle, Global};

use crate::gui::Labels;
use crate::target::Category;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Lang {
    #[default]
    En,
    Ru,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ru => "ru",
        }
    }

    /// The desktop's language, used until the user picks one.
    pub fn from_env() -> Lang {
        let value = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_MESSAGES"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default();
        if value.to_lowercase().starts_with("ru") {
            Lang::Ru
        } else {
            Lang::En
        }
    }
}

/// Declares the string table and the code that pushes it into the UI.
///
/// Each row is `field, setter => (english, russian)`. The setter is the Slint
/// property setter, spelled out because the property names are kebab-case.
macro_rules! labels {
    ($($field:ident, $setter:ident => ($en:literal, $ru:literal)),* $(,)?) => {
        /// Every string the window shows, in one language.
        #[derive(Clone, Copy)]
        pub struct Strings {
            $(pub $field: &'static str,)*
        }

        impl Strings {
            pub fn new(lang: Lang) -> Strings {
                match lang {
                    Lang::En => Strings { $($field: $en,)* },
                    Lang::Ru => Strings { $($field: $ru,)* },
                }
            }
        }

        /// Fills the `Labels` global of `ui` with the strings of `lang`.
        pub fn apply<C>(ui: &C, lang: Lang)
        where
            C: ComponentHandle,
            for<'a> Labels<'a>: Global<'a, C>,
        {
            let s = Strings::new(lang);
            let labels = ui.global::<Labels>();
            $(labels.$setter(s.$field.into());)*
        }
    };
}

impl Strings {
    /// The heading of a group in the target list.
    pub fn category(&self, category: Category) -> &'static str {
        match category {
            Category::VideoHosting => self.category_video_hosting,
            Category::Social => self.category_social,
            Category::Messenger => self.category_messenger,
            Category::News => self.category_news,
            Category::Search => self.category_search,
            Category::Ai => self.category_ai,
            Category::AudioStreaming => self.category_audio,
            Category::VideoStreaming => self.category_video,
            Category::Games => self.category_games,
            Category::Encyclopedia => self.category_encyclopedia,
            Category::Development => self.category_development,
            Category::Custom => self.category_custom,
            Category::Control => self.category_custom,
        }
    }
}

labels! {
    // The run header.
    ready, set_ready => ("Ready to check", "Готов к проверке"),
    checking, set_checking => ("Running…", "Проверяю…"),
    done, set_done => ("Run complete", "Прогон завершён"),
    check, set_check => ("Check", "Проверить"),
    control_dead, set_control_dead => (
        "The control target did not answer: the network is down or filtered as a whole",
        "Контрольная цель не ответила: сеть недоступна или фильтруется целиком"
    ),
    control_dead_short, set_control_dead_short => ("control is silent", "контроль молчит"),
    interrupted, set_interrupted => (
        "The run was interrupted by the watchdog",
        "Прогон прерван сторожевым таймером"
    ),
    run_failed, set_run_failed => ("The run failed", "Прогон не удался"),
    nothing_selected, set_nothing_selected => ("No target is ticked", "Не отмечено ни одной цели"),
    bad_socks5, set_bad_socks5 => ("The SOCKS5 address is not valid", "Адрес SOCKS5 не разобран"),

    // The targets panel.
    targets, set_targets => ("Targets", "Цели"),
    check_all, set_check_all => ("All", "Все"),
    check_none, set_check_none => ("None", "Ничего"),
    add_target, set_add_target => ("Add a target", "Добавить цель"),
    add, set_add => ("Add", "Добавить"),
    cancel, set_cancel => ("Cancel", "Отмена"),
    domain_placeholder, set_domain_placeholder => ("example.org", "example.org"),
    bad_domain, set_bad_domain => (
        "A bare domain, without a scheme or a path",
        "Нужен голый домен, без схемы и пути"
    ),
    duplicate_domain, set_duplicate_domain => (
        "That domain is already in the list",
        "Такой домен уже есть в списке"
    ),
    added, set_added => ("Added", "Добавлено"),

    // The table.
    col_target, set_col_target => ("Target", "Цель"),
    col_reason, set_col_reason => ("Reason", "Причина"),
    col_verdict, set_col_verdict => ("Verdict", "Вердикт"),
    col_time, set_col_time => ("Time", "Время"),

    // The dashboard.
    dash_ok, set_dash_ok => ("reachable", "доступно"),
    dash_blocked, set_dash_blocked => ("blocked", "режется"),
    dash_unknown, set_dash_unknown => ("unknown", "неизвестно"),

    // The verdicts, in four words.
    badge_ok, set_badge_ok => ("reachable", "доступно"),
    badge_provider, set_badge_provider => ("provider", "провайдер"),
    badge_service, set_badge_service => ("the service itself", "сам сервис"),
    badge_unknown, set_badge_unknown => ("unknown", "неизвестно"),
    badge_none, set_badge_none => ("—", "—"),

    // The table's reason column.
    why_ok, set_why_ok => ("every probe passed", "все пробы прошли"),
    why_dns_spoof, set_why_dns_spoof => (
        "the resolver answers with someone else's address",
        "резолвер отдаёт чужой адрес"
    ),
    why_dpi_sni, set_why_dpi_sni => (
        "the handshake dies on the real name",
        "рукопожатие гибнет на настоящем имени"
    ),
    why_ip_block, set_why_ip_block => ("the address does not answer", "адрес не отвечает"),
    why_host_filter, set_why_host_filter => (
        "the request dies on the real Host",
        "запрос гибнет на настоящем Host"
    ),
    why_l4_drop, set_why_l4_drop => (
        "the connection breaks mid-transfer",
        "соединение рвётся на середине передачи"
    ),
    why_geo_block, set_why_geo_block => (
        "the service refuses this region",
        "сервис отказывает этому региону"
    ),
    why_unknown, set_why_unknown => ("the facts do not add up", "факты не сходятся"),
    why_path_block, set_why_path_block => (
        "blocked on the way, open through the tunnel",
        "режется на пути, открыто через туннель"
    ),
    why_both_ok, set_why_both_ok => ("open both ways", "открыто и так, и так"),
    why_service_block, set_why_service_block => ("closed both ways", "закрыто и так, и так"),
    why_not_probed, set_why_not_probed => ("not checked yet", "ещё не проверено"),

    // The inspector.
    step_dns, set_step_dns => ("DNS", "DNS"),
    step_tcp, set_step_tcp => ("TCP", "TCP"),
    step_tls, set_step_tls => ("TLS", "TLS"),
    step_http, set_step_http => ("HTTP", "HTTP"),
    step_payload, set_step_payload => ("l4-25", "l4-25"),
    step_quic, set_step_quic => ("QUIC", "QUIC"),
    step_tunnel, set_step_tunnel => ("Tunnel", "Туннель"),
    note_pending_dns, set_note_pending_dns => ("system against DoH", "система против DoH"),
    note_pending_tcp, set_note_pending_tcp => ("connect 443", "connect 443"),
    note_pending_tls, set_note_pending_tls => ("the real SNI", "настоящий SNI"),
    note_pending_http, set_note_pending_http => ("the real Host", "настоящий Host"),
    note_pending_payload, set_note_pending_payload => ("reads ~64 KB", "чтение ~64 КБ"),
    note_pending_quic, set_note_pending_quic => ("the UDP path", "UDP-путь"),
    note_pending_tunnel, set_note_pending_tunnel => ("direct vs tunnel", "дифф direct/tunnel"),
    res_ok, set_res_ok => ("ok", "ок"),
    res_fail, set_res_fail => ("failed", "сбой"),
    res_na, set_res_na => ("n/a", "н/д"),
    res_silent, set_res_silent => ("silent", "молчит"),
    res_reset, set_res_reset => ("reset", "сброс"),
    res_timeout, set_res_timeout => ("timeout", "таймаут"),
    res_answered, set_res_answered => ("answered", "ответил"),
    res_redirect, set_res_redirect => ("redirect", "редирект"),
    res_drop, set_res_drop => ("drop", "обрыв"),
    res_full, set_res_full => ("full", "полностью"),
    res_stalled, set_res_stalled => ("stalled", "зависло"),
    note_dns_ok, set_note_dns_ok => ("system and DoH agree", "система и DoH сходятся"),
    note_dns_spoof, set_note_dns_spoof => (
        "the system resolver answers with a foreign pool",
        "системный резолвер отдаёт чужой пул"
    ),
    note_dns_ref, set_note_dns_ref => ("the reference is unreachable", "эталон недоступен"),
    note_tcp_ok, set_note_tcp_ok => ("connected", "соединение установлено"),
    note_tcp_fail, set_note_tcp_fail => ("no connection", "соединения нет"),
    note_tls_ok, set_note_tls_ok => ("the server answered", "сервер ответил"),
    note_tls_rst, set_note_tls_rst => (
        "reset right after ClientHello",
        "сброс сразу после ClientHello"
    ),
    note_tls_alert, set_note_tls_alert => ("a TLS alert came back", "вернулся TLS-алерт"),
    note_tls_mismatch, set_note_tls_mismatch => (
        "a certificate for another name — expected",
        "сертификат на другое имя — так и должно быть"
    ),
    note_http_ok, set_note_http_ok => ("the page came back", "страница вернулась"),
    note_http_status, set_note_http_status => ("a status came back", "вернулся статус"),
    note_http_reset, set_note_http_reset => ("reset on the real Host", "сброс на настоящем Host"),
    note_payload_full, set_note_payload_full => ("the body came through", "тело дошло"),
    note_payload_drop, set_note_payload_drop => ("the body broke off", "тело оборвалось"),
    note_payload_na, set_note_payload_na => (
        "the handshake did not get there",
        "до рукопожатия не дошло"
    ),
    note_quic_answer, set_note_quic_answer => (
        "the server answered over UDP",
        "сервер ответил по UDP"
    ),
    note_quic_silent, set_note_quic_silent => (
        "silence — maybe NAT, maybe a block",
        "молчание — может NAT, может блок"
    ),
    note_tunnel_ok, set_note_tunnel_ok => ("open through the tunnel", "через туннель открыто"),
    note_tunnel_path, set_note_tunnel_path => ("blocked on the way", "режется на пути"),
    note_tunnel_service, set_note_tunnel_service => (
        "closed even through the tunnel",
        "закрыто и через туннель"
    ),
    note_tunnel_off, set_note_tunnel_off => ("no tunnel configured", "туннель не задан"),

    // The empty states.
    empty_none_title, set_empty_none_title => ("No targets are ticked", "Ни одна цель не отмечена"),
    empty_none_sub, set_empty_none_sub => (
        "Tick a few on the left — or all of them — and press Check.",
        "Отметьте несколько слева — или все — и нажмите «Проверить»."
    ),
    empty_norun_title, set_empty_norun_title => (
        "Nothing has been checked yet",
        "Проверок ещё не было"
    ),
    empty_norun_sub, set_empty_norun_sub => (
        "The table fills in as the probes come back; the walls end up on top.",
        "Таблица заполняется по мере проб; стены окажутся сверху."
    ),

    // The settings popover.
    timeout, set_timeout => ("Probe timeout, sec", "Таймаут пробы, сек"),
    timeout_hint, set_timeout_hint => (
        "a total budget: the connection and the handshake",
        "общий бюджет: соединение и рукопожатие"
    ),
    socks5, set_socks5 => ("SOCKS5", "SOCKS5"),
    socks5_hint, set_socks5_hint => (
        "empty — no tunnel; an address adds the direct-vs-tunnel diff",
        "пусто — без туннеля; адрес включает дифф «напрямую vs туннель»"
    ),
    socks5_placeholder, set_socks5_placeholder => ("127.0.0.1:1080", "127.0.0.1:1080"),
    dark, set_dark => ("Dark", "Тёмная"),
    light, set_light => ("Light", "Светлая"),
    language, set_language => ("Language", "Язык"),
    frame, set_frame => ("Window frame", "Рамка окна"),

    // The header's icon buttons.
    theme, set_theme => ("Theme", "Тема"),

    // The groups of the target list.
    category_video_hosting, set_category_video_hosting => ("Video hosting", "Видеохостинги"),
    category_social, set_category_social => ("Social networks", "Соцсети"),
    category_messenger, set_category_messenger => ("Messengers", "Мессенджеры"),
    category_audio, set_category_audio => ("Audio streaming", "Аудиостриминг"),
    category_video, set_category_video => ("Video streaming", "Видеостриминг"),
    category_games, set_category_games => ("Games", "Игры"),
    category_encyclopedia, set_category_encyclopedia => ("Encyclopedias", "Энциклопедии"),
    category_development, set_category_development => ("Development", "Разработка"),
    category_custom, set_category_custom => ("Custom", "Пользовательские"),
    category_news, set_category_news => ("News", "Новости"),
    category_search, set_category_search => ("Search", "Поиск"),
    category_ai, set_category_ai => ("AI assistants", "ИИ-ассистенты"),

    // The export and the clock.
    export_title, set_export_title => ("Save the report", "Сохранить отчёт"),
    export_empty, set_export_empty => ("Run the probes first", "Сначала прогон"),
    export_done, set_export_done => ("Written", "Записано"),
    export_failed, set_export_failed => ("Could not write", "Не удалось записать"),
    seconds, set_seconds => ("s", "с"),
    minutes, set_minutes => ("min", "мин"),

    // The run's own count of targets, in the lowercase of the mockup.
    run_count, set_run_count => ("targets", "целей"),

    // The stop button and the run's end.
    stop, set_stop => ("Stop", "Остановить"),
    stopped, set_stopped => ("Run stopped", "Прогон остановлен"),

    // The table's filter chips and the counter beside them.
    filter_all, set_filter_all => ("all", "все"),
    filter_blocked, set_filter_blocked => ("blocked", "режется"),
    filter_ok, set_filter_ok => ("available", "доступно"),
    filter_unknown, set_filter_unknown => ("unknown", "неизвестно"),
    filter_title, set_filter_title => ("filter the table", "фильтр таблицы"),
    shown, set_shown => ("shown", "показано"),
    empty_filter, set_empty_filter => (
        "Nothing matches this filter",
        "Под фильтр ничего не попало"
    ),

    // The search over the target list.
    search, set_search => ("filter targets…", "поиск цели…"),

    // The verdict a target had in the run before this one.
    last_run, set_last_run => ("last run", "в прошлый раз"),

    // The copy button of the inspector.
    copy_title, set_copy_title => ("Copy the result", "Скопировать результат"),
    copied, set_copied => (
        "copied: verdict + ladder + facts",
        "скопировано: вердикт + лестница + факты"
    ),
    copy_failed, set_copy_failed => ("could not copy", "не удалось скопировать"),
    facts_label, set_facts_label => ("facts", "факты"),

    // The verdict tooltips of the table.
    tip_ok, set_tip_ok => (
        "target is fully reachable: DNS, TLS, HTTP all clean",
        "цель доступна целиком: DNS, TLS, HTTP — чисто"
    ),
    tip_path, set_tip_path => (
        "connection is cut by the provider (TSPU/DPI on SNI)",
        "соединение обрывает провайдер (ТСПУ/DPI по SNI)"
    ),
    tip_svc, set_tip_svc => (
        "blocked by the service itself: region or account policy",
        "не пускает сам сервис: регион, аккаунт или его гео-политика"
    ),
    tip_unknown, set_tip_unknown => (
        "probes lack data — open the inspector",
        "пробам не хватило данных — открой инспектор"
    ),

    // The keyboard hints of the status bar.
    key_search, set_key_search => ("search", "поиск"),
    key_run, set_key_run => ("run", "прогон"),
    key_target, set_key_target => ("target", "цель"),
    key_close, set_key_close => ("close", "закрыть"),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_string_has_both_languages() {
        let en = Strings::new(Lang::En);
        let ru = Strings::new(Lang::Ru);
        // The macro makes both structs from the same rows, so a missing
        // translation cannot compile. This test guards the other half: an
        // empty string is a translation someone forgot to write.
        assert!(!en.check.is_empty());
        assert!(!ru.check.is_empty());
        assert!(!en.badge_provider.is_empty());
        assert!(!ru.badge_provider.is_empty());
        assert_ne!(en.check, ru.check);
        assert_ne!(en.badge_provider, ru.badge_provider);
    }

    #[test]
    fn the_language_has_a_code_for_the_switch() {
        assert_eq!(Lang::Ru.code(), "ru");
        assert_eq!(Lang::En.code(), "en");
    }
}
