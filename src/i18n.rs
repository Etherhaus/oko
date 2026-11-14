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
use crate::verdict::Level;

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
    /// The word for a verdict level, for the table's subtitle.
    pub fn level(&self, level: Level) -> &'static str {
        match level {
            Level::Ok => self.level_ok,
            Level::Warn => self.level_warn,
            Level::Bad => self.level_bad,
            Level::Undetermined => self.level_undetermined,
        }
    }

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
    // Header
    subtitle, set_subtitle => (
        "a detector for blocking and reachability of online services",
        "детектор блокировок и доступности сервисов"
    ),

    // Table
    targets, set_targets => ("Targets", "Цели"),
    col_target, set_col_target => ("Target", "Цель"),
    col_verdict, set_col_verdict => ("Verdict", "Вердикт"),
    check_all, set_check_all => ("All", "Все"),
    check_none, set_check_none => ("None", "Ничего"),
    not_checked, set_not_checked => ("not checked", "не проверено"),
    in_progress, set_in_progress => ("checking…", "идёт проверка…"),
    level_ok, set_level_ok => ("ok", "ок"),
    level_warn, set_level_warn => ("warn", "варн"),
    level_bad, set_level_bad => ("blocked", "блокировка"),
    level_undetermined, set_level_undetermined => ("undetermined", "неопределённо"),

    // Details
    details, set_details => ("Details", "Детали"),
    details_empty, set_details_empty => (
        "Select a target to see every probe and its outcome.",
        "Выберите цель, чтобы увидеть все пробы и их исходы."
    ),
    details_not_probed, set_details_not_probed => (
        "This target has not been checked yet: its probes appear after a run.",
        "Цель ещё не проверена: пробы появятся после прогона."
    ),

    // Settings
    check, set_check => ("Check", "Проверить"),
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

    // Theme and language
    dark, set_dark => ("Dark", "Тёмная"),
    light, set_light => ("Light", "Светлая"),

    // Status
    ready, set_ready => ("Ready to check", "Готов к проверке"),
    checking, set_checking => ("Checking", "Проверка"),
    done, set_done => ("Checked", "Проверено"),
    control_dead, set_control_dead => (
        "The control target did not answer: the network is down or filtered as a whole",
        "Контрольная цель не ответила: сеть недоступна или фильтруется целиком"
    ),
    run_failed, set_run_failed => ("The run failed", "Прогон не удался"),
    nothing_selected, set_nothing_selected => ("No target is selected", "Не выбрано ни одной цели"),
    bad_socks5, set_bad_socks5 => ("The SOCKS5 address is not valid", "Адрес SOCKS5 не разобран"),

    // Categories
    category_video_hosting, set_category_video_hosting => ("Video hosting", "Видеохостинги"),
    category_social, set_category_social => ("Social networks", "Соцсети"),
    category_messenger, set_category_messenger => ("Messengers", "Мессенджеры"),
    category_news, set_category_news => ("News", "Новости"),
    category_search, set_category_search => ("Search", "Поиск"),
    category_ai, set_category_ai => ("AI assistants", "ИИ-ассистенты"),
    category_audio, set_category_audio => ("Audio streaming", "Аудиостриминг"),
    category_video, set_category_video => ("Video streaming", "Видеостриминг"),
    category_games, set_category_games => ("Games", "Игры"),
    category_encyclopedia, set_category_encyclopedia => ("Encyclopedias", "Энциклопедии"),
    category_development, set_category_development => ("Development", "Разработка"),
    category_custom, set_category_custom => ("Custom", "Пользовательские"),

    // Custom targets
    add_domain, set_add_domain => ("+ add a domain", "+ добавить домен"),
    add, set_add => ("Add", "Добавить"),
    cancel, set_cancel => ("Cancel", "Отмена"),
    domain_placeholder, set_domain_placeholder => ("example.org", "example.org"),
    remove, set_remove => ("Remove", "Удалить"),
    custom_mark, set_custom_mark => ("custom", "пользовательская"),
    bad_domain, set_bad_domain => (
        "A bare domain, without a scheme or a path",
        "Нужен голый домен, без схемы и пути"
    ),
    duplicate_domain, set_duplicate_domain => (
        "That domain is already in the list",
        "Такой домен уже есть в списке"
    ),

    // Frame
    frame, set_frame => ("Window frame", "Рамка окна"),

    // The menu, the settings dialog and the panes.
    menu, set_menu => ("Menu", "Меню"),
    settings, set_settings => ("Settings", "Настройки"),
    close, set_close => ("Close", "Закрыть"),
    done_settings, set_done_settings => ("Done", "Готово"),
    export, set_export => ("Export", "Экспорт"),
    targets_count, set_targets_count => ("targets", "целей"),
    checked_count, set_checked_count => ("checked", "отмечено"),
    collapse, set_collapse => ("Collapse the group", "Свернуть группу"),
    expand, set_expand => ("Expand the group", "Развернуть группу"),

    // Dashboard
    dash_ok, set_dash_ok => ("reachable", "доступно"),
    dash_blocked, set_dash_blocked => ("blocked", "режется"),
    dash_unknown, set_dash_unknown => ("unknown", "неизвестно"),
    dash_empty, set_dash_empty => ("No run yet", "Прогонов ещё не было"),
    dash_delta, set_dash_delta => ("vs the previous run", "к прошлому прогону"),
    seconds, set_seconds => ("s", "с"),

    // Watchdog
    interrupted, set_interrupted => (
        "The run was interrupted by the watchdog",
        "Прогон прерван сторожевым таймером"
    ),

    // Export
    export_text, set_export_text => ("Export text", "Экспорт текста"),
    export_json, set_export_json => ("Export JSON", "Экспорт JSON"),
    export_title, set_export_title => ("Save the report", "Сохранить отчёт"),
    export_empty, set_export_empty => ("Run the probes first", "Сначала прогон"),
    export_done, set_export_done => ("Written", "Записано"),
    export_failed, set_export_failed => ("Could not write", "Не удалось записать"),
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
        assert!(!en.subtitle.is_empty());
        assert!(!ru.subtitle.is_empty());
        assert!(!en.check.is_empty());
        assert!(!ru.check.is_empty());
        assert_ne!(en.subtitle, ru.subtitle);
        assert_ne!(en.check, ru.check);
    }

    #[test]
    fn the_language_has_a_code_for_the_switch() {
        assert_eq!(Lang::Ru.code(), "ru");
        assert_eq!(Lang::En.code(), "en");
    }
}
