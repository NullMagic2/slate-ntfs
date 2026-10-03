//! Module: slate_ntfs_permissions::window
//! Purpose: present drive permissions and verified application outcomes in GTK.
//! Created: 2026-10-01
//! Architecture: The model supplies policy and live state; RootSession forwards
//! authorized saves to the privileged helper, which performs live remounts.

use crate::icons::ICONS;
use crate::model::Model;
use crate::session::{Refusal, RootSession};
use gtk::prelude::*;
use gtk::{gdk, gio, glib, pango};
use ntfs_permissions::core::{self, Applied, Class, Drive, Kind, Level, Mode, User};
use ntfs_permissions::i18n::{self, tr, trf, Language};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::Duration;

pub const APP_ID: &str = "org.slate_ntfs.Permissions";

pub const CSS: &str = "
.sidebar-pane { background-color: alpha(@theme_fg_color, 0.03);
                border-right: 1px solid alpha(@theme_fg_color, 0.12); }
.sidebar-pane list { background-color: transparent; }
.sidebar-pane list row { padding: 8px 10px; border-radius: 8px; margin: 1px 8px; }
.filter-bar { margin: 12px 12px 6px 12px; }
.filter-bar button { padding: 4px 2px; }
.filter-bar button label { font-size: 0.82em; }
.detail-title { font-size: 1.45em; font-weight: 700; }
.row-title { font-weight: 600; }
.card { border: 1px solid alpha(@theme_fg_color, 0.14); border-radius: 10px;
        background-color: @theme_base_color; }
.card row { padding: 8px 12px; }
.card row:not(:last-child) { border-bottom: 1px solid alpha(@theme_fg_color, 0.08); }
.pill { border-radius: 99px; padding: 2px 10px; font-size: 0.85em; font-weight: 600;
        background-color: alpha(@theme_selected_bg_color, 0.14); color: @theme_selected_bg_color; }
.pill.off { background-color: alpha(@theme_fg_color, 0.08); color: alpha(@theme_fg_color, 0.65); }
.pill.device { font-size: 1.0em; padding: 3px 12px; }
.name-entry { font-size: 1.0em; padding: 2px 8px; min-height: 0; }
.detail-title-entry { font-size: 1.3em; font-weight: 700; padding: 2px 8px; }
.pending { color: @theme_selected_bg_color; font-weight: 700; }
row:selected .pending { color: @theme_selected_fg_color; }
.empty-title { font-size: 1.3em; font-weight: 700; }
.hint { font-size: 0.9em; }
.level-badge { padding: 4px 12px 4px 8px; border-radius: 99px;
               background-color: alpha(@theme_fg_color, 0.06); }
.section-title { font-weight: 700; margin-top: 4px; }
.mode-card { padding: 0; border-radius: 10px; }
.mode-card:checked { box-shadow: inset 0 0 0 2px @theme_selected_bg_color;
                     background-image: none; background-color: alpha(@theme_selected_bg_color, 0.08); }
.rwx-grid checkbutton { padding: 4px; }
.language-row { padding: 6px 10px; }
/* Save: always green with white text, whatever the theme's accent colour. */
button.save-button { background-image: none; background-color: #26a269; border-color: #1f8a58;
                     color: #ffffff; text-shadow: none; box-shadow: none; }
button.save-button label { color: #ffffff; font-weight: 600; }
button.save-button:hover { background-color: #2ec27e; border-color: #26a269; }
button.save-button:active { background-color: #1f8a58; }
button.save-button:disabled { background-color: alpha(#26a269, 0.55); }
button.save-button:disabled label { color: alpha(#ffffff, 0.85); }
button.save-button spinner { color: #ffffff; }
";

// English interface texts; translated when shown.
const LEVELS: [(Level, &str, &str, &str); 4] = [
    (Level::None, "No access", "emblem-unreadable", "Cannot open this drive."),
    (Level::Read, "Read only", "emblem-readonly", "Can open and copy files, but cannot change anything."),
    (Level::Write, "Read & write", "emblem-default", "Can add, change and delete files, like a standard Windows user."),
    (
        Level::Full,
        "Full control",
        "emblem-personal",
        "Administrator of this drive: can do everything, including files Windows protects. Only one person per drive.",
    ),
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    All,
    Only(Kind),
}

const FILTERS: [(Filter, &str, &str, &str, &str); 4] = [
    (Filter::All, "All", "drive-multidisk", "Show all NTFS drives", "No NTFS drives found"),
    (Filter::Only(Kind::Ssd), "SSD", "drive-harddisk-solidstate", "Show only internal SSDs", "No NTFS SSDs"),
    (Filter::Only(Kind::Hdd), "HDD", "drive-harddisk", "Show only internal hard disks", "No NTFS hard disks"),
    (
        Filter::Only(Kind::Portable),
        "Portable",
        "drive-removable-media-usb",
        "Show only USB drives and memory cards",
        "No portable NTFS drives",
    ),
];

const RWX_COLUMNS: [(&str, &str); 3] = [
    ("Read", "Open files and see what is in folders."),
    ("Write", "Create, change, rename and delete files and folders. Needs Read."),
    ("Execute", "Run programs and scripts stored on the drive."),
];

const CLASS_ROWS: [(Class, &str, &str); 3] = [
    (Class::Owner, "Owner", "avatar-default"),
    (Class::Group, "Group", "emblem-people"),
    (Class::Others, "Everyone else", "emblem-shared"),
];

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Ssd => "SSD",
        Kind::Hdd => "Hard disk",
        Kind::Portable => "Portable drive",
    }
}

fn kind_icon(kind: Kind) -> &'static str {
    match kind {
        Kind::Ssd => "drive-harddisk-solidstate",
        Kind::Hdd => "drive-harddisk",
        Kind::Portable => "drive-removable-media-usb",
    }
}

fn filter_info(filter: Filter) -> (&'static str, &'static str) {
    FILTERS.iter().find(|f| f.0 == filter).map(|f| (f.2, f.4)).unwrap()
}

fn my_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// 'root' where the target asks for the root password (Debian with a root
/// password), else an administrator (sudo-group members; Ubuntu and Mint lock root).
fn password() -> String {
    let root = std::fs::read_to_string("/etc/slate-ntfs/auth-mode").map(|t| t.trim() == "root").unwrap_or(false);
    tr(if root { "the root password" } else { "an administrator password" })
}

// ------------------------------------------------------------ helpers ---
fn label(text: &str, classes: &[&str]) -> gtk::Label {
    let widget = gtk::Label::new(Some(text));
    widget.set_xalign(0.0);
    widget.set_ellipsize(pango::EllipsizeMode::End);
    for class in classes {
        widget.style_context().add_class(class);
    }
    widget
}

fn wrapped(text: &str, classes: &[&str]) -> gtk::Label {
    let widget = label(text, classes);
    widget.set_ellipsize(pango::EllipsizeMode::None);
    widget.set_line_wrap(true);
    widget.set_max_width_chars(60);
    widget
}

fn centered(text: &str, classes: &[&str]) -> gtk::Label {
    let widget = wrapped(text, classes);
    widget.set_xalign(0.5);
    widget.set_justify(gtk::Justification::Center);
    widget
}

fn vbox(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Vertical, spacing)
}

fn hbox(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Horizontal, spacing)
}

fn pill(text: &str, active: bool) -> gtk::Label {
    let widget = label(text, &["pill"]);
    if !active {
        widget.style_context().add_class("off");
    }
    widget.set_halign(gtk::Align::Start);
    widget
}

fn scrolled(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    let window = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
    window.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    window.add(child);
    window
}

fn clear(container: &impl IsA<gtk::Container>) {
    for child in container.children() {
        container.remove(&child);
    }
}

fn empty_state(icon: &str, title: &str, detail: &str) -> gtk::Box {
    let box_ = vbox(8);
    box_.set_valign(gtk::Align::Center);
    box_.set_halign(gtk::Align::Center);
    let image = ICONS.with(|i| i.image(icon, 96));
    image.set_opacity(0.55);
    box_.pack_start(&image, false, false, 6);
    box_.pack_start(&centered(&tr(title), &["empty-title"]), false, false, 0);
    if !detail.is_empty() {
        box_.pack_start(&centered(&tr(detail), &["dim-label"]), false, false, 0);
    }
    box_
}

fn level_badge(level: Level) -> gtk::Box {
    let (_, name, icon, tip) = LEVELS.iter().find(|l| l.0 == level).unwrap();
    let box_ = hbox(6);
    box_.set_valign(gtk::Align::Center);
    box_.style_context().add_class("level-badge");
    box_.pack_start(&ICONS.with(|i| i.image(icon, 20)), false, false, 0);
    box_.pack_start(&label(&tr(name), &[]), false, false, 0);
    box_.set_tooltip_text(Some(&tr(tip)));
    box_
}

fn level_combo(level: Level, on_change: impl Fn(Level) + 'static) -> gtk::ComboBox {
    let store = gtk::ListStore::new(&[glib::Type::STRING, glib::Type::STRING, glib::Type::STRING]);
    for (key, name, icon, _) in LEVELS {
        store.insert_with_values(None, &[(0, &icon), (1, &tr(name)), (2, &key.name())]);
    }
    let combo = gtk::ComboBox::with_model(&store);
    combo.set_id_column(2);
    let icon_cell = gtk::CellRendererPixbuf::new();
    combo.pack_start(&icon_cell, false);
    // Surfaces keep icons sharp on HiDPI; set them per cell.
    combo.set_cell_data_func(
        &icon_cell,
        Some(Box::new(|_layout, cell, model, iter| {
            let name: String = model.value(iter, 0).get().unwrap_or_default();
            if let Some(surface) = ICONS.with(|i| i.surface(&name, 20)) {
                cell.set_property("surface", &surface);
            }
        })),
    );
    let text_cell = gtk::CellRendererText::new();
    text_cell.set_padding(4, 0);
    combo.pack_start(&text_cell, true);
    combo.add_attribute(&text_cell, "text", 1);
    combo.set_valign(gtk::Align::Center);
    combo.set_size_request(170, -1);
    combo.set_active_id(Some(level.name()));
    let tooltip = |combo: &gtk::ComboBox| {
        let key = combo.active_id().map(|s| s.to_string()).unwrap_or_default();
        if let Some((_, _, _, tip)) = LEVELS.iter().find(|l| l.0.name() == key) {
            combo.set_tooltip_text(Some(&tr(tip)));
        }
    };
    tooltip(&combo);
    combo.connect_changed(move |combo| {
        tooltip(combo);
        if let Some(level) = combo.active_id().and_then(|id| Level::parse(&id)) {
            on_change(level);
        }
    });
    combo
}

fn filter_bar(current: Filter, on_toggle: impl Fn(Filter) + 'static) -> gtk::Box {
    let on_toggle = Rc::new(on_toggle);
    let box_ = hbox(0);
    box_.set_homogeneous(true);
    box_.style_context().add_class("linked");
    box_.style_context().add_class("filter-bar");
    let mut first: Option<gtk::RadioButton> = None;
    for (filter, name, icon, tip, _) in FILTERS {
        let button = match &first {
            None => gtk::RadioButton::new(),
            Some(group) => gtk::RadioButton::from_widget(group),
        };
        button.set_mode(false);
        let content = vbox(2);
        content.pack_start(&ICONS.with(|i| i.image(icon, 24)), false, false, 0);
        let caption = label(&tr(name), &[]);
        caption.set_xalign(0.5);
        content.pack_start(&caption, false, false, 0);
        button.add(&content);
        button.set_tooltip_text(Some(&tr(tip)));
        button.set_active(filter == current);
        let on_toggle = on_toggle.clone();
        button.connect_toggled(move |b| {
            if b.is_active() {
                on_toggle(filter);
            }
        });
        box_.pack_start(&button, true, true, 0);
        first.get_or_insert(button);
    }
    box_
}

fn drive_title(drive: &Drive) -> String {
    if drive.label.is_empty() {
        trf("{size} volume", &[("size", &core::human_size(drive.size))])
    } else {
        drive.label.clone()
    }
}

fn drive_short(drive: &Drive) -> String {
    format!("{} · {}", core::human_size(drive.size), tr(kind_label(drive.kind)))
}

fn drive_subtitle(drive: &Drive) -> String {
    let mut parts = vec![tr(kind_label(drive.kind)), core::human_size(drive.size)];
    if !drive.model.is_empty() {
        parts.insert(0, drive.model.clone());
    }
    parts.join(" · ")
}

fn display_name(user: &User) -> String {
    if user.uid == my_uid() {
        trf("{name} (you)", &[("name", &user.real_name)])
    } else {
        user.real_name.clone()
    }
}

// --------------------------------------------------------------- window ---
/// Everything kept when the window is rebuilt for another language.
pub struct Carry {
    pub model: Model,
    pub session: Arc<RootSession>,
    pub unlocked: bool,
    pub drive_filter: Filter,
    pub user_filter: Filter,
    pub selected_drive: Option<String>,
    pub selected_user: Option<u32>,
    pub page: String,
}

struct State {
    model: Model,
    unlocked: bool,
    authenticating: bool,
    saving: bool,
    drive_filter: Filter,
    user_filter: Filter,
    selected_drive: Option<String>,
    selected_user: Option<u32>,
    drive_rows: Vec<String>,
    user_rows: Vec<u32>,
    notice: u64,
}

pub struct Ui {
    app: gtk::Application,
    pub window: gtk::ApplicationWindow,
    stack: gtk::Stack,
    drive_list: gtk::ListBox,
    drive_detail: gtk::Box,
    user_list: gtk::ListBox,
    user_detail: gtk::Box,
    save_button: gtk::Button,
    save_label: gtk::Label,
    save_spinner: gtk::Spinner,
    lock_button: gtk::Button,
    lock_image: gtk::Image,
    infobar: gtk::InfoBar,
    infobar_label: gtk::Label,
    lockbar: gtk::InfoBar,
    lock_text: gtk::Label,
    lock_spinner: gtk::Spinner,
    unlock_button: gtk::Button,
    session: Arc<RootSession>,
    st: RefCell<State>,
    filling: Cell<bool>,
    keep_session: Cell<bool>,
    me: RefCell<Weak<Ui>>,
}

type W = Weak<Ui>;

impl Ui {
    fn weak(&self) -> W {
        self.me.borrow().clone()
    }

    pub fn new(app: &gtk::Application, carry: Option<Carry>) -> Rc<Ui> {
        let window = gtk::ApplicationWindow::new(app);
        window.set_title(&tr("NTFS Permissions Manager"));
        // Centred, and never larger than 90% of the screen's usable area.
        let (mut width, mut height) = (940, 760);
        if let Some(monitor) = gtk::gdk::Display::default().and_then(|d| d.primary_monitor().or_else(|| d.monitor(0))) {
            let area = monitor.workarea();
            width = width.min(area.width() * 9 / 10);
            height = height.min(area.height() * 9 / 10);
        }
        window.set_default_size(width, height);
        window.set_position(gtk::WindowPosition::Center);
        window.set_icon_name(Some("slate-ntfs-permissions"));
        ICONS.with(|i| i.set_scale(window.scale_factor()));

        let header = gtk::HeaderBar::new();
        header.set_show_close_button(true);
        header.set_title(Some(&tr("NTFS Permissions Manager")));
        window.set_titlebar(Some(&header));
        let stack = gtk::Stack::new();
        stack.set_transition_type(gtk::StackTransitionType::Crossfade);
        let switcher = gtk::StackSwitcher::new();
        switcher.set_stack(Some(&stack));
        header.set_custom_title(Some(&switcher));

        let refresh = gtk::Button::from_icon_name(Some("view-refresh-symbolic"), gtk::IconSize::Button);
        refresh.set_tooltip_text(Some(&tr("Look for drives and people again")));
        header.pack_start(&refresh);
        let lock_button = gtk::Button::new();
        let lock_image = gtk::Image::new();
        lock_button.add(&lock_image);
        header.pack_start(&lock_button);

        // Always a clear green button with white, centred text; the count shows
        // pending changes. The spinner only takes space while saving.
        let save_button = gtk::Button::new();
        let save_label = gtk::Label::new(Some(&tr("Save")));
        save_label.set_xalign(0.5);
        let save_spinner = gtk::Spinner::new();
        save_spinner.set_no_show_all(true);
        let save_box = hbox(6);
        save_box.set_halign(gtk::Align::Center);
        save_box.pack_start(&save_spinner, false, false, 0);
        save_box.pack_start(&save_label, false, false, 0);
        save_button.add(&save_box);
        save_button.set_size_request(112, -1);
        save_button.style_context().add_class("save-button");
        save_button.set_tooltip_text(Some(&tr("Save and apply the new permissions right away")));
        header.pack_end(&save_button);
        let language = gtk::MenuButton::new();
        header.pack_end(&language);

        let infobar = gtk::InfoBar::new();
        infobar.set_show_close_button(true);
        infobar.set_revealed(false);
        let infobar_label = wrapped("", &[]);
        infobar.content_area().add(&infobar_label);
        infobar.connect_response(|bar, _| bar.set_revealed(false));

        // Shown whenever editing is not possible, with a way to try again.
        let lockbar = gtk::InfoBar::new();
        lockbar.set_revealed(false);
        let lock_content = hbox(10);
        let lock_spinner = gtk::Spinner::new();
        lock_content.pack_start(&lock_spinner, false, false, 0);
        let lock_text = wrapped("", &[]);
        lock_content.pack_start(&lock_text, true, true, 0);
        lockbar.content_area().add(&lock_content);
        let unlock_button = lockbar.add_button(&tr("Unlock…"), gtk::ResponseType::Other(1)).expect("info bar button");

        let drive_list = gtk::ListBox::new();
        let drive_detail = vbox(0);
        let user_list = gtk::ListBox::new();
        let user_detail = vbox(0);

        let (state, session) = match carry {
            Some(c) => (
                State {
                    model: c.model,
                    unlocked: c.unlocked,
                    authenticating: false,
                    saving: false,
                    drive_filter: c.drive_filter,
                    user_filter: c.user_filter,
                    selected_drive: c.selected_drive,
                    selected_user: c.selected_user,
                    drive_rows: vec![],
                    user_rows: vec![],
                    notice: 0,
                },
                c.session,
            ),
            None => (
                State {
                    model: Model::default(),
                    unlocked: core::is_root(),
                    authenticating: false,
                    saving: false,
                    drive_filter: Filter::All,
                    user_filter: Filter::All,
                    selected_drive: None,
                    selected_user: None,
                    drive_rows: vec![],
                    user_rows: vec![],
                    notice: 0,
                },
                Arc::new(RootSession::default()),
            ),
        };
        let page = if state.model.drives.is_empty() && state.model.users.is_empty() { None } else { Some(()) };

        let ui = Rc::new(Ui {
            app: app.clone(),
            window,
            stack,
            drive_list,
            drive_detail,
            user_list,
            user_detail,
            save_button,
            save_label,
            save_spinner,
            lock_button,
            lock_image,
            infobar,
            infobar_label,
            lockbar,
            lock_text,
            lock_spinner,
            unlock_button,
            session,
            st: RefCell::new(state),
            filling: Cell::new(false),
            keep_session: Cell::new(false),
            me: RefCell::new(Weak::new()),
        });
        *ui.me.borrow_mut() = Rc::downgrade(&ui);
        let _ = page;

        ui.stack.add_titled(&ui.build_drives_page(), "drives", &tr("Drives"));
        ui.stack.add_titled(&ui.build_users_page(), "users", &tr("Users"));
        ui.build_language_menu(&language);

        let root = vbox(0);
        root.pack_start(&ui.lockbar, false, false, 0);
        root.pack_start(&ui.infobar, false, false, 0);
        root.pack_start(&ui.stack, true, true, 0);
        ui.window.add(&root);

        let w = ui.weak();
        refresh.connect_clicked(move |_| {
            if let Some(ui) = w.upgrade() {
                ui.reload()
            }
        });
        let w = ui.weak();
        ui.lock_button.connect_clicked(move |_| {
            if let Some(ui) = w.upgrade() {
                ui.toggle_lock()
            }
        });
        let w = ui.weak();
        ui.save_button.connect_clicked(move |_| {
            if let Some(ui) = w.upgrade() {
                ui.save()
            }
        });
        let w = ui.weak();
        ui.lockbar.connect_response(move |_, response| {
            if response == gtk::ResponseType::Other(1) {
                if let Some(ui) = w.upgrade() {
                    ui.authenticate();
                }
            }
        });
        let w = ui.weak();
        ui.window.connect_delete_event(move |_, _| match w.upgrade() {
            Some(ui) => ui.on_close(),
            None => glib::Propagation::Proceed,
        });
        let w = ui.weak();
        ui.window.connect_destroy(move |_| {
            if let Some(ui) = w.upgrade() {
                if !ui.keep_session.get() {
                    ui.session.stop();
                }
            }
        });
        ui.reload();
        ui
    }

    pub fn show(self: &Rc<Self>, page: Option<&str>) {
        self.window.show_all();
        if let Some(page) = page {
            self.stack.set_visible_child_name(page);
        }
        self.update_lock_ui();
        self.window.present();
    }

    pub fn is_unlocked(&self) -> bool {
        self.st.borrow().unlocked
    }

    pub fn carry(&self) -> Carry {
        let mut st = self.st.borrow_mut();
        Carry {
            model: std::mem::take(&mut st.model),
            session: self.session.clone(),
            unlocked: st.unlocked,
            drive_filter: st.drive_filter,
            user_filter: st.user_filter,
            selected_drive: st.selected_drive.clone(),
            selected_user: st.selected_user,
            page: self.stack.visible_child_name().map(|s| s.to_string()).unwrap_or_default(),
        }
    }

    pub fn busy(&self) -> bool {
        let st = self.st.borrow();
        st.saving || st.authenticating
    }

    // ---------------------------------------------------------- language ---
    fn build_language_menu(&self, button: &gtk::MenuButton) {
        let current = i18n::current();
        button.add(&ICONS.with(|i| i.flag(current.flag(), 24)));
        button.set_tooltip_text(Some(&tr("Language")));
        let popover = gtk::Popover::new(Some(button));
        let list = vbox(2);
        list.set_margin(6);
        for language in Language::ALL {
            let item = gtk::Button::new();
            item.set_relief(gtk::ReliefStyle::None);
            let content = hbox(10);
            content.style_context().add_class("language-row");
            content.pack_start(&ICONS.with(|i| i.flag(language.flag(), 28)), false, false, 0);
            content.pack_start(&label(language.native_name(), &[]), true, true, 0);
            if language == current {
                content.pack_end(
                    &gtk::Image::from_icon_name(Some("object-select-symbolic"), gtk::IconSize::Menu),
                    false,
                    false,
                    0,
                );
            }
            item.add(&content);
            let app = self.app.clone();
            let popup = popover.clone();
            item.connect_clicked(move |_| {
                popup.popdown();
                let app = app.clone();
                glib::idle_add_local_once(move || crate::switch_language(&app, language));
            });
            list.pack_start(&item, false, false, 0);
        }
        list.show_all();
        popover.add(&list);
        button.set_popover(Some(&popover));
    }

    // ------------------------------------------------------------- pages ---
    fn sidebar(&self, top: Option<&gtk::Box>, list: &gtk::ListBox) -> gtk::Box {
        let pane = vbox(0);
        pane.style_context().add_class("sidebar-pane");
        pane.set_size_request(290, -1);
        if let Some(top) = top {
            pane.pack_start(top, false, false, 0);
        }
        list.set_selection_mode(gtk::SelectionMode::Browse);
        pane.pack_start(&scrolled(list), true, true, 4);
        pane
    }

    fn build_drives_page(&self) -> gtk::Box {
        let w = self.weak();
        self.drive_list.connect_row_selected(move |_, row| {
            let (Some(ui), Some(row)) = (w.upgrade(), row) else {
                return;
            };
            if ui.filling.get() {
                return;
            }
            let uuid = ui.st.borrow().drive_rows.get(row.index() as usize).cloned();
            ui.st.borrow_mut().selected_drive = uuid;
            ui.show_drive();
        });
        let w = self.weak();
        let current = self.st.borrow().drive_filter;
        let bar = filter_bar(current, move |filter| {
            if let Some(ui) = w.upgrade() {
                ui.st.borrow_mut().drive_filter = filter;
                ui.fill_drive_list();
            }
        });
        let page = hbox(0);
        page.pack_start(&self.sidebar(Some(&bar), &self.drive_list), false, false, 0);
        page.pack_start(&self.drive_detail, true, true, 0);
        page
    }

    fn build_users_page(&self) -> gtk::Box {
        let w = self.weak();
        self.user_list.connect_row_selected(move |_, row| {
            let (Some(ui), Some(row)) = (w.upgrade(), row) else {
                return;
            };
            if ui.filling.get() {
                return;
            }
            let uid = ui.st.borrow().user_rows.get(row.index() as usize).copied();
            ui.st.borrow_mut().selected_user = uid;
            ui.show_user();
        });
        let page = hbox(0);
        page.pack_start(&self.sidebar(None, &self.user_list), false, false, 0);
        page.pack_start(&self.user_detail, true, true, 0);
        page
    }

    // -------------------------------------------------------------- data ---
    fn reload(&self) {
        let result = self.st.borrow_mut().model.load();
        if let Err(error) = result {
            self.notify(gtk::MessageType::Error, &trf("Could not list drives: {error}", &[("error", &error)]), 0);
        }
        let errors = self.st.borrow().model.errors.join("\n");
        if !errors.is_empty() {
            self.notify(gtk::MessageType::Warning, &errors, 0);
        }
        self.fill_drive_list();
        self.fill_user_list();
        self.update_save_button();
    }

    fn visible_drives(&self, filter: Filter) -> Vec<Drive> {
        self.st
            .borrow()
            .model
            .drives
            .iter()
            .filter(|d| filter == Filter::All || filter == Filter::Only(d.kind))
            .cloned()
            .collect()
    }

    fn fill_drive_list(&self) {
        self.filling.set(true);
        clear(&self.drive_list);
        let filter = self.st.borrow().drive_filter;
        let drives = self.visible_drives(filter);
        let mut chosen = 0;
        {
            let st = self.st.borrow();
            for (index, drive) in drives.iter().enumerate() {
                let row = gtk::ListBoxRow::new();
                let box_ = hbox(10);
                box_.pack_start(&ICONS.with(|i| i.image(kind_icon(drive.kind), 40)), false, false, 0);
                let text = vbox(1);
                text.set_valign(gtk::Align::Center);
                text.pack_start(&self.drive_name(drive, false), false, false, 0);
                let mode =
                    if st.model.policy(&drive.uuid, false).mode == Mode::Desktop { tr("Simple") } else { tr("Strict") };
                text.pack_start(&label(&format!("{} · {mode}", drive_short(drive)), &["dim-label"]), false, false, 0);
                if st.model.drive_read_only(&drive.uuid) {
                    text.pack_start(&label(&tr("Drive is open read-only"), &["dim-label"]), false, false, 0);
                }
                box_.pack_start(&text, true, true, 0);
                if st.model.is_changed(&drive.uuid) {
                    let dot = label("●", &["pending"]);
                    dot.set_tooltip_text(Some(&tr("Unsaved changes")));
                    box_.pack_end(&dot, false, false, 0);
                }
                row.set_tooltip_text(Some(&format!("{}\n{}", drive_subtitle(drive), drive.device)));
                row.add(&box_);
                self.drive_list.add(&row);
                if st.selected_drive.as_deref() == Some(drive.uuid.as_str()) {
                    chosen = index;
                }
            }
        }
        self.st.borrow_mut().drive_rows = drives.iter().map(|d| d.uuid.clone()).collect();
        self.drive_list.show_all();
        if !drives.is_empty() {
            self.st.borrow_mut().selected_drive = Some(drives[chosen].uuid.clone());
            self.drive_list.select_row(self.drive_list.row_at_index(chosen as i32).as_ref());
        }
        self.filling.set(false);
        self.show_drive();
    }

    fn fill_user_list(&self) {
        self.filling.set(true);
        clear(&self.user_list);
        let users = self.st.borrow().model.users.clone();
        let mut chosen = 0;
        {
            let st = self.st.borrow();
            for (index, user) in users.iter().enumerate() {
                let row = gtk::ListBoxRow::new();
                let box_ = hbox(10);
                box_.pack_start(&ICONS.with(|i| i.avatar(user.icon.as_deref(), 40)), false, false, 0);
                let text = vbox(1);
                text.set_valign(gtk::Align::Center);
                text.pack_start(&label(&display_name(user), &["row-title"]), false, false, 0);
                text.pack_start(&label(&self.user_summary(&st.model, user), &["dim-label"]), false, false, 0);
                box_.pack_start(&text, true, true, 0);
                if st.model.drives.iter().any(|d| st.model.user_changed(&d.uuid, user.uid)) {
                    box_.pack_end(&label("●", &["pending"]), false, false, 0);
                }
                row.add(&box_);
                self.user_list.add(&row);
                if st.selected_user == Some(user.uid) {
                    chosen = index;
                }
            }
        }
        self.st.borrow_mut().user_rows = users.iter().map(|u| u.uid).collect();
        self.user_list.show_all();
        if !users.is_empty() {
            self.st.borrow_mut().selected_user = Some(users[chosen].uid);
            self.user_list.select_row(self.user_list.row_at_index(chosen as i32).as_ref());
        }
        self.filling.set(false);
        self.show_user();
    }

    fn name_of(&self, model: &Model, uid: u32) -> String {
        if let Some(user) = model.user(uid) {
            return display_name(user);
        }
        if uid == 0 {
            return "root".into();
        }
        core::getpwuid(uid).map(|p| p.name).unwrap_or_else(|| tr("Unknown person"))
    }

    fn user_summary(&self, model: &Model, user: &User) -> String {
        let count = model.drives.iter().filter(|d| model.access(&d.uuid, user.uid, false).0 != Level::None).count();
        let total = model.drives.len();
        let counted = if total == 1 {
            trf("{count} of 1 drive", &[("count", &count.to_string())])
        } else {
            trf("{count} of {total} drives", &[("count", &count.to_string()), ("total", &total.to_string())])
        };
        format!("@{} · {counted}", user.name)
    }

    // ------------------------------------------------------------ detail ---
    fn detail_header(&self, image: &gtk::Image, title: &gtk::Widget, subtitle: &str, pills: &[gtk::Label]) -> gtk::Box {
        let header = hbox(16);
        header.set_margin(24);
        header.set_margin_bottom(12);
        header.pack_start(image, false, false, 0);
        let text = vbox(4);
        text.set_valign(gtk::Align::Center);
        let line = hbox(12);
        line.pack_start(title, false, false, 0);
        for widget in pills {
            widget.set_valign(gtk::Align::Center);
            line.pack_start(widget, false, false, 0);
        }
        text.pack_start(&line, false, false, 0);
        text.pack_start(&label(subtitle, &["dim-label"]), false, false, 0);
        header.pack_start(&text, true, true, 0);
        header
    }

    // ------------------------------------------------------------ rename ---
    /// The drive's name; double-clicking turns it into a text field that
    /// renames the drive itself (its NTFS volume label). Administrators only.
    fn drive_name(&self, drive: &Drive, title: bool) -> gtk::Widget {
        let stack = gtk::Stack::new();
        stack.set_homogeneous(false);
        stack.set_halign(gtk::Align::Start);
        let events = gtk::EventBox::new();
        events.set_visible_window(false);
        let text = label(&drive_title(drive), &[if title { "detail-title" } else { "row-title" }]);
        events.add(&text);
        let entry = gtk::Entry::new();
        entry.set_max_length(ntfs_permissions::label::MAX_LABEL_CHARS as i32);
        entry.set_width_chars(if title { 22 } else { 16 });
        entry.style_context().add_class(if title { "detail-title-entry" } else { "name-entry" });
        stack.add_named(&events, "label");
        stack.add_named(&entry, "entry");
        if self.st.borrow().unlocked {
            events.set_tooltip_text(Some(&tr("Double-click to rename")));
        }
        let editing = Rc::new(Cell::new(false));
        let (uuid, old) = (drive.uuid.clone(), drive.label.clone());
        {
            let (w, stack, entry, editing, old) =
                (self.weak(), stack.clone(), entry.clone(), editing.clone(), old.clone());
            events.connect_button_press_event(move |_, event| {
                if event.event_type() != gdk::EventType::DoubleButtonPress || event.button() != 1 {
                    return glib::Propagation::Proceed;
                }
                let Some(ui) = w.upgrade() else {
                    return glib::Propagation::Proceed;
                };
                if !ui.st.borrow().unlocked {
                    ui.notify(gtk::MessageType::Info, &tr("Only an administrator can rename drives."), 5);
                    return glib::Propagation::Stop;
                }
                if ui.busy() {
                    return glib::Propagation::Stop;
                }
                // Open the field once the click is over: in the drive list the
                // row takes the keyboard focus on release, which would close it.
                let (stack, entry, editing, old) = (stack.clone(), entry.clone(), editing.clone(), old.clone());
                glib::timeout_add_local_once(Duration::from_millis(150), move || {
                    editing.set(true);
                    entry.set_text(&old);
                    stack.set_visible_child_name("entry");
                    entry.grab_focus();
                });
                glib::Propagation::Stop
            });
        }
        // Enter or leaving the field renames; Escape cancels.
        let finish = {
            let (w, stack, editing) = (self.weak(), stack.clone(), editing.clone());
            Rc::new(move |entry: &gtk::Entry, commit: bool| {
                if !editing.replace(false) {
                    return;
                }
                stack.set_visible_child_name("label");
                let wanted = entry.text().trim().to_owned();
                if commit && wanted != old {
                    let (w, uuid) = (w.clone(), uuid.clone());
                    // After this handler returns: renaming rebuilds these widgets.
                    glib::idle_add_local_once(move || {
                        if let Some(ui) = w.upgrade() {
                            ui.rename(uuid, wanted);
                        }
                    });
                }
            })
        };
        {
            let finish = finish.clone();
            entry.connect_activate(move |entry| finish(entry, true));
        }
        {
            let finish = finish.clone();
            entry.connect_key_press_event(move |entry, event| {
                if event.keyval() == gdk::keys::constants::Escape {
                    finish(entry, false);
                    return glib::Propagation::Stop;
                }
                glib::Propagation::Proceed
            });
        }
        entry.connect_focus_out_event(move |entry, _| {
            finish(entry, true);
            glib::Propagation::Proceed
        });
        stack.show_all();
        stack.set_visible_child_name("label");
        stack.upcast()
    }

    fn rename(&self, uuid: String, wanted: String) {
        if let Err(message) = ntfs_permissions::label::validate_label(&wanted) {
            self.notify(gtk::MessageType::Error, &tr(message), 6);
            return;
        }
        {
            let mut st = self.st.borrow_mut();
            if st.saving || !st.unlocked {
                return;
            }
            st.saving = true;
        }
        self.stack.set_sensitive(false);
        self.save_button.set_sensitive(false);
        self.notify(gtk::MessageType::Info, &tr("Renaming the drive…"), 0);
        let session = self.session.clone();
        let w = self.weak();
        glib::MainContext::default().spawn_local(async move {
            let request = json!({"cmd": "rename", "uuid": uuid, "label": wanted});
            let result = gio::spawn_blocking({
                let session = session.clone();
                move || session.request(&request)
            })
            .await
            .unwrap_or_else(|_| Err("administrator session ended".into()));
            let lost = result.is_err() && !session.active();
            if let Some(ui) = w.upgrade() {
                ui.rename_finished(result, lost);
            }
        });
    }

    fn rename_finished(&self, result: Result<Value, String>, lost: bool) {
        self.st.borrow_mut().saving = false;
        self.stack.set_sensitive(true);
        match result {
            Err(_) if lost => {
                self.st.borrow_mut().unlocked = false;
                self.lock_text.set_text(&tr("The administrator session ended. Unlock again to save your changes."));
                self.update_lock_ui();
                self.notify(gtk::MessageType::Error, &tr("Not renamed: the administrator session ended."), 0);
            }
            Err(error) => {
                self.update_save_button();
                self.notify(
                    gtk::MessageType::Error,
                    &trf("Could not rename the drive: {error}", &[("error", &error)]),
                    0,
                );
            }
            Ok(data) => {
                let status = data.get("status").and_then(Value::as_str).unwrap_or("error");
                let message = data.get("message").and_then(Value::as_str).unwrap_or_default();
                let detail = data.get("detail").and_then(Value::as_str).unwrap_or_default();
                // The drive list is read again either way: it shows the name the drive really has.
                self.reload();
                if status == Applied::Error.name() {
                    let text = if detail.is_empty() { tr(message) } else { format!("{} {detail}", tr(message)) };
                    self.notify(gtk::MessageType::Error, &text, 0);
                } else {
                    self.notify(gtk::MessageType::Info, &tr("Drive renamed."), 4);
                }
            }
        }
    }

    fn card(rows: &[gtk::ListBoxRow]) -> gtk::ListBox {
        let list = gtk::ListBox::new();
        list.set_selection_mode(gtk::SelectionMode::None);
        list.style_context().add_class("card");
        for row in rows {
            list.add(row);
        }
        list
    }

    fn row(
        image: &gtk::Image,
        title: &str,
        subtitle: Option<&str>,
        widget: Option<&gtk::Widget>,
        changed: bool,
    ) -> gtk::ListBoxRow {
        let row = gtk::ListBoxRow::new();
        row.set_activatable(false);
        let box_ = hbox(12);
        box_.pack_start(image, false, false, 0);
        let text = vbox(1);
        text.set_valign(gtk::Align::Center);
        text.pack_start(&label(title, &["row-title"]), false, false, 0);
        if let Some(subtitle) = subtitle {
            text.pack_start(&wrapped(subtitle, &["dim-label"]), false, false, 0);
        }
        box_.pack_start(&text, true, true, 0);
        if changed {
            box_.pack_start(&label(&tr("Changed"), &["pending"]), false, false, 0);
        }
        if let Some(widget) = widget {
            box_.pack_end(widget, false, false, 0);
        }
        row.add(&box_);
        row
    }

    fn section(body: &gtk::Box, title: &str, subtitle: Option<&str>) {
        body.pack_start(&label(&tr(title), &["section-title"]), false, false, 0);
        if let Some(subtitle) = subtitle {
            body.pack_start(&wrapped(&tr(subtitle), &["dim-label", "hint"]), false, false, 0);
        }
    }

    fn mode_chooser(&self, uuid: &str) -> gtk::Box {
        let (current, unlocked) = {
            let st = self.st.borrow();
            (st.model.policy(uuid, false).mode, st.unlocked)
        };
        let box_ = hbox(10);
        box_.set_homogeneous(true);
        let choices = [
            (
                Mode::Desktop,
                "emblem-people",
                "Simple",
                "Mounting permissions: pick an owner, a group and what everyone may do. \
              The drive’s Windows permissions are kept, not used.",
            ),
            (
                Mode::Windows,
                "emblem-system",
                "Strict",
                "Use the permissions Windows stored on the drive, with a level for each person. \
              For drives shared with Windows users.",
            ),
        ];
        let mut first: Option<gtk::RadioButton> = None;
        for (mode, icon, title, text) in choices {
            let button = match &first {
                None => gtk::RadioButton::new(),
                Some(group) => gtk::RadioButton::from_widget(group),
            };
            button.set_mode(false);
            button.style_context().add_class("mode-card");
            let content = hbox(12);
            content.set_margin(10);
            content.pack_start(&ICONS.with(|i| i.image(icon, 40)), false, false, 0);
            let words = vbox(3);
            words.pack_start(&label(&tr(title), &["row-title"]), false, false, 0);
            words.pack_start(&wrapped(&tr(text), &["dim-label", "hint"]), false, false, 0);
            content.pack_start(&words, true, true, 0);
            button.add(&content);
            button.set_active(mode == current);
            button.set_sensitive(unlocked || mode == current);
            let w = self.weak();
            let uuid = uuid.to_owned();
            button.connect_toggled(move |b| {
                if !b.is_active() {
                    return;
                }
                let Some(ui) = w.upgrade() else { return };
                let changed = {
                    let mut st = ui.st.borrow_mut();
                    if st.unlocked && st.model.policy(&uuid, false).mode != mode {
                        st.model.set_mode(&uuid, mode);
                        true
                    } else {
                        false
                    }
                };
                if changed {
                    ui.edited();
                }
            });
            box_.pack_start(&button, true, true, 0);
            first.get_or_insert(button);
        }
        box_
    }

    fn owner_combo(&self, uuid: &str) -> gtk::ComboBoxText {
        let st = self.st.borrow();
        let policy = st.model.policy(uuid, false);
        let combo = gtk::ComboBoxText::new();
        let hint = st.model.owner_hint.get(uuid).copied().flatten();
        let auto = match hint {
            Some(uid) => trf("Whoever opens the drive ({name})", &[("name", &self.name_of(&st.model, uid))]),
            None => tr("Whoever opens the drive"),
        };
        combo.append(Some("auto"), &auto);
        for user in &st.model.users {
            combo.append(Some(&user.uid.to_string()), &display_name(user));
        }
        let active = policy.owner.map_or("auto".to_owned(), |uid| uid.to_string());
        if !combo.set_active_id(Some(&active)) {
            combo.append(Some(&active), &self.name_of(&st.model, policy.owner.unwrap_or(0)));
            combo.set_active_id(Some(&active));
        }
        combo.set_valign(gtk::Align::Center);
        combo.set_sensitive(st.unlocked);
        let w = self.weak();
        let uuid = uuid.to_owned();
        combo.connect_changed(move |combo| {
            let Some(ui) = w.upgrade() else { return };
            let new = combo.active_id().and_then(|id| id.parse::<u32>().ok());
            let changed = {
                let mut st = ui.st.borrow_mut();
                if st.model.policy(&uuid, false).owner != new {
                    st.model.edit(&uuid).owner = new;
                    true
                } else {
                    false
                }
            };
            if changed {
                ui.edited();
            }
        });
        combo
    }

    fn group_combo(&self, uuid: &str) -> gtk::ComboBoxText {
        let st = self.st.borrow();
        let policy = st.model.policy(uuid, false);
        let combo = gtk::ComboBoxText::new();
        combo.append(Some("auto"), &tr("The owner’s own group"));
        for group in &st.model.groups {
            let text = if group.name == "users" {
                trf("{name} (everyone with a login)", &[("name", &group.name)])
            } else {
                group.name.clone()
            };
            combo.append(Some(&group.gid.to_string()), &text);
        }
        let active = policy.group.map_or("auto".to_owned(), |gid| gid.to_string());
        if !combo.set_active_id(Some(&active)) {
            combo.append(Some(&active), &st.model.group_name(policy.group));
            combo.set_active_id(Some(&active));
        }
        combo.set_valign(gtk::Align::Center);
        combo.set_sensitive(st.unlocked);
        let w = self.weak();
        let uuid = uuid.to_owned();
        combo.connect_changed(move |combo| {
            let Some(ui) = w.upgrade() else { return };
            let new = combo.active_id().and_then(|id| id.parse::<u32>().ok());
            let notice = {
                let mut st = ui.st.borrow_mut();
                let policy = st.model.policy(&uuid, false);
                if policy.group == new {
                    return;
                }
                st.model.edit(&uuid).group = new;
                let rwx = core::rwx_from_modes(policy.file_mode, policy.dir_mode);
                if new.is_some() && !rwx[1].iter().any(|b| *b) {
                    // Choosing a group means sharing with it: offer read & write.
                    st.model.set_rwx(&uuid, Class::Group, 1, true);
                    Some(trf(
                        "The group “{group}” can now read and write. Untick the boxes to change that.",
                        &[("group", &st.model.group_name(new))],
                    ))
                } else {
                    None
                }
            };
            if let Some(text) = notice {
                ui.notify(gtk::MessageType::Info, &text, 6);
            }
            ui.edited();
        });
        combo
    }

    fn preset_combo(&self, uuid: &str) -> gtk::ComboBoxText {
        let st = self.st.borrow();
        let policy = st.model.policy(uuid, false);
        let combo = gtk::ComboBoxText::new();
        for (key, name, _, _) in core::PRESETS {
            combo.append(Some(key), &tr(name));
        }
        combo.append(Some("custom"), &tr("Custom"));
        let matched =
            core::PRESETS.iter().find(|p| (p.2, p.3) == (policy.file_mode, policy.dir_mode)).map_or("custom", |p| p.0);
        combo.set_active_id(Some(matched));
        combo.set_valign(gtk::Align::Center);
        combo.set_sensitive(st.unlocked);
        let w = self.weak();
        let uuid = uuid.to_owned();
        combo.connect_changed(move |combo| {
            let Some(ui) = w.upgrade() else { return };
            let Some(key) = combo.active_id() else { return };
            if key == "custom" {
                return;
            }
            ui.st.borrow_mut().model.set_preset(&uuid, &key);
            ui.edited();
        });
        combo
    }

    fn members_text(&self, model: &Model, gid: Option<u32>) -> Option<String> {
        let gid = gid?;
        let Some(info) = model.group_info(gid) else {
            return Some(tr("Group members are not listed"));
        };
        let names: Vec<String> =
            info.members.iter().map(|m| model.user_by_name(m).map_or(m.clone(), display_name)).collect();
        Some(if names.is_empty() {
            tr("No people in this group yet")
        } else {
            trf("Members: {names}", &[("names", &names.join(", "))])
        })
    }

    fn rwx_grid(&self, uuid: &str) -> gtk::Box {
        let st = self.st.borrow();
        let policy = st.model.policy(uuid, false);
        let rwx = core::rwx_from_modes(policy.file_mode, policy.dir_mode);
        let grid = gtk::Grid::new();
        grid.set_column_spacing(6);
        grid.set_row_spacing(2);
        grid.set_margin(12);
        grid.style_context().add_class("rwx-grid");
        for (column, (name, tip)) in RWX_COLUMNS.iter().enumerate() {
            let head = label(&tr(name), &["row-title"]);
            head.set_xalign(0.5);
            head.set_tooltip_text(Some(&tr(tip)));
            head.set_size_request(92, -1);
            grid.attach(&head, column as i32 + 1, 0, 1, 1);
        }
        let owner = st.model.owner(uuid, false);
        for (line, (class, title, icon)) in CLASS_ROWS.iter().enumerate() {
            let image = match (class, owner.and_then(|uid| st.model.user(uid))) {
                (Class::Owner, Some(user)) => ICONS.with(|i| i.avatar(user.icon.as_deref(), 32)),
                _ => ICONS.with(|i| i.image(icon, 32)),
            };
            let head = hbox(10);
            head.pack_start(&image, false, false, 0);
            head.pack_start(&label(&tr(title), &["row-title"]), true, true, 0);
            head.set_hexpand(true);
            head.set_margin_top(6);
            head.set_margin_bottom(6);
            grid.attach(&head, 0, line as i32 + 1, 1, 1);
            let class_index = Class::ALL.iter().position(|c| c == class).unwrap();
            for index in 0..3 {
                let check = gtk::CheckButton::new();
                check.set_halign(gtk::Align::Center);
                check.set_valign(gtk::Align::Center);
                check.set_active(rwx[class_index][index]);
                check.set_sensitive(st.unlocked);
                check.set_tooltip_text(Some(&tr(RWX_COLUMNS[index].1)));
                let w = self.weak();
                let uuid = uuid.to_owned();
                let class = *class;
                check.connect_toggled(move |check| {
                    let Some(ui) = w.upgrade() else { return };
                    let value = check.is_active();
                    {
                        let mut st = ui.st.borrow_mut();
                        let policy = st.model.policy(&uuid, false);
                        if core::rwx_from_modes(policy.file_mode, policy.dir_mode)[class_index][index] == value {
                            return;
                        }
                        st.model.set_rwx(&uuid, class, index, value);
                    }
                    ui.edited();
                });
                grid.attach(&check, index as i32 + 1, line as i32 + 1, 1, 1);
            }
        }
        let frame = hbox(0);
        frame.style_context().add_class("card");
        frame.pack_start(&grid, true, true, 0);
        frame
    }

    fn show_drive(&self) {
        clear(&self.drive_detail);
        let (drive, filter) = {
            let st = self.st.borrow();
            let drive = st.selected_drive.as_deref().and_then(|u| st.model.drive(u)).cloned();
            let visible = drive.filter(|d| st.drive_filter == Filter::All || st.drive_filter == Filter::Only(d.kind));
            (visible, st.drive_filter)
        };
        let Some(drive) = drive else {
            let (icon, text) = filter_info(filter);
            self.drive_detail.pack_start(
                &empty_state(
                    icon,
                    text,
                    "Connect a drive formatted with NTFS (for example a Windows disk or a USB stick).",
                ),
                true,
                true,
                0,
            );
            self.drive_detail.show_all();
            return;
        };
        let uuid = drive.uuid.clone();
        let device = pill(&drive.device, false);
        device.style_context().add_class("device");
        self.drive_detail.pack_start(
            &self.detail_header(
                &ICONS.with(|i| i.image(kind_icon(drive.kind), 64)),
                &self.drive_name(&drive, true),
                &drive_subtitle(&drive),
                &[device],
            ),
            false,
            false,
            0,
        );
        let body = vbox(10);
        body.set_margin(24);
        body.set_margin_top(0);
        if self.st.borrow().model.drive_read_only(&uuid) {
            let warning = gtk::InfoBar::new();
            warning.set_message_type(gtk::MessageType::Warning);
            let words = vbox(4);
            words.pack_start(&label(&tr("Drive is open read-only"), &["row-title"]), false, false, 0);
            words.pack_start(&wrapped(&tr(ntfs_permissions::mount::READ_ONLY_HINT), &[]), false, false, 0);
            warning.content_area().add(&words);
            body.pack_start(&warning, false, false, 0);
            let retry = gtk::Button::with_label(&tr("Try write access again"));
            retry.set_halign(gtk::Align::Start);
            {
                let st = self.st.borrow();
                retry.set_sensitive(
                    st.unlocked
                        && core::policy_wants_write(&st.model.policy(&uuid, false), st.model.owner(&uuid, false)),
                );
            }
            let (w, uuid) = (self.weak(), uuid.clone());
            retry.connect_clicked(move |_| {
                if let Some(ui) = w.upgrade() {
                    ui.save_drives(vec![uuid.clone()]);
                }
            });
            body.pack_start(&retry, false, false, 0);
        }
        Self::section(&body, "How access is decided", None);
        body.pack_start(&self.mode_chooser(&uuid), false, false, 0);
        let mode = self.st.borrow().model.policy(&uuid, false).mode;
        body.pack_start(&hbox(0), false, false, 4);
        if mode == Mode::Desktop {
            Self::section(
                &body,
                "Mounting permissions",
                Some("Apply to every file and folder while the drive is open on this computer."),
            );
            let members = {
                let st = self.st.borrow();
                self.members_text(&st.model, st.model.group(&uuid, false))
            };
            let owner_row = Self::row(
                &ICONS.with(|i| i.image("avatar-default", 32)),
                &tr("Owner"),
                None,
                Some(self.owner_combo(&uuid).upcast_ref()),
                false,
            );
            let group_row = Self::row(
                &ICONS.with(|i| i.image("emblem-people", 32)),
                &tr("Group"),
                members.as_deref(),
                Some(self.group_combo(&uuid).upcast_ref()),
                false,
            );
            let preset_row = Self::row(
                &ICONS.with(|i| i.image("emblem-system", 32)),
                &tr("Quick setup"),
                None,
                Some(self.preset_combo(&uuid).upcast_ref()),
                false,
            );
            body.pack_start(&Self::card(&[owner_row, group_row, preset_row]), false, false, 0);
            body.pack_start(&self.rwx_grid(&uuid), false, false, 0);
        } else {
            Self::section(
                &body,
                "Who can use this drive",
                Some("Each level becomes a Windows identity, and the drive’s own Windows permissions decide the rest."),
            );
            let st = self.st.borrow();
            let mut rows = Vec::new();
            for user in &st.model.users {
                let level = st.model.strict_level(&uuid, user.uid, false);
                let widget: gtk::Widget = if st.unlocked {
                    let w = self.weak();
                    let (uuid, uid) = (uuid.clone(), user.uid);
                    level_combo(level, move |value| {
                        if let Some(ui) = w.upgrade() {
                            ui.on_level(&uuid, uid, value)
                        }
                    })
                    .upcast()
                } else {
                    level_badge(level).upcast()
                };
                rows.push(Self::row(
                    &ICONS.with(|i| i.avatar(user.icon.as_deref(), 36)),
                    &display_name(user),
                    Some(&format!("@{}", user.name)),
                    Some(&widget),
                    st.model.user_changed(&uuid, user.uid),
                ));
            }
            body.pack_start(&Self::card(&rows), false, false, 0);
        }
        self.drive_detail.pack_start(&scrolled(&body), true, true, 0);
        self.drive_detail.show_all();
    }

    fn show_user(&self) {
        clear(&self.user_detail);
        let user = {
            let st = self.st.borrow();
            st.selected_user.and_then(|uid| st.model.user(uid)).cloned()
        };
        let Some(user) = user else {
            self.user_detail.pack_start(
                &empty_state(
                    "avatar-default",
                    "No user accounts",
                    "People with a login on this computer appear here. Add one in Settings › System › Users.",
                ),
                true,
                true,
                0,
            );
            self.user_detail.show_all();
            return;
        };
        let (filter, drives, subtitle) = {
            let st = self.st.borrow();
            let groups: Vec<String> = st
                .model
                .groups
                .iter()
                .filter(|g| g.members.contains(&user.name) && g.name != user.name)
                .map(|g| g.name.clone())
                .collect();
            let subtitle = if groups.is_empty() {
                format!("@{}", user.name)
            } else {
                format!("@{} · {}", user.name, trf("Groups: {groups}", &[("groups", &groups.join(", "))]))
            };
            (st.user_filter, (), subtitle)
        };
        let _ = drives;
        self.user_detail.pack_start(
            &self.detail_header(
                &ICONS.with(|i| i.avatar(user.icon.as_deref(), 64)),
                label(&display_name(&user), &["detail-title"]).upcast_ref(),
                &subtitle,
                &[],
            ),
            false,
            false,
            0,
        );
        let body = vbox(10);
        body.set_margin(24);
        body.set_margin_top(0);
        let heading = hbox(12);
        heading.pack_start(&label(&tr("Drives this person can use"), &["section-title"]), true, true, 0);
        let w = self.weak();
        let bar = filter_bar(filter, move |filter| {
            let Some(ui) = w.upgrade() else { return };
            if ui.st.borrow().user_filter != filter {
                ui.st.borrow_mut().user_filter = filter;
                let w = ui.weak();
                glib::idle_add_local_once(move || {
                    if let Some(ui) = w.upgrade() {
                        ui.show_user()
                    }
                });
            }
        });
        bar.set_margin_top(0);
        bar.set_margin_bottom(0);
        bar.set_margin_end(0);
        heading.pack_end(&bar, false, false, 0);
        body.pack_start(&heading, false, false, 0);
        let drives = self.visible_drives(filter);
        if drives.is_empty() {
            let (icon, text) = filter_info(filter);
            body.pack_start(&empty_state(icon, text, ""), true, true, 24);
        } else {
            let st = self.st.borrow();
            let mut rows = Vec::new();
            for drive in &drives {
                let strict = st.model.policy(&drive.uuid, false).mode == Mode::Windows;
                let (level, why) = st.model.access(&drive.uuid, user.uid, false);
                let (widget, mut note): (gtk::Widget, String) = if strict && st.unlocked {
                    let w = self.weak();
                    let (uuid, uid) = (drive.uuid.clone(), user.uid);
                    (
                        level_combo(level, move |value| {
                            if let Some(ui) = w.upgrade() {
                                ui.on_level(&uuid, uid, value)
                            }
                        })
                        .upcast(),
                        format!("{} · {}", drive_short(drive), tr("Strict: Windows permissions")),
                    )
                } else {
                    let badge = level_badge(level);
                    let note = if strict {
                        format!("{} · {}", drive_short(drive), tr("Strict: Windows permissions"))
                    } else {
                        badge.set_tooltip_text(Some(&tr(
                            "Set by this drive’s mounting permissions. Change them on the Drives tab.",
                        )));
                        format!("{} · {}", drive_short(drive), trf("Simple: {why}", &[("why", &why)]))
                    };
                    (badge.upcast(), note)
                };
                if st.model.drive_read_only(&drive.uuid) {
                    note.push_str(&format!(" · {}", tr("Drive is open read-only")));
                }
                rows.push(Self::row(
                    &ICONS.with(|i| i.image(kind_icon(drive.kind), 36)),
                    &drive_title(drive),
                    Some(&note),
                    Some(&widget),
                    st.model.user_changed(&drive.uuid, user.uid),
                ));
            }
            body.pack_start(&Self::card(&rows), false, false, 0);
            body.pack_start(
                &wrapped(
                    &tr("For drives using Simple mounting permissions, access comes from the owner, \
                                          group and everyone-else settings on the Drives tab."),
                    &["dim-label", "hint"],
                ),
                false,
                false,
                4,
            );
        }
        self.user_detail.pack_start(&scrolled(&body), true, true, 0);
        self.user_detail.show_all();
    }

    // ------------------------------------------------------------ events ---
    fn edited(&self) {
        // Rebuild after the widget's own signal handler has returned.
        let w = self.weak();
        glib::idle_add_local_once(move || {
            if let Some(ui) = w.upgrade() {
                ui.refresh_after_edit()
            }
        });
    }

    fn refresh_after_edit(&self) {
        self.fill_drive_list();
        self.fill_user_list();
        self.update_save_button();
    }

    fn on_level(&self, uuid: &str, uid: u32, level: Level) {
        let demoted = {
            let mut st = self.st.borrow_mut();
            if st.model.strict_level(uuid, uid, false) == level {
                return;
            }
            st.model.set_level(uuid, uid, level).map(|other| self.name_of(&st.model, other))
        };
        if let Some(name) = demoted {
            self.notify(
                gtk::MessageType::Info,
                &trf(
                    "Only one person can have full control of a drive, so {name} now has Read & write.",
                    &[("name", &name)],
                ),
                6,
            );
        }
        self.edited();
    }

    fn update_save_button(&self) {
        let st = self.st.borrow();
        self.save_button.set_visible(st.unlocked);
        let count = st.model.change_count();
        self.save_label.set_text(&if count > 0 {
            trf("Save ({count})", &[("count", &count.to_string())])
        } else {
            tr("Save")
        });
        self.save_button.set_sensitive(!st.saving);
    }

    fn notify(&self, kind: gtk::MessageType, text: &str, timeout: u32) {
        self.infobar.set_message_type(kind);
        self.infobar_label.set_text(text);
        self.infobar.set_revealed(true);
        self.infobar.show_all();
        let token = {
            let mut st = self.st.borrow_mut();
            st.notice += 1;
            st.notice
        };
        if timeout > 0 {
            let w = self.weak();
            glib::timeout_add_seconds_local_once(timeout, move || {
                if let Some(ui) = w.upgrade() {
                    if ui.st.borrow().notice == token {
                        ui.infobar.set_revealed(false);
                    }
                }
            });
        }
    }

    // -------------------------------------------------------------- lock ---
    pub fn update_lock_ui(&self) {
        let (unlocked, authenticating, saving) = {
            let st = self.st.borrow();
            (st.unlocked, st.authenticating, st.saving)
        };
        if unlocked {
            self.lock_image.set_from_icon_name(Some("changes-allow-symbolic"), gtk::IconSize::Button);
            self.lock_button.set_tooltip_text(Some(&tr("Unlocked: you can change permissions. Click to lock.")));
            self.lockbar.set_revealed(false);
        } else {
            self.lock_image.set_from_icon_name(Some("changes-prevent-symbolic"), gtk::IconSize::Button);
            self.lock_button
                .set_tooltip_text(Some(&trf("Locked: click to unlock with {password}.", &[("password", &password())])));
            if authenticating {
                self.lockbar.set_message_type(gtk::MessageType::Info);
                self.lock_spinner.start();
                self.lock_spinner.show();
                self.lock_text.set_text(&trf("Waiting for {password}…", &[("password", &password())]));
            } else {
                self.lockbar.set_message_type(gtk::MessageType::Warning);
                self.lock_spinner.stop();
                self.lock_spinner.hide();
            }
            self.unlock_button.set_visible(!authenticating);
            self.lockbar.set_revealed(true);
        }
        self.lock_button.set_sensitive(!authenticating && !saving && !core::is_root());
        self.update_save_button();
        self.fill_drive_list();
        self.fill_user_list();
    }

    fn toggle_lock(&self) {
        if !self.st.borrow().unlocked {
            self.authenticate();
            return;
        }
        if self.st.borrow().model.change_count() > 0 {
            let dialog = gtk::MessageDialog::new(
                Some(&self.window),
                gtk::DialogFlags::MODAL,
                gtk::MessageType::Question,
                gtk::ButtonsType::None,
                &tr("Discard unsaved changes?"),
            );
            dialog.set_secondary_text(Some(&tr("Locking discards the changes you have not saved.")));
            dialog.add_button(&tr("Cancel"), gtk::ResponseType::Cancel);
            let discard = dialog.add_button(&tr("Discard and lock"), gtk::ResponseType::Ok);
            discard.style_context().add_class("destructive-action");
            let response = dialog.run();
            dialog.close();
            if response != gtk::ResponseType::Ok {
                return;
            }
        }
        {
            let mut st = self.st.borrow_mut();
            st.model.edits.clear();
            st.unlocked = false;
        }
        self.session.stop();
        self.lock_text.set_text(&tr("Locked. You are viewing permissions only."));
        self.update_lock_ui();
    }

    pub fn authenticate(&self) {
        {
            let mut st = self.st.borrow_mut();
            if st.unlocked || st.authenticating {
                return;
            }
            st.authenticating = true;
        }
        self.update_lock_ui();
        let session = self.session.clone();
        let w = self.weak();
        glib::MainContext::default().spawn_local(async move {
            let refusal = gio::spawn_blocking(move || session.start())
                .await
                .unwrap_or(Some(Refusal::Text("Authentication failed.")));
            let Some(ui) = w.upgrade() else { return };
            {
                let mut st = ui.st.borrow_mut();
                st.authenticating = false;
                st.unlocked = refusal.is_none();
            }
            if let Some(refusal) = refusal {
                let reason = match refusal {
                    Refusal::Text(text) => tr(text),
                    Refusal::Raw(text) => {
                        trf("The administrator helper stopped (status {status}).", &[("status", &text)])
                    }
                };
                ui.lock_text.set_text(&trf(
                    "{reason} You can view permissions, but changing them needs {password}.",
                    &[("reason", &reason), ("password", &password())],
                ));
            }
            ui.update_lock_ui();
        });
    }

    // -------------------------------------------------------------- save ---
    fn save(&self) {
        let uuids = self.st.borrow().model.changed_drives();
        self.save_drives(uuids);
    }

    // Explicit UUIDs let the retry button reapply an unchanged saved policy
    // after volume recovery. Retain the same unlock and in-flight-save guards.
    fn save_drives(&self, uuids: Vec<String>) {
        let (changes, names) = {
            let mut st = self.st.borrow_mut();
            if st.saving || !st.unlocked {
                return;
            }
            if uuids.is_empty() {
                drop(st);
                self.notify(gtk::MessageType::Info, &tr("There are no changes to save."), 4);
                return;
            }
            st.saving = true;
            let changes: serde_json::Map<String, Value> =
                uuids.iter().map(|u| (u.clone(), st.model.payload(u))).collect();
            let names: Vec<(String, String)> =
                uuids.iter().filter_map(|u| st.model.drive(u).map(|d| (u.clone(), drive_title(d)))).collect();
            (changes, names)
        };
        self.stack.set_sensitive(false);
        self.save_spinner.show();
        self.save_spinner.start();
        self.save_label.set_text(&tr("Saving…"));
        self.save_button.set_sensitive(false);
        let session = self.session.clone();
        let w = self.weak();
        glib::MainContext::default().spawn_local(async move {
            let request = json!({"cmd": "save", "changes": changes});
            let result = gio::spawn_blocking({
                let session = session.clone();
                move || session.request(&request)
            })
            .await
            .unwrap_or_else(|_| Err("administrator session ended".into()));
            let lost = result.is_err() && !session.active();
            if let Some(ui) = w.upgrade() {
                ui.save_finished(result, lost, &names);
            }
        });
    }

    fn save_finished(&self, result: Result<Value, String>, lost: bool, names: &[(String, String)]) {
        self.st.borrow_mut().saving = false;
        self.stack.set_sensitive(true);
        self.save_spinner.stop();
        self.save_spinner.hide();
        let data = match result {
            Err(_) if lost => {
                self.st.borrow_mut().unlocked = false;
                self.lock_text.set_text(&tr("The administrator session ended. Unlock again to save your changes."));
                self.update_lock_ui();
                self.notify(gtk::MessageType::Error, &tr("Not saved: the administrator session ended."), 0);
                return;
            }
            Err(error) => {
                self.update_save_button();
                self.notify(
                    gtk::MessageType::Error,
                    &trf("Could not save permissions: {error}", &[("error", &error)]),
                    0,
                );
                return;
            }
            Ok(data) => data,
        };
        let name = |uuid: &str| names.iter().find(|n| n.0 == uuid).map_or(uuid.to_owned(), |n| n.1.clone());
        let mut problems = Vec::new();
        let mut pending = Vec::new();
        let mut blocked = Vec::new();
        let mut restart = false;
        for (uuid, result) in data.as_object().into_iter().flatten() {
            let status = result.get("status").and_then(Value::as_str).unwrap_or("error");
            let message = result.get("message").and_then(Value::as_str).unwrap_or_default();
            let detail = result.get("detail").and_then(Value::as_str).unwrap_or_default();
            if status == Applied::Error.name() {
                let text = if detail.is_empty() { tr(message) } else { format!("{} {detail}", tr(message)) };
                problems.push(format!("{}: {text}", name(uuid)));
            } else {
                // Saved (and applied, or waiting for the drive / a restart).
                self.st.borrow_mut().model.edits.remove(uuid);
            }
            if status == Applied::Pending.name() {
                if message.starts_with("Saved. Restart") {
                    restart = true;
                } else {
                    pending.push(format!("{}: {}", name(uuid), tr(message)));
                }
            }
            if status == Applied::ReadOnly.name() {
                let text = if detail.is_empty() { tr(message) } else { format!("{}\n{detail}", tr(message)) };
                blocked.push(format!("{}: {text}", name(uuid)));
            }
        }
        self.reload();
        if !problems.is_empty() {
            problems.extend(blocked);
            self.notify(gtk::MessageType::Error, &problems.join("\n"), 0);
        } else if !blocked.is_empty() {
            self.notify(gtk::MessageType::Warning, &blocked.join("\n"), 0);
        } else if restart {
            self.notify(
                gtk::MessageType::Info,
                &tr("Saved. Restart the computer once to load the updated driver; \
                                                     after that, changes apply instantly."),
                0,
            );
        } else if !pending.is_empty() {
            self.notify(gtk::MessageType::Info, &pending.join("\n"), 8);
        } else {
            self.notify(gtk::MessageType::Info, &tr("Permissions saved and applied."), 5);
        }
    }

    fn on_close(&self) -> glib::Propagation {
        if self.st.borrow().saving {
            return glib::Propagation::Stop;
        }
        if self.st.borrow().model.change_count() == 0 {
            return glib::Propagation::Proceed;
        }
        let dialog = gtk::MessageDialog::new(
            Some(&self.window),
            gtk::DialogFlags::MODAL,
            gtk::MessageType::Question,
            gtk::ButtonsType::None,
            &tr("Save changes before closing?"),
        );
        dialog.set_secondary_text(Some(&tr("Your permission changes have not been saved.")));
        let close = dialog.add_button(&tr("Close without saving"), gtk::ResponseType::Close);
        close.style_context().add_class("destructive-action");
        dialog.add_button(&tr("Cancel"), gtk::ResponseType::Cancel);
        let save = dialog.add_button(&tr("Save"), gtk::ResponseType::Ok);
        save.style_context().add_class("suggested-action");
        let response = dialog.run();
        dialog.close();
        match response {
            gtk::ResponseType::Close => glib::Propagation::Proceed,
            gtk::ResponseType::Ok => {
                self.save();
                glib::Propagation::Stop
            }
            _ => glib::Propagation::Stop,
        }
    }

    /// Replaced by a window in another language: keep the helper running.
    pub fn retire(&self) {
        self.keep_session.set(true);
        // SAFETY: the window is not used after this; GTK owns its destruction.
        unsafe { self.window.destroy() };
    }
}

pub fn install_css() {
    let provider = gtk::CssProvider::new();
    if provider.load_from_data(CSS.as_bytes()).is_ok() {
        if let Some(screen) = gtk::gdk::Screen::default() {
            gtk::StyleContext::add_provider_for_screen(&screen, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
        }
    }
}

pub fn delay() -> Duration {
    Duration::from_millis(250)
}
