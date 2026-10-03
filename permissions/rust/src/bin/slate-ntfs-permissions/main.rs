//! Module: ntfs_permissions::main
//! Purpose: Present per-drive ownership and Windows ACL policies.
//! Created: 2026-10-01
//! Architecture: The GTK model edits policies through one pkexec policy-helper session.
//! Desktop mode applies mount-wide ownership; strict mode uses on-disk ACLs.

mod icons;
mod model;
mod session;
mod window;

use gtk::glib;
use gtk::prelude::*;
use ntfs_permissions::i18n::{self, Language};
use std::cell::RefCell;
use std::rc::Rc;
use window::Ui;

thread_local! {
    static CURRENT: RefCell<Option<Rc<Ui>>> = const { RefCell::new(None) };
}

/// Rebuild the window in another language, keeping edits and the session.
pub fn switch_language(app: &gtk::Application, language: Language) {
    let Some(old) = CURRENT.with(|c| c.borrow().clone()) else {
        return;
    };
    if language == i18n::current() || old.busy() {
        return;
    }
    i18n::choose(language);
    let (width, height) = old.window.size();
    let carry = old.carry();
    let page = carry.page.clone();
    let new = Ui::new(app, Some(carry));
    new.window.resize(width, height);
    new.show(Some(&page));
    CURRENT.with(|c| *c.borrow_mut() = Some(new));
    old.retire(); // after the new window exists, so the application keeps running
}

fn main() -> glib::ExitCode {
    let app = gtk::Application::builder().application_id(window::APP_ID).build();
    app.connect_startup(|_| {
        i18n::load();
        window::install_css();
    });
    app.connect_activate(|app| {
        if let Some(ui) = CURRENT.with(|c| c.borrow().clone()) {
            ui.window.present();
            return;
        }
        let ui = Ui::new(app, None);
        ui.show(None);
        CURRENT.with(|c| *c.borrow_mut() = Some(ui.clone()));
        // Ask for the administrator password as soon as the window is up.
        if !ui.is_unlocked() {
            let weak = Rc::downgrade(&ui);
            glib::timeout_add_local_once(window::delay(), move || {
                if let Some(ui) = weak.upgrade() {
                    ui.authenticate();
                }
            });
        }
    });
    app.run_with_args::<&str>(&[])
}
