//! Module: ntfs_permissions::icons
//! Purpose: Bundle Yaru icons, flags and account pictures for the GTK window.
//! Created: 2026-10-01
//! Architecture: The frontend loads scale-aware Cairo surfaces from these bundled assets.

use gtk::prelude::*;
use gtk::{cairo, gdk, gdk_pixbuf::Pixbuf};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub fn icon_dir() -> PathBuf {
    std::env::var_os("SLATE_NTFS_ICON_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/share/slate-ntfs/icons"))
}

#[derive(Default)]
pub struct Icons {
    scale: Cell<i32>,
    cache: RefCell<HashMap<(String, i32), cairo::Surface>>,
}

thread_local! {
    pub static ICONS: Icons = Icons { scale: Cell::new(1), cache: RefCell::default() };
}

fn to_surface(pixbuf: &Pixbuf, scale: i32) -> Option<cairo::Surface> {
    pixbuf.create_surface(scale, None::<&gdk::Window>)
}

impl Icons {
    pub fn set_scale(&self, scale: i32) {
        if scale != self.scale.get() {
            self.scale.set(scale.max(1));
            self.cache.borrow_mut().clear();
        }
    }

    fn pixbuf(&self, name: &str, px: i32) -> Option<Pixbuf> {
        let dir = icon_dir();
        let mut chosen = None;
        for (folder, size) in [("24x24@2x", 48), ("48x48@2x", 96), ("256x256", 256)] {
            let path = dir.join(folder).join(format!("{name}.png"));
            if path.exists() {
                chosen = Some(path);
                if size >= px {
                    break;
                }
            }
        }
        if let Some(path) = chosen {
            if let Ok(pixbuf) = Pixbuf::from_file_at_scale(&path, px, px, true) {
                return Some(pixbuf);
            }
        }
        gtk::IconTheme::default()?.load_icon(name, px, gtk::IconLookupFlags::FORCE_SIZE).ok().flatten()
    }

    pub fn surface(&self, name: &str, size: i32) -> Option<cairo::Surface> {
        let scale = self.scale.get();
        let key = (name.to_owned(), size * scale);
        if let Some(surface) = self.cache.borrow().get(&key) {
            return Some(surface.clone());
        }
        let surface = to_surface(&self.pixbuf(name, size * scale)?, scale)?;
        self.cache.borrow_mut().insert(key, surface.clone());
        Some(surface)
    }

    pub fn image(&self, name: &str, size: i32) -> gtk::Image {
        match self.surface(name, size) {
            Some(surface) => gtk::Image::from_surface(Some(&surface)),
            None => gtk::Image::from_icon_name(Some(name), gtk::IconSize::Dialog),
        }
    }

    /// Rounded flag (flag-icons, MIT) at width × ¾ width.
    pub fn flag(&self, code: &str, width: i32) -> gtk::Image {
        let scale = self.scale.get();
        let px = width * scale;
        let key = (format!("flag:{code}"), px);
        let cached = self.cache.borrow().get(&key).cloned();
        let surface = cached.or_else(|| {
            let file = icon_dir().join("flags").join(format!("{code}-{}.png", if px <= 32 { 32 } else { 64 }));
            let pixbuf = Pixbuf::from_file_at_scale(&file, px, px * 3 / 4, true).ok()?;
            let surface = to_surface(&pixbuf, scale)?;
            self.cache.borrow_mut().insert(key, surface.clone());
            Some(surface)
        });
        gtk::Image::from_surface(surface.as_ref())
    }

    /// The account picture, clipped round; Yaru's default avatar otherwise.
    pub fn avatar(&self, picture: Option<&Path>, size: i32) -> gtk::Image {
        let Some(path) = picture else {
            return self.image("avatar-default", size);
        };
        let scale = self.scale.get();
        let px = size * scale;
        let key = (format!("avatar:{}", path.display()), px);
        if let Some(surface) = self.cache.borrow().get(&key) {
            return gtk::Image::from_surface(Some(surface));
        }
        let round = (|| -> Option<cairo::Surface> {
            let pixbuf = Pixbuf::from_file_at_scale(path, px, px, false).ok()?;
            let surface = cairo::ImageSurface::create(cairo::Format::ARgb32, px, px).ok()?;
            let context = cairo::Context::new(&surface).ok()?;
            let half = f64::from(px) / 2.0;
            context.arc(half, half, half, 0.0, 2.0 * std::f64::consts::PI);
            context.clip();
            context.set_source_pixbuf(&pixbuf, 0.0, 0.0);
            context.paint().ok()?;
            drop(context);
            surface.set_device_scale(f64::from(scale), f64::from(scale));
            Some((*surface).clone())
        })();
        match round {
            Some(surface) => {
                self.cache.borrow_mut().insert(key, surface.clone());
                gtk::Image::from_surface(Some(&surface))
            }
            None => self.image("avatar-default", size),
        }
    }
}
