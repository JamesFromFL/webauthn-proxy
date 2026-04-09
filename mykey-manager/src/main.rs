// main.rs — MyKey Manager: GTK4 credential management GUI.

mod ui;

use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, CssProvider, Notebook};

const APP_ID: &str = "com.mykey.Manager";

fn main() {
    env_logger::init();

    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    // ── CSS ───────────────────────────────────────────────────────────────────
    let css = CssProvider::new();
    css.load_from_path(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("styles.css"),
    );
    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().expect("no display"),
        &css,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // ── Notebook tabs ─────────────────────────────────────────────────────────
    let notebook = Notebook::new();
    notebook.set_hexpand(true);
    notebook.set_vexpand(true);

    let tabs: &[(&str, gtk4::Widget)] = &[
        ("Credentials",      ui::credentials::build()),
        ("Biometrics",       ui::biometrics::build()),
        ("Secure Folder",    ui::secure_folder::build()),
        ("Mobile Companion", ui::mobile_companion::build()),
    ];

    for (label, widget) in tabs {
        notebook.append_page(widget, Some(&gtk4::Label::new(Some(label))));
    }

    // ── Window ────────────────────────────────────────────────────────────────
    let window = ApplicationWindow::builder()
        .application(app)
        .title("MyKey Manager")
        .default_width(900)
        .default_height(600)
        .child(&notebook)
        .build();

    window.set_size_request(900, 600);
    window.present();
}
