// credentials.rs — Credentials tab: list registered WebAuthn keys with inline editing.

use gtk4::prelude::*;
use gtk4::{
    Align, Box as GtkBox, Button, ColumnView, ColumnViewColumn, CssProvider, Dialog,
    DialogFlags, Label, ListItem, Orientation, ResponseType, ScrolledWindow,
    SignalListItemFactory, SingleSelection, StringList, Widget,
};

struct CredRow {
    key: &'static str,
    date: &'static str,
    time: &'static str,
    cred_type: &'static str,
    name: &'static str,
    notes: &'static str,
}

const STUB_ROWS: &[CredRow] = &[
    CredRow {
        key: "f0f1168c1ac1362f...",
        date: "06/04/2026",
        time: "23:41",
        cred_type: "Extension",
        name: "NordPass",
        notes: "",
    },
    CredRow {
        key: "a1b2c3d4e5f6...",
        date: "06/04/2026",
        time: "23:45",
        cred_type: "Website",
        name: "webauthn.io",
        notes: "Test credential",
    },
];

/// Build and return the Credentials tab widget.
pub fn build() -> Widget {
    let root = GtkBox::new(Orientation::Vertical, 0);
    root.add_css_class("tab-content");

    // ── Header ────────────────────────────────────────────────────────────────
    let header = GtkBox::new(Orientation::Vertical, 4);
    header.set_margin_bottom(12);

    let title = Label::new(Some("Credentials"));
    title.add_css_class("title-2");
    title.set_halign(Align::Start);

    let subtitle = Label::new(Some("Manage your registered authentication keys"));
    subtitle.add_css_class("dim-label");
    subtitle.set_halign(Align::Start);

    header.append(&title);
    header.append(&subtitle);
    root.append(&header);

    // ── Model — flat StringList encoding rows as tab-separated fields ─────────
    // Each entry encodes one column value; we build one StringList per column.
    let col_key = build_string_list(STUB_ROWS.iter().map(|r| r.key));
    let col_date = build_string_list(STUB_ROWS.iter().map(|r| r.date));
    let col_time = build_string_list(STUB_ROWS.iter().map(|r| r.time));
    let col_type = build_string_list(STUB_ROWS.iter().map(|r| r.cred_type));
    let col_name = build_string_list(STUB_ROWS.iter().map(|r| r.name));
    let col_notes = build_string_list(STUB_ROWS.iter().map(|r| r.notes));

    // The selection model drives the ColumnView; we key it off col_key.
    let selection = SingleSelection::new(Some(col_key.clone()));
    selection.set_autoselect(false);
    selection.set_can_unselect(true);

    let column_view = ColumnView::new(Some(selection.clone()));
    column_view.set_hexpand(true);
    column_view.set_vexpand(true);
    column_view.set_show_row_separators(true);
    column_view.set_show_column_separators(true);

    column_view.append_column(&make_column("Key", &col_key, true, false));
    column_view.append_column(&make_column("Date", &col_date, false, false));
    column_view.append_column(&make_column("Time", &col_time, false, false));
    column_view.append_column(&make_column("Type", &col_type, false, false));
    column_view.append_column(&make_column("Name", &col_name, false, true));
    column_view.append_column(&make_column("Notes", &col_notes, false, true));

    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);
    scroll.set_child(Some(&column_view));
    root.append(&scroll);

    // ── Bottom action bar ──────────────────────────────────────────────────────
    let action_bar = GtkBox::new(Orientation::Horizontal, 8);
    action_bar.set_margin_top(8);
    action_bar.set_halign(Align::End);

    let delete_btn = Button::with_label("Delete");
    delete_btn.add_css_class("destructive-action");
    delete_btn.set_sensitive(false);

    // Enable Delete only when a row is selected.
    selection.connect_selection_changed({
        let delete_btn = delete_btn.clone();
        let selection = selection.clone();
        move |_, _, _| {
            delete_btn.set_sensitive(selection.selected() != gtk4::INVALID_LIST_POSITION);
        }
    });

    // Delete confirmation dialog.
    delete_btn.connect_clicked({
        let root = root.clone();
        move |_| {
            show_delete_dialog(root.upcast_ref());
        }
    });

    action_bar.append(&delete_btn);
    root.append(&action_bar);

    root.upcast()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_string_list<'a>(items: impl Iterator<Item = &'a str>) -> StringList {
    let list = StringList::new(&[]);
    for item in items {
        list.append(item);
    }
    list
}

/// Build a ColumnViewColumn backed by a separate StringList model.
fn make_column(
    title: &str,
    model: &StringList,
    monospace: bool,
    _editable: bool,
) -> ColumnViewColumn {
    let factory = SignalListItemFactory::new();
    let model = model.clone();

    factory.connect_setup(move |_, list_item| {
        let item = list_item.downcast_ref::<ListItem>().unwrap();
        let label = Label::new(None);
        label.set_halign(Align::Start);
        label.set_max_width_chars(30);
        label.set_ellipsize(gtk4::pango::EllipsizeMode::End);
        if monospace {
            label.add_css_class("monospace");
        }
        item.set_child(Some(&label));
    });

    factory.connect_bind({
        let model = model.clone();
        move |_, list_item| {
            let item = list_item.downcast_ref::<ListItem>().unwrap();
            let pos = item.position();
            if let Some(s) = model.string(pos) {
                let label = item.child().unwrap().downcast::<Label>().unwrap();
                label.set_text(&s);
            }
        }
    });

    let col = ColumnViewColumn::new(Some(title), Some(factory.upcast::<gtk4::ListItemFactory>()));
    col.set_resizable(true);
    col.set_expand(title == "Name" || title == "Notes");
    col
}

fn show_delete_dialog(parent: &Widget) {
    let window = parent
        .ancestor(gtk4::Window::static_type())
        .and_then(|w| w.downcast::<gtk4::Window>().ok());

    let dialog = Dialog::with_buttons(
        Some("Delete Credential"),
        window.as_ref(),
        DialogFlags::MODAL | DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", ResponseType::Cancel),
            ("Delete", ResponseType::Accept),
        ],
    );

    let content = dialog.content_area();
    content.set_margin_top(16);
    content.set_margin_bottom(16);
    content.set_margin_start(16);
    content.set_margin_end(16);
    content.set_spacing(8);

    let msg = Label::new(Some(
        "Are you sure you want to delete this key?\n\n\
         Deleting this credential may lock you out of associated services.\n\
         This action cannot be undone.",
    ));
    msg.set_wrap(true);
    msg.set_max_width_chars(50);
    content.append(&msg);

    if let Some(delete_btn) = dialog.widget_for_response(ResponseType::Accept) {
        delete_btn.add_css_class("destructive-action");
    }

    dialog.connect_response(|dialog, response| {
        if response == ResponseType::Accept {
            // TODO: polkit-authenticated credential deletion
        }
        dialog.close();
    });

    dialog.show();
}
