// secure_folder.rs — Secure Folder tab: manage TPM-sealed encrypted folders.

use gtk4::prelude::*;
use gtk4::{
    Align, Box as GtkBox, Button, ColumnView, ColumnViewColumn, Dialog, DialogFlags, Label,
    ListItem, Orientation, ResponseType, ScrolledWindow, SignalListItemFactory, SingleSelection,
    StringList, Widget,
};

struct FolderRow {
    name: &'static str,
    date: &'static str,
    time: &'static str,
    location: &'static str,
    notes: &'static str,
    locked: bool,
}

const STUB_ROWS: &[FolderRow] = &[FolderRow {
    name: "Secure Folder",
    date: "06/04/2026",
    time: "23:50",
    location: "/home/james/SecureFolder",
    notes: "",
    locked: true,
}];

/// Build and return the Secure Folder tab widget.
pub fn build() -> Widget {
    let root = GtkBox::new(Orientation::Vertical, 0);
    root.add_css_class("tab-content");

    // ── Header with "Create New" button ───────────────────────────────────────
    let header_row = GtkBox::new(Orientation::Horizontal, 0);
    header_row.set_margin_bottom(12);

    let header = GtkBox::new(Orientation::Vertical, 4);
    header.set_hexpand(true);

    let title = Label::new(Some("Secure Folders"));
    title.add_css_class("title-2");
    title.set_halign(Align::Start);

    let subtitle = Label::new(Some("TPM-encrypted folders — all-or-nothing access"));
    subtitle.add_css_class("dim-label");
    subtitle.set_halign(Align::Start);

    header.append(&title);
    header.append(&subtitle);

    let create_btn = Button::with_label("Create New Secure Folder");
    create_btn.set_valign(Align::Center);

    header_row.append(&header);
    header_row.append(&create_btn);
    root.append(&header_row);

    // ── Model ─────────────────────────────────────────────────────────────────
    let col_name = build_string_list(STUB_ROWS.iter().map(|r| r.name));
    let col_date = build_string_list(STUB_ROWS.iter().map(|r| r.date));
    let col_time = build_string_list(STUB_ROWS.iter().map(|r| r.time));
    let col_loc = build_string_list(STUB_ROWS.iter().map(|r| r.location));
    let col_notes = build_string_list(STUB_ROWS.iter().map(|r| r.notes));

    let locked_flags: Vec<bool> = STUB_ROWS.iter().map(|r| r.locked).collect();

    let selection = SingleSelection::new(Some(col_name.clone()));
    selection.set_autoselect(false);
    selection.set_can_unselect(true);

    let column_view = ColumnView::new(Some(selection.clone()));
    column_view.set_hexpand(true);
    column_view.set_vexpand(true);
    column_view.set_show_row_separators(true);
    column_view.set_show_column_separators(true);

    column_view.append_column(&make_column("Name", &col_name, false));
    column_view.append_column(&make_column("Date", &col_date, false));
    column_view.append_column(&make_column("Time", &col_time, false));
    column_view.append_column(&make_column("Location", &col_loc, true));
    column_view.append_column(&make_column("Notes", &col_notes, true));

    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);
    scroll.set_child(Some(&column_view));
    root.append(&scroll);

    // ── Bottom action bar ──────────────────────────────────────────────────────
    let action_bar = GtkBox::new(Orientation::Horizontal, 8);
    action_bar.set_margin_top(8);
    action_bar.set_halign(Align::End);

    let unlock_btn = Button::with_label("Unlock");
    unlock_btn.set_sensitive(false);

    let rename_btn = Button::with_label("Rename");
    rename_btn.set_sensitive(false);

    let move_btn = Button::with_label("Move");
    move_btn.set_sensitive(false);

    let delete_btn = Button::with_label("Delete");
    delete_btn.add_css_class("destructive-action");
    delete_btn.set_sensitive(false);

    // Update button states on selection change.
    selection.connect_selection_changed({
        let unlock_btn = unlock_btn.clone();
        let rename_btn = rename_btn.clone();
        let move_btn = move_btn.clone();
        let delete_btn = delete_btn.clone();
        let locked_flags = locked_flags.clone();
        let selection = selection.clone();
        move |_, _, _| {
            let pos = selection.selected();
            let selected = pos != gtk4::INVALID_LIST_POSITION;
            let is_locked = selected
                && locked_flags.get(pos as usize).copied().unwrap_or(true);

            unlock_btn.set_sensitive(selected);
            unlock_btn.set_label(if is_locked { "Unlock" } else { "Lock" });
            rename_btn.set_sensitive(selected);
            move_btn.set_sensitive(selected);
            delete_btn.set_sensitive(selected);
        }
    });

    delete_btn.connect_clicked({
        let root = root.clone();
        move |_| show_delete_dialog(root.upcast_ref())
    });

    create_btn.connect_clicked({
        let root = root.clone();
        move |_| show_create_dialog(root.upcast_ref())
    });

    action_bar.append(&unlock_btn);
    action_bar.append(&rename_btn);
    action_bar.append(&move_btn);
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

fn make_column(title: &str, model: &StringList, expand: bool) -> ColumnViewColumn {
    let factory = SignalListItemFactory::new();
    let model = model.clone();

    factory.connect_setup(|_, list_item| {
        let item = list_item.downcast_ref::<ListItem>().unwrap();
        let label = Label::new(None);
        label.set_halign(Align::Start);
        label.set_max_width_chars(40);
        label.set_ellipsize(gtk4::pango::EllipsizeMode::Middle);
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
    col.set_expand(expand);
    col
}

fn show_delete_dialog(parent: &Widget) {
    let window = parent
        .ancestor(gtk4::Window::static_type())
        .and_then(|w| w.downcast::<gtk4::Window>().ok());

    let dialog = Dialog::with_buttons(
        Some("Delete Secure Folder"),
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
        "Are you sure? The secure folder and ALL its contents will be\n\
         permanently deleted. This cannot be undone.",
    ));
    msg.set_wrap(true);
    msg.set_max_width_chars(50);
    content.append(&msg);

    if let Some(delete_btn) = dialog.widget_for_response(ResponseType::Accept) {
        delete_btn.add_css_class("destructive-action");
    }

    dialog.connect_response(|dialog, response| {
        if response == ResponseType::Accept {
            // TODO: TPM-authenticated secure folder deletion
        }
        dialog.close();
    });

    dialog.show();
}

fn show_create_dialog(parent: &Widget) {
    let window = parent
        .ancestor(gtk4::Window::static_type())
        .and_then(|w| w.downcast::<gtk4::Window>().ok());

    let dialog = Dialog::with_buttons(
        Some("Create New Secure Folder"),
        window.as_ref(),
        DialogFlags::MODAL | DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("Cancel", ResponseType::Cancel),
            ("Create", ResponseType::Accept),
        ],
    );

    let content = dialog.content_area();
    content.set_margin_top(16);
    content.set_margin_bottom(16);
    content.set_margin_start(16);
    content.set_margin_end(16);
    content.set_spacing(8);

    let msg = Label::new(Some("Secure folder creation coming soon."));
    content.append(&msg);

    dialog.connect_response(|dialog, _| dialog.close());
    dialog.show();
}
