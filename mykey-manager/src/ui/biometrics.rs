// biometrics.rs — Biometrics tab: manage PAM/fprintd/Howdy authentication methods.

use gtk4::prelude::*;
use gtk4::{
    Align, Box as GtkBox, Button, ColumnView, ColumnViewColumn, Dialog, DialogFlags, Label,
    ListItem, MessageDialog, MessageType, Orientation, ResponseType, ScrolledWindow,
    SignalListItemFactory, SingleSelection, StringList, Widget,
};

struct BioRow {
    daemon: &'static str,
    date: &'static str,
    time: &'static str,
    bio_type: &'static str,
    name: &'static str,
    locked: bool,
}

const STUB_ROWS: &[BioRow] = &[
    BioRow {
        daemon: "User",
        date: "01/01/2024",
        time: "00:00",
        bio_type: "Password",
        name: "james",
        locked: true,
    },
    BioRow {
        daemon: "fprintd",
        date: "06/04/2026",
        time: "23:41",
        bio_type: "Fingerprint",
        name: "Scan 1",
        locked: false,
    },
];

/// Build and return the Biometrics tab widget.
pub fn build() -> Widget {
    let root = GtkBox::new(Orientation::Vertical, 0);
    root.add_css_class("tab-content");

    // ── Header ────────────────────────────────────────────────────────────────
    let header = GtkBox::new(Orientation::Vertical, 4);
    header.set_margin_bottom(12);

    let title = Label::new(Some("Biometrics"));
    title.add_css_class("title-2");
    title.set_halign(Align::Start);

    let subtitle = Label::new(Some("Manage authentication methods"));
    subtitle.add_css_class("dim-label");
    subtitle.set_halign(Align::Start);

    header.append(&title);
    header.append(&subtitle);
    root.append(&header);

    // ── Model ─────────────────────────────────────────────────────────────────
    let col_daemon = build_string_list(STUB_ROWS.iter().map(|r| r.daemon));
    let col_date = build_string_list(STUB_ROWS.iter().map(|r| r.date));
    let col_time = build_string_list(STUB_ROWS.iter().map(|r| r.time));
    let col_type = build_string_list(STUB_ROWS.iter().map(|r| r.bio_type));
    let col_name = build_string_list(STUB_ROWS.iter().map(|r| r.name));

    // locked flags indexed by position
    let locked_flags: Vec<bool> = STUB_ROWS.iter().map(|r| r.locked).collect();

    let selection = SingleSelection::new(Some(col_daemon.clone()));
    selection.set_autoselect(false);
    selection.set_can_unselect(true);

    let column_view = ColumnView::new(Some(selection.clone()));
    column_view.set_hexpand(true);
    column_view.set_vexpand(true);
    column_view.set_show_row_separators(true);
    column_view.set_show_column_separators(true);

    column_view.append_column(&make_column("Daemon", &col_daemon));
    column_view.append_column(&make_column("Date", &col_date));
    column_view.append_column(&make_column("Time", &col_time));
    column_view.append_column(&make_column("Type", &col_type));
    column_view.append_column(&make_name_column("Name", &col_name, &locked_flags));

    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);
    scroll.set_child(Some(&column_view));
    root.append(&scroll);

    // ── Bottom action bar ──────────────────────────────────────────────────────
    let action_bar = GtkBox::new(Orientation::Horizontal, 8);
    action_bar.set_margin_top(8);
    action_bar.set_halign(Align::End);

    let enroll_btn = Button::with_label("Enroll…");

    let delete_btn = Button::with_label("Delete");
    delete_btn.add_css_class("destructive-action");
    delete_btn.set_sensitive(false);

    // Update button states when selection changes.
    selection.connect_selection_changed({
        let delete_btn = delete_btn.clone();
        let locked_flags = locked_flags.clone();
        let selection = selection.clone();
        move |_, _, _| {
            let pos = selection.selected();
            let selected = pos != gtk4::INVALID_LIST_POSITION;
            let locked = selected && locked_flags.get(pos as usize).copied().unwrap_or(true);
            delete_btn.set_sensitive(selected && !locked);
        }
    });

    enroll_btn.connect_clicked({
        let root = root.clone();
        move |_| show_enroll_dialog(root.upcast_ref())
    });

    delete_btn.connect_clicked({
        let root = root.clone();
        move |_| show_delete_dialog(root.upcast_ref())
    });

    action_bar.append(&enroll_btn);
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

fn make_column(title: &str, model: &StringList) -> ColumnViewColumn {
    let factory = SignalListItemFactory::new();
    let model = model.clone();

    factory.connect_setup(|_, list_item| {
        let item = list_item.downcast_ref::<ListItem>().unwrap();
        let label = Label::new(None);
        label.set_halign(Align::Start);
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
    col
}

/// Name column shows a lock icon for locked (User) rows.
fn make_name_column(
    title: &str,
    model: &StringList,
    locked_flags: &[bool],
) -> ColumnViewColumn {
    let factory = SignalListItemFactory::new();
    let model = model.clone();
    let locked_flags = locked_flags.to_vec();

    factory.connect_setup(|_, list_item| {
        let item = list_item.downcast_ref::<ListItem>().unwrap();
        let row = GtkBox::new(Orientation::Horizontal, 4);
        let label = Label::new(None);
        label.set_halign(Align::Start);
        let lock = Label::new(Some("🔒"));
        lock.set_visible(false);
        row.append(&label);
        row.append(&lock);
        item.set_child(Some(&row));
    });

    factory.connect_bind({
        move |_, list_item| {
            let item = list_item.downcast_ref::<ListItem>().unwrap();
            let pos = item.position();
            if let Some(s) = model.string(pos) {
                let row = item.child().unwrap().downcast::<GtkBox>().unwrap();
                let label = row.first_child().unwrap().downcast::<Label>().unwrap();
                let lock = label.next_sibling().unwrap().downcast::<Label>().unwrap();
                label.set_text(&s);
                let is_locked = locked_flags.get(pos as usize).copied().unwrap_or(false);
                lock.set_visible(is_locked);
            }
        }
    });

    let col = ColumnViewColumn::new(Some(title), Some(factory.upcast::<gtk4::ListItemFactory>()));
    col.set_resizable(true);
    col.set_expand(true);
    col
}

fn show_enroll_dialog(parent: &Widget) {
    let window = parent
        .ancestor(gtk4::Window::static_type())
        .and_then(|w| w.downcast::<gtk4::Window>().ok());

    let dialog = MessageDialog::new(
        window.as_ref(),
        DialogFlags::MODAL | DialogFlags::DESTROY_WITH_PARENT,
        MessageType::Info,
        gtk4::ButtonsType::Close,
        "To enroll a new biometric, use your system tools:\n\n\
         Fingerprint:  fprintd-enroll\n\
         Face recognition:  howdy add",
    );
    dialog.set_title(Some("Enroll Biometric"));
    dialog.connect_response(|d, _| d.close());
    dialog.show();
}

fn show_delete_dialog(parent: &Widget) {
    let window = parent
        .ancestor(gtk4::Window::static_type())
        .and_then(|w| w.downcast::<gtk4::Window>().ok());

    let dialog = Dialog::with_buttons(
        Some("Delete Biometric"),
        window.as_ref(),
        DialogFlags::MODAL | DialogFlags::DESTROY_WITH_PARENT,
        &[
            ("No", ResponseType::Cancel),
            ("Yes", ResponseType::Accept),
        ],
    );

    let content = dialog.content_area();
    content.set_margin_top(16);
    content.set_margin_bottom(16);
    content.set_margin_start(16);
    content.set_margin_end(16);

    let msg = Label::new(Some("Are you sure you want to delete this biometric?"));
    msg.set_wrap(true);
    content.append(&msg);

    if let Some(yes_btn) = dialog.widget_for_response(ResponseType::Accept) {
        yes_btn.add_css_class("destructive-action");
    }

    dialog.connect_response(|dialog, response| {
        if response == ResponseType::Accept {
            // TODO: fprintd/howdy deletion
        }
        dialog.close();
    });

    dialog.show();
}
