// mobile_companion.rs — Mobile Companion tab: coming-soon placeholder.

use gtk4::prelude::*;
use gtk4::{Align, Box as GtkBox, Image, Label, Orientation, Widget};

/// Build and return the Mobile Companion tab widget.
pub fn build() -> Widget {
    let root = GtkBox::new(Orientation::Vertical, 0);
    root.add_css_class("tab-content");
    root.set_halign(Align::Fill);
    root.set_valign(Align::Fill);

    // Inner box centres content both axes.
    let inner = GtkBox::new(Orientation::Vertical, 16);
    inner.set_halign(Align::Center);
    inner.set_valign(Align::Center);
    inner.set_hexpand(true);
    inner.set_vexpand(true);

    // ── Icon ──────────────────────────────────────────────────────────────────
    let icon = Image::from_icon_name("network-wireless-symbolic");
    icon.set_pixel_size(64);
    icon.add_css_class("dim-label");

    // ── Title ─────────────────────────────────────────────────────────────────
    let title = Label::new(Some("Mobile Companion — Coming Soon"));
    title.add_css_class("title-1");
    title.set_halign(Align::Center);

    // ── Description ───────────────────────────────────────────────────────────
    let desc = Label::new(Some(
        "Pair MyKey Proxy with the MyKey Proxy companion app for iOS and Android \
         to forward authentication requests to your mobile device. Approve \
         WebAuthn requests using your phone's biometrics — Face ID, fingerprint, \
         or PIN — as a trusted credential on your Linux desktop. Secure pairing \
         via QR code with end-to-end encrypted communication over your local \
         network, with an encrypted relay as fallback.",
    ));
    desc.set_wrap(true);
    desc.set_wrap_mode(gtk4::pango::WrapMode::Word);
    desc.set_justify(gtk4::Justification::Center);
    desc.set_halign(Align::Center);
    desc.set_max_width_chars(60);
    desc.add_css_class("dim-label");

    // ── Subtitle ──────────────────────────────────────────────────────────────
    let sub = Label::new(Some("Available in a future release."));
    sub.add_css_class("dim-label");
    sub.set_halign(Align::Center);

    inner.append(&icon);
    inner.append(&title);
    inner.append(&desc);
    inner.append(&sub);

    root.append(&inner);
    root.upcast()
}
