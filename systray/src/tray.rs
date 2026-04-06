// tray.rs — ksni::Tray implementation for MyKey Proxy.

use ksni::{menu, Icon, Tray};

static LOGO_BYTES: &[u8] =
    include_bytes!("../assets/AuthnProxyLogoCircle.png");

pub struct WebAuthnTray {
    icons: Vec<Icon>,
}

impl WebAuthnTray {
    pub fn new() -> Self {
        WebAuthnTray {
            icons: load_icons(),
        }
    }
}

impl Tray for WebAuthnTray {
    fn id(&self) -> String {
        "mykey-proxy".into()
    }

    fn title(&self) -> String {
        "MyKey Proxy".into()
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        self.icons.clone()
    }

    fn menu(&self) -> Vec<menu::MenuItem<Self>> {
        vec![
            menu::StandardItem {
                label:   "MyKey Proxy".into(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            menu::MenuItem::Separator,
            menu::StandardItem {
                label:   "Status: Running".into(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            menu::MenuItem::Separator,
            menu::StandardItem {
                label:    "Quit".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

// ---------------------------------------------------------------------------
// PNG → ksni ARGB32 icon conversion
// ---------------------------------------------------------------------------

fn load_icons() -> Vec<Icon> {
    let img = match image::load_from_memory(LOGO_BYTES) {
        Ok(i) => i,
        Err(e) => {
            log::warn!("[tray] Failed to load logo PNG: {e}");
            return vec![];
        }
    };

    vec![
        encode_icon(&img, 128),
        encode_icon(&img, 64),
    ]
}

fn encode_icon(img: &image::DynamicImage, size: u32) -> Icon {
    let resized = img.resize_exact(size, size, image::imageops::FilterType::Lanczos3);
    let rgba = resized.to_rgba8();

    // ksni expects ARGB32 big-endian packed into Vec<u8>
    let data: Vec<u8> = rgba
        .pixels()
        .flat_map(|p| {
            let [r, g, b, a] = p.0;
            [a, r, g, b]
        })
        .collect();

    Icon {
        width:  size as i32,
        height: size as i32,
        data,
    }
}
