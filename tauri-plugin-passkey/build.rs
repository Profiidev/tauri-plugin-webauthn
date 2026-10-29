const COMMANDS: &[&str] = &[
    "register",
    "authenticate",
    "send_pin",
    "select_key",
    "cancel",
];

fn main() {
    // if you think these look redundant, you are correct.
    // the cfg guard prevents this block on windows and linux
    // while the env var check prevents this block on ios,
    // because, for reasons, when building for ios, target_os = "macos" here
    #[cfg(target_os = "macos")]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
            use swift_rs::SwiftLinker;
            SwiftLinker::new("14.0")
                .with_package("WebauthnBridge", "macos")
                .link();
            link_xcode27_products_fallback();
        }
    }

    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}

/// Xcode 27's SwiftPM writes the static library to
/// `<OUT_DIR>/swift-rs/WebauthnBridge/out/Products/<Configuration>`, a layout
/// older swift-rs releases do not search. Add that directory to the link search
/// path whenever it actually holds the archive; harmless when swift-rs already
/// found it.
#[cfg(target_os = "macos")]
fn link_xcode27_products_fallback() {
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let configuration = if std::env::var("PROFILE").as_deref() == Ok("release") {
        "Release"
    } else {
        "Debug"
    };
    let dir = std::path::Path::new(&out_dir)
        .join("swift-rs")
        .join("WebauthnBridge")
        .join("out")
        .join("Products")
        .join(configuration);
    if dir.join("libWebauthnBridge.a").exists() {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
}
