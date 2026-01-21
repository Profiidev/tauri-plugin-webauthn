{ pkgs, lib, ... }:

let
  libs = with pkgs; [
    pkg-config
    openssl
    at-spi2-atk
    atkmm
    cairo
    gdk-pixbuf
    glib
    gtk3
    harfbuzz
    librsvg
    libsoup_3
    pango
    webkitgtk_4_1
    wayland
    libxkbcommon
    udev
  ];
in
{
  packages =
    with pkgs;
    [
      pkg-config
    ]
    ++ libs;

  env.LD_LIBRARY_PATH = "${lib.makeLibraryPath libs}:$LD_LIBRARY_PATH";
}
