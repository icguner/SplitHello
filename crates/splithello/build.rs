// Embeds the app icon (resource 101, the id the tray loads) like src/SplitHello.rc.
fn main() {
    embed_resource::compile("splithello.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
