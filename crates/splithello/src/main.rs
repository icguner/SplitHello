//! Rust entry point. Until the engine reaches parity (stage 4 of the plan) this
//! binary does nothing on the network; the C++ `splithello.exe` stays in use.

fn main() {
    eprintln!("SplitHello (Rust) gelistirme surumu: henuz ag motoru yok; C++ surumunu kullanin.");
    std::process::exit(1);
}
