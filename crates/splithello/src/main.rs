//! SplitHello (Rust). Until stage 4 lands, only the manual-proxy engine and
//! the strategy one-shots run here; the C++ splithello.exe stays the product.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(sh_engine::run(args));
}
