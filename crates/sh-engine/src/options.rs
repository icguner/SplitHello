//! Command line (port of `parseArgs`, `src/main.cpp`): same flags, defaults,
//! validation and exit code 1 on bad input.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuicMode {
    #[default]
    Allow,
    Adaptive,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// Tray (default) or engine/console run.
    #[default]
    Run,
    Help,
    Setup,
    SetupOnly,
    Redeploy,
    RestoreProxy,
    EnableStartup,
    ForgetToken,
    ForgetStrategies,
    ListStrategies,
    /// Internal: the egui panel process the tray opens.
    Panel,
    /// Internal: run as the Windows service (started by the SCM).
    Service,
    /// Installer: register the service and the shared state folder.
    InstallService,
    UninstallService,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub action: Action,
    pub worker_url: String,
    pub forced_strategy: String,
    pub process_include: Vec<String>,
    pub process_exclude: Vec<String>,
    pub quic_mode: QuicMode,
    pub verbose: bool,
    pub console: bool,
    pub engine: bool,
    pub shutdown_event: String,
    pub ready_event: String,
    pub parent_pid: u32,
}

impl Options {
    /// A plain launch (no engine/console/manual flags) runs the tray.
    pub fn tray_mode(&self) -> bool {
        self.action == Action::Run && !self.engine && !self.console && !self.verbose
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            action: Action::Run,
            worker_url: String::new(),
            forced_strategy: String::new(),
            process_include: Vec::new(),
            process_exclude: Vec::new(),
            quic_mode: QuicMode::Allow,
            verbose: false,
            console: false,
            engine: false,
            shutdown_event: String::new(),
            ready_event: String::new(),
            parent_pid: 0,
        }
    }
}

const MAX_RULE_LENGTH: usize = 1024;

/// `args` excludes the program name. Err carries the exit code (0 for none).
pub fn parse(args: &[String]) -> Result<Options, i32> {
    let mut options = Options::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| -> Result<String, i32> {
            iter.next().cloned().ok_or_else(|| {
                eprintln!("Bilinmeyen parametre: {name}\n");
                print_usage();
                1
            })
        };
        match arg.as_str() {
            "--worker" => options.worker_url = value(arg)?,
            "--strategy" => {
                options.forced_strategy = value(arg)?;
                if sh_proto::packet::mode_for_profile(&options.forced_strategy).is_none() {
                    eprintln!("Bilinmeyen profil: {}\n", options.forced_strategy);
                    return Err(1);
                }
            }
            "--allow-quic" => options.quic_mode = QuicMode::Allow,
            "--quic-mode" => {
                let mode = value(arg)?;
                options.quic_mode = match mode.as_str() {
                    "adaptive" => QuicMode::Adaptive,
                    "block" => QuicMode::Block,
                    "allow" => QuicMode::Allow,
                    _ => {
                        eprintln!("Gecersiz QUIC modu: {mode} (allow, adaptive veya block)");
                        return Err(1);
                    }
                };
            }
            "--include-process" | "--exclude-process" => {
                let pattern = value(arg)?;
                if pattern.is_empty() || pattern.len() > MAX_RULE_LENGTH {
                    eprintln!("Gecersiz surec deseni (bos veya 1024 bayttan uzun)");
                    return Err(1);
                }
                if arg == "--include-process" {
                    options.process_include.push(pattern);
                } else {
                    options.process_exclude.push(pattern);
                }
            }
            "--enable-startup" => options.action = Action::EnableStartup,
            "--restore-proxy" => options.action = Action::RestoreProxy,
            "--forget-token" => options.action = Action::ForgetToken,
            "--forget-strategies" => options.action = Action::ForgetStrategies,
            "--list-strategies" => options.action = Action::ListStrategies,
            "--verbose" => options.verbose = true,
            "--console" => options.console = true,
            "--engine" => options.engine = true,
            "--shutdown-event" => options.shutdown_event = value(arg)?,
            "--ready-event" => options.ready_event = value(arg)?,
            "--parent-pid" => {
                let text = value(arg)?;
                options.parent_pid = text.parse().map_err(|_| {
                    eprintln!("Gecersiz ust surec kimligi: {text}");
                    1
                })?;
            }
            "--setup" => options.action = Action::Setup,
            "--setup-only" => options.action = Action::SetupOnly,
            "--redeploy" => options.action = Action::Redeploy,
            "--help" => options.action = Action::Help,
            "--panel" => options.action = Action::Panel,
            "--service" => options.action = Action::Service,
            "--install-service" => options.action = Action::InstallService,
            "--uninstall-service" => options.action = Action::UninstallService,
            other => {
                eprintln!("Bilinmeyen parametre: {other}\n");
                print_usage();
                return Err(1);
            }
        }
    }
    Ok(options)
}

pub fn print_usage() {
    println!(
        "SplitHello - adaptive DPI diagnosis and direct-path bypass\n\n\
         Kullanim: splithello [secenekler]\n\n\
         Secenekler:\n\
         \x20 --setup              Cloudflare hesabini bagla ve worker deploy et\n\
         \x20 --redeploy           Worker kodunu guncelle, gizli anahtari yenile\n\
         \x20 --worker <url>       Worker URL (config yerine manuel belirt)\n\
         \x20 --strategy <ad>      Paket profili (varsayilan: packet-autottl)\n\
         \x20 --quic-mode <mod>    allow (varsayilan), adaptive veya block\n\
         \x20 --allow-quic         Eski ad; --quic-mode allow ile ayni\n\
         \x20 --include-process <desen>  Yalniz eslesen exe yollarini isle (tekrarlanabilir)\n\
         \x20 --exclude-process <desen>  Eslesen exe yollarini atla (tekrarlanabilir)\n\
         \x20 --restore-proxy      Cokme sonrasi kalan proxy yedegini geri yukle ve cik\n\
         \x20 --enable-startup     'Windows ile baslat' gorevini olustur ve cik\n\
         \x20 --forget-token       Eski surumden kalan API token alanini sil ve cik\n\
         \x20 --forget-strategies  Ogrenilen alan adi stratejilerini sifirla ve cik\n\
         \x20 --list-strategies    DPI uyarlama profillerini listele ve cik\n\
         \x20 --console            Tray yerine konsolda calistir\n\
         \x20 --verbose            Debug loglama (konsol modunu acar)\n\
         \x20 --help               Bu yardimi goster"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn defaults_match_the_cpp_build() {
        let options = parse(&[]).unwrap();
        assert!(options.forced_strategy.is_empty());
        assert_eq!(options.quic_mode, QuicMode::Allow);
        assert_eq!(options.action, Action::Run);
    }

    #[test]
    fn parses_engine_flags_and_values() {
        let options = parse(&args(&[
            "--strategy",
            "packet-seqovl",
            "--quic-mode",
            "adaptive",
            "--include-process",
            "chrome.exe",
            "--exclude-process",
            "steam.exe",
            "--engine",
            "--shutdown-event",
            "Local\\S",
            "--parent-pid",
            "42",
        ]))
        .unwrap();
        assert!(options.engine);
        assert_eq!(options.forced_strategy, "packet-seqovl");
        assert_eq!(options.quic_mode, QuicMode::Adaptive);
        assert_eq!(
            (options.process_include.len(), options.process_exclude.len()),
            (1, 1)
        );
        assert_eq!(
            (options.parent_pid, options.shutdown_event.as_str()),
            (42, "Local\\S")
        );
    }

    #[test]
    fn rejects_bad_input_with_exit_code_1() {
        for bad in [
            &["--strategy", "retired"][..],
            // Removed with the relay: record profiles and its own switches.
            &["--strategy", "sni-mid"],
            &["--manual-proxy"],
            &["--port", "1080"],
            &["--quic-mode", "fast"],
            &["--include-process", ""],
            &["--parent-pid", "x"],
            &["--strategy"],
            &["--bogus"],
        ] {
            assert_eq!(parse(&args(bad)).unwrap_err(), 1, "{bad:?}");
        }
        assert_eq!(
            parse(&args(&["--include-process", &"a".repeat(1025)])).unwrap_err(),
            1
        );
    }
}
