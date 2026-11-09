# SplitHello → Rust: modüler yeniden yazım planı

## Bağlam
Kullanıcı tüm uygulamayı (motor + tray + panel) modüler şekilde Rust'a taşımak istiyor. Beklenti: kararlılık (bellek güvenliği) ve hız. Panel ayrıca AdGuard benzeri olacak.

Mevcut C++ kod:
- `src/` yaklaşık 14,9 bin satır: motor ~11 bin, tray ~1,1 bin, panel ~2,6 bin.
- `tests/` içinde 209 test (23 dosya), `fuzz/` içinde 3 fuzzer, CI tanımı `.github/workflows/ci.yml`.

Yöntem: **strangler**. C++ ürün, Rust sürümü her aşamada eşdeğerliğini kanıtlayana kadar çalışan sürüm olarak kalır. Rust motoru C++ ile aynı dosyaları, CLI'ı, çıkış kodlarını ve paylaşımlı bellek düzenini kullanır. Böylece iki sürüm birbirinin yerine geçebilir ve A/B karşılaştırılabilir.

## Sözleşmeler (birebir korunacak)
- **CLI:** bayraklar ve varsayılanlar (`--port 1080` + otomatik port kaydırma, `--manual-proxy`, `--quic-mode`, `--strategy`, süreç kuralları, tek seferlik eylemler). İç bayraklar: `--engine --shutdown-event --ready-event --parent-pid --live-stats`. Kaynak: `src/main.cpp` `parseArgs`.
- **Çıkış kodları:** 0/1/2/3/10–16 ve `0xDEAD0001` (`src/EngineExitCodes.hpp`). Ready event yalnızca relay, DNS ve WinDivert sırayla açıldıktan sonra set edilir.
- **`%APPDATA%\splithello` dosyaları:**
  - `config.json`: aynı anahtarlar. DPAPI entropisi `SplitHello/config/v1`, açılamayan blob aynen geri yazılır.
  - `strategies.json`: v2 biçimi `networkId|host` → `profile;kind;conf;expires;failures;verified`.
  - `telemetry.db`: aynı şema, `user_version=2`, WAL.
  - `splithello.log`: aynı desen, 512 KiB × 3.
  - `adblock-*` dosyaları.
  - Tüm yazımlar atomik (tmp + flush + `MoveFileEx`).
- **Canlı istatistik:** 176 baytlık paylaşımlı bellek, magic `0x53484C53`, v2. Profil slot sırası `src/Strategy.cpp:118-131` ile aynı.
- **Worker protokolü:** `/resolve`, `/dns-query`, `/tunnel`, Bearer kimlik doğrulaması. `worker/src/index.js` değişmez, `include_str!` ile gömülür.
- **Exe adı `splithello.exe`:** installer'daki firewall kuralı ve `\SplitHello` zamanlanmış görevi bu yola bağlı.

## Mimari (Cargo workspace: `crates/`)
| Crate | İçerik | C++ kaynağı |
|---|---|---|
| `sh-proto` | Saf ayrıştırıcı/kurucular: TLS ClientHello ve sunucu yanıtı, DNS mesajı (ECH kırpma, TC kesme), QUIC Initial, IPv4/IPv6/TCP paket kurucu + checksum. I/O yok, fuzz hedefi | TlsHello, DnsMessage, QuicStrategy, PacketStrategy (kurucular), WinDivertPacket |
| `sh-strategy` | Profil tablosu, FragmentPlan, Diagnosis, öğrenme deposu (iki aşamalı öğrenme, yeniden doğrulama, saat koruması) | Strategy, Diagnosis |
| `sh-core` | Yollar, atomik dosya yazma, config + DPAPI, log (tracing + boyutla dönen dosya), canlı istatistik, NetworkIdentity, RecoveryPolicy | Config, Secure, FileUtil, LiveStats, NetworkIdentity, RecoveryPolicy |
| `sh-telemetry` | rusqlite (bundled), aynı şema/saklama/toplu yazma, panel sorguları | Telemetry |
| `sh-adblock` | Liste ayrıştırma, kilitsiz set değişimi, güncelleyici, recent/allow dosyaları | AdBlock |
| `sh-net` | hyper + tokio-rustls (Windows sertifika doğrulama), `connectPort` aktarım portu + SNI/Host; WebSocket tüneli; Happy Eyeballs | Http, WsClient, TcpConnect |
| `sh-dns` | Resolver (önbellek, tek uçuş, bootstrap, Worker sağlığı), şeffaf DNS proxy | Dns, TransparentDnsProxy |
| `sh-relay` | tokio tabanlı dinleyici (SOCKS5/CONNECT + şeffaf), DirectRelay (probe döngüsü, pump), tünel fallback, flow kayıtları | SocksProxy, DirectRelay, Relay, TransparentFlow |
| `sh-divert` | WinDivert 2.2.2 FFI (kendi bağlamamız, DLL hash'i sabit), paket döngüsü, reflect/redirect, paket stratejileri, QUIC, süreç filtresi. Test için trait arayüzü | WinDivertInterceptor, ProcessFilter |
| `sh-setup` | Wrangler/node akışı, Worker doğrulama | Setup, Wrangler |
| `sh-ui` | Win32 tray (`windows` crate) + motor denetçisi; panel ayrı süreç (`--panel`, egui/eframe) | TrayApp, DashboardPanel |
| `splithello` (bin) | CLI dağıtımı: tray / engine / panel / setup / tek seferlik eylemler | main |

**Bilinçli teknik kararlar:**
- **Bağlantılar:** tokio async task. Thread-per-connection kalkar, ama 1024 bağlantı sınırı, 10 dk boşta kalma süresi ve `stop()` sırasında herkesi bekleme aynen kalır.
- **WinDivert döngüsü:** tek, adanmış OS thread (C++ ile aynı). Süreç arama bu thread'de kalır, sonradan iyileştirilebilir.
- **Panel ayrı süreç:** winit event loop'u bir süreçte bir kez kurulabiliyor, ve motor denetimi pencerenin çizilmesine bağlı olmamalı. Tray ile panel `config.json`, dosyalar ve tray penceresine `PostMessage` üzerinden konuşur.
- **Davranış koruması:** ajan raporundaki 29 değişmez, kod içi yorumlarla taşınır. Örnekler: yalnızca SYN'ini gördüğümüz akışları yeniden yaz; açık proxy yok; motorun kendi trafiği `connectPort` ile kendine dönmez; önce relay, sonra DNS, sonra WinDivert başlatma sırası; fail-open; iki aşamalı öğrenme; "uygulandı" doğrulaması; AutoTTL'nin dokunulmamış hello göndermemesi.
- **Düzeltilecek bilinen kusur:** reklam listesi güncelleyicisi şu an motorun kendi trafiğinden geçiyor. Rust'ta `connectPort` üzerinden gidecek.

## Aşamalar (her biri tek başına çalışır ve test edilir)
0. **Hazırlık:**
   - Bekleyen port düzeltmesini commit et (kullanıcı onayıyla).
   - Workspace iskeleti ve `rust-toolchain.toml`.
   - CI'ya Windows'ta `cargo fmt/clippy/test`, Ubuntu'da cargo-fuzz duman testi.
   - WinDivert indirmesi, SHA256 sabitli `build.rs`.
1. **Saf çekirdek** (`sh-proto`, `sh-strategy` mantığı, `sh-adblock` ayrıştırma, flow kayıtları, süreç kuralları, QUIC, RecoveryPolicy):
   - Yaklaşık 150 saf test birebir taşınır (`HelloBuilder` ve `DnsQueryBuilder` dahil).
   - fuzz hedefleri: tls, dns, config.
2. **Kalıcılık ve platform** (`sh-core`, `sh-telemetry`, strateji deposu): C++'ın ürettiği gerçek `config.json` (DPAPI), `strategies.json` ve `telemetry.db` dosyalarını fixture olarak okuyan uyumluluk testleri, iki yönde.
3. **Ağ** (`sh-net`, `sh-dns`, `sh-relay`): `--manual-proxy` uçtan uca çalışır, yönetici gerekmez. İlk A/B: aynı sitelerde C++ ile karşılaştırma.
4. **Yakalama** (`sh-divert`): tam motor eşdeğerliği. Yönetici konsolunda `splithello.exe --console` ile çalışır, birkaç gün telemetri ve log C++ ile karşılaştırılır.
5. **Arayüz ve kurulum** (`sh-ui`, `sh-setup`):
   - Tray: başlat/durdur, yeniden başlatma bütçesi, 10 sn takılma, çıkış kodu nedenleri, Windows ile başlat, DNS modu, kurulum.
   - Panel sayfaları: **Durum**, **Reklam engeli** (sayaç, son engellenenler, serbest bırak), **Listeler**, **İzinli alanlar**, **Süreç kuralları**, **Teşhis** (telemetri), **Log**.
   - Installer Rust exe'ye geçer. C++ kodu ancak kullanıcı onayıyla silinir.

Her aşama ayrı commit/PR. Aşama 1'den sonra crate'ler bağımsız olduğu için bazıları paralel oturumlara bölünebilir.

## Doğrulama
- **Her aşamada:** `cargo test --workspace`, `cargo clippy -D warnings`, fuzz duman testi.
- **Uyumluluk:** C++'ın ürettiği dosyalar Rust'ta okunur, Rust'ın yazdıkları C++ testlerinde okunur.
- **Aşama 3:** `curl --socks5-hostname 127.0.0.1:1080 https://…` ile engelli/serbest siteler.
- **Aşama 4:** yönetici olarak motoru çalıştır; engelli siteler açılıyor mu, reklam engeli, DNS proxy, öğrenme logu, canlı istatistik. Bağlantı ve bellek gözlemi (eski 1 GB sızıntısına karşı).
- **Aşama 5:** tray başlat/durdur/çökme simülasyonu (yeniden başlatma bütçesi), panel sayfaları, installer kurulumu, firewall kuralı, zamanlanmış görev.

## Riskler
- **DPI atlatma:** yalnızca gerçek ağda (Türkiye) doğrulanabilir, A/B şart.
- **unsafe FFI:** WinDivert ve Win32 bağlamaları `unsafe` içerir; yalnızca `sh-divert` ve `sh-core` içinde tutulur.
- **İş büyüklüğü:** çok oturumluk bir iş. Mavi ekran WFP/sürücü kaynaklı; dil değişikliği onu çözmez.
