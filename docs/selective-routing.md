# Alan adına göre seçici yönlendirme

## Hedef

Yalnız gerçekten engellendiği doğrulanan HTTPS alan adlarının TLS ClientHello'sunu değiştirmek. Normal alan adları uygulamanın kendi TCP bağlantısında kalmalı; tarayıcı, Discord veya başka bir uygulamanın exe'si ya da proxy ayarı değişmemeli. Yeni bir engel ilk bağlantıda hemen bilinemeyeceği için pasif gözlem ve sonraki denemede doğrulama gerekir.

## Mevcut sınır

Şeffaf WinDivert modu TCP/443 SYN paketini alan adı bilinmeden yerel relay'e yönlendiriyor. SNI, TCP bağlantısı kurulduktan sonra ClientHello içinde geliyor. Relay normal sitelerde TLS baytlarını değiştirmese de o bağlantı boyunca veri yolunda kalıyor. Dolayısıyla mevcut relay ile alan adına göre karar verip normal sitelerde sıfır relay yükü sağlamak mümkün değil. WinDivert'in network katmanında süreç kimliği de doğrudan bulunmuyor. [WinDivert katmanları ve filtreleri](https://reqrypt.org/windivert-doc.html).

## Denenen ara yol

PAC dosyası normal alan adlarında `DIRECT`, Discord'da yerel proxy döndürdü. Chromium yeni oturumda bu kararı uyguladı. Bu makinedeki Discord masaüstü sürümü sistem PAC ayarını ağ bağlantılarında kullanmadı; Discord sunucularına yerel proxy üzerinden bağlanmadı. Electron'un açık `--proxy-server` seçeneği çalıştı, fakat Discord sürecinin diğer alan adlarını da proxy'ye aldı. Kullanıcı exe'ye veya uygulamaya özel ayar istemediği için bu çözüm devreye alınmadı. Deneme kodu yerel Git stash'inde saklandı; çalışan sürüm etkilenmedi. [Electron proxy seçenekleri](https://www.electronjs.org/docs/latest/api/command-line-switches).

## Önerilen mimari

Belgelerden ve mevcut relay sınırından yaptığımız çıkarıma göre en uygun katman, küçük bir **WFP stream callout** ve kullanıcı modunda kalan politika servisidir. Callout ilk TLS verisini gerektiğinde biriktirip SNI'yi okuyabilir; normal akışları hemen `PERMIT` eder. Yalnız doğrulanmış hedefin ilk TLS kaydını engelleyip değiştirilmiş akış verisini enjekte eder. Böylece TCP sıra numaralarının yönetimi ağ yığınına bırakılır; bütün bağlantıyı kullanıcı modundaki relay'e taşımak gerekmez. Microsoft, stream verisini bekleme ve değiştirme/enjekte etme akışını belgeler: [stream inspection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/stream-inspection), [modifying stream data](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/modifying-stream-data).

Kullanıcı modu DNS/DoH, ağ kimliği, aday alan adları, iki bağımsız başarısızlık, çalışan profil doğrulaması ve günlüklerden sorumlu kalmalı. Sürücü yalnız kısa, sınırlandırılmış ilk el sıkışmayı incelemeli; ayrıştırma veya servis hatasında akışı değiştirmeden geçirmeli. QUIC/UDP/443 ve gerçek ECH ayrı tasarım gerektirir. İlk engelli istek, öğrenme tamamlanmadan başarısız olabilir.

## Uygulama önkoşulu

Bu makinede WDK'nin `fwpsk.h` başlıkları ve kernel kütüphaneleri bulunmuyor. Ayrıca yeni bir Windows kernel sürücüsünün yüklenmesi için uygun imza gerekir; Secure Boot açık sistemde test imzası tek başına yeterli olmayabilir. Bu nedenle üretim bilgisayarında hemen yükleme denenmemeli. Önce WDK yüklü bir test ortamında Microsoft'un WFP örneği temel alınarak küçük permit/continue sürücüsü, ardından tek yönde TLS kaydı değiştirme ve fail-open kapanış doğrulanmalı. [Windows sürücü imzalama gereksinimleri](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-).
