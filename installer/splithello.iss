; Build with installer\build.ps1, or directly:
;   ISCC /DAppVersion=1.0.0 /DBuildDir=<folder with splithello.exe> splithello.iss
; Saved as UTF-8 with BOM so the Turkish text survives.

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef BuildDir
  #define BuildDir "..\build"
#endif

[Setup]
AppId={{8F3C2A64-5B1D-4E7A-9C0F-2D6A71B4E935}
AppName=SplitHello
AppVersion={#AppVersion}
AppPublisher=icguner
AppPublisherURL=https://github.com/icguner/SplitHello
AppSupportURL=https://github.com/icguner/SplitHello/issues
; The engine loads a kernel driver and runs elevated, and the app only enables
; "start with Windows" from a folder a standard user cannot write to. So the
; default is Program Files; "just me" (%LOCALAPPDATA%\Programs) is still offered
; but leaves that tray option disabled.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\SplitHello
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; Held by the tray process; Setup/uninstall ask the user to quit it first.
AppMutex=Local\SplitHello-Tray
WizardStyle=modern
ShowLanguageDialog=auto
SetupIconFile=..\assets\splithello.ico
WizardImageFile=gen\wizard-100.bmp,gen\wizard-200.bmp
WizardSmallImageFile=gen\small-100.bmp,gen\small-200.bmp
UninstallDisplayIcon={app}\splithello.exe
Compression=lzma2/ultra
SolidCompression=yes
OutputDir=..\dist
OutputBaseFilename=SplitHello-Setup-{#AppVersion}

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
english.StartWithWindows=Start SplitHello when Windows starts
turkish.StartWithWindows=Windows ile birlikte başlat
english.RemoveData=Also delete your SplitHello settings and history (%%APPDATA%%\splithello)?%n%nThis includes the saved Worker secret.
turkish.RemoveData=SplitHello ayarlarını ve geçmişini de (%%APPDATA%%\splithello) silmek istiyor musunuz?%n%nKayıtlı Worker anahtarı da silinir.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startup"; Description: "{cm:StartWithWindows}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#BuildDir}\splithello.exe"; DestDir: "{app}"; Flags: ignoreversion
; The exe loads WinDivert.dll, which loads the driver from the same folder.
Source: "{#BuildDir}\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\WinDivert-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\SplitHello"; Filename: "{app}\splithello.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\SplitHello"; Filename: "{app}\splithello.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Registers the SYSTEM service that runs the engine: the only elevation SplitHello
; needs. The tray and panel then run as the user, without UAC prompts.
Filename: "{app}\splithello.exe"; Parameters: "--install-service"; WorkingDir: "{app}"; Flags: runhidden
; The relay's redirected SYNs arrive as inbound traffic for this exe, so a Block rule
; (Windows adds one when its first-listen prompt is dismissed) silently kills every
; HTTPS connection. Drop any rule for this path, then allow it explicitly.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=all program=""{app}\splithello.exe"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""SplitHello"" dir=in action=allow program=""{app}\splithello.exe"" profile=any"; Flags: runhidden
; Registers the logon task (same one as the tray's "Windows ile başlat"); needs the
; elevated Setup token, and is refused for a per-user install location.
Filename: "{app}\splithello.exe"; Parameters: "--enable-startup"; WorkingDir: "{app}"; Flags: runhidden; Tasks: startup
; The exe elevates itself (UAC), so start it as the original user.
Filename: "{app}\splithello.exe"; WorkingDir: "{app}"; Description: "{cm:LaunchProgram,SplitHello}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\splithello.exe"; Parameters: "--uninstall-service"; Flags: runhidden; RunOnceId: "UninstallService"
; The tray's "Windows ile başlat" task; absent if it was never enabled (error ignored).
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""\SplitHello"" /F"; Flags: runhidden; RunOnceId: "DeleteStartupTask"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=all program=""{app}\splithello.exe"""; Flags: runhidden; RunOnceId: "DeleteFirewallRule"

[Code]
// An upgrade must replace splithello.exe, which the running service keeps open.
// shortcut: a fixed 3 s wait for the stop; poll the service state if that proves short.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  if Exec(ExpandConstant('{sys}\sc.exe'), 'stop SplitHello', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    Sleep(3000);
  Result := '';
end;

// Settings, history and the DPAPI-protected Worker secret live in %APPDATA%\splithello;
// keep them unless the user says otherwise (default button is "No").
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
    if MsgBox(CustomMessage('RemoveData'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    begin
      DelTree(ExpandConstant('{userappdata}\splithello'), True, True, True);
      DelTree(ExpandConstant('{commonappdata}\SplitHello'), True, True, True);
    end;
end;
