//! "Windows ile başlat": the `\SplitHello` scheduled task (port of the
//! startup helpers in `src/TrayApp.cpp`). The task runs this exe elevated at
//! every logon, so it is only registered from a location a standard user
//! cannot modify; otherwise a user-writable exe would be a privilege escalation.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TASK_NAME: &str = "\\SplitHello";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Task Scheduler calls must never block the tray for long.
const SCHEDULER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupResult {
    Ok,
    Failed,
    UnsafeLocation,
}

fn schtasks() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(|root| PathBuf::from(root).join("System32").join("schtasks.exe"))
        .unwrap_or_else(|| PathBuf::from("schtasks.exe"))
}

/// Runs a hidden child; None when it could not start or ran past the timeout
/// (it is killed then).
fn run_hidden(program: &Path, arguments: &[&str]) -> Option<i32> {
    let mut child = Command::new(program)
        .args(arguments)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + SCHEDULER_TIMEOUT;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    tracing::warn!("Gorev zamanlayici komutu zaman asimina ugradi, sonlandiriliyor");
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// None: the Task Scheduler did not answer in time.
pub fn task_exists() -> Option<bool> {
    run_hidden(&schtasks(), &["/Query", "/TN", TASK_NAME]).map(|code| code == 0)
}

pub fn set_enabled(enabled: bool) -> StartupResult {
    if !enabled {
        if task_exists() == Some(false) {
            return StartupResult::Ok;
        }
        return match run_hidden(&schtasks(), &["/Delete", "/TN", TASK_NAME, "/F"]) {
            Some(0) => StartupResult::Ok,
            _ => StartupResult::Failed,
        };
    }

    let Ok(executable) = std::env::current_exe() else {
        return StartupResult::Failed;
    };
    if !security::location_needs_admin_to_modify(&executable) {
        return StartupResult::UnsafeLocation;
    }
    let Some(user) = security::current_user_id() else {
        return StartupResult::Failed;
    };
    // The XML lives next to the exe: that folder was just verified to be
    // admin-only, so a standard user cannot swap it between write and import.
    let Some(folder) = executable.parent() else {
        return StartupResult::Failed;
    };
    let xml_path = folder.join("splithello-startup-task.xml");
    let xml = task_xml(&executable.to_string_lossy(), &user);
    // schtasks wants UTF-16 (with BOM) for /XML.
    let bytes: Vec<u8> = std::iter::once(0xFEFFu16)
        .chain(xml.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    if std::fs::write(&xml_path, bytes).is_err() {
        let _ = std::fs::remove_file(&xml_path);
        return StartupResult::Failed;
    }
    let xml_text = xml_path.to_string_lossy().into_owned();
    let code = run_hidden(
        &schtasks(),
        &["/Create", "/TN", TASK_NAME, "/XML", &xml_text, "/F"],
    );
    let _ = std::fs::remove_file(&xml_path);
    if code == Some(0) {
        StartupResult::Ok
    } else {
        StartupResult::Failed
    }
}

/// `--enable-startup` (installer use); 0 on success.
pub fn enable_from_command_line() -> i32 {
    match set_enabled(true) {
        StartupResult::Ok => 0,
        StartupResult::UnsafeLocation => {
            eprintln!("Otomatik baslangic yalnizca yonetici korumali bir klasorden etkinlesir.");
            1
        }
        StartupResult::Failed => 1,
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// schtasks flags alone cannot clear the 72 h execution limit or the battery
/// conditions, so the task is registered from XML.
fn task_xml(executable: &str, user_id: &str) -> String {
    let user = xml_escape(user_id);
    let folder = Path::new(executable)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
\x20 <RegistrationInfo><Description>SplitHello</Description></RegistrationInfo>\r\n\
\x20 <Triggers>\r\n\
\x20   <LogonTrigger>\r\n\
\x20     <Enabled>true</Enabled>\r\n\
\x20     <UserId>{user}</UserId>\r\n\
\x20     <Delay>PT5S</Delay>\r\n\
\x20   </LogonTrigger>\r\n\
\x20 </Triggers>\r\n\
\x20 <Principals>\r\n\
\x20   <Principal id=\"Author\">\r\n\
\x20     <UserId>{user}</UserId>\r\n\
\x20     <LogonType>InteractiveToken</LogonType>\r\n\
\x20     <RunLevel>HighestAvailable</RunLevel>\r\n\
\x20   </Principal>\r\n\
\x20 </Principals>\r\n\
\x20 <Settings>\r\n\
\x20   <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n\
\x20   <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n\
\x20   <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n\
\x20   <AllowHardTerminate>true</AllowHardTerminate>\r\n\
\x20   <StartWhenAvailable>false</StartWhenAvailable>\r\n\
\x20   <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n\
\x20   <AllowStartOnDemand>true</AllowStartOnDemand>\r\n\
\x20   <Enabled>true</Enabled>\r\n\
\x20   <Hidden>false</Hidden>\r\n\
\x20   <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n\
\x20   <Priority>7</Priority>\r\n\
\x20 </Settings>\r\n\
\x20 <Actions Context=\"Author\">\r\n\
\x20   <Exec>\r\n\
\x20     <Command>\"{}\"</Command>\r\n\
\x20     <WorkingDirectory>{}</WorkingDirectory>\r\n\
\x20   </Exec>\r\n\
\x20 </Actions>\r\n\
</Task>\r\n",
        xml_escape(executable),
        xml_escape(&folder)
    )
}

mod security {
    use std::path::Path;

    use windows::Win32::Foundation::{
        CloseHandle, GENERIC_ALL, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetTokenInformation, INHERIT_ONLY_ACE, IsWellKnownSid, LookupAccountSidW,
        PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WELL_KNOWN_SID_TYPE, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid,
        WinWorldSid,
    };
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{HSTRING, PWSTR};

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    /// The process token's user SID bytes (kept alive by the returned buffer).
    fn token_user() -> Option<Vec<u8>> {
        let mut token = HANDLE::default();
        // SAFETY: token handle closed below; buffer sized by the first call.
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
            let mut size = 0;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
            let mut buffer = vec![0u8; size as usize];
            let ok = size != 0
                && GetTokenInformation(
                    token,
                    TokenUser,
                    Some(buffer.as_mut_ptr().cast()),
                    size,
                    &mut size,
                )
                .is_ok();
            let _ = CloseHandle(token);
            ok.then_some(buffer)
        }
    }

    fn user_sid(buffer: &[u8]) -> PSID {
        // SAFETY: `buffer` holds a TOKEN_USER written by GetTokenInformation.
        unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    /// True when `path` has an effective allow ACE matching `mask` for a
    /// non-admin principal (Everyone, Authenticated Users, Users, Interactive
    /// or the current user). Unknown ACLs count as risky.
    fn low_privilege_can_modify(path: &Path, mask: u32, current_user: Option<PSID>) -> bool {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: out-pointers are valid; the descriptor is freed below and
        // `dacl` points into it.
        unsafe {
            if GetNamedSecurityInfoW(
                &HSTRING::from(path.as_os_str()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
            .is_err()
            {
                return true;
            }
            let well_known: [WELL_KNOWN_SID_TYPE; 4] = [
                WinWorldSid,
                WinAuthenticatedUserSid,
                WinBuiltinUsersSid,
                WinInteractiveSid,
            ];
            let mut risky = dacl.is_null(); // a NULL DACL grants everyone full control
            let count = if dacl.is_null() { 0 } else { (*dacl).AceCount };
            for index in 0..u32::from(count) {
                if risky {
                    break;
                }
                let mut raw = std::ptr::null_mut();
                if GetAce(dacl, index, &mut raw).is_err() || raw.is_null() {
                    continue;
                }
                let header = &*raw.cast::<ACE_HEADER>();
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0
                {
                    continue;
                }
                let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                if ace.Mask & mask == 0 {
                    continue;
                }
                let sid = PSID(std::ptr::from_ref(&ace.SidStart).cast_mut().cast());
                risky = well_known
                    .iter()
                    .any(|kind| IsWellKnownSid(sid, *kind).as_bool())
                    || current_user.is_some_and(|user| EqualSid(sid, user).is_ok());
            }
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            risky
        }
    }

    /// Only accept locations that need admin rights to change: the exe, its
    /// folder, and any parent a standard user could rename.
    pub fn location_needs_admin_to_modify(executable: &Path) -> bool {
        let Ok(real) = std::fs::canonicalize(executable) else {
            return false;
        };
        let user = token_user();
        let current_user = user.as_deref().map(user_sid);
        let object_mask = FILE_WRITE_DATA.0
            | FILE_APPEND_DATA.0
            | FILE_DELETE_CHILD.0
            | DELETE.0
            | WRITE_DAC.0
            | WRITE_OWNER.0
            | GENERIC_WRITE.0
            | GENERIC_ALL.0;
        // Parents only matter if the user can rename/replace the child below them.
        let ancestor_mask =
            FILE_DELETE_CHILD.0 | DELETE.0 | WRITE_DAC.0 | WRITE_OWNER.0 | GENERIC_ALL.0;
        if low_privilege_can_modify(&real, object_mask, current_user) {
            return false;
        }
        let mut directory = true;
        let mut current = real.parent();
        while let Some(path) = current {
            let mask = if directory {
                object_mask
            } else {
                ancestor_mask
            };
            if low_privilege_can_modify(path, mask, current_user) {
                return false;
            }
            directory = false;
            current = path.parent();
        }
        true
    }

    /// "DOMAIN\user" for the task's UserId, falling back to the SID string.
    pub fn current_user_id() -> Option<String> {
        let buffer = token_user()?;
        let sid = user_sid(&buffer);
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let (mut name_len, mut domain_len) = (256u32, 256u32);
        let mut use_ = SID_NAME_USE::default();
        // SAFETY: buffers are valid for the given lengths; the SID string is freed.
        unsafe {
            if LookupAccountSidW(
                None,
                sid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut use_,
            )
            .is_ok()
                && name_len > 0
            {
                let name = String::from_utf16_lossy(&name[..name_len as usize]);
                let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
                return Some(if domain.is_empty() {
                    name
                } else {
                    format!("{domain}\\{name}")
                });
            }
            let mut text = PWSTR::null();
            ConvertSidToStringSidW(sid, &mut text).ok()?;
            let result = text.to_string().ok();
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_xml_escapes_and_points_at_the_exe() {
        let xml = task_xml("C:\\Program Files\\SplitHello\\splithello.exe", "PC\\A&B");
        assert!(xml.contains("<UserId>PC\\A&amp;B</UserId>"));
        assert!(
            xml.contains("<Command>\"C:\\Program Files\\SplitHello\\splithello.exe\"</Command>")
        );
        assert!(xml.contains("<WorkingDirectory>C:\\Program Files\\SplitHello</WorkingDirectory>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    }

    #[test]
    fn user_folders_are_not_a_safe_task_location() {
        // The test exe lives under the user's profile: writable by them.
        let exe = std::env::current_exe().unwrap();
        assert!(!security::location_needs_admin_to_modify(&exe));
        let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("notepad.exe");
        assert!(security::location_needs_admin_to_modify(&system));
        assert!(security::current_user_id().is_some_and(|id| !id.is_empty()));
    }
}
