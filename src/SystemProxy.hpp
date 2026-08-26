#pragma once

#include <cstdint>
#include <string>

// Windows system proxy settings (Internet Options), so every app that honours
// them routes through us without per-app configuration.
//
// The previous settings are written to disk *before* we overwrite them. Keeping
// them only in memory meant a hard kill (taskkill, power loss, crash) left the
// machine pointed at a proxy that no longer exists, with no record of what to
// restore. On startup we look for that file and put the old values back.
class SystemProxy {
public:
    // Snapshots the current settings to `backupPath`, then points the system at
    // 127.0.0.1:port.
    static bool enable(uint16_t port, const std::string& backupPath);

    // Restores the snapshot taken by enable() and removes the backup file.
    static bool disable();

    // True if the system proxy currently points at our loopback port.
    static bool isOurs(uint16_t port);

    // Called at startup: if a backup from a previous run is still on disk,
    // restore it. When `force` is false this only happens if the registry still
    // points at the port we recorded - otherwise the user has since changed the
    // setting themselves and we leave it alone.
    // Returns true if settings were restored.
    static bool restoreLeftovers(const std::string& backupPath, bool force = false);

private:
    struct Snapshot {
        uint32_t enabled = 0;
        std::string server;
        std::string bypass;
        uint16_t ourPort = 0;
    };

    static bool saved_;
    static Snapshot snapshot_;
    static std::string backupPath_;

    static bool readCurrent(Snapshot& out);
    static bool applySnapshot(const Snapshot& snapshot);
    static bool writeBackup(const std::string& path, const Snapshot& snapshot);
    static bool readBackup(const std::string& path, Snapshot& out);
    static void notifySystem();
};
