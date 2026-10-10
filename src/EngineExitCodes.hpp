#pragma once

// Exit codes of the hidden `--engine` process, read by the tray to tell the
// user why protection stopped. Codes 2 (generic fail-open, auto-restart) and 3
// (recovery::kWorkerUnavailableExitCode, Worker down) predate this header.
//
//   0   clean shutdown
//   1   generic startup error (bad arguments, WSAStartup, ...)
//   2   fail-open after a runtime error; the tray restarts automatically
//   3   Worker unreachable; not restarted automatically
//   10  transparent relay could not start (port in use)
//   11  transparent DNS relay could not start (port in use)
//   12  WinDivert could not be opened (driver missing/blocked, no admin rights)
//   13  process_include rules are all invalid; refused instead of widening scope
//   14  Worker setup required (engine never runs the interactive setup)
//   15  parent/shutdown channel could not be opened; refused to run unmonitored
//   16  config file exists but could not be read
//   0xC0000135  (loader) WinDivert.dll not found next to the executable
namespace engine_exit {

inline constexpr int kRelayPortInUse = 10;
inline constexpr int kDnsRelayPortInUse = 11;
inline constexpr int kWinDivertOpenFailed = 12;
inline constexpr int kInvalidProcessRules = 13;
inline constexpr int kSetupRequired = 14;
inline constexpr int kMonitorUnavailable = 15;
inline constexpr int kConfigUnreadable = 16;
inline constexpr unsigned long kDllNotFound = 0xC0000135UL;

// Codes where an automatic restart cannot help; the user must act first.
constexpr bool needsUserAction(unsigned long code) {
    return code == static_cast<unsigned long>(kWinDivertOpenFailed) ||
           code == static_cast<unsigned long>(kInvalidProcessRules) ||
           code == static_cast<unsigned long>(kSetupRequired) ||
           code == static_cast<unsigned long>(kConfigUnreadable) ||
           code == kDllNotFound;
}

} // namespace engine_exit
