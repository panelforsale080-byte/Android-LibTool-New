# Android LibTool

This is my own app build for testing and security research. The project
contains native ImGui tooling and Frida support for authorized testing of apps
and devices that I own or have permission to inspect.

## Processes tab

The tab is implemented as a small native module:

- `Tool/ProcessTab.h` declares the tab entry point.
- `Tool/ProcessTab.cpp` scans `/proc`, reads process names, parses
  `/proc/<pid>/maps`, and renders the ImGui tables.
- `Main.cpp` adds the `Processes` tab beside the existing `Strings` and
  `Dumper` tabs.
- `Android.mk` includes the C++ source in the native shared library.

### Process list

The tab reads accessible numeric directories under `/proc`. It displays the
PID and process name, with manual refresh, optional refresh every two seconds,
and a PID/name filter. Android may restrict access to some entries; those
entries are skipped and the tab reports the count.

### Shared-library mapping view

Tap a process name to select it. The selected-process panel then reads only
accessible shared-library mappings whose path starts with `/data/app/` from
`/proc/<pid>/maps` and shows each `.so` mapping path, start/end addresses,
permissions, and the mapping offset relative to that library's ELF load base
address. This is a read-only view.

The previous shared-library mapping *monitor* mode (Start monitor, NEW/REMOVED
mapping-change events, library dropdown) has been removed from this build.

## So Monitor tab (NEW)

A generic address monitor for ANY loaded `.so` (not just il2cpp). It lets you:

1. Pick any loaded shared library from a dropdown (populated via
   `dl_iterate_phdr`), with its load base and size shown.
2. Enter an address in hex. If the value is a runtime address it is converted
   to an offset; if the value is smaller than the module base it is treated as
   an offset and converted to a runtime address. Both values are shown so the
   offset is always accurate for the selected `.so`.
3. Press **Start monitor** to instrument that address with Dobby
   (`DobbyInstrument`). Every call executed at that address is logged with its
   offset, the first eight argument registers (x0-x7), LR and SP.
4. **Stop monitor** removes the instrumentation; **Clear log** empties the
   table; **Copy all** copies the full log to the Android clipboard.

Files:

- `Tool/SoMonitor.h` / `Tool/SoMonitor.cpp` implement the tab.
- `Main.cpp` adds the `So Monitor` tab.
- `Android.mk` includes `Tool/SoMonitor.cpp` in the native library.

Note: the monitor only instruments addresses inside a loaded module. If the
address is not a valid function entry, Dobby reports a failure and the tab
shows the error instead of silently doing nothing.
