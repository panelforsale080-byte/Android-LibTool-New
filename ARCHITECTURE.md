# Il2Cpp Dumper App Architecture

## Overview

This document describes the architecture for transforming Android-LibTool-New from a mod menu into a standalone Il2Cpp dumper app that can dump metadata from a running Unity game process without root access.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Android App (com.android.support)            │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────┐ │
│  │   MainActivity   │◄──►│  DumperActivity   │◄──►│ FileBrowser│ │
│  │  (Process List)  │    │  (Scan/Dump UI)   │    │  (Output) │ │
│  └────────┬─────────┘    └────────┬──────────┘    └──────────┘ │
│           │                       │                            │
│           ▼                       ▼                            │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                    JNI Bridge Layer                      │ │
│  │  - listProcesses()                                       │ │
│  │  - scanProcess(pid)                                      │ │
│  │  - dumpProcess(pid, outputPath)                          │ │
│  │  - generateDumpCs(soPath, metadataPath, outputPath)      │ │
│  │  - getLogOutput()                                        │ │
│  └──────────────────────────────────────────────────────────┘ │
│           │                                                    │
│           ▼                                                    │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                 Native C++ Layer (libDumper.so)          │ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐ │ │
│  │  │ ProcessScanner│  │ Il2CppDetector│  │ MemoryDumper   │ │ │
│  │  │ - /proc scan  │  │ - ELF parsing │  │ - process_vm_  │ │ │
│  │  │ - maps parse  │  │ - signature   │  │   readv        │ │ │
│  │  │ - PID listing │  │   scanning    │  │ - file extract │ │ │
│  │  └──────────────┘  │ - metadata    │  │ - .so dump     │ │ │
│  │                    │   detection   │  │ - metadata     │ │ │
│  │                    └──────────────┘  │   extraction     │ │ │
│  │                                      └────────────────┘ │ │
│  │                                                          │ │
│  │  ┌────────────────────────────────────────────────────┐ │ │
│  │  │           DumpGenerator (Il2CppDumper logic)       │ │ │
│  │  │  - metadata parsing                                │ │ │
│  │  │  - type definition reconstruction                  │ │ │
│  │  │  - dump.cs generation                              │ │ │
│  │  └────────────────────────────────────────────────────┘ │ │
│  │                                                          │ │
│  │  ┌────────────────────────────────────────────────────┐ │ │
│  │  │           VirtualApp Integration Layer             │ │ │
│  │  │  - VirtualApp SDK                                  │ │ │
│  │  │  - Same-UID process management                     │ │ │
│  │  │  - SELinux policy handling                         │ │ │
│  │  └────────────────────────────────────────────────────┘ │ │
│  └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Process Selection Flow
```
User opens app → MainActivity loads → JNI calls listProcesses()
→ Native scans /proc for running processes → Returns list of {PID, name}
→ User selects a process → DumperActivity opens with selected PID
```

### 2. Il2Cpp Detection Flow
```
User clicks "Scan" → JNI calls scanProcess(pid)
→ Native reads /proc/<pid>/maps → Lists all .so mappings
→ For each .so: parse ELF header → Check dynamic symbol table for il2cpp_init
→ Search memory for global-metadata.dat magic (0xFAB11BAF)
→ Returns list of detected Il2Cpp libraries with base addresses
→ UI displays results in log area
```

### 3. Dump Flow
```
User clicks "Dump" → JNI calls dumpProcess(pid, outputPath)
→ Native dumps Il2Cpp .so via process_vm_readv (same UID)
→ Extracts global-metadata.dat from APK or memory
→ Calls generateDumpCs(soPath, metadataPath, outputPath)
→ Il2CppDumper logic parses metadata → Generates dump.cs
→ UI shows completion notification + file browser
```

## JNI Interface Specification

### Process Management
```cpp
// List all running processes
extern "C" JNIEXPORT jobject JNICALL
Java_com_android_support_DumperService_listProcesses(JNIEnv *env, jobject thiz);

// Scan a process for Il2Cpp libraries
extern "C" JNIEXPORT jobject JNICALL
Java_com_android_support_DumperService_scanProcess(JNIEnv *env, jobject thiz, jint pid);

// Dump Il2Cpp library and metadata
extern "C" JNIEXPORT jboolean JNICALL
Java_com_android_support_DumperService_dumpProcess(JNIEnv *env, jobject thiz, jint pid, jstring outputPath);

// Generate dump.cs from dumped files
extern "C" JNIEXPORT jboolean JNICALL
Java_com_android_support_DumperService_generateDumpCs(JNIEnv *env, jobject thiz, jstring soPath, jstring metadataPath, jstring outputPath);

// Get log output
extern "C" JNIEXPORT jstring JNICALL
Java_com_android_support_DumperService_getLogOutput(JNIEnv *env, jobject thiz);
```

### Java/Kotlin Interface
```kotlin
class DumperService {
    companion object {
        init { System.loadLibrary("Dumper") }
        
        @JvmStatic external fun listProcesses(): List<ProcessInfo>
        @JvmStatic external fun scanProcess(pid: Int): ScanResult
        @JvmStatic external fun dumpProcess(pid: Int, outputPath: String): Boolean
        @JvmStatic external fun generateDumpCs(soPath: String, metadataPath: String, outputPath: String): Boolean
        @JvmStatic external fun getLogOutput(): String
    }
}

data class ProcessInfo(val pid: Int, val name: String, val hasIl2Cpp: Boolean = false)
data class ScanResult(val libraries: List<Il2CppLibrary>, val metadataLocation: String?, val error: String?)
data class Il2CppLibrary(val name: String, val baseAddress: Long, val size: Long, val isIl2Cpp: Boolean)
```

## VirtualApp Integration Approach

### Architecture
The dumper app embeds VirtualApp as a library to create a virtual environment where:
1. The target game is installed and launched inside the virtual space
2. The dumper app and the virtual game share the same UID
3. This allows `process_vm_readv` and `ptrace` without root

### Integration Steps
1. **Add VirtualApp SDK** to the project as a dependency
2. **Configure same-UID**: Set `android:sharedUserId` in manifest
3. **Virtual environment setup**:
   - Use `com.lody.virtual.client.VirtualClient` to launch target apps
   - The virtual process runs under the dumper app's UID
4. **SELinux handling**: Request `android.permission.DUMP` or use `setenforce 0` if rooted

### Permissions Required
```xml
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
<uses-permission android:name="android.permission.GET_ACCOUNTS" />
```

## Native Module Details

### ProcessScanner
- Scans `/proc` for numeric directories (PIDs)
- Reads `/proc/<pid>/cmdline` and `/proc/<pid>/comm` for process names
- Returns list of running processes

### Il2CppDetector
- Reads `/proc/<pid>/maps` to enumerate loaded libraries
- For each `.so` file:
  - Parses ELF header (32-bit and 64-bit)
  - Reads dynamic section for symbol table
  - Searches for `il2cpp_init` symbol
  - Scans for `global-metadata.dat` magic bytes (0xAF 0x1B 0xB1 0xFA)
- Returns detected Il2Cpp libraries with metadata locations

### MemoryDumper
- Uses `process_vm_readv` for cross-process memory reading (same UID)
- Falls back to `/proc/<pid>/mem` if process_vm_readv unavailable
- Dumps entire .so file from memory to disk
- Extracts global-metadata.dat from APK assets or memory

### DumpGenerator
- Integrates Il2CppDumper's core parsing logic
- Parses metadata file to reconstruct type definitions
- Generates dump.cs with all classes, methods, fields
- Handles different Il2Cpp versions (24, 27, 29, 31+)

## UI Flow

### MainActivity
- Process list with PID, name, Il2Cpp detection status
- Refresh button
- Process selection → opens DumperActivity

### DumperActivity
- Selected process info display
- "Scan" button → runs Il2Cpp detection
- Results display (detected libraries, metadata location)
- "Dump" button → runs full dump + dump.cs generation
- Progress bar during dump
- Log area for progress and errors
- File browser button to access output files

### FileBrowserActivity
- Browse `/sdcard/Android/data/<package>/files/dump/`
- List generated files (dump.cs, .so, metadata)
- Share/export functionality

## Build Configuration

### Gradle
- Standard Android application module
- NDK with CMake for native builds
- Dependencies: VirtualApp SDK, RecyclerView, etc.

### CMake
- Builds libDumper.so from native source
- Links against: log, dl, android, EGL, GLESv3
- Includes: imgui (for potential future UI), Dobby, xdl, KittyMemory

### Output
- APK with embedded native library
- VirtualApp integration for non-root operation
- dump.cs and related files saved to `/sdcard/Android/data/<package>/files/dump/`