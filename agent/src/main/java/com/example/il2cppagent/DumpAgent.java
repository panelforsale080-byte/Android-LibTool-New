package com.example.il2cppagent;

/**
 * Not required at runtime.
 *
 * libTool.so auto-dumps dump.cs in the host process after Unity/IL2CPP
 * is loaded. No Java call and no Toast.
 */
public final class DumpAgent {
    private DumpAgent() {
    }
}
