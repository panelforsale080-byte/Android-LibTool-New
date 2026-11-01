package com.example.il2cppagent;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

import java.io.File;

/**
 * Opt-in same-process IL2CPP dump helper for an app you own or are
 * authorized to modify.
 *
 * Load this after Unity/IL2CPP has initialized, for example from a late
 * Activity callback in your own UnityPlayerActivity:
 *
 *   DumpAgent.dump(this);
 *
 * The native library resolves IL2CPP APIs already loaded in this process
 * and writes dump.cs under the app-specific external files directory.
 */
public final class DumpAgent {
    static {
        System.loadLibrary("il2cpp_agent");
    }

    private DumpAgent() {
    }

    public static void dump(final Context context) {
        if (context == null) {
            return;
        }

        final Context appContext = context.getApplicationContext();
        final File filesDir = appContext.getExternalFilesDir(null);
        if (filesDir == null) {
            showToast(appContext, "Dump failed: app-specific files directory is unavailable.");
            return;
        }

        final String outputPath = new File(filesDir, "dump.cs").getAbsolutePath();
        new Thread(() -> {
            final String result = nativeDump(outputPath);
            showToast(appContext, result);
        }, "il2cpp-dump-agent").start();
    }

    private static void showToast(final Context context, final String message) {
        new Handler(Looper.getMainLooper()).post(() ->
                Toast.makeText(context, message, Toast.LENGTH_LONG).show());
    }

    private static native String nativeDump(String outputPath);
}
