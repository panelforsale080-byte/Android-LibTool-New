package imgui.il2cpp.tool;

import android.view.Surface;

public final class NativeMethods
{
    static
    {
        System.loadLibrary("Tool");
    }

    private NativeMethods() {}

    public static native void onDrawFrame();

    public static native void onSurfaceChanged(int width, int height);

    public static native void onSurfaceCreate();

    public static native void onTouchEvent(int action, float x, int xOrig, float y, int yOrig);

    public static native void onSurfaceCreated(Surface surface);

    public static native String getWindowRect();
}
