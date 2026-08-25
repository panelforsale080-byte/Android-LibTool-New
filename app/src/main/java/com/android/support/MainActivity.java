package com.android.support;

import android.app.Activity;
import android.opengl.GLSurfaceView;
import android.os.Bundle;
import android.view.MotionEvent;

import imgui.il2cpp.tool.NativeMethods;

import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;

/** Standalone test shell for libTool.so (AIDE / debug builds). */
public class MainActivity extends Activity
{
    private GLSurfaceView glView;

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        glView = new GLSurfaceView(this);
        glView.setEGLContextClientVersion(3);
        glView.setRenderer(new GLSurfaceView.Renderer()
        {
            @Override
            public void onSurfaceCreated(GL10 gl, EGLConfig config)
            {
                NativeMethods.onSurfaceCreate();
            }

            @Override
            public void onSurfaceChanged(GL10 gl, int width, int height)
            {
                NativeMethods.onSurfaceChanged(width, height);
            }

            @Override
            public void onDrawFrame(GL10 gl)
            {
                NativeMethods.onDrawFrame();
            }
        });
        setContentView(glView);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event)
    {
        NativeMethods.onTouchEvent(
                event.getAction(),
                event.getX(),
                (int) event.getX(),
                event.getY(),
                (int) event.getY());
        return glView.onTouchEvent(event) || super.onTouchEvent(event);
    }
}
