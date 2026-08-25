#include "Keyboard.h"
#include "Il2cpp/Il2cpp.h"
#include "string"

namespace Keyboard
{
    Il2CppClass *TouchScreenKeyboard = nullptr;
    Il2CppObject *openedKeyboard = nullptr;
    std::function<void(const std::string &)> lastCallback = nullptr;
    std::string lastText = "";
    bool callbackOnDoneOnly = false;

    void Init()
    {
        TouchScreenKeyboard = Il2cpp::FindClass("UnityEngine.TouchScreenKeyboard");
        LOGPTR(TouchScreenKeyboard);
    }

    void Open(const std::function<void(const std::string &)> &callback, bool onDoneOnly)
    {
        Open("", callback, onDoneOnly);
    }
    void Open(const char *text, const std::function<void(const std::string &)> &callback, bool onDoneOnly)
    {
        LOGD("Keyboard Open");
        openedKeyboard = TouchScreenKeyboard->invoke_static_method<Il2CppObject *>("Open", Il2cpp::NewString(text), 0,
                                                                                   0, 0, 0, Il2cpp::NewString(""), 0);
        lastCallback = callback;
        lastText = text;
        callbackOnDoneOnly = onDoneOnly;
    }

    void Reset()
    {
        lastCallback = nullptr;
        lastText = "";
        callbackOnDoneOnly = false;

        // private System.Void Destroy(); // 0x28c52e8
        // protected override System.Void Finalize(); // 0x28c53b4
        static auto Destroy = openedKeyboard->klass->getMethod("Destroy");
        static auto Finalize = openedKeyboard->klass->getMethod("Finalize");
        if (Destroy)
        {
            Destroy->invoke_static<void>(openedKeyboard);
        }
        if (Finalize)
        {
            Finalize->invoke_static<void>(openedKeyboard);
        }
        openedKeyboard = nullptr;
    }

    void Update()
    {
        if (openedKeyboard)
        {
            static auto get_statusMethod = TouchScreenKeyboard->getMethod("get_status");
            TouchScreenKeyboardStatus status = Canceled;
            if (check)
            {
                status = openedKeyboard->invoke_method<TouchScreenKeyboardStatus>("get_status");
            }
            else
            {
                auto result = Il2cpp::RuntimeInvoke(get_statusMethod, openedKeyboard, nullptr, nullptr);
                if (!result)
                {
                    return Reset();
                }
                status = Il2cpp::GetUnboxedValue<TouchScreenKeyboardStatus>(result);
            }

            if (status == Visible || status == Done)
            {
                static auto get_textMethod = TouchScreenKeyboard->getMethod("get_text");
                static auto get_text =
                    (Il2CppString * (*)(void *, MethodInfo *, Il2CppObject *, void *)) get_textMethod->invoker_method;
                Il2CppString *text = nullptr;
                if (check)
                {
                    text = openedKeyboard->invoke_method<Il2CppString *>("get_text");
                }
                else
                {
                    text = get_text(get_textMethod->methodPointer, get_textMethod, openedKeyboard, nullptr);
                }

                if (!text)
                {
                    return;
                }

                auto currentText = text->to_string();
                if (lastCallback && currentText != lastText && !callbackOnDoneOnly)
                {
                    lastText = currentText;
                    lastCallback(currentText);
                }

                if (status == Done)
                {
                    if (lastCallback && callbackOnDoneOnly)
                    {
                        lastCallback(currentText);
                    }
                    Reset();
                    LOGD("Keyboard Done");
                }
            }
            else
            {
                Reset();
                LOGD("Keyboard Canceled");
            }
        }
    }

    bool IsOpen()
    {
        return openedKeyboard != nullptr;
    }
} // namespace Keyboard
