#include "Frida.h"
#include "frida-gum.h"
#include "Frida/gumpp/gumpp.hpp"
#include "Il2cpp/Il2cpp.h"
#include "Il2cpp/il2cpp-class.h"
#include "Tool/Tool.h"

// extern std::unordered_map<void *, HookerData> hookerMap;
extern std::mutex hookerMtx;
extern int maxLine;
extern std::vector<MethodInfo *> g_Methods;

MethodInfo *binarySearchClosest(const uintptr_t addr)
{
    int left = 0;
    int right = g_Methods.size() - 1;

    while (left <= right)
    {
        int pivot = (left + right) / 2;
        int comparison = (uintptr_t)g_Methods[pivot]->methodPointer - addr;

        if (comparison == 0)
        {
            return g_Methods[pivot];
        }
        else if (comparison > 0)
        {
            right = pivot - 1;
        }
        else
        {
            left = pivot + 1;
        }
    }
    return g_Methods[right];
}
namespace Frida
{
    class TraceListener : public Gum::InvocationListener
    {
      private:
        Gum::RefPtr<Gum::Backtracer> backtracer;

      public:
        TraceListener() : backtracer(Gum::Backtracer_make_accurate())
        {
            if (!backtracer)
            {
                LOGE("Failed to create backtracer");
            }
        }

        void Backtracer(Gum::InvocationContext *context)
        {
            auto hookerData = context->get_listener_function_data<HookerData>();
            // hookerData->backtraced.clear();
            // hookerData->backtracing = false;
            
            {
                Gum::ReturnAddressArray return_addresses;
                backtracer->generate(context->get_cpu_context(), return_addresses);
                LOGD("========================================");
                std::vector<std::string> result;
                for (int i = 0; i < return_addresses.len; i++)
                {
                    auto addr = return_addresses.items[i];
                    // auto result =
                    //     std::min_element(g_Methods.begin(), g_Methods.end(),
                    //                      [&addr](const auto &a, const auto &b)
                    //                      {
                    //                          // Calculate absolute differences
                    //                          auto diffA = std::abs(static_cast<int>((uintptr_t)a->methodPointer -
                    //                                                                 reinterpret_cast<uintptr_t>(addr)));
                    //                          auto diffB = std::abs(static_cast<int>((uintptr_t)b->methodPointer -
                    //                                                                 reinterpret_cast<uintptr_t>(addr)));

                    //                          // Ensure addr is greater than the address
                    //                          if (addr <= a->methodPointer)
                    //                          {
                    //                              return diffA < diffB;
                    //                          }
                    //                          else
                    //                          {
                    //                              return diffB < diffA;
                    //                          }
                    //                      });
                    auto closestMethod = binarySearchClosest((uintptr_t)addr);
                    if (closestMethod)
                    {
                        intptr_t offset = (intptr_t)addr - (intptr_t)closestMethod->methodPointer;
                        if (offset < 0)
                        {
                            offset = -offset;
                        }
                        if (offset <= 0x1000)
                        {
                            char buffer[265];
                            sprintf(buffer, "%s::%s+0x%" PRIxPTR, closestMethod->getClass()->getFullName().c_str(),
                                    closestMethod->getName(), offset);
                            // LOGD("%s::%s+0x%lx => %p", closestPtr->second->getClass()->getFullName().c_str(),
                            //      closestPtr->second->getName(), gap, (void *)closestPtr->first);

                            result.push_back(buffer);
                        }
                        else
                        {
                            LOGE("Offset too big: %" PRIxPTR, offset);
                            LOGD("%s => %p", gum_symbol_name_from_address(addr), addr);
                        }
                    }
                    else
                    {
                        LOGE("Not found: %p", (void *)addr);
                        LOGD("%s => %p", gum_symbol_name_from_address(addr), addr);
                    }

                    // LOGD("%s => %p", gum_symbol_name_from_address(addr), addr);
                }
                if (!result.empty())
                    hookerData->backtraced.push_back(result);
            }
        }

        virtual void on_enter(Gum::InvocationContext *context)
        {
            auto hookerData = context->get_listener_function_data<HookerData>();

            // Multiple threads can hit on_enter, int++ is not atomic
            hookerMtx.lock();
            hookerData->hitCount++;

            if (hookerData->silent)
            {
                hookerMtx.unlock();
                return;
            }

            if (hookerData->backtracing)
            {
                // Backtracer might need the lock or be slow
                Backtracer(context);
            }

            hookerData->time = 1.f;
            auto method = hookerData->method;
            auto name = method->getName();
            auto className = method->getClass()->getName();
            auto absAddress = method->getAbsAddress();
            auto klass = method->getClass();

            if (!Il2cpp::GetIsMethodStatic(method))
            {
                auto thiz = context->get_nth_argument<Il2CppObject *>(0);
                if (thiz)
                {
                    HookerData::collectSet[klass].emplace(thiz);
                }
            }
            hookerMtx.unlock();

            char buffer[256]{0};
            sprintf(buffer, "%p | %s::%s", (void *)absAddress, className, name);

            // CircularBuffer has its own lock
            if (!HookerData::visited.empty())
            {
                for (auto it = HookerData::visited.rbegin(); it != HookerData::visited.rend(); ++it)
                {
                    if (it->name == buffer)
                    {
                        it->goneTime = 10.f;
                        it->time = 2.f;
                        it->hitCount++;
                        return;
                    }
                }
            }
            HookerData::visited.push_back({buffer, 2.f, 10.f, 0});
        }

        virtual void on_leave(Gum::InvocationContext *context)
        {
        }
    };

    Gum::RefPtr<Gum::Interceptor> interceptor;
    TraceListener *traceListener;
    std::unordered_map<void *, std::unique_ptr<TraceListener>> traceListeners;
    void Init()
    {
        interceptor = Gum::Interceptor_obtain();
        traceListener = new TraceListener();
    }

    bool Trace(MethodInfo *method, HookerData *data)
    {
        auto it = traceListeners.find(data->method->methodPointer);
        if (it != traceListeners.end())
        {
            LOGE("Already hooked %s", data->method->getName());
            return false;
        }
        traceListeners[method->methodPointer] = std::make_unique<TraceListener>();
        bool result = interceptor->attach(method->methodPointer, traceListeners[method->methodPointer].get(), data);
        if (!result)
        {
            traceListeners.erase(method->methodPointer);
        }
        return result;
    }

    bool Untrace(MethodInfo *method)
    {
        auto it = traceListeners.find(method->methodPointer);
        if (it == traceListeners.end())
            return false;

        interceptor->detach(it->second.get());
        traceListeners.erase(it);
        return true;
    }

    bool isTraced(MethodInfo *method)
    {
        return traceListeners.find(method->methodPointer) != traceListeners.end();
    }
} // namespace Frida
