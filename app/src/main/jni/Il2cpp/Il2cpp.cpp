//
// Created by Perfare on 2020/7/4.
//

#include "Il2cpp.h"
#include <chrono>
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <jni.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include "Includes/Utils.h"
#include <unistd.h>
#include <unordered_map>
#include <iomanip>
#include <sys/mman.h>
#include <codecvt>
#include <locale>
#include <algorithm>
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

#include "xdl/include/xdl.h"

#define DO_API(r, n, p) r(*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

uint64_t il2cpp_base = 0;
static bool g_initialized = false;
static bool g_DoLog = true;

void init_il2cpp_api(void *handle){
#define DO_API(r, n, p)                                                                                                \
    {                                                                                                                  \
        n = (r(*) p)xdl_sym(handle, #n, nullptr);                                                                      \
    }

#include "il2cpp-api-functions.h"

#undef DO_API
}

namespace Il2cpp {
std::string GetMethodModifier(uint32_t flags)
{
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access)
    {
        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC)
    {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT)
    {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
        {
            outPut << "override ";
        }
    }
    else if (flags & METHOD_ATTRIBUTE_FINAL)
    {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
        {
            outPut << "sealed override ";
        }
    }
    else if (flags & METHOD_ATTRIBUTE_VIRTUAL)
    {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT)
        {
            outPut << "virtual ";
        }
        else
        {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL)
    {
        outPut << "extern ";
    }
    return outPut.str();
}
} // namespace Il2cpp

bool _il2cpp_type_is_byref(Il2CppType *type)
{
    auto byref = type->byref;
    if (il2cpp_type_is_byref)
    {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

// ============================================================================
// C# Type Name Translation
// ============================================================================

namespace Il2cpp {
std::string GetCsTypeName(Il2CppClass* klass) {
    if (!klass) return "void";

    const Il2CppType* type = (const Il2CppType*)il2cpp_class_get_type(klass);
    if (type) {
        switch (type->type) {
            case IL2CPP_TYPE_SZARRAY: {
                Il2CppClass* elementClass = (Il2CppClass*)il2cpp_class_get_element_class(klass);
                return GetCsTypeName(elementClass) + "[]";
            }
            case IL2CPP_TYPE_ARRAY: {
                Il2CppClass* elementClass = (Il2CppClass*)il2cpp_class_get_element_class(klass);
                std::string rankStr = "[";
                int rank = il2cpp_class_get_rank(klass);
                for (int i = 1; i < rank; i++) rankStr += ",";
                rankStr += "]";
                return GetCsTypeName(elementClass) + rankStr;
            }
            case IL2CPP_TYPE_PTR: {
                Il2CppClass* elementClass = (Il2CppClass*)il2cpp_class_get_element_class(klass);
                return GetCsTypeName(elementClass) + "*";
            }
            default:
                break;
        }
    }

    const char* name = il2cpp_class_get_name(klass);
    if (!name) return "unknown";

    std::string typeName = name;

    if (typeName == "Single") return "float";
    if (typeName == "Int32") return "int";
    if (typeName == "Int64") return "long";
    if (typeName == "Boolean") return "bool";
    if (typeName == "String") return "string";
    if (typeName == "Void") return "void";
    if (typeName == "Object") return "object";
    if (typeName == "Byte") return "byte";
    if (typeName == "SByte") return "sbyte";
    if (typeName == "UInt32") return "uint";
    if (typeName == "UInt64") return "ulong";
    if (typeName == "Char") return "char";
    if (typeName == "Double") return "double";
    if (typeName == "Decimal") return "decimal";
    if (typeName == "Int16") return "short";
    if (typeName == "UInt16") return "ushort";

    return typeName;
}

std::string GetCsTypeNameFromType(Il2CppType* type) {
    if (!type) return "void";
    Il2CppClass* klass = il2cpp_class_from_type(type);
    return GetCsTypeName(klass);
}

std::string GetMethodSignature(MethodInfo* method) {
    std::stringstream outPut;
    uint32_t iflags = 0;
    auto flags = il2cpp_method_get_flags(method, &iflags);
    outPut << GetMethodModifier(flags);

    auto return_type = il2cpp_method_get_return_type(method);
    if (_il2cpp_type_is_byref(return_type))
    {
        outPut << "ref ";
    }

    Il2CppClass* return_class = (Il2CppClass*)il2cpp_class_from_type(return_type);
    outPut << GetCsTypeName(return_class) << " " << il2cpp_method_get_name(method) << "(";

    auto param_count = il2cpp_method_get_param_count(method);
    for (int i = 0; i < param_count; ++i)
    {
        auto param = il2cpp_method_get_param(method, i);
        auto attrs = param->attrs;
        
        if (_il2cpp_type_is_byref(param))
        {
            if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN))
            {
                outPut << "out ";
            }
            else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT))
            {
                outPut << "in ";
            }
            else
            {
                outPut << "ref ";
            }
        }
        else
        {
            if (attrs & PARAM_ATTRIBUTE_IN)
            {
                outPut << "[In] ";
            }
            if (attrs & PARAM_ATTRIBUTE_OUT)
            {
                outPut << "[Out] ";
            }
        }

        Il2CppClass* param_class = (Il2CppClass*)il2cpp_class_from_type(param);
        outPut << GetCsTypeName(param_class) << " ";
        const char* param_name = il2cpp_method_get_param_name(method, i);
        outPut << (param_name ? param_name : "param" + std::to_string(i));
        outPut << ", ";
    }
    if (param_count > 0)
    {
        outPut.seekp(-2, outPut.cur);
    }
    outPut << ")";
    return outPut.str();
}
} // namespace Il2cpp

std::string dump_method_cs(Il2CppClass *klass)
{
    std::stringstream outPut;
    outPut << "\n\t// Methods";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter))
    {
        outPut << "\n\t// Offset: 0x";
        outPut << std::hex << (uint64_t)method->methodPointer - il2cpp_base;
        outPut << "\n\t";
        outPut << Il2cpp::GetMethodSignature(method) << " { }\n";
    }
    return outPut.str();
}

std::string dump_property_cs(Il2CppClass *klass)
{
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter))
    {
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get)
        {
            outPut << Il2cpp::GetMethodModifier(il2cpp_method_get_flags(get, &iflags));
            auto retType = il2cpp_method_get_return_type(get);
            prop_class = (Il2CppClass*)il2cpp_class_from_type(retType);
        }
        else if (set)
        {
            outPut << Il2cpp::GetMethodModifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = (Il2CppClass*)il2cpp_class_from_type(param);
        }
        if (prop_class)
        {
            outPut << Il2cpp::GetCsTypeName(prop_class) << " " << prop_name << " { ";
            if (get)
            {
                outPut << "get; ";
            }
            if (set)
            {
                outPut << "set; ";
            }
            outPut << "}\n";
        }
        else
        {
            if (prop_name)
            {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field_cs(Il2CppClass *klass)
{
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter))
    {
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access)
        {
            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL)
        {
            outPut << "const ";
        }
        else
        {
            if (attrs & FIELD_ATTRIBUTE_STATIC)
            {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY)
            {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        Il2CppClass* field_class = (Il2CppClass*)il2cpp_class_from_type(field_type);
        outPut << Il2cpp::GetCsTypeName(field_class) << " " << il2cpp_field_get_name(field);
        
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum)
        {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type_cs(Il2CppType *type)
{
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE)
    {
        outPut << "[Serializable]\n";
    }
    
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility)
    {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            outPut << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            outPut << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            outPut << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            outPut << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED)
    {
        outPut << "static ";
    }
    else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT)
    {
        outPut << "abstract ";
    }
    else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED)
    {
        outPut << "sealed ";
    }
    
    if (flags & TYPE_ATTRIBUTE_INTERFACE)
    {
        outPut << "interface ";
    }
    else if (is_enum)
    {
        outPut << "enum ";
    }
    else if (is_valuetype)
    {
        outPut << "struct ";
    }
    else
    {
        outPut << "class ";
    }
    
    outPut << Il2cpp::GetCsTypeName(klass);
    
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent)
    {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT)
        {
            extends.emplace_back(Il2cpp::GetCsTypeName(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter))
    {
        extends.emplace_back(Il2cpp::GetCsTypeName(itf));
    }
    
    if (!extends.empty())
    {
        outPut << " : " << extends[0];
        for (size_t i = 1; i < extends.size(); ++i)
        {
            outPut << ", " << extends[i];
        }
    }
    
    outPut << "\n{";
    outPut << dump_field_cs(klass);
    outPut << dump_property_cs(klass);
    outPut << dump_method_cs(klass);
    outPut << "\n}\n";
    return outPut.str();
}

// ============================================================================
// Package Name Helper
// ============================================================================

static std::string GetPackageName() {
    static char packageName[256] = {0};
    if (packageName[0] == 0) {
        FILE* fp = fopen("/proc/self/cmdline", "r");
        if (fp) {
            fread(packageName, sizeof(packageName) - 1, 1, fp);
            fclose(fp);
        }
    }
    return packageName;
}

// ============================================================================
// Il2cpp Namespace Implementation
// ============================================================================

namespace Il2cpp
{
    void Init()
    {
        auto handle = xdl_open(targetLibName, 0);
        init_il2cpp_api(handle);

        // Get base address
        void *sym = xdl_sym(handle, "il2cpp_domain_get", nullptr);
        if (sym) {
            Dl_info info;
            if (dladdr(sym, &info)) {
                il2cpp_base = (uint64_t)info.dli_fbase;
                LOGI("il2cpp_base: %p", (void*)il2cpp_base);
            }
        }

        xdl_close(handle);
        g_initialized = true;
    }

    bool EnsureAttached()
    {
        auto curr = il2cpp_thread_current();
        if (!curr)
        {
            LOGI("Foreign thread!");
        }
        else
        {
            LOGI("Already Attached -> %p", curr);
            return true;
        }
        LOGI("Attaching Thread");
        auto *thread = il2cpp_thread_attach(il2cpp_domain_get());
        while (!il2cpp_is_vm_thread(thread))
        {
            LOGI("Waiting...");
            sleep(1);
        }
        if (!thread)
        {
            LOGE("Attaching Failed");
            return false;
        }
        LOGI("Thread Attached");
        return true;
    }

    void Detach()
    {
        auto curr = il2cpp_thread_current();
        if (!curr)
        {
            LOGI("Foreign thread!");
            return;
        }
        LOGI("Detaching Thread");
        il2cpp_thread_detach(curr);
        LOGI("Thread Detached");
    }

    Il2CppDomain *GetDomain()
    {
        return il2cpp_domain_get();
    }

    Il2CppAssembly *GetAssembly(const char *name)
    {
        auto result = il2cpp_domain_assembly_open(il2cpp_domain_get(), name);
        if (!result && g_DoLog)
            LOGE("There's no assembly : %s", name);
        return result;
    }

    Il2CppImage *GetImage(Il2CppAssembly *assembly)
    {
        auto result = il2cpp_assembly_get_image(assembly);
        if (!result && g_DoLog)
            LOGE("GetImage return nullptr");
        return result;
    }

    Il2CppImage *GetCorlib()
    {
        return il2cpp_get_corlib();
    }

    Il2CppImage *GetImage(const char *assemblyName)
    {
        return GetImage(GetAssembly(assemblyName));
    }

    Il2CppClass *GetClass(Il2CppImage *image, const char *name)
    {
        std::string nameStr = name;
        size_t dotIndex = nameStr.find_last_of('.');
        std::string classNamespace = (dotIndex == std::string::npos) ? "" : nameStr.substr(0, dotIndex);
        const std::string className = nameStr.substr(dotIndex + 1);
        auto result = il2cpp_class_from_name(image, classNamespace.c_str(), className.c_str());
        if (!result)
        {
            auto size = il2cpp_image_get_class_count(image);
            for (size_t i{0}; i < size; i++)
            {
                auto klass = il2cpp_image_get_class(image, i);
                auto type = il2cpp_class_get_type(klass);
                const char* typeName = il2cpp_type_get_name(type);
                if (typeName && std::string(typeName).compare(name) == 0)
                {
                    result = klass;
                    break;
                }
            }
            if (!result && g_DoLog)
                LOGE("There's no class : %s", name);
        }
        return result;
    }

    MethodInfo *GetClassMethod(Il2CppClass *klass, const char *methodName, int argsCount)
    {
        auto result = il2cpp_class_get_method_from_name(klass, methodName, argsCount);
        if (!result && g_DoLog)
            LOGE("There's no method : %s in %s", methodName, il2cpp_class_get_name(klass));
        return result;
    }

    Il2CppImage *GetClassImage(Il2CppClass *klass)
    {
        return il2cpp_class_get_image(klass);
    }

    FieldInfo *GetClassField(Il2CppClass *klass, const char *fieldName)
    {
        auto result = il2cpp_class_get_field_from_name(klass, fieldName);
        if (!result && g_DoLog)
            LOGE("There's no field : %s", fieldName);
        return result;
    }

    void GetFieldValue(Il2CppObject *object, FieldInfo *field, void *outValue)
    {
        il2cpp_field_get_value(object, field, outValue);
    }

    void SetFieldValue(Il2CppObject *object, FieldInfo *field, void *newValue)
    {
        il2cpp_field_set_value(object, field, newValue);
    }

    FieldInfo *GetClassFields(Il2CppClass *klass, void **iter)
    {
        return il2cpp_class_get_fields(klass, iter);
    }

    void GetFieldStaticValue(FieldInfo *field, void *outValue)
    {
        il2cpp_field_static_get_value(field, outValue);
    }

    void SetFieldStaticValue(FieldInfo *field, void *outValue)
    {
        il2cpp_field_static_set_value(field, outValue);
    }

    Il2CppObject *GetFieldValueObject(Il2CppObject *object, FieldInfo *field)
    {
        return il2cpp_field_get_value_object(field, object);
    }

    void SetFieldValueObject(Il2CppObject *object, FieldInfo *field, Il2CppObject *newValue)
    {
        return il2cpp_field_set_value_object(object, field, newValue);
    }

    MethodInfo *GetClassMethods(Il2CppClass *klass, void **iter)
    {
        return il2cpp_class_get_methods(klass, iter);
    }

    int32_t GetClassSize(Il2CppClass *klass)
    {
        return il2cpp_class_instance_size(klass);
    }

    int32_t GetClassValueSize(Il2CppClass *klass)
    {
        return il2cpp_class_value_size(klass, NULL);
    }

    uint32_t GetObjectSize(Il2CppObject *object)
    {
        return il2cpp_object_get_size(object);
    }
    
    Il2CppObject *NewObject(Il2CppClass *klass)
    {
        return il2cpp_object_new(klass);
    }

    Il2CppClass *GetClassParent(Il2CppClass *klass)
    {
        return il2cpp_class_get_parent(klass);
    }

    Il2CppClass *GetObjectClass(Il2CppObject *object)
    {
        return il2cpp_object_get_class(object);
    }

    bool IsClassParentOf(Il2CppClass *klass, Il2CppClass *parent)
    {
        while (klass)
        {
            if (klass == parent)
                return true;
            klass = GetClassParent(klass);
        }
        return false;
    }

    uint32_t GetMethodParamCount(MethodInfo *method)
    {
        return il2cpp_method_get_param_count(method);
    }

    const char *GetMethodParamName(MethodInfo *method, uint32_t index)
    {
        return il2cpp_method_get_param_name(method, index);
    }

    std::vector<Il2CppClass *> GetClasses(Il2CppImage *image, const char *filter)
    {
        std::vector<Il2CppClass *> classes;
        auto size = il2cpp_image_get_class_count(image);
        for (size_t i{0}; i < size; i++)
        {
            auto klass = il2cpp_image_get_class(image, i);
            auto type = il2cpp_class_get_type(klass);
            const char* typeName = il2cpp_type_get_name(type);
            if (!filter || (typeName && strstr(typeName, filter)))
                classes.push_back(klass);
        }
        return classes;
    }

    const char *GetMethodName(MethodInfo *method)
    {
        return il2cpp_method_get_name(method);
    }

    const char *GetClassName(Il2CppClass *klass)
    {
        return il2cpp_class_get_name(klass);
    }

    const char *GetClassNamespace(Il2CppClass *klass)
    {
        return il2cpp_class_get_namespace(klass);
    }

    uintptr_t GetFieldOffset(FieldInfo *field)
    {
        return il2cpp_field_get_offset(field);
    }

    void forEachClass(Il2CppClass *klass, void *classesPtr)
    {
        auto classes = *(std::vector<Il2CppClass *> *)classesPtr;
        classes.push_back(klass);
    }

    std::vector<Il2CppClass *> GetClasses()
    {
        std::vector<Il2CppClass *> classes;
        il2cpp_class_for_each(forEachClass, &classes);
        return classes;
    }

    std::unordered_map<Il2CppClass *, std::tuple<Il2CppClass **, size_t>> subClassesCache;
    const std::tuple<Il2CppClass **, size_t> &GetSubClasses(Il2CppClass *klass)
    {
        auto it = subClassesCache.find(klass);
        if (it != subClassesCache.end())
        {
            return it->second;
        }
        std::vector<Il2CppClass *> subClasses{};
        void *iter = nullptr;
        while (auto subKlass = il2cpp_class_get_nested_types(klass, &iter))
        {
            subClasses.push_back(subKlass);
        }
        subClassesCache.insert(std::make_pair(klass, std::make_tuple(subClasses.data(), subClasses.size())));
        return subClassesCache.at(klass);
    }

    Il2CppType *GetClassType(Il2CppClass *klass)
    {
        return il2cpp_class_get_type(klass);
    }

    bool GetClassIsGeneric(Il2CppClass *klass)
    {
        return il2cpp_class_is_generic(klass);
    }

    Il2CppClass *FindClass(const char *klassName)
    {
        auto &images = GetImages();
        for (auto image : images)
        {
            auto klass = GetClass(image, klassName);
            if (klass)
                return klass;
        }
        return nullptr;
    }

    Il2CppClass *GetClassFromSystemType(Il2CppReflectionType *type)
    {
        return il2cpp_class_from_system_type(type);
    }

    Il2CppType *GetBaseType(Il2CppClass *klass)
    {
        return il2cpp_class_enum_basetype(klass);
    }

    bool GetClassIsValueType(Il2CppClass *klass)
    {
        return il2cpp_class_is_valuetype(klass);
    }

    bool GetClassIsEnum(Il2CppClass *klass)
    {
        return il2cpp_class_is_enum(klass);
    }

    bool GetClassIsStatic(Il2CppClass *klass)
    {
        auto flags = il2cpp_class_get_flags(klass);
        return flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED;
    }

    Il2CppType *GetMethodReturnType(MethodInfo *method)
    {
        return il2cpp_method_get_return_type(method);
    }

    Il2CppType *GetMethodParam(MethodInfo *method, uint32_t index)
    {
        return il2cpp_method_get_param(method, index);
    }

    bool GetIsMethodGeneric(MethodInfo *method)
    {
        return il2cpp_method_is_generic(method);
    }

    bool GetIsMethodInflated(MethodInfo *method)
    {
        return il2cpp_method_is_inflated(method);
    }

    bool GetIsMethodStatic(MethodInfo *method)
    {
        return !il2cpp_method_is_instance(method);
    }

    Il2CppReflectionMethod *GetMethodObject(MethodInfo *method, Il2CppClass *refclass)
    {
        return il2cpp_method_get_object(method, refclass);
    }

    MethodInfo *GetMethodFromReflection(Il2CppReflectionMethod *method)
    {
        return il2cpp_method_get_from_reflection(method);
    }

    uint32_t GetMethodGenericCount(MethodInfo *method)
    {
        auto obj = method->getObject();
        auto args = obj->invoke_method<Il2CppArray<Il2CppObject *> *>("GetGenericArguments");
        return args->length();
    }

    MethodInfo *FindMethod(const char *klassName, const char *methodName, size_t argsCount)
    {
        auto &images = GetImages();
        for (auto image : images)
        {
            auto klass = GetClass(image, klassName);
            if (klass)
            {
                return GetClassMethod(klass, methodName, argsCount);
            }
        }
        return nullptr;
    }

    Il2CppClass *GetMethodClass(MethodInfo *method)
    {
        return il2cpp_method_get_class(method);
    }

    Il2CppClass *GetClassFromType(Il2CppType *type)
    {
        return il2cpp_class_from_type(type);
    }

    Il2CppClass *GetTypeClass(Il2CppType *type)
    {
        return il2cpp_type_get_class_or_element_class(type);
    }

    bool GetTypeIsPointer(Il2CppType *type)
    {
        return il2cpp_type_is_pointer_type(type);
    }

    bool GetTypeIsStatic(Il2CppType *type)
    {
        return il2cpp_type_is_static(type);
    }

    Il2CppType *GetFieldType(FieldInfo *field)
    {
        return il2cpp_field_get_type(field);
    }

    const char *GetFieldName(FieldInfo *field)
    {
        return il2cpp_field_get_name(field);
    }

    int GetFieldFlags(FieldInfo *field)
    {
        return il2cpp_field_get_flags(field);
    }

    const char *GetTypeName(Il2CppType *type)
    {
        return il2cpp_type_get_name(type);
    }

    Il2CppObject *GetTypeObject(Il2CppType *type)
    {
        return il2cpp_type_get_object(type);
    }

    const char *GetChars(Il2CppString *str)
    {
        return reinterpret_cast<const char *>(il2cpp_string_chars(str));
    }

    Il2CppString *NewString(const char *str)
    {
        return il2cpp_string_new(str);
    }

    const char *GetImageName(Il2CppImage *image)
    {
        return il2cpp_image_get_name(image);
    }

    uint32_t GetArrayLength(_Il2CppArray *array)
    {
        return il2cpp_array_length(array);
    }

    _Il2CppArray *ArrayNew(Il2CppClass *elementTypeInfo, il2cpp_array_size_t length)
    {
        return il2cpp_array_new(elementTypeInfo, length);
    }

    Il2CppObject *GetBoxedValue(Il2CppClass *klass, void *value)
    {
        return il2cpp_value_box(klass, value);
    }

    void *GetUnboxedValue(Il2CppObject *object)
    {
        return il2cpp_object_unbox(object);
    }

    Il2CppObject *RuntimeInvoke(MethodInfo *method, void *obj, void **params, Il2CppException **exc)
    {
        return il2cpp_runtime_invoke(method, obj, params, exc);
    }

    Il2CppObject *RuntimeInvokeConvertArgs(MethodInfo *method, void *obj, Il2CppObject **params, int paramCount)
    {
        return il2cpp_runtime_invoke_convert_args(method, obj, params, paramCount, nullptr);
    }

    std::tuple<Il2CppAssembly **, size_t> assembliesCache{nullptr, 0};
    const std::tuple<Il2CppAssembly **, size_t> &GetAssemblies()
    {
        const auto &[ass, size2] = assembliesCache;
        if (size2 > 0)
        {
            return assembliesCache;
        }
        size_t size = 0;
        auto asss = il2cpp_domain_get_assemblies(GetDomain(), &size);
        assembliesCache = std::make_tuple(asss, size);
        return assembliesCache;
    }

    std::vector<Il2CppImage *> imagesCache;
    const std::vector<Il2CppImage *> &GetImages()
    {
        if (!imagesCache.empty())
            return imagesCache;
        const auto &[ass, size] = GetAssemblies();
        for (size_t i = 0; i < size; i++)
        {
            imagesCache.push_back(GetImage(ass[i]));
        }
        return imagesCache;
    }

    std::string GetDumpPath() {
        std::string packageName = GetPackageName();
        std::string archSuffix = (sizeof(void*) == 8) ? "_64bit" : "_32bit";
        std::string fileName = packageName + archSuffix + ".cs";
        return "/storage/emulated/0/Android/data/" + packageName + "/files/" + fileName;
    }

    bool IsDumperReady() {
        return g_initialized && il2cpp_image_get_class != nullptr;
    }

    std::string getUnityVersion()
    {
        static auto Application = FindClass("UnityEngine.Application");
        if (!Application) return "unknown_unity_version";
        static auto get_unityVersion = GetClassMethod(Application, "get_unityVersion", 0);
        if (!get_unityVersion) return "unknown_unity_version";
        
        auto unityVersion = (Il2CppString*)il2cpp_runtime_invoke(get_unityVersion, nullptr, nullptr, nullptr);
        if (unityVersion)
        {
            static auto str = unityVersion->to_string();
            return str;
        }
        else
        {
            LOGE("Failed to get unityVersion");
            return "unknown_unity_version";
        }
    }

    std::string getDataPath()
    {
        static auto Application = FindClass("UnityEngine.Application");
        if (!Application) return "unknown_data_path";
        static auto get_persistentDataPath = GetClassMethod(Application, "get_persistentDataPath", 0);
        if (!get_persistentDataPath) return "unknown_data_path";
        
        auto dataPath = (Il2CppString*)il2cpp_runtime_invoke(get_persistentDataPath, nullptr, nullptr, nullptr);
        if (dataPath)
        {
            static auto str = dataPath->to_string();
            return str;
        }
        else
        {
            LOGE("Failed to get dataPath");
            return "unknown_data_path";
        }
    }

    std::string getPackageName()
    {
        static auto Application = FindClass("UnityEngine.Application");
        if (!Application) return "unknown_package_name";
        static auto get_identifier = GetClassMethod(Application, "get_identifier", 0);
        if (!get_identifier) return "unknown_package_name";
        
        auto identifier = (Il2CppString*)il2cpp_runtime_invoke(get_identifier, nullptr, nullptr, nullptr);
        if (identifier)
        {
            static auto str = identifier->to_string();
            return str;
        }
        else
        {
            LOGE("Failed to get packageName");
            return "unknown_package_name";
        }
    }

    std::string getGameVersion()
    {
        static auto Application = FindClass("UnityEngine.Application");
        if (!Application) return "unknown_game_version";
        static auto get_version = GetClassMethod(Application, "get_version", 0);
        if (!get_version) return "unknown_game_version";
        
        auto version = (Il2CppString*)il2cpp_runtime_invoke(get_version, nullptr, nullptr, nullptr);
        if (version)
        {
            static auto str = version->to_string();
            return str;
        }
        else
        {
            LOGE("Failed to get game version");
            return "unknown_game_version";
        }
    }

    bool Dump(ProgressCallback callback) {
        if (!g_initialized) {
            LOGE("Il2Cpp not initialized");
            return false;
        }

        if (!il2cpp_domain_get || !il2cpp_domain_get_assemblies) {
            LOGE("Required IL2CPP functions not available");
            return false;
        }

        Dl_info dlInfo;
        if (dladdr((void*)il2cpp_domain_get, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        }

        auto domain = il2cpp_domain_get();
        if (!domain) {
            LOGE("Failed to get IL2CPP domain");
            return false;
        }

        if (il2cpp_thread_attach) {
            il2cpp_thread_attach(domain);
        }

        size_t size = 0;
        auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
        if (!assemblies || size == 0) {
            LOGE("No assemblies found");
            return false;
        }

        std::string outputPath = GetDumpPath();
        
        std::stringstream headerOutput;
        headerOutput << "// IL2CPP Dumped\n";
        headerOutput << "// Package: " << GetPackageName() << "\n";
        headerOutput << "// Date: " << __DATE__ << " " << __TIME__ << "\n\n";

        std::stringstream imageOutput;
        for (size_t i = 0; i < size; ++i) {
            Il2CppImage* image = il2cpp_assembly_get_image(assemblies[i]);
            imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
        }

        std::vector<std::string> outputs;
        int totalClasses = 0;
        
        if (il2cpp_image_get_class) {
            for (size_t i = 0; i < size; ++i) {
                Il2CppImage* image = il2cpp_assembly_get_image(assemblies[i]);
                totalClasses += il2cpp_image_get_class_count(image);
            }
        }

        int processedClasses = 0;
        
        if (il2cpp_image_get_class) {
            for (size_t i = 0; i < size; ++i) {
                Il2CppImage* image = il2cpp_assembly_get_image(assemblies[i]);
                std::string imageName = il2cpp_image_get_name(image);
                
                if (callback) {
                    DumpProgress progress;
                    progress.currentAssembly = imageName;
                    progress.totalAssemblies = size;
                    progress.currentAssemblyIndex = i;
                    progress.totalClasses = totalClasses;
                    progress.currentClassIndex = processedClasses;
                    progress.progress = totalClasses > 0 ? (float)processedClasses / (float)totalClasses : 0.0f;
                    callback(progress);
                }
                
                uint32_t classCount = il2cpp_image_get_class_count(image);
                for (uint32_t j = 0; j < classCount; ++j) {
                    Il2CppClass* klass = il2cpp_image_get_class(image, j);
                    const Il2CppType* type = (const Il2CppType*)il2cpp_class_get_type((Il2CppClass*)klass);
                    std::string out = dump_type_cs((Il2CppType*)type);
                    outputs.push_back(out);
                    processedClasses++;
                }
            }
        }

        std::ofstream outStream(outputPath);
        if (!outStream.is_open()) {
            LOGE("Failed to open output file: %s", outputPath.c_str());
            return false;
        }

        outStream << headerOutput.str();
        outStream << imageOutput.str();
        
        auto count = outputs.size();
        for (size_t i = 0; i < count; ++i) {
            outStream << outputs[i];
        }
        
        outStream.close();
        
        if (callback) {
            DumpProgress progress;
            progress.progress = 1.0f;
            progress.currentClassIndex = totalClasses;
            progress.totalClasses = totalClasses;
            callback(progress);
        }
        
        LOGI("Dump completed: %s", outputPath.c_str());
        return true;
    }

    bool Dump(const std::string& outputPath, ProgressCallback callback) {
        if (!g_initialized) {
            LOGE("Il2Cpp not initialized");
            return false;
        }

        if (!il2cpp_domain_get || !il2cpp_domain_get_assemblies) {
            LOGE("Required IL2CPP functions not available");
            return false;
        }

        Dl_info dlInfo;
        if (dladdr((void*)il2cpp_domain_get, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        }

        auto domain = il2cpp_domain_get();
        if (!domain) {
            LOGE("Failed to get IL2CPP domain");
            return false;
        }

        if (il2cpp_thread_attach) {
            il2cpp_thread_attach(domain);
        }

        size_t size = 0;
        auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
        if (!assemblies || size == 0) {
            LOGE("No assemblies found");
            return false;
        }

        std::stringstream headerOutput;
        headerOutput << "// IL2CPP Dumper\n";
        headerOutput << "// Package: " << GetPackageName() << "\n";
        headerOutput << "// Date: " << __DATE__ << " " << __TIME__ << "\n\n";

        std::stringstream imageOutput;
        for (size_t i = 0; i < size; ++i) {
            Il2CppImage* image = il2cpp_assembly_get_image(assemblies[i]);
            imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
        }

        std::vector<std::string> outputs;
        int totalClasses = 0;
        
        if (il2cpp_image_get_class) {
            for (size_t i = 0; i < size; ++i) {
                Il2CppImage* image = il2cpp_assembly_get_image(assemblies[i]);
                totalClasses += il2cpp_image_get_class_count(image);
            }
        }

        int processedClasses = 0;
        
        if (il2cpp_image_get_class) {
            for (size_t i = 0; i < size; ++i) {
                Il2CppImage* image = il2cpp_assembly_get_image(assemblies[i]);
                std::string imageName = il2cpp_image_get_name(image);
                
                if (callback) {
                    DumpProgress progress;
                    progress.currentAssembly = imageName;
                    progress.totalAssemblies = size;
                    progress.currentAssemblyIndex = i;
                    progress.totalClasses = totalClasses;
                    progress.currentClassIndex = processedClasses;
                    progress.progress = totalClasses > 0 ? (float)processedClasses / (float)totalClasses : 0.0f;
                    callback(progress);
                }
                
                uint32_t classCount = il2cpp_image_get_class_count(image);
                for (uint32_t j = 0; j < classCount; ++j) {
                    Il2CppClass* klass = il2cpp_image_get_class(image, j);
                    const Il2CppType* type = (const Il2CppType*)il2cpp_class_get_type((Il2CppClass*)klass);
                    std::string out = dump_type_cs((Il2CppType*)type);
                    outputs.push_back(out);
                    processedClasses++;
                }
            }
        }

        std::ofstream outStream(outputPath);
        if (!outStream.is_open()) {
            LOGE("Failed to open output file: %s", outputPath.c_str());
            return false;
        }

        outStream << headerOutput.str();
        outStream << imageOutput.str();
        
        auto count = outputs.size();
        for (size_t i = 0; i < count; ++i) {
            outStream << outputs[i];
        }
        
        outStream.close();
        
        if (callback) {
            DumpProgress progress;
            progress.progress = 1.0f;
            progress.currentClassIndex = totalClasses;
            progress.totalClasses = totalClasses;
            callback(progress);
        }
        
        LOGI("Dump completed: %s", outputPath.c_str());
        return true;
    }

    namespace GC
    {
        std::vector<Il2CppObject *> FindObjects(Il2CppClass *klass)
        {
            LOGD("Searching objects for %s", il2cpp_class_get_name(klass));

            std::vector<Il2CppObject *> objects;
            auto callback = [](Il2CppObject **arr, int size, void *userdata)
            {
                auto objects = reinterpret_cast<std::vector<Il2CppObject *> *>(userdata);
                objects->insert(objects->end(), arr, arr + size);
            };

            auto realloc = [](void *ptr, size_t size, void *userdata) -> void *
            {
                if (ptr != nullptr && size == 0)
                {
                    il2cpp_free(ptr);
                    return nullptr;
                }
                else
                {
                    return il2cpp_alloc(size);
                }
            };

            il2cpp_stop_gc_world();
            auto state = il2cpp_unity_liveness_allocate_struct(klass, 0, callback, &objects, realloc);
            il2cpp_unity_liveness_calculation_from_statics(state);
            il2cpp_unity_liveness_finalize(state);
            il2cpp_start_gc_world();
            il2cpp_unity_liveness_free_struct(state);

            LOGD("Found %lu objects", objects.size());
            return objects;
        }

        void KeepAlive(Il2CppObject *object)
        {
            static auto SystemGC = FindClass("System.GC");
            if (SystemGC) {
                auto keepAlive = GetClassMethod(SystemGC, "KeepAlive", 1);
                if (keepAlive) {
                    void* params[] = { object };
                    il2cpp_runtime_invoke(keepAlive, nullptr, params, nullptr);
                }
            }
        }
    } // namespace GC

} // namespace Il2cpp
