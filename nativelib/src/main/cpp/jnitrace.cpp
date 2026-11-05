//
// Created by zgy on 2025/10/30.
//

#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include "jnitrace.h"
#include "HookUtils.h"
#include "TraceUtils.h"
#include "logger.h"

const JNINativeInterface* pJFunc = nullptr;
 JNIEnv * jniEnv = nullptr;
JNITraceMap* _g_jni_trace = nullptr;
static bool debug = false;
/* 是否允许在QBDI回调里通过JNI反射解析 obj 类名 / method 名称。
 * 某些加固/自定义VM上JNIEnv不可靠时可关掉，保证trace稳定 */
static bool jniResolveEnabled = true;

void enable_jni_resolve(bool enable)
{
    jniResolveEnabled = enable;
}

/*
 * 查询地址所在内存映射是否具备某个权限位。
 * perms 形如 "r-xp"：index0=r, index1=w, index2=x。
 * dlsym / ELF符号解析在某些机型上可能返回非可执行地址，直接调用会 access violation，
 * 调用前必须先校验，否则会把整个进程带崩。
 */
static bool isAddrWithPerm(size_t addr, int permIndex)
{
    if (addr == 0)
    {
        return false;
    }
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr)
    {
        LOGE("isAddrWithPerm: open maps fail");
        return false;
    }
    bool ok = false;
    char *line = nullptr;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1)
    {
        size_t start = 0;
        size_t end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3 &&
            addr >= start && addr < end)
        {
            ok = (perms[permIndex] != '-');
            break;
        }
    }
    free(line);
    fclose(fp);
    return ok;
}

/* 地址是否可执行 */
static bool isAddrExecutable(size_t addr)
{
    return isAddrWithPerm(addr, 2);
}

/* 地址是否可读（用于校验传入的 JNIEnv* 是否像合法指针） */
static bool isAddrReadable(size_t addr)
{
    return isAddrWithPerm(addr, 0);
}

static void* resolveJniGetCreatedJavaVMs()
{
    //1.全局符号表（部分系统/机型上libart不在全局符号表里，dlsym会返回NULL）
    void* sym = dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    if (sym != nullptr)
    {
        LOGE("JNI_GetCreatedJavaVMs from RTLD_DEFAULT:%p", sym);
        return sym;
    }
    //2.通过libart.so句柄查找
    void* handle = dlopen("libart.so", RTLD_NOW);
    if (handle != nullptr)
    {
        sym = dlsym(handle, "JNI_GetCreatedJavaVMs");
        dlclose(handle);
        if (sym != nullptr)
        {
            LOGE("JNI_GetCreatedJavaVMs from libart.so:%p", sym);
            return sym;
        }
    }
    //3.直接解析libart.so的ELF动态符号表
    size_t addr = findSymbolInLibArt("libart.so", "JNI_GetCreatedJavaVMs");
    if (addr != 0 && addr != (size_t)-1)
    {
        LOGE("JNI_GetCreatedJavaVMs from libart elf:%p", (void*)addr);
        return (void*)addr;
    }
    return nullptr;
}

void initJni()
{
    if(pJFunc != nullptr)
    {
        LOGE("jni env already set, skip initJni");
        return;
    }
    LOGE("Find Jni");
    typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
    auto getCreatedVMs = (JNI_GetCreatedJavaVMs_t)resolveJniGetCreatedJavaVMs();
    JavaVM* jvm = nullptr;
    jsize count = 0;
    if(getCreatedVMs == nullptr)
    {
        LOGE("无法获取 JNI_GetCreatedJavaVMs 符号地址");
        return;
    }

    if(!isAddrExecutable((size_t)getCreatedVMs))
    {
        LOGE("JNI_GetCreatedJavaVMs(%p) 不在可执行段, 跳过jni trace", (void*)getCreatedVMs);
        return;
    }
    jint result = getCreatedVMs(&jvm, 1, &count);

    if (result != JNI_OK || count == 0) {
        LOGE("无法获取 JavaVM 实例");
        return ;
    } else{
        LOGE("get JavaVM success");
    }

    JNIEnv* env = nullptr;
    result = jvm->AttachCurrentThread((JNIEnv **) &env, nullptr);

    if (result != JNI_OK || !env) {
        LOGE("无法获取 JNIEnv 实例");
        return ;
    }
    jint jniVersion = env->GetVersion();
    LOGE("get JNIEnv success:%x",jniVersion);
    setup_jfunc(env);
}

/*
 * 由外部(frida)直接传入JNIEnv，避开dlsym/ELF解析拿到无效地址的问题。
 * frida侧: lingyi_vm_set_jnienv(Java.vm.getEnv().handle)
 */
int setup_jni_env(void* env)
{
    if(env == nullptr)
    {
        LOGE("setup_jni_env: env is null");
        return -1;
    }
    //校验传入的确实是JNIEnv*：env可读，且其函数表里的已知函数位于可执行段
    if(!isAddrReadable((size_t)env))
    {
        LOGE("setup_jni_env: %p 不在可读内存, 请传JNIEnv*而不是函数地址", env);
        return -1;
    }
    JNIEnv* jni = (JNIEnv*)env;
    const JNINativeInterface* funcs = jni->functions;
    if(funcs == nullptr ||
       !isAddrReadable((size_t)funcs) ||
       !isAddrExecutable((size_t)funcs->GetVersion) ||
       !isAddrExecutable((size_t)funcs->NewStringUTF))
    {
        LOGE("setup_jni_env: %p 不是合法的JNIEnv(函数表无效), 请传 Java.vm.getEnv().handle", env);
        return -1;
    }
    setup_jfunc(jni);
    LOGE("setup_jni_env from caller:%p", env);
    return 0;
}

void enable_jni_trace_debug(bool enable)
{
    debug = enable;
}

bool is_jni_trace_enabled()
{
    return debug;
}

static bool checkSetup()
{
    if(pJFunc == nullptr)
    {
        LOGE("checkJniCall,pJFunc not init");
        return false;
    }
    if(_logger == nullptr)
    {
        LOGE("checkJniCall,_logger not init");
        return false;
    }
    return true;
}

/* 安全读取C字符串，成功返回true */
static bool readCString(uint64_t addr, char* out, size_t size)
{
    if (addr == 0 || size < 2)
    {
        return false;
    }
    for (size_t i = 0; i + 1 < size; ++i)
    {
        uint8_t ch = 0;
        if (!safeReadMemory(addr + i, &ch, 1))
        {
            out[i] = 0;
            return false;
        }
        out[i] = (char)ch;
        if (ch == 0)
        {
            return true;
        }
    }
    out[size - 1] = 0;
    return true;
}

/* 追加字符串参数: "xxx"，读不到时输出原始地址 */
static void appendStringArg(uint64_t addr)
{
    char s[256] = {0};
    if (readCString(addr, s, sizeof(s)))
    {
        appendformat("\"%s\"", s);
    }
    else
    {
        appendformat("0x%lx", addr);
    }
}

/* 把[addr,addr+len)按hexdump写入日志，最多输出maxLen字节 */
static void appendHexdump(uint64_t addr, uint64_t len, uint64_t maxLen)
{
    if (addr == 0 || len == 0)
    {
        appendlog("   <null>\n");
        return;
    }
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    uint64_t n = len < maxLen ? len : maxLen;
    if (n > sizeof(buf))
    {
        n = sizeof(buf);
    }
    if (!safeReadMemory(addr, buf, n))
    {
        appendformat("   <read 0x%lx failed>\n", addr);
        return;
    }
    for (uint64_t off = 0; off < n; off += 16)
    {
        char line[160];
        int l = snprintf(line, sizeof(line), "   0x%lx:", addr + off);
        char ascii[17] = {0};
        for (uint64_t i = 0; i < 16 && off + i < n; ++i)
        {
            uint8_t b = buf[off + i];
            l += snprintf(line + l, sizeof(line) - l, " %02x", b);
            ascii[i] = (b >= 0x20 && b <= 0x7e) ? (char)b : '.';
        }
        appendlog_n(line, l);
        appendformat("  |%s|\n", ascii);
    }
    if (len > n)
    {
        appendformat("   ... (len=0x%lx)\n", len);
    }
}

/*
 * 当前被trace的JNI调用自己的JNIEnv(x0)。
 * JNI局部引用/jmethodID与线程和env绑定，解析时必须用调用现场的env，
 * 不能用初始化阶段保存的其它线程env，否则ART会解出非法引用并崩溃。
 */
static JNIEnv* currentCallEnv()
{
    uint64_t env = (uint64_t)g_deferred_call_env;
    if (env == 0)
    {
        return nullptr;
    }
    //同一线程的env会复用，做个轻量校验+缓存，防止异常env把解析流程带崩
    static thread_local uint64_t lastEnv = 0;
    static thread_local bool lastEnvOk = false;
    if (env == lastEnv)
    {
        return lastEnvOk ? (JNIEnv*)env : nullptr;
    }
    lastEnv = env;
    uint64_t functions = 0;
    lastEnvOk = safeReadMemory(env, (uint8_t*)&functions, sizeof(functions)) &&
                isValidAddress(functions);
    if (!lastEnvOk)
    {
        LOGE("jnitrace: invalid JNIEnv 0x%lx, skip jni resolve", env);
    }
    return lastEnvOk ? (JNIEnv*)env : nullptr;
}

/* 清除回调内自己触发的JNI异常，避免影响目标代码 */
static void clearPendingException()
{
    if (pJFunc != nullptr && currentCallEnv() != nullptr && pJFunc->ExceptionCheck(currentCallEnv()))
    {
        pJFunc->ExceptionClear(currentCallEnv());
    }
}

/*
 * 通过JNI反射解析jobject/jclass对应的java类名，例如：
 *   obj            -> java.lang.String
 *   jclass(String) -> java.lang.String
 * 解析失败(非指针/非法引用)时返回false，不输出类名。
 */
static bool resolveJavaClassName(uint64_t ref, char* out, size_t size)
{
    if (out == nullptr || size == 0)
    {
        return false;
    }
    out[0] = 0;
    if (!jniResolveEnabled)
    {
        return false;
    }
    //防止target模块就是libart时，解析过程被自己的回调再次捕获导致递归
    static thread_local bool resolving = false;
    if (resolving)
    {
        return false;
    }
    struct ResolveGuard {
        bool& flag;
        explicit ResolveGuard(bool& f) : flag(f) { flag = true; }
        ~ResolveGuard() { flag = false; }
    } guard(resolving);
    if (ref < 0x1000 || currentCallEnv() == nullptr || pJFunc == nullptr)
    {
        return false;
    }
    //目标代码可能正处于异常状态，此时调用JNI会破坏原有异常，直接跳过解析
    if (pJFunc->ExceptionCheck(currentCallEnv()))
    {
        return false;
    }
    //jobject可能是带tag的指针，也可能只是编码后的index，先验证地址可读
    uint8_t probe = 0;
    if (!safeReadMemory(ref & ~(uint64_t)7, &probe, sizeof(probe)))
    {
        return false;
    }
    static jmethodID getNameMethod = nullptr;
    jclass clazz = (jclass)pJFunc->GetObjectClass(currentCallEnv(), (jobject)ref);
    if (clazz == nullptr)
    {
        clearPendingException();
        return false;
    }
    if (getNameMethod == nullptr)
    {
        getNameMethod = pJFunc->GetMethodID(currentCallEnv(), clazz, "getName", "()Ljava/lang/String;");
    }
    if (getNameMethod == nullptr)
    {
        pJFunc->DeleteLocalRef(currentCallEnv(), clazz);
        clearPendingException();
        return false;
    }
    jstring jname = (jstring)pJFunc->CallObjectMethod(currentCallEnv(), clazz, getNameMethod);
    bool ok = false;
    if (jname != nullptr)
    {
        const char* utf = pJFunc->GetStringUTFChars(currentCallEnv(), jname, nullptr);
        if (utf != nullptr)
        {
            snprintf(out, size, "%s", utf);
            pJFunc->ReleaseStringUTFChars(currentCallEnv(), jname, utf);
            ok = true;
        }
        pJFunc->DeleteLocalRef(currentCallEnv(), jname);
    }
    pJFunc->DeleteLocalRef(currentCallEnv(), clazz);
    if (!ok)
    {
        clearPendingException();
    }
    return ok;
}

/* 输出一行 "obj = java.lang.String" / "clazz = com.xxx.A"，解析失败也给出标记 */
static void appendJavaClassLine(const char* label, uint64_t ref)
{
    if (ref == 0)
    {
        appendformat("      %s = <null>\n", label);
        return;
    }
    char cls[256] = {0};
    if (resolveJavaClassName(ref, cls, sizeof(cls)))
    {
        appendformat("      %s = %s\n", label, cls);
    }
    else
    {
        appendformat("      %s = <unknown>\n", label);
    }
}

/* ---------------- methodID / fieldID -> 名称 ---------------- */

static std::unordered_map<uint64_t, std::string> g_method_names;   // methodID  -> 方法名
static std::unordered_map<uint64_t, std::string> g_field_names;    // fieldID   -> 字段名
static std::unordered_map<uint64_t, bool> g_method_name_failed;    // 反查失败的方法，避免重复扫描
static int g_method_reflect_budget = 128;                          // 反射反查预算(每个methodID只扫一次)

/* 安全读取C字符串到缓冲区，读不到/没有终止符时返回false */
static bool readCStringSafe(uint64_t addr, char* out, size_t size)
{
    if (addr == 0 || out == nullptr || size < 2)
    {
        return false;
    }
    size_t chunkList[] = {size - 1, 33, 17};
    for (size_t c = 0; c < sizeof(chunkList) / sizeof(chunkList[0]); ++c)
    {
        size_t len = chunkList[c];
        if (len >= size)
        {
            len = size - 1;
        }
        if (len == 0)
        {
            continue;
        }
        memset(out, 0, size);
        if (safeReadMemory(addr, (uint8_t*)out, len) && memchr(out, 0, len) != nullptr)
        {
            return out[0] != 0;
        }
    }
    return false;
}

/* GetMethodID/GetStaticMethodID 调用时直接把 id->name 记下来，后续 Call*Method 零成本命中 */
static void cacheMethodName(uint64_t methodId, uint64_t namePtr)
{
    if (methodId == 0)
    {
        return;
    }
    char name[128] = {0};
    if (readCStringSafe(namePtr, name, sizeof(name)))
    {
        g_method_names[methodId] = name;
    }
}

static void cacheFieldName(uint64_t fieldId, uint64_t namePtr)
{
    if (fieldId == 0)
    {
        return;
    }
    char name[128] = {0};
    if (readCStringSafe(namePtr, name, sizeof(name)))
    {
        g_field_names[fieldId] = name;
    }
}

/* 只查缓存 */
static bool lookupMethodName(uint64_t methodId, char* out, size_t size)
{
    auto it = g_method_names.find(methodId);
    if (it == g_method_names.end() || it->second.empty())
    {
        return false;
    }
    snprintf(out, size, "%s", it->second.c_str());
    return true;
}

/* 在 Method[] 里按 FromReflectedMethod 的返回值找目标 methodID */
static bool scanMethodArray(jobjectArray methods, uint64_t methodId, char* out, size_t size)
{
    if (methods == nullptr)
    {
        return false;
    }
    jsize count = pJFunc->GetArrayLength(currentCallEnv(), methods);
    if (count > 4096)
    {
        count = 4096;
    }
    static jmethodID methodGetName = nullptr;
    for (jsize i = 0; i < count; ++i)
    {
        jobject method = pJFunc->GetObjectArrayElement(currentCallEnv(), methods, i);
        if (method == nullptr)
        {
            continue;
        }
        jmethodID id = pJFunc->FromReflectedMethod(currentCallEnv(), method);
        if (id == (jmethodID)methodId)
        {
            jclass methodClass = pJFunc->GetObjectClass(currentCallEnv(), method);
            if (methodClass != nullptr)
            {
                if (methodGetName == nullptr)
                {
                    methodGetName = pJFunc->GetMethodID(currentCallEnv(), methodClass, "getName",
                                                       "()Ljava/lang/String;");
                }
                if (methodGetName != nullptr)
                {
                    jstring jname = (jstring)pJFunc->CallObjectMethod(currentCallEnv(), methodClass, methodGetName);
                    if (jname != nullptr)
                    {
                        const char* utf = pJFunc->GetStringUTFChars(currentCallEnv(), jname, nullptr);
                        if (utf != nullptr)
                        {
                            snprintf(out, size, "%s", utf);
                            pJFunc->ReleaseStringUTFChars(currentCallEnv(), jname, utf);
                            pJFunc->DeleteLocalRef(currentCallEnv(), jname);
                            pJFunc->DeleteLocalRef(currentCallEnv(), methodClass);
                            pJFunc->DeleteLocalRef(currentCallEnv(), method);
                            return out[0] != 0;
                        }
                        pJFunc->DeleteLocalRef(currentCallEnv(), jname);
                    }
                }
                pJFunc->DeleteLocalRef(currentCallEnv(), methodClass);
            }
        }
        pJFunc->DeleteLocalRef(currentCallEnv(), method);
    }
    return false;
}

/*
 * 解析 jmethodID 对应的方法名。
 * targetIsClass=true 时 target 直接当作 jclass(静态调用/已拿到jclass)，
 * 否则把 target 当 jobject 用 GetObjectClass 取类。
 * 先查缓存(GetMethodID时已记录)，未命中再用 Class 反射反查。
 */
static bool resolveMethodName(uint64_t methodId, uint64_t target, bool targetIsClass,
                              char* out, size_t size)
{
    if (out == nullptr || size == 0)
    {
        return false;
    }
    out[0] = 0;
    if (methodId == 0 || currentCallEnv() == nullptr || pJFunc == nullptr)
    {
        return false;
    }
    if (lookupMethodName(methodId, out, size))
    {
        return true;
    }
    //方法名缓存不需要JNI，反射反查才需要，关闭解析时直接返回
    if (!jniResolveEnabled)
    {
        return false;
    }
    if (g_method_name_failed.find(methodId) != g_method_name_failed.end())
    {
        return false;
    }
    if (g_method_reflect_budget <= 0)
    {
        return false;
    }
    //反射本身会调用JNI，避免被自己的回调再次捕获导致递归
    static thread_local bool resolving = false;
    if (resolving)
    {
        return false;
    }
    struct ResolveGuard {
        bool& flag;
        explicit ResolveGuard(bool& f) : flag(f) { flag = true; }
        ~ResolveGuard() { flag = false; }
    } guard(resolving);
    if (pJFunc->ExceptionCheck(currentCallEnv()))
    {
        return false;
    }
    --g_method_reflect_budget;

    jclass clazz = targetIsClass ? (jclass)target
                                 : (jclass)pJFunc->GetObjectClass(currentCallEnv(), (jobject)target);
    bool ok = false;
    if (clazz != nullptr)
    {
        //getDeclaredMethods/getMethods 是 java.lang.Class 的方法，必须从 Class 类上取 methodID
        static jclass classClass = nullptr;
        static jmethodID getDeclaredMethods = nullptr;
        static jmethodID getMethods = nullptr;
        if (classClass == nullptr)
        {
            jclass localClass = pJFunc->FindClass(currentCallEnv(), "java/lang/Class");
            if (localClass != nullptr)
            {
                classClass = (jclass)pJFunc->NewGlobalRef(currentCallEnv(), localClass);
                pJFunc->DeleteLocalRef(currentCallEnv(), localClass);
            }
        }
        if (classClass != nullptr)
        {
            if (getDeclaredMethods == nullptr)
            {
                getDeclaredMethods = pJFunc->GetMethodID(currentCallEnv(), classClass, "getDeclaredMethods",
                                                         "()[Ljava/lang/reflect/Method;");
            }
            if (getMethods == nullptr)
            {
                getMethods = pJFunc->GetMethodID(currentCallEnv(), classClass, "getMethods",
                                                 "()[Ljava/lang/reflect/Method;");
            }
        }
        if (getDeclaredMethods != nullptr)
        {
            jobjectArray arr = (jobjectArray)pJFunc->CallObjectMethod(currentCallEnv(), clazz, getDeclaredMethods);
            ok = scanMethodArray(arr, methodId, out, size);
            if (arr != nullptr)
            {
                pJFunc->DeleteLocalRef(currentCallEnv(), arr);
            }
        }
        if (!ok && getMethods != nullptr)
        {
            jobjectArray arr = (jobjectArray)pJFunc->CallObjectMethod(currentCallEnv(), clazz, getMethods);
            ok = scanMethodArray(arr, methodId, out, size);
            if (arr != nullptr)
            {
                pJFunc->DeleteLocalRef(currentCallEnv(), arr);
            }
        }
        if (!targetIsClass)
        {
            pJFunc->DeleteLocalRef(currentCallEnv(), clazz);
        }
    }
    if (ok)
    {
        g_method_names[methodId] = out;
    }
    else
    {
        g_method_name_failed[methodId] = true;
        clearPendingException();
    }
    return ok;
}

/* 输出 "method = toString"，解析不到时输出 <unknown> */
static void appendMethodLine(uint64_t methodId, uint64_t target, bool targetIsClass)
{
    char name[128] = {0};
    if (resolveMethodName(methodId, target, targetIsClass, name, sizeof(name)))
    {
        appendformat("      method = %s\n", name);
    }
    else
    {
        appendlog("      method = <unknown>\n");
    }
}

/* 输出 "field = mField"，来自 GetFieldID 时记录的缓存 */
static void appendFieldLine(uint64_t fieldId)
{
    auto it = g_field_names.find(fieldId);
    if (it != g_field_names.end() && !it->second.empty())
    {
        appendformat("      field = %s\n", it->second.c_str());
    }
    else
    {
        appendlog("      field = <unknown>\n");
    }
}

/* Call*Method 系列: 由函数名生成标准JNI原型 */
static bool buildCallMethodPrototype(const char* name, char* out, size_t size)
{
    const char* p = name;
    bool isStatic = (strncmp(p, "CallStatic", 10) == 0);
    bool isNonvirtual = (strncmp(p, "CallNonvirtual", 14) == 0);
    p += isStatic ? 10 : (isNonvirtual ? 14 : 4);
    const char* methodPos = strstr(p, "Method");
    if (methodPos == nullptr)
    {
        return false;
    }
    size_t typeLen = (size_t)(methodPos - p);
    if (typeLen == 0 || typeLen >= 16)
    {
        return false;
    }
    char type[16] = {0};
    memcpy(type, p, typeLen);
    bool isV = (strcmp(methodPos, "MethodV") == 0);

    const char* retType = nullptr;
    if (strcmp(type, "Object") == 0)       retType = "jobject";
    else if (strcmp(type, "Boolean") == 0) retType = "jboolean";
    else if (strcmp(type, "Byte") == 0)    retType = "jbyte";
    else if (strcmp(type, "Char") == 0)    retType = "jchar";
    else if (strcmp(type, "Short") == 0)   retType = "jshort";
    else if (strcmp(type, "Int") == 0)     retType = "jint";
    else if (strcmp(type, "Long") == 0)    retType = "jlong";
    else if (strcmp(type, "Float") == 0)   retType = "jfloat";
    else if (strcmp(type, "Double") == 0)  retType = "jdouble";
    else if (strcmp(type, "Void") == 0)    retType = "void";
    else return false;

    snprintf(out, size, "%s %s(JNIEnv *env, %s, jmethodID methodID, %s);",
             retType, name,
             isStatic ? "jclass clazz" : (isNonvirtual ? "jobject obj, jclass clazz" : "jobject obj"),
             isV ? "va_list args" : "...");
    return true;
}

/* Get/Set<Type>Field 系列: 由函数名生成标准JNI原型 */
static bool buildFieldPrototype(const char* name, char* out, size_t size)
{
    bool isSet = (strncmp(name, "Set", 3) == 0);
    const char* p = name + 3;
    bool isStatic = (strncmp(p, "Static", 6) == 0);
    if (isStatic)
    {
        p += 6;
    }
    const char* fieldPos = strstr(p, "Field");
    if (fieldPos == nullptr)
    {
        return false;
    }
    size_t typeLen = (size_t)(fieldPos - p);
    if (typeLen == 0 || typeLen >= 16)
    {
        return false;
    }
    char type[16] = {0};
    memcpy(type, p, typeLen);

    const char* jniType = nullptr;
    if (strcmp(type, "Object") == 0)       jniType = "jobject";
    else if (strcmp(type, "Boolean") == 0) jniType = "jboolean";
    else if (strcmp(type, "Byte") == 0)    jniType = "jbyte";
    else if (strcmp(type, "Char") == 0)    jniType = "jchar";
    else if (strcmp(type, "Short") == 0)   jniType = "jshort";
    else if (strcmp(type, "Int") == 0)     jniType = "jint";
    else if (strcmp(type, "Long") == 0)    jniType = "jlong";
    else if (strcmp(type, "Float") == 0)   jniType = "jfloat";
    else if (strcmp(type, "Double") == 0)  jniType = "jdouble";
    else return false;

    if (isSet)
    {
        snprintf(out, size, "void %s(JNIEnv *env, %s %s, jfieldID fieldID, %s value);",
                 name, isStatic ? "jclass" : "jobject",
                 isStatic ? "clazz" : "obj", jniType);
    }
    else
    {
        snprintf(out, size, "%s %s(JNIEnv *env, %s %s, jfieldID fieldID);",
                 jniType, name, isStatic ? "jclass" : "jobject",
                 isStatic ? "clazz" : "obj");
    }
    return true;
}

/* New*Array / Get|Set*ArrayRegion / Get|Release*ArrayElements 系列原型 */
static bool buildArrayPrototype(const char* name, char* out, size_t size)
{
    bool isNew = (strncmp(name, "New", 3) == 0);
    bool isGet = (strncmp(name, "Get", 3) == 0);
    bool isSet = (strncmp(name, "Set", 3) == 0);
    bool isRegion = (strstr(name, "ArrayRegion") != nullptr);
    bool isElements = (strstr(name, "ArrayElements") != nullptr);
    if (!isNew && !isRegion && !isElements)
    {
        return false;
    }
    const char* p = name;
    if (isNew || isGet || isSet)
    {
        p += 3;
    }
    else if (strncmp(p, "Release", 7) == 0)
    {
        p += 7;
    }
    const char* end = strstr(p, "Array");
    if (end == nullptr)
    {
        return false;
    }
    size_t typeLen = (size_t)(end - p);
    if (typeLen == 0 || typeLen >= 16)
    {
        return false;
    }
    char type[16] = {0};
    memcpy(type, p, typeLen);

    const char* jniType = nullptr;
    const char* jniArray = nullptr;
    if (strcmp(type, "Boolean") == 0)      { jniType = "jboolean"; jniArray = "jbooleanArray"; }
    else if (strcmp(type, "Byte") == 0)    { jniType = "jbyte";    jniArray = "jbyteArray"; }
    else if (strcmp(type, "Char") == 0)    { jniType = "jchar";    jniArray = "jcharArray"; }
    else if (strcmp(type, "Short") == 0)   { jniType = "jshort";   jniArray = "jshortArray"; }
    else if (strcmp(type, "Int") == 0)     { jniType = "jint";     jniArray = "jintArray"; }
    else if (strcmp(type, "Long") == 0)    { jniType = "jlong";    jniArray = "jlongArray"; }
    else if (strcmp(type, "Float") == 0)   { jniType = "jfloat";   jniArray = "jfloatArray"; }
    else if (strcmp(type, "Double") == 0)  { jniType = "jdouble";  jniArray = "jdoubleArray"; }
    else return false;

    if (isNew)
    {
        snprintf(out, size, "%s %s(JNIEnv *env, jsize length);", jniArray, name);
    }
    else if (isRegion)
    {
        snprintf(out, size, "void %s(JNIEnv *env, %s array, jsize start, jsize len, %s%s *buf);",
                 name, jniArray, isSet ? "const " : "", jniType);
    }
    else if (isElements && isGet)
    {
        snprintf(out, size, "%s *%s(JNIEnv *env, %s array, jboolean *isCopy);",
                 jniType, name, jniArray);
    }
    else
    {
        snprintf(out, size, "void %s(JNIEnv *env, %s array, %s *elems, jint mode);",
                 name, jniArray, jniType);
    }
    return true;
}

struct JniPrototypeEntry {
    const char* name;
    const char* proto;
};

/* 常用JNI函数的C原型，输出在参数行下一行 */
static const JniPrototypeEntry g_jni_prototypes[] = {
    {"NewStringUTF",        "jstring NewStringUTF(JNIEnv *env, const char *bytes);"},
    {"GetStringUTFChars",   "const char *GetStringUTFChars(JNIEnv *env, jstring string, jboolean *isCopy);"},
    {"ReleaseStringUTFChars","void ReleaseStringUTFChars(JNIEnv *env, jstring string, const char *utf);"},
    {"NewString",           "jstring NewString(JNIEnv *env, const jchar *unicodeChars, jsize len);"},
    {"GetStringLength",     "jsize GetStringLength(JNIEnv *env, jstring string);"},
    {"GetStringUTFLength",  "jsize GetStringUTFLength(JNIEnv *env, jstring string);"},
    {"GetStringChars",      "const jchar *GetStringChars(JNIEnv *env, jstring string, jboolean *isCopy);"},
    {"ReleaseStringChars",  "void ReleaseStringChars(JNIEnv *env, jstring string, const jchar *chars);"},
    {"GetStringRegion",     "void GetStringRegion(JNIEnv *env, jstring str, jsize start, jsize len, jchar *buf);"},
    {"GetStringUTFRegion",  "void GetStringUTFRegion(JNIEnv *env, jstring str, jsize start, jsize len, char *buf);"},
    {"FindClass",           "jclass FindClass(JNIEnv *env, const char *name);"},
    {"GetObjectClass",      "jclass GetObjectClass(JNIEnv *env, jobject obj);"},
    {"GetSuperclass",       "jclass GetSuperclass(JNIEnv *env, jclass clazz);"},
    {"IsAssignableFrom",    "jboolean IsAssignableFrom(JNIEnv *env, jclass clazz1, jclass clazz2);"},
    {"IsInstanceOf",        "jboolean IsInstanceOf(JNIEnv *env, jobject obj, jclass clazz);"},
    {"GetObjectRefType",    "jobjectRefType GetObjectRefType(JNIEnv *env, jobject obj);"},
    {"NewGlobalRef",        "jobject NewGlobalRef(JNIEnv *env, jobject obj);"},
    {"NewLocalRef",         "jobject NewLocalRef(JNIEnv *env, jobject ref);"},
    {"DeleteGlobalRef",     "void DeleteGlobalRef(JNIEnv *env, jobject globalRef);"},
    {"DeleteWeakGlobalRef", "void DeleteWeakGlobalRef(JNIEnv *env, jweak ref);"},
    {"DeleteLocalRef",      "void DeleteLocalRef(JNIEnv *env, jobject localRef);"},
    {"IsSameObject",        "jboolean IsSameObject(JNIEnv *env, jobject ref1, jobject ref2);"},
    {"GetFieldID",          "jfieldID GetFieldID(JNIEnv *env, jclass clazz, const char *name, const char *sig);"},
    {"GetStaticFieldID",    "jfieldID GetStaticFieldID(JNIEnv *env, jclass clazz, const char *name, const char *sig);"},
    {"GetMethodID",         "jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);"},
    {"GetStaticMethodID",   "jmethodID GetStaticMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);"},
    {"RegisterNatives",     "jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);"},
    {"UnregisterNatives",   "jint UnregisterNatives(JNIEnv *env, jclass clazz);"},
    {"NewObject",           "jobject NewObject(JNIEnv *env, jclass clazz, jmethodID methodID, ...);"},
    {"NewObjectV",          "jobject NewObjectV(JNIEnv *env, jclass clazz, jmethodID methodID, va_list args);"},
    {"NewObjectA",          "jobject NewObjectA(JNIEnv *env, jclass clazz, jmethodID methodID, const jvalue *args);"},
    {"AllocObject",         "jobject AllocObject(JNIEnv *env, jclass clazz);"},
    {"GetArrayLength",      "jsize GetArrayLength(JNIEnv *env, jarray array);"},
    {"NewByteArray",        "jbyteArray NewByteArray(JNIEnv *env, jsize length);"},
    {"NewBooleanArray",     "jbooleanArray NewBooleanArray(JNIEnv *env, jsize length);"},
    {"NewCharArray",        "jcharArray NewCharArray(JNIEnv *env, jsize length);"},
    {"NewShortArray",       "jshortArray NewShortArray(JNIEnv *env, jsize length);"},
    {"NewIntArray",         "jintArray NewIntArray(JNIEnv *env, jsize length);"},
    {"NewLongArray",        "jlongArray NewLongArray(JNIEnv *env, jsize length);"},
    {"NewFloatArray",       "jfloatArray NewFloatArray(JNIEnv *env, jsize length);"},
    {"NewDoubleArray",      "jdoubleArray NewDoubleArray(JNIEnv *env, jsize length);"},
    {"NewObjectArray",      "jobjectArray NewObjectArray(JNIEnv *env, jsize length, jclass elementClass, jobject initialElement);"},
    {"GetObjectArrayElement","jobject GetObjectArrayElement(JNIEnv *env, jobjectArray array, jsize index);"},
    {"SetObjectArrayElement","void SetObjectArrayElement(JNIEnv *env, jobjectArray array, jsize index, jobject value);"},
    {"GetByteArrayElements","jbyte *GetByteArrayElements(JNIEnv *env, jbyteArray array, jboolean *isCopy);"},
    {"ReleaseByteArrayElements","void ReleaseByteArrayElements(JNIEnv *env, jbyteArray array, jbyte *elems, jint mode);"},
    {"GetByteArrayRegion",  "void GetByteArrayRegion(JNIEnv *env, jbyteArray array, jsize start, jsize len, jbyte *buf);"},
    {"SetByteArrayRegion",  "void SetByteArrayRegion(JNIEnv *env, jbyteArray array, jsize start, jsize len, const jbyte *buf);"},
    {"ExceptionOccurred",   "jthrowable ExceptionOccurred(JNIEnv *env);"},
    {"ExceptionCheck",      "jboolean ExceptionCheck(JNIEnv *env);"},
    {"ExceptionDescribe",   "void ExceptionDescribe(JNIEnv *env);"},
    {"ExceptionClear",      "void ExceptionClear(JNIEnv *env);"},
    {"Throw",               "jint Throw(JNIEnv *env, jthrowable obj);"},
    {"ThrowNew",            "jint ThrowNew(JNIEnv *env, jclass clazz, const char *message);"},
    {"MonitorEnter",        "jint MonitorEnter(JNIEnv *env, jobject obj);"},
    {"MonitorExit",         "jint MonitorExit(JNIEnv *env, jobject obj);"},
    {"GetJavaVM",           "jint GetJavaVM(JNIEnv *env, JavaVM **vm);"},
    {"GetVersion",          "jint GetVersion(JNIEnv *env);"},
    {"DefineClass",         "jclass DefineClass(JNIEnv *env, const char *name, jobject loader, const jbyte *buf, jsize bufLen);"},
    {"GetDirectBufferAddress","void *GetDirectBufferAddress(JNIEnv *env, jobject buf);"},
    {"GetDirectBufferCapacity","jlong GetDirectBufferCapacity(JNIEnv *env, jobject buf);"},
    {"EnsureLocalCapacity",  "jint EnsureLocalCapacity(JNIEnv *env, jint capacity);"},
    {"__END__", ""},
};

/* 打印一行缩进后的JNI函数原型 */
static void appendJniPrototype(const char* name)
{
    if (name == nullptr)
    {
        return;
    }
    char line[256] = {0};
    if (!buildCallMethodPrototype(name, line, sizeof(line)) &&
        !buildFieldPrototype(name, line, sizeof(line)) &&
        !buildArrayPrototype(name, line, sizeof(line)))
    {
        const size_t count = sizeof(g_jni_prototypes) / sizeof(g_jni_prototypes[0]);
        for (size_t i = 0; i < count; ++i)
        {
            if (strcmp(g_jni_prototypes[i].name, name) == 0)
            {
                snprintf(line, sizeof(line), "%s", g_jni_prototypes[i].proto);
                break;
            }
        }
    }
    if (line[0] != 0)
    {
        appendformat("      %s\n", line);
    }
}

/* 解析AArch64的va_list，输出前几个可变参数槽位（不再hexdump） */
static void appendVaList(uint64_t va)
{
    if (va == 0)
    {
        appendlog(", args=0x0");
        return;
    }
    // AArch64 __va_list: {void* stack; void* gr_top; void* vr_top; int gr_offs; int vr_offs;}
    struct VaList {
        uint64_t stack;
        uint64_t gr_top;
        uint64_t vr_top;
        int32_t  gr_offs;
        int32_t  vr_offs;
    } vaList;
    memset(&vaList, 0, sizeof(vaList));
    if (!safeReadMemory(va, (uint8_t*)&vaList, sizeof(vaList)) || vaList.gr_top == 0)
    {
        appendformat(", args=0x%lx", va);
        return;
    }
    //可变参数从 gr_top + gr_offs 开始，最多取4个通用参数槽位
    uint64_t argsAddr = (uint64_t)((int64_t)vaList.gr_top + (int64_t)vaList.gr_offs);
    uint64_t values[4] = {0};
    if (safeReadMemory(argsAddr, (uint8_t*)values, sizeof(values)))
    {
        appendformat(", args=[0x%lx, 0x%lx, 0x%lx, 0x%lx]",
                     values[0], values[1], values[2], values[3]);
    }
    else
    {
        appendformat(", args=0x%lx", va);
    }
}

/* 根据函数名输出JNI返回值(x0)，Object类型额外解析java类名 */
static void appendJniReturn(const char* name, uint64_t retval)
{
    if (name == nullptr || strstr(name, "Void") != nullptr)
    {
        return;
    }
    appendformat("      return x0 = 0x%lx", retval);
    if (strstr(name, "Object") != nullptr || strstr(name, "Class") != nullptr)
    {
        char cls[256] = {0};
        if (retval != 0 && resolveJavaClassName(retval, cls, sizeof(cls)))
        {
            appendformat(" (%s)", cls);
        }
    }
    else if (strstr(name, "Boolean") != nullptr || strcmp(name, "IsSameObject") == 0 ||
             strcmp(name, "IsAssignableFrom") == 0 || strcmp(name, "IsInstanceOf") == 0)
    {
        appendformat(" (%s)", retval ? "true" : "false");
    }
    else if (strstr(name, "Int") != nullptr || strstr(name, "Short") != nullptr ||
             strstr(name, "Byte") != nullptr)
    {
        appendformat(" (%d)", (int32_t)(uint32_t)retval);
    }
    appendlog("\n");
}

void trace_FindClass(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t classname = QBDI_GPR_GET(gprState, 1);
    appendlog("  [JNI] FindClass(name=");
    appendStringArg(classname);
    appendlog(")\n");
    appendJniPrototype("FindClass");
    appendJniReturn("FindClass", (uint64_t)g_deferred_call_retval);
}

void trace_GetStringUTFChars(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jstr = QBDI_GPR_GET(gprState,1);
    uint64_t isCopy = QBDI_GPR_GET(gprState,2);
    appendformat("  [JNI] GetStringUTFChars(string=0x%lx, isCopy=0x%lx)\n", jstr, isCopy);
    appendJniPrototype("GetStringUTFChars");
    appendformat("      return x0 = 0x%lx (", (uint64_t)g_deferred_call_retval);
    //返回值(x0)就是转换后的C字符串指针
    appendStringArg((uint64_t)g_deferred_call_retval);
    appendlog(")\n");
}

void trace_GetFieldID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t clazz = QBDI_GPR_GET(gprState,1);
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    appendformat("  [JNI] GetFieldID(clazz=0x%lx, name=", clazz);
    appendStringArg(name);
    appendlog(", sig=");
    appendStringArg(sig);
    appendlog(")\n");
    appendJniPrototype("GetFieldID");
    appendJavaClassLine("clazz", clazz);
    cacheFieldName((uint64_t)g_deferred_call_retval, name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

void trace_GetStaticFieldID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t clazz = QBDI_GPR_GET(gprState,1);
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    appendformat("  [JNI] GetStaticFieldID(clazz=0x%lx, name=", clazz);
    appendStringArg(name);
    appendlog(", sig=");
    appendStringArg(sig);
    appendlog(")\n");
    appendJniPrototype("GetStaticFieldID");
    appendJavaClassLine("clazz", clazz);
    cacheFieldName((uint64_t)g_deferred_call_retval, name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

void trace_GetByteArrayElements(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    uint64_t isCopy = QBDI_GPR_GET(gprState,2);
    //返回值(x0)是jbyte*缓冲区
    appendformat("  [JNI] GetByteArrayElements(array=0x%lx, isCopy=0x%lx)\n", arr, isCopy);
    appendJniPrototype("GetByteArrayElements");
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

void trace_GetObjectArrayElement(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t arr   = QBDI_GPR_GET(gprState, 1);  // jobjectArray array
    uint64_t index = QBDI_GPR_GET(gprState, 2);  // jsize index
    appendformat("  [JNI] GetObjectArrayElement(array=0x%lx, index=%ld)\n",
                 arr, (int64_t)(int32_t)(uint32_t)index);
    appendJniPrototype("GetObjectArrayElement");
    appendJniReturn("GetObjectArrayElement", (uint64_t)g_deferred_call_retval);
}
void trace_GetArrayLength(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    appendformat("  [JNI] GetArrayLength(array=0x%lx)\n", arr);
    appendJniPrototype("GetArrayLength");
    appendformat("      return x0 = 0x%lx (%d)\n",
                 (uint64_t)g_deferred_call_retval,
                 (int)(int32_t)(uint32_t)g_deferred_call_retval);
}

void trace_GetByteArrayRegion(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t env = QBDI_GPR_GET(gprState,0);
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    int32_t start = (int32_t)(uint32_t)QBDI_GPR_GET(gprState,2);
    int32_t len = (int32_t)(uint32_t)QBDI_GPR_GET(gprState,3);
    uint64_t buf = QBDI_GPR_GET(gprState,4);
    //回调在调用返回后执行，此时buf里已经是拷贝完成的真实数据
    appendformat("  [JNI] GetByteArrayRegion(env=0x%lx, array=0x%lx, start=0x%x, len=0x%x, buf=0x%lx)\n",
                 env, arr, (uint32_t)start, (uint32_t)len, buf);
    appendJniPrototype("GetByteArrayRegion");
    if (len > 0)
    {
        appendHexdump(buf, (uint64_t)len, 256);
    }
}

/*
 * Get<Type>Field / GetStatic<Type>Field / Set<Type>Field / SetStatic<Type>Field 通用回调。
 * 函数名由注册时传入(addJNITrace)：Get* 的字段值在返回值x0，Set* 的字段值在x3。
 */
void trace_GetField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "GetField";
    bool isSet = (strncmp(name, "Set", 3) == 0);
    bool isStatic = (strstr(name, "Static") != nullptr);
    uint64_t target = QBDI_GPR_GET(gprState, 1);   // obj 或 clazz
    uint64_t fieldId = QBDI_GPR_GET(gprState, 2);
    uint64_t value = isSet ? QBDI_GPR_GET(gprState, 3) : (uint64_t)g_deferred_call_retval;

    appendformat("  [JNI] %s(%s=0x%lx, fieldID=0x%lx", name,
                 isStatic ? "clazz" : "obj", target, fieldId);
    if (isSet)
    {
        appendformat(", value=0x%lx", value);
    }
    appendlog(")\n");
    appendJniPrototype(name);
    if (isStatic)
    {
        appendJavaClassLine("clazz", target);
    }
    else
    {
        appendJavaClassLine("obj", target);
    }
    appendFieldLine(fieldId);
    if (!isSet)
    {
        appendJniReturn(name, (uint64_t)g_deferred_call_retval);
    }
}

/* 兼容旧接口：统一交给 trace_CallMethod 处理 */
void trace_CallStaticObjectMethodV(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    trace_CallMethod(vm, gprState);
}
void trace_GetStaticMethodID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t clazz = QBDI_GPR_GET(gprState,1);
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    appendformat("  [JNI] GetStaticMethodID(clazz=0x%lx, name=", clazz);
    appendStringArg(name);
    appendlog(", sig=");
    appendStringArg(sig);
    appendlog(")\n");
    appendJniPrototype("GetStaticMethodID");
    appendJavaClassLine("clazz", clazz);
    cacheMethodName((uint64_t)g_deferred_call_retval, name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}
/* 兼容旧接口：统一走 trace_GetField */
void trace_GetLongField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    trace_GetField(vm, gprState);
}

void trace_RegisterNatives(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t clazz = QBDI_GPR_GET(gprState,1);
    uint64_t funcs = QBDI_GPR_GET(gprState,2);
    uint64_t funcNum = QBDI_GPR_GET(gprState,3);
    appendformat("  [JNI] RegisterNatives(clazz=0x%lx, methods=0x%lx, n=%lu)\n",
                 clazz, funcs, (unsigned long)funcNum);
    appendJniPrototype("RegisterNatives");
    appendJavaClassLine("clazz", clazz);
    if (funcNum > 256)
    {
        funcNum = 256;
    }
    for (uint64_t i = 0; i < funcNum; ++i)
    {
        JNINativeMethod method;
        memset(&method, 0, sizeof(method));
        //数组来自Java层，必须安全读取，避免非法指针把trace带崩
        if (!safeReadMemory(funcs + i * sizeof(JNINativeMethod), (uint8_t*)&method, sizeof(method)))
        {
            appendformat("   [%lu] <read methods failed>\n", (unsigned long)i);
            break;
        }
        appendformat("   [%lu] name=", (unsigned long)i);
        appendStringArg((uint64_t)method.name);
        appendlog(", sig=");
        appendStringArg((uint64_t)method.signature);
        if (_g_trace_data != nullptr && (size_t)method.fnPtr >= _g_trace_data->base)
        {
            appendformat(", fn=0x%lx (offset 0x%lx)\n",
                         (size_t)method.fnPtr, (size_t)method.fnPtr - _g_trace_data->base);
        }
        else
        {
            appendformat(", fn=0x%lx\n", (size_t)method.fnPtr);
        }
    }
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

void trace_GetMethodID(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t clazz = QBDI_GPR_GET(gprState,1);
    uint64_t name = QBDI_GPR_GET(gprState,2);
    uint64_t sig = QBDI_GPR_GET(gprState,3);
    appendformat("  [JNI] GetMethodID(clazz=0x%lx, name=", clazz);
    appendStringArg(name);
    appendlog(", sig=");
    appendStringArg(sig);
    appendlog(")\n");
    appendJniPrototype("GetMethodID");
    appendJavaClassLine("clazz", clazz);
    cacheMethodName((uint64_t)g_deferred_call_retval, name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

void trace_NewString(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t unicode = QBDI_GPR_GET(gprState, 1);
    uint64_t len = QBDI_GPR_GET(gprState, 2);
    appendformat("  [JNI] NewString(unicode=0x%lx, len=0x%lx)\n", unicode, len);
    appendJniPrototype("NewString");
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

void trace_NewStringUTF(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t bytes = QBDI_GPR_GET(gprState, 1);
    appendlog("  [JNI] NewStringUTF(bytes=");
    appendStringArg(bytes);
    appendlog(")\n");
    appendJniPrototype("NewStringUTF");
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

/*
 * Call*Method / CallStatic*Method 系列通用回调。
 * 函数名由注册时传入(addJNITrace)，延迟回调执行前会写入 g_deferred_call_name。
 *  - JNIEnv*: x0, jobject/jclass: x1, jmethodID: x2
 *  - V 版本: x3 = va_list；非V版本: x3~x7 就是可变参数
 * 输出: 参数行 -> 函数原型 -> obj/clazz解析出的java类 -> 返回值
 */
void trace_CallMethod(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "CallMethod";
    bool isStatic = (strncmp(name, "CallStatic", 10) == 0);
    size_t nameLen = strlen(name);
    bool isVaList = (nameLen > 0 && name[nameLen - 1] == 'V');

    uint64_t env = QBDI_GPR_GET(gprState, 0);
    uint64_t obj = QBDI_GPR_GET(gprState, 1);
    uint64_t methodId = QBDI_GPR_GET(gprState, 2);
    uint64_t args = QBDI_GPR_GET(gprState, 3);

    appendformat("  [JNI] %s(env=0x%lx, %s=0x%lx, methodID=0x%lx",
                 name, env, isStatic ? "clazz" : "obj", obj, methodId);
    if (isVaList)
    {
        appendVaList(args);
    }
    else
    {
        //非V版本可变参数直接放在x3~x7
        appendformat(", arg0=0x%lx, arg1=0x%lx, arg2=0x%lx, arg3=0x%lx, arg4=0x%lx",
                     args,
                     QBDI_GPR_GET(gprState, 4),
                     QBDI_GPR_GET(gprState, 5),
                     QBDI_GPR_GET(gprState, 6),
                     QBDI_GPR_GET(gprState, 7));
    }
    appendlog(")\n");
    appendJniPrototype(name);
    appendJavaClassLine(isStatic ? "clazz" : "obj", obj);
    appendMethodLine(methodId, obj, isStatic);
    appendJniReturn(name, (uint64_t)g_deferred_call_retval);
}

/*
 * DeleteLocalRef(JNIEnv *env, jobject localRef)
 * x1 = 要删除的局部引用
 */
void trace_DeleteLocalRef(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t ref = QBDI_GPR_GET(gprState, 1);
    appendformat("  [JNI] DeleteLocalRef(ref=0x%lx)\n", ref);
    appendJniPrototype("DeleteLocalRef");
}

/*
 * 异常相关JNI函数通用回调，函数名由注册时传入：
 *   jthrowable ExceptionOccurred(JNIEnv *env);
 *   jboolean   ExceptionCheck(JNIEnv *env);
 *   void       ExceptionDescribe(JNIEnv *env);
 *   void       ExceptionClear(JNIEnv *env);
 *   jint       Throw(JNIEnv *env, jthrowable obj);
 *   jint       ThrowNew(JNIEnv *env, jclass clazz, const char *message);
 */
void trace_ExceptionFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "Exception";

    if (strcmp(name, "ThrowNew") == 0)
    {
        uint64_t clazz = QBDI_GPR_GET(gprState, 1);
        uint64_t msg = QBDI_GPR_GET(gprState, 2);
        appendformat("  [JNI] ThrowNew(clazz=0x%lx, msg=", clazz);
        appendStringArg(msg);
        appendlog(")\n");
        appendJniPrototype(name);
        appendJavaClassLine("clazz", clazz);
        appendformat("      return x0 = 0x%lx (%d)\n",
                     (uint64_t)g_deferred_call_retval,
                     (int32_t)(uint32_t)g_deferred_call_retval);
        return;
    }
    if (strcmp(name, "Throw") == 0)
    {
        uint64_t thr = QBDI_GPR_GET(gprState, 1);
        appendformat("  [JNI] Throw(throwable=0x%lx)\n", thr);
        appendJniPrototype(name);
        appendformat("      return x0 = 0x%lx (%d)\n",
                     (uint64_t)g_deferred_call_retval,
                     (int32_t)(uint32_t)g_deferred_call_retval);
        return;
    }
    if (strcmp(name, "ExceptionOccurred") == 0)
    {
        appendlog("  [JNI] ExceptionOccurred()\n");
        appendJniPrototype(name);
        appendJniReturn(name, (uint64_t)g_deferred_call_retval);
        return;
    }
    if (strcmp(name, "ExceptionCheck") == 0)
    {
        appendlog("  [JNI] ExceptionCheck()\n");
        appendJniPrototype(name);
        appendformat("      return x0 = 0x%lx (%d)\n",
                     (uint64_t)g_deferred_call_retval,
                     (int)(uint32_t)g_deferred_call_retval);
        return;
    }
    //ExceptionDescribe / ExceptionClear 无参数无返回值
    appendformat("  [JNI] %s()\n", name);
    appendJniPrototype(name);
}

/*
 * NewObject / NewObjectV / NewObjectA / AllocObject 通用回调。
 *  - NewObjectV: x3 = va_list, NewObjectA: x3 = const jvalue*, NewObject: x3~x7
 */
void trace_NewObject(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "NewObject";
    uint64_t clazz = QBDI_GPR_GET(gprState, 1);
    uint64_t methodId = QBDI_GPR_GET(gprState, 2);
    uint64_t args = QBDI_GPR_GET(gprState, 3);

    appendformat("  [JNI] %s(clazz=0x%lx", name, clazz);
    if (strcmp(name, "AllocObject") != 0)
    {
        appendformat(", methodID=0x%lx", methodId);
        if (strcmp(name, "NewObjectV") == 0)
        {
            appendVaList(args);
        }
        else if (strcmp(name, "NewObjectA") == 0)
        {
            appendformat(", jvalues=0x%lx", args);
        }
        else
        {
            appendformat(", arg0=0x%lx, arg1=0x%lx, arg2=0x%lx, arg3=0x%lx, arg4=0x%lx",
                         args,
                         QBDI_GPR_GET(gprState, 4),
                         QBDI_GPR_GET(gprState, 5),
                         QBDI_GPR_GET(gprState, 6),
                         QBDI_GPR_GET(gprState, 7));
        }
    }
    appendlog(")\n");
    appendJniPrototype(name);
    appendJavaClassLine("clazz", clazz);
    if (strcmp(name, "AllocObject") != 0)
    {
        //构造方法名一般是<init>，在GetMethodID阶段已经缓存
        char methodName[128] = {0};
        if (lookupMethodName(methodId, methodName, sizeof(methodName)))
        {
            appendformat("      method = %s\n", methodName);
        }
    }
    appendJniReturn(name, (uint64_t)g_deferred_call_retval);
}

/* NewGlobalRef / NewLocalRef / DeleteGlobalRef / DeleteWeakGlobalRef / IsSameObject / EnsureLocalCapacity */
void trace_ReferenceFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "Reference";
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    if (strcmp(name, "IsSameObject") == 0)
    {
        appendformat("  [JNI] IsSameObject(ref1=0x%lx, ref2=0x%lx)\n", x1, x2);
    }
    else if (strcmp(name, "EnsureLocalCapacity") == 0)
    {
        appendformat("  [JNI] EnsureLocalCapacity(capacity=%ld)\n", (int64_t)(int32_t)(uint32_t)x1);
    }
    else
    {
        appendformat("  [JNI] %s(ref=0x%lx)\n", name, x1);
    }
    appendJniPrototype(name);
    if (strcmp(name, "DeleteGlobalRef") != 0 && strcmp(name, "DeleteWeakGlobalRef") != 0)
    {
        appendJniReturn(name, (uint64_t)g_deferred_call_retval);
    }
}

/* GetStringLength / GetStringUTFLength */
void trace_StringLengthFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "GetStringLength";
    uint64_t str = QBDI_GPR_GET(gprState, 1);
    appendformat("  [JNI] %s(string=0x%lx)\n", name, str);
    appendJniPrototype(name);
    appendformat("      return x0 = 0x%lx (%d)\n",
                 (uint64_t)g_deferred_call_retval,
                 (int)(int32_t)(uint32_t)g_deferred_call_retval);
}

/* GetStringChars / GetStringRegion / GetStringUTFRegion / ReleaseStringChars */
void trace_StringFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "String";
    uint64_t str = QBDI_GPR_GET(gprState, 1);
    if (strcmp(name, "ReleaseStringChars") == 0)
    {
        appendformat("  [JNI] ReleaseStringChars(string=0x%lx, chars=0x%lx)\n",
                     str, QBDI_GPR_GET(gprState, 2));
    }
    else if (strcmp(name, "ReleaseStringUTFChars") == 0)
    {
        appendformat("  [JNI] ReleaseStringUTFChars(string=0x%lx, utf=0x%lx)\n",
                     str, QBDI_GPR_GET(gprState, 2));
        appendJniPrototype(name);
        return;
    }
    else if (strstr(name, "Region") != nullptr)
    {
        uint64_t start = QBDI_GPR_GET(gprState, 2);
        uint64_t len = QBDI_GPR_GET(gprState, 3);
        uint64_t buf = QBDI_GPR_GET(gprState, 4);
        appendformat("  [JNI] %s(string=0x%lx, start=%d, len=%d, buf=0x%lx)\n",
                     name, str, (int)(int32_t)(uint32_t)start,
                     (int)(int32_t)(uint32_t)len, buf);
        appendJniPrototype(name);
        if (buf != 0 && (int32_t)(uint32_t)len > 0)
        {
            appendHexdump(buf, (uint64_t)(int32_t)(uint32_t)len, 128);
        }
        return;
    }
    else
    {
        appendformat("  [JNI] %s(string=0x%lx, isCopy=0x%lx)\n",
                     name, str, QBDI_GPR_GET(gprState, 2));
    }
    appendJniPrototype(name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}
/*
 * 数组相关通用回调：New*Array / Get|Set*ArrayRegion / Get|Release*ArrayElements /
 * NewObjectArray / SetObjectArrayElement。函数名由注册时传入。
 */
void trace_ArrayFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "ArrayFunc";
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    uint64_t x3 = QBDI_GPR_GET(gprState, 3);
    uint64_t x4 = QBDI_GPR_GET(gprState, 4);

    if (strncmp(name, "New", 3) == 0 && strcmp(name, "NewObjectArray") != 0)
    {
        //NewByteArray / NewIntArray ... 只有一个length参数
        appendformat("  [JNI] %s(length=%d)\n", name, (int)(int32_t)(uint32_t)x1);
        appendJniPrototype(name);
        appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
        return;
    }
    if (strcmp(name, "NewObjectArray") == 0)
    {
        appendformat("  [JNI] NewObjectArray(length=%d, elementClass=0x%lx, initialElement=0x%lx)\n",
                     (int)(int32_t)(uint32_t)x1, x2, x3);
        appendJniPrototype(name);
        appendJavaClassLine("elementClass", x2);
        appendJniReturn(name, (uint64_t)g_deferred_call_retval);
        return;
    }
    if (strcmp(name, "SetObjectArrayElement") == 0)
    {
        appendformat("  [JNI] SetObjectArrayElement(array=0x%lx, index=%d, value=0x%lx)\n",
                     x1, (int)(int32_t)(uint32_t)x2, x3);
        appendJniPrototype(name);
        return;
    }
    if (strstr(name, "Region") != nullptr)
    {
        //Get/Set<Type>ArrayRegion(array, start, len, buf)
        appendformat("  [JNI] %s(array=0x%lx, start=%d, len=%d, buf=0x%lx)\n",
                     name, x1, (int)(int32_t)(uint32_t)x2,
                     (int)(int32_t)(uint32_t)x3, x4);
        appendJniPrototype(name);
        if (x4 != 0 && (int32_t)(uint32_t)x3 > 0)
        {
            appendHexdump(x4, (uint64_t)(int32_t)(uint32_t)x3, 128);
        }
        return;
    }
    if (strstr(name, "Elements") != nullptr)
    {
        appendformat("  [JNI] %s(array=0x%lx, x2=0x%lx, x3=0x%lx)\n", name, x1, x2, x3);
        appendJniPrototype(name);
        if (strncmp(name, "Release", 7) != 0)
        {
            appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
        }
        return;
    }
    appendformat("  [JNI] %s(x1=0x%lx, x2=0x%lx, x3=0x%lx)\n", name, x1, x2, x3);
    appendJniPrototype(name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

/* MonitorEnter / MonitorExit */
void trace_MonitorFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "Monitor";
    uint64_t obj = QBDI_GPR_GET(gprState, 1);
    appendformat("  [JNI] %s(obj=0x%lx)\n", name, obj);
    appendJniPrototype(name);
    appendJavaClassLine("obj", obj);
    appendformat("      return x0 = 0x%lx (%d)\n",
                 (uint64_t)g_deferred_call_retval,
                 (int32_t)(uint32_t)g_deferred_call_retval);
}

/* GetObjectClass */
void trace_GetObjectClass(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t obj = QBDI_GPR_GET(gprState, 1);
    appendformat("  [JNI] GetObjectClass(obj=0x%lx)\n", obj);
    appendJniPrototype("GetObjectClass");
    appendJavaClassLine("obj", obj);
    appendJniReturn("GetObjectClass", (uint64_t)g_deferred_call_retval);
}

/* GetSuperclass / IsAssignableFrom / IsInstanceOf / GetObjectRefType */
void trace_ClassFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "Class";
    uint64_t x1 = QBDI_GPR_GET(gprState, 1);
    uint64_t x2 = QBDI_GPR_GET(gprState, 2);
    if (strcmp(name, "GetSuperclass") == 0)
    {
        appendformat("  [JNI] GetSuperclass(clazz=0x%lx)\n", x1);
        appendJavaClassLine("clazz", x1);
    }
    else if (strcmp(name, "IsAssignableFrom") == 0)
    {
        appendformat("  [JNI] IsAssignableFrom(clazz1=0x%lx, clazz2=0x%lx)\n", x1, x2);
        appendJavaClassLine("clazz1", x1);
        appendJavaClassLine("clazz2", x2);
    }
    else if (strcmp(name, "IsInstanceOf") == 0)
    {
        appendformat("  [JNI] IsInstanceOf(obj=0x%lx, clazz=0x%lx)\n", x1, x2);
        appendJavaClassLine("obj", x1);
        appendJavaClassLine("clazz", x2);
    }
    else
    {
        appendformat("  [JNI] %s(ref=0x%lx)\n", name, x1);
        appendJniPrototype(name);
        //GetObjectRefType返回jobjectRefType枚举，不能按对象解析
        appendformat("      return x0 = 0x%lx (%d)\n",
                     (uint64_t)g_deferred_call_retval,
                     (int32_t)(uint32_t)g_deferred_call_retval);
        return;
    }
    appendJniPrototype(name);
    appendJniReturn(name, (uint64_t)g_deferred_call_retval);
}

/* GetVersion / GetJavaVM */
void trace_VersionFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "GetVersion";
    if (strcmp(name, "GetJavaVM") == 0)
    {
        appendformat("  [JNI] GetJavaVM(vm=0x%lx)\n", QBDI_GPR_GET(gprState, 1));
    }
    else
    {
        appendlog("  [JNI] GetVersion()\n");
    }
    appendJniPrototype(name);
    appendformat("      return x0 = 0x%lx (%d)\n",
                 (uint64_t)g_deferred_call_retval,
                 (int32_t)(uint32_t)g_deferred_call_retval);
}

/* DefineClass */
void trace_DefineClass(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t name = QBDI_GPR_GET(gprState, 1);
    uint64_t loader = QBDI_GPR_GET(gprState, 2);
    uint64_t buf = QBDI_GPR_GET(gprState, 3);
    uint64_t len = QBDI_GPR_GET(gprState, 4);
    appendlog("  [JNI] DefineClass(name=");
    appendStringArg(name);
    appendformat(", loader=0x%lx, buf=0x%lx, len=0x%lx)\n", loader, buf, len);
    appendJniPrototype("DefineClass");
    appendJniReturn("DefineClass", (uint64_t)g_deferred_call_retval);
}

/* GetDirectBufferAddress / GetDirectBufferCapacity */
void trace_DirectBufferFunc(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "DirectBuffer";
    uint64_t buf = QBDI_GPR_GET(gprState, 1);
    appendformat("  [JNI] %s(buf=0x%lx)\n", name, buf);
    appendJniPrototype(name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

/* CallNonvirtual<Type>Method(V)：x1=obj, x2=jclass, x3=methodID，参数从x4开始 */
void trace_CallNonvirtualMethod(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "CallNonvirtualMethod";
    uint64_t obj = QBDI_GPR_GET(gprState, 1);
    uint64_t clazz = QBDI_GPR_GET(gprState, 2);
    uint64_t methodId = QBDI_GPR_GET(gprState, 3);
    size_t nameLen = strlen(name);
    bool isVaList = (nameLen > 0 && name[nameLen - 1] == 'V');
    appendformat("  [JNI] %s(obj=0x%lx, clazz=0x%lx, methodID=0x%lx", name, obj, clazz, methodId);
    if (isVaList)
    {
        appendVaList(QBDI_GPR_GET(gprState, 4));
    }
    else
    {
        appendformat(", arg0=0x%lx, arg1=0x%lx, arg2=0x%lx, arg3=0x%lx",
                     QBDI_GPR_GET(gprState, 4), QBDI_GPR_GET(gprState, 5),
                     QBDI_GPR_GET(gprState, 6), QBDI_GPR_GET(gprState, 7));
    }
    appendlog(")\n");
    appendJniPrototype(name);
    appendJavaClassLine("obj", obj);
    appendJavaClassLine("clazz", clazz);
    appendMethodLine(methodId, clazz, true);
    appendJniReturn(name, (uint64_t)g_deferred_call_retval);
}

/* 未单独解析的JNI函数通用输出：寄存器参数 + 原型 + 返回值 */
void trace_GenericJni(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    const char* name = (g_deferred_call_name != nullptr) ? g_deferred_call_name : "JNI";
    appendformat("  [JNI] %s(env=0x%lx, x1=0x%lx, x2=0x%lx, x3=0x%lx, x4=0x%lx, x5=0x%lx)\n",
                 name,
                 QBDI_GPR_GET(gprState, 0),
                 QBDI_GPR_GET(gprState, 1),
                 QBDI_GPR_GET(gprState, 2),
                 QBDI_GPR_GET(gprState, 3),
                 QBDI_GPR_GET(gprState, 4),
                 QBDI_GPR_GET(gprState, 5));
    appendJniPrototype(name);
    appendformat("      return x0 = 0x%lx\n", (uint64_t)g_deferred_call_retval);
}

void addJNITrace(void* target,const char* funcname,TraceCallBack callback)
{
    if(_g_jni_trace == nullptr)
    {
        LOGE("jnitrace: not init!");
        return;
    }
    auto it = _g_jni_trace->map.find((size_t)target);
    if(it != _g_jni_trace->map.end())
    {
        LOGE("jnitrace: %p has installed!",target);
        return;
    }
    auto* jni_trace_func = new TraceFunc();
    jni_trace_func->callback = callback;
    jni_trace_func->name = funcname;
    _g_jni_trace->map[(size_t)target] = jni_trace_func;
    LOGE("jnitrace: %s,%p install",funcname,target);
}

void setup_jfunc(JNIEnv * jnienv)
{
    jniEnv = jnienv;
    pJFunc = jnienv->functions;
    //重复初始化时不要覆盖已有的hook表，避免hook丢失和内存泄漏
    if(_g_jni_trace == nullptr)
    {
        _g_jni_trace = new JNITraceMap();
        _g_jni_trace->map.reserve(10);
    }
}