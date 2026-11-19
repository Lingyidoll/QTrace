//
// Created by zgy on 2025/10/30.
//

#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>
#include "jnitrace.h"
#include "HookUtils.h"
#include "TraceUtils.h"
#include "logger.h"

const JNINativeInterface* pJFunc = nullptr;
 JNIEnv * jniEnv = nullptr;
JNITraceMap* _g_jni_trace = nullptr;
static bool debug = false;
/* 是否允许做需要调用JNI的解析(obj/clazz 类名：GetObjectClass + Class.getName())。
 * methodID/fieldID 名称不走JNI：JNIEnv一就绪(setup_jni_env/initJni)就装函数表hook并一直记录。
 * 某些加固/自定义VM上JNIEnv不可靠时可关掉，保证trace稳定 */
static bool jniResolveEnabled = true;

/* ---------------- methodID / fieldID -> 名称 ---------------- */

static std::unordered_map<uint64_t, std::string> g_method_names;   // methodID  -> 方法名
static std::unordered_map<uint64_t, std::string> g_method_sigs;    // methodID  -> 方法签名，如 "()Ljava/lang/String;"
static std::unordered_map<uint64_t, std::string> g_field_names;    // fieldID   -> 字段名
static std::unordered_map<uint64_t, std::string> g_class_names;    // jclass    -> 类名
static std::unordered_map<uint64_t, uint64_t> g_object_classes;    // jobject   -> jclass
/* 创建即已知类型的引用(NewStringUTF/NewString 的 jstring、NewObject 的实例、FindClass 的 jclass)。
 * ART 会把回收的局部引用句柄值复用给新对象，只靠 obj->jclass 反查会命中上一个对象留下的
 * 脏映射(例如新建的 String 显示成 com.meituan.robust.PatchProxy)，所以这里按句柄直接记类名 */
static std::unordered_map<uint64_t, std::string> g_ref_class_names;
/* java.lang.Class 的全局引用和 Class.getName() 的methodID，解析类名时复用，
 * 避免每次都 FindClass("java/lang/Class") */
static jclass g_java_lang_class = nullptr;
static jmethodID g_class_get_name = nullptr;
/* GetMethodID/GetStaticMethodID 的hook可能在任意线程触发，缓存表读写必须加锁 */
static std::mutex g_jni_name_mutex;

static void cacheMethodName(uint64_t methodId, uint64_t namePtr);
static void cacheMethodSig(uint64_t methodId, uint64_t sigPtr);
static void cacheFieldName(uint64_t fieldId, uint64_t namePtr);
static void cacheClassName(uint64_t clazz, JNIEnv* env);
static void cacheClassNameFromDescriptor(uint64_t clazz, const char* name);
static void cacheObjectClass(uint64_t obj, uint64_t clazz);
static void cacheKnownRefClass(uint64_t ref, const char* className);
/* 引用句柄与类信息的关联：只在trace回调里做纯查表，不hook任何JNIEnv槽位 */
static void linkRefClassName(uint64_t srcRef, uint64_t newRef);
static void forgetRefClass(uint64_t ref);
static void installJniIdHooks();

/*
 * 开关"需要JNI调用的名称解析"(obj/clazz 类名)。
 * methodID/fieldID -> 名称 的缓存不依赖这个开关：hook在setup_jni_env/initJni里就已经装好，
 * 只要能拿到JNIEnv就持续记录，trace时只查表。
 */
void enable_jni_resolve(bool enable)
{
    jniResolveEnabled = enable;
    if (enable)
    {
        //兜底：JNIEnv已就绪但之前装hook失败(例如RELRO页不可写)时再试一次
        installJniIdHooks();
    }
}

/*
 * 查询地址所在内存映射的权限。perms 形如 "r-xp"：index0=r, index1=w, index2=x。
 * dlsym / ELF符号解析在某些机型上可能返回非可执行地址，直接调用会 access violation，
 * 调用前必须先校验，否则会把整个进程带崩。
 */
static bool getAddrPerms(size_t addr, char* perms, size_t size)
{
    if (addr == 0 || perms == nullptr || size < 4)
    {
        return false;
    }
    perms[0] = 0;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr)
    {
        LOGE("getAddrPerms: open maps fail");
        return false;
    }
    bool ok = false;
    char *line = nullptr;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1)
    {
        size_t start = 0;
        size_t end = 0;
        char tmp[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, tmp) == 3 &&
            addr >= start && addr < end)
        {
            snprintf(perms, size, "%s", tmp);
            ok = true;
            break;
        }
    }
    free(line);
    fclose(fp);
    return ok;
}

static bool isAddrWithPerm(size_t addr, int permIndex)
{
    char perms[8] = {0};
    if (!getAddrPerms(addr, perms, sizeof(perms)))
    {
        return false;
    }
    return perms[permIndex] != '-';
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

/* ---------------- JNIEnv 函数表 hook：记录 id -> 名称 ----------------
 * JNINativeInterface 是libart里的全局只读表，所有JNI调用都从这张表进入ART。
 * 把 GetMethodID/GetStaticMethodID/GetFieldID/GetStaticFieldID 换成包装函数后，
 * 进程内(包括trace开始前的JNI_OnLoad阶段)拿到的id都会带着名字写进缓存表，
 * 后续trace只查缓存，不再做JNI反射反查，简单且没有额外解析开销。
 */
typedef jmethodID (*JNIGetMethodIDFn)(JNIEnv*, jclass, const char*, const char*);
typedef jfieldID (*JNIGetFieldIDFn)(JNIEnv*, jclass, const char*, const char*);
typedef jclass (*JNIFindClassFn)(JNIEnv*, const char*);
typedef jclass (*JNIGetObjectClassFn)(JNIEnv*, jobject);

static JNIGetMethodIDFn g_orig_GetMethodID = nullptr;
static JNIGetMethodIDFn g_orig_GetStaticMethodID = nullptr;
static JNIGetFieldIDFn g_orig_GetFieldID = nullptr;
static JNIGetFieldIDFn g_orig_GetStaticFieldID = nullptr;
static JNIFindClassFn g_orig_FindClass = nullptr;
static JNIGetObjectClassFn g_orig_GetObjectClass = nullptr;
static bool g_jni_id_hook_installed = false;

static jmethodID JNICALL hook_GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig)
{
    jmethodID id = g_orig_GetMethodID != nullptr ? g_orig_GetMethodID(env, clazz, name, sig) : nullptr;
    //纯粹记账，不调用任何JNI，始终记录，保证trace时能直接查到名字
    cacheMethodName((uint64_t)id, (uint64_t)name);
    //签名也要记：Call*Method 的变参必须按签名逐个解码
    cacheMethodSig((uint64_t)id, (uint64_t)sig);
    cacheClassName((uint64_t)clazz, env);
    return id;
}

static jmethodID JNICALL hook_GetStaticMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig)
{
    jmethodID id = g_orig_GetStaticMethodID != nullptr ? g_orig_GetStaticMethodID(env, clazz, name, sig) : nullptr;
    cacheMethodName((uint64_t)id, (uint64_t)name);
    cacheMethodSig((uint64_t)id, (uint64_t)sig);
    cacheClassName((uint64_t)clazz, env);
    return id;
}

static jfieldID JNICALL hook_GetFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig)
{
    jfieldID id = g_orig_GetFieldID != nullptr ? g_orig_GetFieldID(env, clazz, name, sig) : nullptr;
    cacheFieldName((uint64_t)id, (uint64_t)name);
    cacheClassName((uint64_t)clazz, env);
    return id;
}

static jfieldID JNICALL hook_GetStaticFieldID(JNIEnv* env, jclass clazz, const char* name, const char* sig)
{
    jfieldID id = g_orig_GetStaticFieldID != nullptr ? g_orig_GetStaticFieldID(env, clazz, name, sig) : nullptr;
    cacheFieldName((uint64_t)id, (uint64_t)name);
    cacheClassName((uint64_t)clazz, env);
    return id;
}

/* FindClass 的返回值直接就是 jclass，类名来自入参，不需要任何反射 */
static jclass JNICALL hook_FindClass(JNIEnv* env, const char* name)
{
    jclass clazz = g_orig_FindClass != nullptr ? g_orig_FindClass(env, name) : nullptr;
    cacheClassNameFromDescriptor((uint64_t)clazz, name);
    return clazz;
}

/* GetObjectClass 记录 obj -> jclass，trace时就能反查 obj 的类名 */
static jclass JNICALL hook_GetObjectClass(JNIEnv* env, jobject obj)
{
    jclass clazz = g_orig_GetObjectClass != nullptr ? g_orig_GetObjectClass(env, obj) : nullptr;
    //返回的是新的局部引用，句柄值可能刚被ART复用给别的类：
    //先清掉这个句柄上的旧信息，否则 cacheClassName 会直接命中上次的类名
    forgetRefClass((uint64_t)clazz);
    cacheObjectClass((uint64_t)obj, (uint64_t)clazz);
    //类名缓存里还没有时，趁现在(不在QBDI里)补一次 Class.getName()
    cacheClassName((uint64_t)clazz, env);
    return clazz;
}

/*
 * 修改JNIEnv函数表里的一个函数指针槽位，原函数保存到origFunc里。
 * 该表在libart的RELRO段中，默认只读，先mprotect成可写，改完恢复原来的权限。
 */
static bool patchJniFuncSlot(void** slot, void* newFunc, void** origFunc)
{
    if (slot == nullptr || *slot == nullptr || newFunc == nullptr || origFunc == nullptr)
    {
        return false;
    }
    if (*slot == newFunc)
    {
        return true;    //已经装过了
    }
    char perms[8] = {0};
    if (!getAddrPerms((size_t)slot, perms, sizeof(perms)))
    {
        LOGE("jni resolve: read maps fail for %p", (void*)slot);
        return false;
    }
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0)
    {
        pageSize = 4096;
    }
    uintptr_t pageMask = (uintptr_t)pageSize - 1;
    uintptr_t pageStart = (uintptr_t)slot & ~pageMask;
    uintptr_t pageEnd = ((uintptr_t)slot + sizeof(void*) + pageMask) & ~pageMask;
    int prot = 0;
    if (perms[0] == 'r') prot |= PROT_READ;
    if (perms[1] == 'w') prot |= PROT_WRITE;
    if (perms[2] == 'x') prot |= PROT_EXEC;
    if (mprotect((void*)pageStart, pageEnd - pageStart, prot | PROT_WRITE) != 0)
    {
        LOGE("jni resolve: mprotect %p fail", (void*)slot);
        return false;
    }
    //对齐的8字节写入在arm64上是原子的，不需要额外同步
    *origFunc = *slot;
    *slot = newFunc;
    mprotect((void*)pageStart, pageEnd - pageStart, prot);
    return true;
}

/* 在JNIEnv函数表上装hook，失败时静默降级为只依赖QBDI trace到的GetMethodID */
static void installJniIdHooks()
{
    if (g_jni_id_hook_installed || pJFunc == nullptr)
    {
        return;
    }
    auto* funcs = const_cast<JNINativeInterface*>(pJFunc);
    bool ok = patchJniFuncSlot((void**)&funcs->GetMethodID, (void*)hook_GetMethodID,
                               (void**)&g_orig_GetMethodID);
    ok &= patchJniFuncSlot((void**)&funcs->GetStaticMethodID, (void*)hook_GetStaticMethodID,
                           (void**)&g_orig_GetStaticMethodID);
    ok &= patchJniFuncSlot((void**)&funcs->GetFieldID, (void*)hook_GetFieldID,
                           (void**)&g_orig_GetFieldID);
    ok &= patchJniFuncSlot((void**)&funcs->GetStaticFieldID, (void*)hook_GetStaticFieldID,
                           (void**)&g_orig_GetStaticFieldID);
    //类名相关：FindClass 直接带类名，GetObjectClass 给出 obj -> jclass 的对应关系
    ok &= patchJniFuncSlot((void**)&funcs->FindClass, (void*)hook_FindClass,
                           (void**)&g_orig_FindClass);
    ok &= patchJniFuncSlot((void**)&funcs->GetObjectClass, (void*)hook_GetObjectClass,
                           (void**)&g_orig_GetObjectClass);
    //注意：这里必须无条件置位。函数表一旦被patch，addJNItrace 注册的就是hook地址；
    //如果之后又重装并改动函数表，trace表里就只剩ART地址，目标代码直接调hook会trace不到
    //(表现为FindClass等函数完全没有 [JNI] 日志，只剩一行 "Call addr: ... libnativelib.so")。
    g_jni_id_hook_installed = true;
    LOGE("jni resolve: hook JNIEnv Get*ID/FindClass/GetObjectClass %s", ok ? "success" : "partial");
}

/* 函数表被hook后，注册QBDI trace要用原始ART函数地址，否则trace不到目标代码里的JNI调用 */
static void* jniOriginalFunc(void* target)
{
    if (target == (void*)hook_GetMethodID && g_orig_GetMethodID != nullptr)
    {
        return (void*)g_orig_GetMethodID;
    }
    if (target == (void*)hook_GetStaticMethodID && g_orig_GetStaticMethodID != nullptr)
    {
        return (void*)g_orig_GetStaticMethodID;
    }
    if (target == (void*)hook_GetFieldID && g_orig_GetFieldID != nullptr)
    {
        return (void*)g_orig_GetFieldID;
    }
    if (target == (void*)hook_GetStaticFieldID && g_orig_GetStaticFieldID != nullptr)
    {
        return (void*)g_orig_GetStaticFieldID;
    }
    if (target == (void*)hook_FindClass && g_orig_FindClass != nullptr)
    {
        return (void*)g_orig_FindClass;
    }
    if (target == (void*)hook_GetObjectClass && g_orig_GetObjectClass != nullptr)
    {
        return (void*)g_orig_GetObjectClass;
    }
    return target;
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
    //JNIEnv一就绪就装函数表hook，尽早开始记录 methodID/fieldID -> 名称
    installJniIdHooks();
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
    //拿到JNIEnv就立刻装hook：之后进程内所有GetMethodID/GetFieldID调用都会把id->名称记进缓存表，
    //比等到enable_jni_resolve(trace开始前)再装要早得多
    installJniIdHooks();
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

/* 清除我们自己在hook里触发的JNI异常，避免影响目标代码 */
static void clearExceptionOn(JNIEnv* env)
{
    if (pJFunc != nullptr && env != nullptr && pJFunc->ExceptionCheck(env))
    {
        pJFunc->ExceptionClear(env);
    }
}

/*
 * 懒加载 java.lang.Class 的全局引用：解析类名要用。
 * 失败返回nullptr(下次调用会重试)。
 */
static jclass ensureJavaLangClass(JNIEnv* env)
{
    if (g_java_lang_class != nullptr || env == nullptr || pJFunc == nullptr)
    {
        return g_java_lang_class;
    }
    jclass localClass = pJFunc->FindClass(env, "java/lang/Class");
    if (localClass == nullptr)
    {
        clearExceptionOn(env);
        return nullptr;
    }
    jclass globalClass = (jclass)pJFunc->NewGlobalRef(env, localClass);
    pJFunc->DeleteLocalRef(env, localClass);
    //局部句柄已释放，FindClass hook顺手记下的那条类名要一起清掉，避免句柄复用时张冠李戴
    forgetRefClass((uint64_t)localClass);
    if (globalClass == nullptr)
    {
        clearExceptionOn(env);
        return nullptr;
    }
    g_java_lang_class = globalClass;
    return g_java_lang_class;
}

/* 懒加载 Class.getName() 的methodID，methodID只能从 java.lang.Class 取 */
static jmethodID ensureClassGetNameMethod(JNIEnv* env)
{
    if (g_class_get_name != nullptr || env == nullptr || pJFunc == nullptr)
    {
        return g_class_get_name;
    }
    jclass classClass = ensureJavaLangClass(env);
    if (classClass == nullptr)
    {
        return nullptr;
    }
    //用原始GetMethodID，避免递归进入本文件的hook
    JNIGetMethodIDFn getMethodId = g_orig_GetMethodID != nullptr ? g_orig_GetMethodID
                                                                : pJFunc->GetMethodID;
    jmethodID method = getMethodId(env, classClass, "getName", "()Ljava/lang/String;");
    if (method == nullptr)
    {
        clearExceptionOn(env);
        return nullptr;
    }
    g_class_get_name = method;
    return g_class_get_name;
}

/*
 * 解析 jclass -> 类名 并缓存，供trace时直接查表。
 * 只允许在"当前线程没有跑QBDI trace"时调用：QBDI执行期间调JNI，一旦ART抛Java异常，它会走
 * Throwable.fillInStackTrace -> StackVisitor::WalkStack 去遍历被QBDI改写过的栈帧，读到垃圾指针
 * 直接SIGSEGV(加固so上必崩)。本函数在JNIEnv函数表hook里执行，是普通native上下文，安全。
 */
static void cacheClassName(uint64_t clazz, JNIEnv* env)
{
    if (clazz == 0 || env == nullptr || pJFunc == nullptr || !jniResolveEnabled)
    {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_jni_name_mutex);
        if (g_class_names.find(clazz) != g_class_names.end())
        {
            return;     //已经缓存过
        }
    }
    //QBDI执行期间绝对不碰JNI
    if (is_trace_running())
    {
        return;
    }
    //防止GetMethodID的hook递归回自己
    static thread_local bool resolving = false;
    if (resolving)
    {
        return;
    }
    struct ResolveGuard {
        bool& flag;
        explicit ResolveGuard(bool& f) : flag(f) { flag = true; }
        ~ResolveGuard() { flag = false; }
    } guard(resolving);

    jmethodID getNameMethod = ensureClassGetNameMethod(env);
    if (getNameMethod == nullptr)
    {
        return;
    }
    //clazz本身就是一个 java.lang.Class 实例，直接调 Class.getName()
    jstring jname = (jstring)pJFunc->CallObjectMethod(env, (jobject)clazz, getNameMethod);
    if (jname == nullptr)
    {
        clearExceptionOn(env);
        return;
    }
    const char* utf = pJFunc->GetStringUTFChars(env, jname, nullptr);
    if (utf != nullptr)
    {
        std::string name(utf);
        pJFunc->ReleaseStringUTFChars(env, jname, utf);
        std::lock_guard<std::mutex> lock(g_jni_name_mutex);
        g_class_names[clazz] = name;
    }
    else
    {
        clearExceptionOn(env);
    }
    pJFunc->DeleteLocalRef(env, jname);
}

/*
 * 输出obj/clazz的类名：只查缓存表，trace回调里不做任何JNI调用。
 * 缓存全部由JNIEnv函数表hook(installJniIdHooks)填充：
 *   FindClass(clazz)     -> jclass -> 类名
 *   GetObjectClass(obj)  -> obj -> jclass
 *   Get*ID(clazz,...)    -> 兜底用 Class.getName() 补类名
 * 所以obj会先查 obj->jclass，再查 jclass->类名。
 */
static bool resolveJavaClassName(uint64_t ref, char* out, size_t size)
{
    if (out == nullptr || size == 0)
    {
        return false;
    }
    out[0] = 0;
    if (ref == 0 || !jniResolveEnabled)
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    //优先用"创建时就确定类型"的记录(NewStringUTF/NewString/NewObject/FindClass)，
    //句柄值被ART复用后，obj->jclass 这条链路可能还指着上一个对象
    auto knownIt = g_ref_class_names.find(ref);
    if (knownIt != g_ref_class_names.end() && !knownIt->second.empty())
    {
        snprintf(out, size, "%s", knownIt->second.c_str());
        return true;
    }
    uint64_t cls = ref;
    auto objIt = g_object_classes.find(ref);
    if (objIt != g_object_classes.end())
    {
        cls = objIt->second;    //GetObjectClass hook记录过 obj -> jclass
    }
    auto it = g_class_names.find(cls);
    if (it == g_class_names.end() || it->second.empty())
    {
        return false;
    }
    snprintf(out, size, "%s", it->second.c_str());
    return true;
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
    if (methodId == 0 || namePtr == 0)
    {
        return;
    }
    char name[128] = {0};
    if (!readCStringSafe(namePtr, name, sizeof(name)) || name[0] == 0)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    g_method_names[methodId] = name;
}

static void cacheFieldName(uint64_t fieldId, uint64_t namePtr)
{
    if (fieldId == 0 || namePtr == 0)
    {
        return;
    }
    char name[128] = {0};
    if (!readCStringSafe(namePtr, name, sizeof(name)) || name[0] == 0)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    g_field_names[fieldId] = name;
}

/* GetMethodID/GetStaticMethodID 时把签名一起记下来：Call*Method 的变参要按签名解码 */
static void cacheMethodSig(uint64_t methodId, uint64_t sigPtr)
{
    if (methodId == 0 || sigPtr == 0)
    {
        return;
    }
    char sig[128] = {0};
    if (!readCStringSafe(sigPtr, sig, sizeof(sig)) || sig[0] != '(')
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    g_method_sigs[methodId] = sig;
}

/* FindClass 的入参是 "java/lang/String" 这种描述符，转成 "java.lang.String" 直接存进类名表 */
static void cacheClassNameFromDescriptor(uint64_t clazz, const char* name)
{
    if (clazz == 0 || name == nullptr || name[0] == 0 || !jniResolveEnabled)
    {
        return;
    }
    std::string cls(name);
    for (size_t i = 0; i < cls.size(); ++i)
    {
        if (cls[i] == '/')
        {
            cls[i] = '.';
        }
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    //句柄值可能被ART复用(上一个对象刚被回收)，先清掉旧映射
    g_object_classes.erase(clazz);
    g_ref_class_names[clazz] = cls;
    //FindClass 的返回值类型是确定的，两张表都写：linkRefClassName 靠 g_class_names 判断"引用的是类本身"
    g_class_names[clazz] = cls;
}

/* GetObjectClass 的返回值：记录 obj -> jclass，trace时反查 obj 的类名 */
static void cacheObjectClass(uint64_t obj, uint64_t clazz)
{
    if (obj == 0 || clazz == 0 || !jniResolveEnabled)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    //局部引用被ART复用，条目数量有限，这里再做一层上限保护
    if (g_object_classes.size() >= 8192)
    {
        return;
    }
    g_object_classes[obj] = clazz;
}

/*
 * 刚创建出来的引用，类型是确定的（用的是同一个句柄值也可能刚被回收复用），
 * 所以先把这个句柄上的旧映射清掉，再记真实类名，trace时优先查这张表。
 */
static void cacheKnownRefClass(uint64_t ref, const char* className)
{
    if (ref == 0 || className == nullptr || className[0] == 0 || !jniResolveEnabled)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    g_object_classes.erase(ref);
    g_class_names.erase(ref);
    g_ref_class_names[ref] = className;
}

/* ---------------- 引用句柄与类信息的关联 ----------------
 * NewGlobalRef/NewLocalRef 返回的是新句柄，ART里新句柄的值和源引用不相等；
 * DeleteGlobalRef/DeleteWeakGlobalRef 之后句柄值会被ART回收复用。
 * 这里只在QBDI的trace回调(trace_ReferenceFunc)里做纯查表的继承/删除，
 * 不hook任何JNIEnv槽位(在函数表上拦引用函数会造成崩溃)。
 */

/* 删掉一个句柄上的全部类信息 */
static void forgetRefClass(uint64_t ref)
{
    if (ref == 0)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    g_class_names.erase(ref);
    g_object_classes.erase(ref);
    g_ref_class_names.erase(ref);
}

/*
 * 把 srcRef 上缓存的类信息复制给新句柄 newRef（newRef = NewGlobalRef/NewLocalRef(srcRef)）。
 * 纯查表，不调用任何JNI，可以在QBDI trace回调里安全执行。
 */
static void linkRefClassName(uint64_t srcRef, uint64_t newRef)
{
    if (srcRef == 0 || newRef == 0 || srcRef == newRef || !jniResolveEnabled)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    //"创建即已知类型"的引用(NewStringUTF/NewObject/FindClass)直接有类名
    auto knownIt = g_ref_class_names.find(srcRef);
    if (knownIt != g_ref_class_names.end() && !knownIt->second.empty())
    {
        g_object_classes.erase(newRef);
        g_class_names.erase(newRef);
        g_ref_class_names[newRef] = knownIt->second;
        return;
    }
    //源引用是 jclass(FindClass/Get*ID 记过)：新句柄就是同一个类的jclass
    auto clsIt = g_class_names.find(srcRef);
    if (clsIt != g_class_names.end() && !clsIt->second.empty())
    {
        g_object_classes.erase(newRef);
        g_ref_class_names.erase(newRef);
        g_class_names[newRef] = clsIt->second;
        return;
    }
    //普通实例：新句柄仍是同一个类的实例，补一条 obj -> jclass
    auto objIt = g_object_classes.find(srcRef);
    if (objIt != g_object_classes.end() && objIt->second != 0)
    {
        if (g_object_classes.size() < 8192)
        {
            g_object_classes[newRef] = objIt->second;
        }
    }
}

/* 只查缓存 */
static bool lookupMethodName(uint64_t methodId, char* out, size_t size)
{
    if (out == nullptr || size == 0)
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    auto it = g_method_names.find(methodId);
    if (it == g_method_names.end() || it->second.empty())
    {
        return false;
    }
    snprintf(out, size, "%s", it->second.c_str());
    return true;
}

/*
 * 解析 jmethodID 对应的方法名：只查缓存表。
 * 缓存由JNIEnv函数表hook(GetMethodID/GetStaticMethodID)填充，
 * trace时不做任何JNI反射，命中不了就输出 <unknown>。
 */
static bool resolveMethodName(uint64_t methodId, char* out, size_t size)
{
    if (out == nullptr || size == 0)
    {
        return false;
    }
    out[0] = 0;
    if (methodId == 0)
    {
        return false;
    }
    return lookupMethodName(methodId, out, size);
}

/* 输出 "method = toString"，解析不到时输出 <unknown> */
static void appendMethodLine(uint64_t methodId)
{
    char name[128] = {0};
    if (resolveMethodName(methodId, name, sizeof(name)))
    {
        appendformat("      method = %s\n", name);
    }
    else
    {
        appendlog("      method = <unknown>\n");
    }
}

/* 输出 "field = mField"，来自 GetFieldID/GetStaticFieldID hook记录的缓存 */
static void appendFieldLine(uint64_t fieldId)
{
    std::string name;
    {
        std::lock_guard<std::mutex> lock(g_jni_name_mutex);
        auto it = g_field_names.find(fieldId);
        if (it != g_field_names.end())
        {
            name = it->second;
        }
    }
    if (!name.empty())
    {
        appendformat("      field = %s\n", name.c_str());
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
    bool isA = (strcmp(methodPos, "MethodA") == 0);

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
             isV ? "va_list args" : (isA ? "const jvalue *args" : "..."));
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

/* ---------------- 变参解码 ----------------
 * Call*Method / NewObject 的变参有两种形态：
 *   V 版本: AArch64 va_list = {void* stack; void* gr_top; void* vr_top; int gr_offs; int vr_offs;}
 *           通用参数在 gr_top + gr_offs(每槽8字节)，浮点参数在 vr_top + vr_offs(每槽16字节)
 *   非V版本: 参数直接放在 x3~x7(非虚调用是 x4~x7)
 *
 * 关键点：本trace的回调是**调用返回之后**才执行的，此时 ART 已经把 va_list 消费完
 * (gr_offs/vr_offs 被推进到末尾、__stack 也可能前进)，按结构体里的现成偏移去取只会读到
 * 保存区之外的脏数据 —— 以前固定读4个槽位，toString()/intern() 这种无参方法打出来的
 * 就是这么来的垃圾值。所以这里按 AAPCS64 的 va_start 规则还原起始偏移，
 * 再按被调方法的签名逐个取值(参数个数、类型都以签名为准)：
 *   gr_offs = -(8 - 命名通用参数个数) * 8     vr_offs = -(8 - 命名浮点参数个数) * 16
 */

/* 取方法签名(GetMethodID/GetStaticMethodID 时记录)，没有就返回false */
static bool lookupMethodSig(uint64_t methodId, std::string& out)
{
    if (methodId == 0)
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_jni_name_mutex);
    auto it = g_method_sigs.find(methodId);
    if (it == g_method_sigs.end() || it->second.empty())
    {
        return false;
    }
    out = it->second;
    return true;
}

/*
 * 从签名里取下一个参数描述符：*p 指向 '(' 之后(或上一个参数之后)。
 * 返回参数类型字符：'Z'/'B'/'C'/'S'/'I'/'J'/'F'/'D'，对象和数组统一返回 'L'；
 * 完整描述符(如 "Ljava/lang/String;"、"[B")拷贝到 desc。签名结束返回 0。
 */
static char nextParamDesc(const char** p, char* desc, size_t descSize)
{
    if (p == nullptr || *p == nullptr)
    {
        return 0;
    }
    const char* start = *p;
    while (**p == '[')
    {
        ++(*p);
    }
    char kind = **p;
    if (kind == 0 || kind == ')' || kind == 'V')
    {
        return 0;
    }
    if (kind == 'L')
    {
        const char* end = strchr(*p, ';');
        if (end == nullptr)
        {
            return 0;
        }
        *p = end + 1;
    }
    else
    {
        ++(*p);
    }
    if (desc != nullptr && descSize > 0)
    {
        size_t len = (size_t)(*p - start);
        if (len >= descSize)
        {
            len = descSize - 1;
        }
        memcpy(desc, start, len);
        desc[len] = 0;
    }
    return kind;
}

/*
 * 输出一个参数值。arrayDesc 非空表示是数组/对象描述符(如 "[B"、"Ljava/lang/String;")。
 * floatIsPromoted: C 可变参数里 float 会提升成 double(V版本读到的是 double)，
 * 而 jvalue 数组里存的是原始 4 字节 float。
 */
static void appendJValueArg(char kind, const char* arrayDesc, uint64_t value, bool floatIsPromoted)
{
    switch (kind)
    {
        case 'Z': appendformat("jboolean %s", value ? "true" : "false"); return;
        case 'B': appendformat("jbyte %d", (int)(int8_t)(uint8_t)value); return;
        case 'C': appendformat("jchar 0x%x", (unsigned)(uint16_t)value); return;
        case 'S': appendformat("jshort %d", (int)(int16_t)(uint16_t)value); return;
        case 'I': appendformat("jint %d", (int)(int32_t)(uint32_t)value); return;
        case 'J': appendformat("jlong 0x%lx", value); return;
        case 'F':
        {
            float f = 0;
            if (floatIsPromoted)
            {
                double d = 0;
                memcpy(&d, &value, sizeof(d));
                f = (float)d;
            }
            else
            {
                memcpy(&f, &value, sizeof(f));
            }
            appendformat("jfloat %g", (double)f);
            return;
        }
        case 'D':
        {
            double d = 0;
            memcpy(&d, &value, sizeof(d));
            appendformat("jdouble %g", d);
            return;
        }
        default:
        {
            if (arrayDesc != nullptr)
            {
                appendformat("%s@0x%lx", arrayDesc, value);
                return;
            }
            char cls[256] = {0};
            if (value != 0 && resolveJavaClassName(value, cls, sizeof(cls)))
            {
                appendformat("%s@0x%lx", cls, value);
            }
            else
            {
                appendformat("jobject@0x%lx", value);
            }
            return;
        }
    }
}

/*
 * 解析 V 版本。namedGp 是该 JNI 入口的命名通用参数个数：
 * Call*Method/CallStatic*Method/NewObject* 为 3，CallNonvirtual*Method 为 4。
 */
static void appendVaList(uint64_t va, uint64_t methodId, int namedGp)
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
    std::string sig;
    if (!lookupMethodSig(methodId, sig))
    {
        //没有签名就不知道有几个参数：宁可不输出，也不把保存区里的脏槽位当参数打出来
        appendformat(", args=<sig unknown, va=0x%lx>", va);
        return;
    }
    if (namedGp < 0)
    {
        namedGp = 0;
    }
    if (namedGp > 8)
    {
        namedGp = 8;
    }
    //va_start 的初值，不能用结构体里已经被消费过的偏移
    int64_t grOffs = -(int64_t)(8 - namedGp) * 8;
    int64_t vrOffs = -(int64_t)(8 * 16);     //这些JNI入口没有浮点命名参数
    const uint64_t grBase = vaList.gr_top;
    const uint64_t vrBase = vaList.vr_top;

    appendlog(", args=[");
    const char* p = sig.c_str();
    if (*p == '(')
    {
        ++p;
    }
    int count = 0;
    while (true)
    {
        char desc[64] = {0};
        char kind = nextParamDesc(&p, desc, sizeof(desc));
        if (kind == 0)
        {
            break;
        }
        uint64_t value = 0;
        bool ok = false;
        if (kind == 'F' || kind == 'D')
        {
            if (vrOffs < 0 &&
                safeReadMemory((uint64_t)((int64_t)vrBase + vrOffs), (uint8_t*)&value, sizeof(value)))
            {
                vrOffs += 16;
                ok = true;
            }
        }
        else if (grOffs < 0 &&
                 safeReadMemory((uint64_t)((int64_t)grBase + grOffs), (uint8_t*)&value, sizeof(value)))
        {
            grOffs += 8;
            ok = true;
        }
        if (count > 0)
        {
            appendlog(", ");
        }
        if (!ok)
        {
            //参数超过寄存器槽位(落到栈上)或内存读不到
            appendlog("...");
            break;
        }
        appendJValueArg(kind, desc[0] == '[' ? desc : nullptr, value, true);
        ++count;
    }
    appendlog("]");
}

/*
 * 解析非V版本(可变参数直接放在寄存器里)：从 x{firstIdx} 开始。
 * 浮点参数在 v0~v7，回调只拿到GPR状态，取不到值，只能标出位置。
 */
static void appendRegArgs(QBDI::GPRState *gprState, int firstIdx, uint64_t methodId)
{
    std::string sig;
    if (!lookupMethodSig(methodId, sig))
    {
        //没有签名：退化成原始寄存器槽位，明确标出是猜的
        for (int i = firstIdx; i <= 7; ++i)
        {
            appendformat(", arg%d=0x%lx", i - firstIdx, QBDI_GPR_GET(gprState, i));
        }
        return;
    }
    appendlog(", args=[");
    const char* p = sig.c_str();
    if (*p == '(')
    {
        ++p;
    }
    int gp = firstIdx;
    int fp = 0;
    int count = 0;
    while (true)
    {
        char desc[64] = {0};
        char kind = nextParamDesc(&p, desc, sizeof(desc));
        if (kind == 0)
        {
            break;
        }
        if (count > 0)
        {
            appendlog(", ");
        }
        if (kind == 'F' || kind == 'D')
        {
            appendformat("j%s <in v%d>", kind == 'F' ? "float" : "double", fp);
            ++fp;
        }
        else if (gp <= 7)
        {
            appendJValueArg(kind, desc[0] == '[' ? desc : nullptr, QBDI_GPR_GET(gprState, gp), true);
            ++gp;
        }
        else
        {
            appendlog("...");
            break;
        }
        ++count;
    }
    appendlog("]");
}

/* 解析 A 版本：const jvalue* 是连续的 8 字节 union 数组，按签名顺序读 */
static void appendJValues(uint64_t ptr, uint64_t methodId)
{
    if (ptr == 0)
    {
        appendlog(", jvalues=0x0");
        return;
    }
    std::string sig;
    if (!lookupMethodSig(methodId, sig))
    {
        appendformat(", jvalues=0x%lx", ptr);
        return;
    }
    appendlog(", args=[");
    const char* p = sig.c_str();
    if (*p == '(')
    {
        ++p;
    }
    int count = 0;
    while (true)
    {
        char desc[64] = {0};
        char kind = nextParamDesc(&p, desc, sizeof(desc));
        if (kind == 0)
        {
            break;
        }
        uint64_t value = 0;
        bool ok = safeReadMemory(ptr + (uint64_t)count * sizeof(jvalue),
                                 (uint8_t*)&value, sizeof(value));
        if (count > 0)
        {
            appendlog(", ");
        }
        if (!ok)
        {
            appendlog("...");
            break;
        }
        appendJValueArg(kind, desc[0] == '[' ? desc : nullptr, value, false);
        ++count;
    }
    appendlog("]");
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
    cacheKnownRefClass((uint64_t)g_deferred_call_retval, "java.lang.String");
    appendformat("      return x0 = 0x%lx (java.lang.String)\n", (uint64_t)g_deferred_call_retval);
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
    //NewStringUTF 返回的一定是 java.lang.String：直接记下，句柄被复用也不会显示成别的类
    cacheKnownRefClass((uint64_t)g_deferred_call_retval, "java.lang.String");
    appendformat("      return x0 = 0x%lx (java.lang.String)\n", (uint64_t)g_deferred_call_retval);
}

/*
 * Call*Method / CallStatic*Method 系列通用回调。
 * 函数名由注册时传入(addJNITrace)，延迟回调执行前会写入 g_deferred_call_name。
 *  - JNIEnv*: x0, jobject/jclass: x1, jmethodID: x2
 *  - V 版本: x3 = va_list；A 版本: x3 = const jvalue*；非V版本: x3~x7 就是可变参数
 *  - 变参按 GetMethodID 记下的方法签名解码(appendVaList/appendJValues/appendRegArgs)
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
    bool isJvalues = (nameLen > 0 && name[nameLen - 1] == 'A');

    uint64_t env = QBDI_GPR_GET(gprState, 0);
    uint64_t obj = QBDI_GPR_GET(gprState, 1);
    uint64_t methodId = QBDI_GPR_GET(gprState, 2);
    uint64_t args = QBDI_GPR_GET(gprState, 3);

    appendformat("  [JNI] %s(env=0x%lx, %s=0x%lx, methodID=0x%lx",
                 name, env, isStatic ? "clazz" : "obj", obj, methodId);
    if (isVaList)
    {
        //V版本: x3 是 va_list，按方法签名解码
        appendVaList(args, methodId, 3);
    }
    else if (isJvalues)
    {
        //A版本: x3 是 const jvalue*，按方法签名逐个读
        appendJValues(args, methodId);
    }
    else
    {
        //非V版本: 可变参数直接在 x3~x7 里
        appendRegArgs(gprState, 3, methodId);
    }
    appendlog(")\n");
    appendJniPrototype(name);
    appendJavaClassLine(isStatic ? "clazz" : "obj", obj);
    appendMethodLine(methodId);
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
            appendVaList(args, methodId, 3);
        }
        else if (strcmp(name, "NewObjectA") == 0)
        {
            appendJValues(args, methodId);
        }
        else
        {
            appendRegArgs(gprState, 3, methodId);
        }
    }
    appendlog(")\n");
    appendJniPrototype(name);
    appendJavaClassLine("clazz", clazz);
    //NewObject/AllocObject 返回的一定是 clazz 的实例：按类名直接记账，句柄复用也不会串类
    {
        char cls[256] = {0};
        if (g_deferred_call_retval != 0 && resolveJavaClassName(clazz, cls, sizeof(cls)))
        {
            cacheKnownRefClass((uint64_t)g_deferred_call_retval, cls);
        }
    }
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
    if (strcmp(name, "DeleteGlobalRef") == 0 || strcmp(name, "DeleteWeakGlobalRef") == 0)
    {
        //句柄已经被ART回收，后面可能复用给别的对象/类，类信息一起删掉(纯查表，不调JNI)
        forgetRefClass(x1);
    }
    else
    {
        appendJniReturn(name, (uint64_t)g_deferred_call_retval);
        if ((strcmp(name, "NewGlobalRef") == 0 || strcmp(name, "NewLocalRef") == 0) &&
            g_deferred_call_retval != 0)
        {
            //新句柄的值和源引用不相等，把源引用上的类信息继承过来，trace时才能显示类名
            linkRefClassName(x1, (uint64_t)g_deferred_call_retval);
            appendJavaClassLine("ref", (uint64_t)g_deferred_call_retval);
        }
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
    bool isJvalues = (nameLen > 0 && name[nameLen - 1] == 'A');
    appendformat("  [JNI] %s(obj=0x%lx, clazz=0x%lx, methodID=0x%lx", name, obj, clazz, methodId);
    if (isVaList)
    {
        //非虚调用多一个 jclass 命名参数(env/obj/clazz/methodID)，va_list 从 x4 开始
        appendVaList(QBDI_GPR_GET(gprState, 4), methodId, 4);
    }
    else if (isJvalues)
    {
        //A版本x4是const jvalue*
        appendJValues(QBDI_GPR_GET(gprState, 4), methodId);
    }
    else
    {
        //非虚调用参数从 x4 开始
        appendRegArgs(gprState, 4, methodId);
    }
    appendlog(")\n");
    appendJniPrototype(name);
    appendJavaClassLine("obj", obj);
    appendJavaClassLine("clazz", clazz);
    appendMethodLine(methodId);
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

/* 重新同步trace表时不需要打印"已注册"的日志 */
static bool g_jni_trace_quiet = false;

void setJNITraceQuiet(bool quiet)
{
    g_jni_trace_quiet = quiet;
}

/* 注册一个JNI trace地址(地址 -> 回调)，已注册过则跳过 */
static void addJNITraceEntry(void* target, const char* funcname, TraceCallBack callback)
{
    if (target == nullptr)
    {
        return;
    }
    auto it = _g_jni_trace->map.find((size_t)target);
    if (it != _g_jni_trace->map.end())
    {
        if (!g_jni_trace_quiet)
        {
            LOGE("jnitrace: %p has installed!", target);
        }
        return;
    }
    auto* jni_trace_func = new TraceFunc();
    jni_trace_func->callback = callback;
    jni_trace_func->name = funcname;
    _g_jni_trace->map[(size_t)target] = jni_trace_func;
    if (!g_jni_trace_quiet)
    {
        LOGE("jnitrace: %s,%p install", funcname, target);
    }
}

void addJNITrace(void* target,const char* funcname,TraceCallBack callback)
{
    if(_g_jni_trace == nullptr)
    {
        LOGE("jnitrace: not init!");
        return;
    }
    //Get*ID被解析hook接管时，目标代码通过函数表拿到的是我们的hook地址:
    //原始ART地址和hook地址都注册，bl直接调用和blr间接调用都能命中同一个回调
    void* orig = jniOriginalFunc(target);
    addJNITraceEntry(orig, funcname, callback);
    if (orig != target)
    {
        addJNITraceEntry(target, funcname, callback);
    }
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