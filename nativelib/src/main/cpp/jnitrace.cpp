//
// Created by zgy on 2025/10/30.
//

#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include "jnitrace.h"
#include "HookUtils.h"
#include "TraceUtils.h"
#include "logger.h"

const JNINativeInterface* pJFunc = nullptr;
 JNIEnv * jniEnv = nullptr;
JNITraceMap* _g_jni_trace = nullptr;
static bool debug = false;

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

void trace_FindClass(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t classname = QBDI_GPR_GET(gprState, 1);
    appendlog("  [JNI] FindClass(");
    appendStringArg(classname);
    appendlog(")\n");
}

void trace_GetStringUTFChars(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t jstr = QBDI_GPR_GET(gprState,1);
    uint64_t isCopy = QBDI_GPR_GET(gprState,2);
    //返回值(x0)就是转换后的C字符串指针
    appendformat("  [JNI] GetStringUTFChars(string=0x%lx, isCopy=0x%lx) -> ", jstr, isCopy);
    appendStringArg((uint64_t)g_deferred_call_retval);
    appendlog("\n");
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
    appendformat("  [JNI] GetByteArrayElements(array=0x%lx, isCopy=0x%lx) -> buf=0x%lx\n",
                 arr, isCopy, (uint64_t)g_deferred_call_retval);
}

void trace_GetArrayLength(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t arr = QBDI_GPR_GET(gprState,1);
    //返回值(x0)是jsize
    appendformat("  [JNI] GetArrayLength(array=0x%lx) -> %d\n",
                 arr, (int)(int32_t)(uint32_t)g_deferred_call_retval);
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
    if (len > 0)
    {
        appendHexdump(buf, (uint64_t)len, 256);
    }
}

void trace_GetIntField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t obj = QBDI_GPR_GET(gprState,1);
    uint64_t fieldId = QBDI_GPR_GET(gprState,2);
    //返回值(x0)是jint字段值
    appendformat("  [JNI] GetIntField(obj=0x%lx, fieldID=0x%lx) -> 0x%x\n",
                 obj, fieldId, (uint32_t)g_deferred_call_retval);
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
}

void trace_CallStaticObjectMethodV(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t clazz = QBDI_GPR_GET(gprState,1);
    uint64_t methodId = QBDI_GPR_GET(gprState,2);
    uint64_t args = QBDI_GPR_GET(gprState,3);
    appendformat("  [JNI] CallStaticObjectMethodV(clazz=0x%lx, methodID=0x%lx, args=0x%lx) -> 0x%lx\n",
                 clazz, methodId, args, (uint64_t)g_deferred_call_retval);
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
}
void trace_GetLongField(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t obj = QBDI_GPR_GET(gprState,1);
    uint64_t fieldId = QBDI_GPR_GET(gprState,2);
    //返回值(x0)是jlong字段值
    appendformat("  [JNI] GetLongField(obj=0x%lx, fieldID=0x%lx) -> 0x%lx\n",
                 obj, fieldId, (uint64_t)g_deferred_call_retval);
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
}

void trace_NewStringUTF(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    if(!checkSetup())
    {
        return;
    }
    uint64_t bytes = QBDI_GPR_GET(gprState, 1);
    appendlog("  [JNI] NewStringUTF(");
    appendStringArg(bytes);
    appendlog(")\n");
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