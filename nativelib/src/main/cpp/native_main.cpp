#include <jni.h>
#include <dlfcn.h>
#include <mutex>
#include "vm.h"
#include "HookUtils.h"
#include "qbdihook.h"
#include "jnitrace.h"
#include "libctrace.h"
#include "lingyi_vm.h"
using namespace std;

static void addHooks()
{
    addHook(0x71DD54,hook_0x71DD54);
}

static void addLibctrace()
{
    void * handle = dlopen("libc.so",RTLD_LAZY);
    if(handle == nullptr)
    {
        LOGE("dlopen libc fail");
        return;
    }
    addLibctrace(handle,libc_access,"access");
    addLibctrace(handle,libc_system_property_get,"__system_property_get");
    addLibctrace(handle,libc_memcpy,"memcpy");
    addLibctrace(handle,libc_pthread_create,"pthread_create");
    addLibctrace(handle,libc_fopen,"fopen");
    addLibctrace(handle,libc_lstat,"lstat");
    addLibctrace(handle,libc_stat,"stat");
    addLibctrace(handle,libc_fstatat,"fstatat");
    addLibctrace(handle,libc_execve,"execve");
    addLibctrace(handle,libc_clock_gettime,"clock_gettime");
    addLibctrace(handle,libc_strlen,"strlen");
    addLibctrace(handle,libc_strcmp,"strcmp");
    addLibctrace(handle,libc_memmove,"memmove");
    addLibctrace(handle,libc_memset,"memset");
    addLibctrace(handle,libc_kill,"kill");
    addLibctrace(handle,libc_abort,"abort");
    addLibctrace(handle,libc_exit,"exit");
    dlclose(handle);
}

static void addJNItrace()
{
    //initJni失败时pJFunc为空，直接解引用会崩溃，这里必须判空
    if(pJFunc == nullptr)
    {
        LOGE("jni trace disabled: pJFunc is null");
        return;
    }
    addJNITrace((void*)pJFunc->NewStringUTF,"NewStringUTF",trace_NewStringUTF);
    addJNITrace((void*)pJFunc->GetStringUTFChars,"GetStringUTFChars",trace_GetStringUTFChars);
    addJNITrace((void*)pJFunc->NewString,"NewString",trace_NewString);
    addJNITrace((void*)pJFunc->FindClass,"FindClass",trace_FindClass);
    addJNITrace((void*)pJFunc->GetFieldID,"GetFieldID",trace_GetFieldID);
    addJNITrace((void*)pJFunc->GetMethodID,"GetMethodID",trace_GetMethodID);
    addJNITrace((void*)pJFunc->RegisterNatives,"RegisterNatives",trace_RegisterNatives);
    addJNITrace((void*)pJFunc->GetLongField,"GetLongField",trace_GetLongField);
    addJNITrace((void*)pJFunc->GetStaticMethodID,"GetStaticMethodID",trace_GetStaticMethodID);
    addJNITrace((void*)pJFunc->CallStaticObjectMethodV,"CallStaticObjectMethodV",trace_CallStaticObjectMethodV);
    addJNITrace((void*)pJFunc->GetStaticFieldID,"GetStaticFieldID",trace_GetStaticFieldID);
    addJNITrace((void*)pJFunc->GetIntField,"GetIntField",trace_GetIntField);
    addJNITrace((void*)pJFunc->GetByteArrayRegion,"GetByteArrayRegion",trace_GetByteArrayRegion);
    addJNITrace((void*)pJFunc->GetArrayLength,"GetArrayLength",trace_GetArrayLength);
    addJNITrace((void*)pJFunc->GetByteArrayElements,"GetByteArrayElements",trace_GetByteArrayElements);
}

/* trace环境初始化：只会在第一次调用 lingyi_vm_init / lingyi_vm_call 时执行一次 */
static std::once_flag g_trace_init_flag;

static void initTraceEnv()
{
    //trace buffer 累计多少字节往本地写一次。设置为0表示每trace一条指令就写入本地
    setBufferSize(0x10000000);//每256M写一次

    //是否开启逐指令日志，每条指令trace都会输出在logcat中，数据量巨大，用于调试时使用。
    enableDebugInsn(false);

    //是否开启jni trace 日志，可在logcat中查看jni调用
    enable_jni_trace_debug(true);

    //是否开启libc trace 日志，可在logcat中查看libc调用
    enable_libc_trace_debug(true);

    /*JNI Trace*/
    initJni();
    //添加监控的jni函数
    addJNItrace();

    /*libc Trace*/
    initLibcTrace();
    //添加监控的libc函数
    addLibctrace();

    /*自定义hook监控*/
    initHookData();
    //添加目标so的hook点位
    addHooks();
}

/*
 * 只初始化trace环境（JNI/libc/自定义hook表），不执行trace。
 * 用于把"环境初始化"和"QBDI执行目标函数"两步分开排查，frida可直接调用。
 * @return 0 表示初始化流程执行完成
 */
extern "C" __attribute__((visibility("default")))
int lingyi_vm_init(void)
{
    LOGI("lingyi_vm_init enter");
    std::call_once(g_trace_init_flag, initTraceEnv);
    LOGI("lingyi_vm_init done");
    return 0;
}

/*
 * 由frida把JNIEnv直接传给QTrace，绕开设备上 JNI_GetCreatedJavaVMs 找不到/地址无效的问题。
 * frida侧：lingyi_vm_set_jnienv(Java.vm.getEnv().handle)，建议在 lingyi_vm_call 之前调用。
 * @return 0 成功，-1 失败
 */
extern "C" __attribute__((visibility("default")))
int lingyi_vm_set_jnienv(void *jni_env)
{
    if (setup_jni_env(jni_env) != 0)
    {
        return -1;
    }
    //如果initTraceEnv里JNI没初始化成功，这里补装JNI trace
    addJNItrace();
    LOGI("lingyi_vm_set_jnienv done,env:%p", jni_env);
    return 0;
}

/*
 * 对外导出的trace接口，frida可以直接调用（不再依赖shadowhook inline hook）：
 *   var vmCall = new NativeFunction(addr, 'pointer',
 *              ['pointer','pointer','uint32','pointer','uint32']);
 *   var ret = vmCall(targetFunc, argsPtr, argNum, logPathPtr, 0);
 */
extern "C" __attribute__((visibility("default")))
size_t lingyi_vm_call(void *func_addr, size_t *args, uint32_t arg_num, const char *log_path, uint32_t flags)
{
    std::call_once(g_trace_init_flag, initTraceEnv);

    if (flags != LINGYI_VM_FLAG_NONE)
    {
        LOGW("lingyi_vm_call: flags(0x%x) is reserved, ignored", flags);
    }

    LOGI("lingyi_vm_call target:%p,arg_num:%u,log:%s", func_addr, arg_num,
         log_path != nullptr ? log_path : "default");

    return trace_call(func_addr, args, arg_num, log_path);
}

// no auto trace after injection, call lingyi_vm_call from frida
__unused __attribute__((constructor)) void init_main() {
    LOGE("Injected! call lingyi_vm_call to start trace");
}