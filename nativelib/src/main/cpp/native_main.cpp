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
    /*
     * 库函数 trace 表只安装一次：
     *  - std::call_once 保证多线程/多次进入 initTraceEnv 时也只有第一次真正注册；
     *  - addLibctrace(handle,...) 内部还会按地址查重，所以即使别处再调一遍，
     *    也只是打印 "already installed" 后跳过，不会覆盖已有回调、也不会泄漏 TraceFunc。
     * 之前"每次trace都重装库函数钩子"的担心不会发生：trace_call 只做 QBDI 重放，
     * 不会调用 initTraceEnv；表是全局的，后续调用直接复用。
     */
    static std::once_flag libc_trace_once;
    std::call_once(libc_trace_once, []()
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
        addLibctrace(handle,libc_strncmp,"strncmp");
        addLibctrace(handle,libc_strstr,"strstr");
        addLibctrace(handle,libc_strcpy,"strcpy");
        addLibctrace(handle,libc_strncpy,"strncpy");
        addLibctrace(handle,libc_memcmp,"memcmp");
        //常用内存/文件函数
        addLibctrace(handle,libc_malloc,"malloc");
        addLibctrace(handle,libc_free,"free");
        addLibctrace(handle,libc_calloc,"calloc");
        addLibctrace(handle,libc_realloc,"realloc");
        addLibctrace(handle,libc_getenv,"getenv");
        addLibctrace(handle,libc_open,"open");
        addLibctrace(handle,libc_openat,"openat");
        addLibctrace(handle,libc_read,"read");
        addLibctrace(handle,libc_write,"write");
        addLibctrace(handle,libc_close,"close");
        //bionic内部实现，dlsym找不到时addLibctrace会回退到ELF动态符号表解析
        addLibctrace(handle,libc_strlen,"__strlen_aarch64");
        addLibctrace(handle,libc_memset,"__memset_aarch64");
        //内存映射 / 动态符号 / 字符串复制
        addLibctrace(handle,libc_mmap,"mmap");
        addLibctrace(handle,libc_munmap,"munmap");
        addLibctrace(handle,libc_dlsym,"dlsym");
        addLibctrace(handle,libc_strdup,"strdup");
        //线程同步函数
        addLibctrace(handle,libc_pthread_mutex_lock,"pthread_mutex_lock");
        addLibctrace(handle,libc_pthread_mutex_unlock,"pthread_mutex_unlock");
        addLibctrace(handle,libc_pthread_rwlock_init,"pthread_rwlock_init");
        addLibctrace(handle,libc_pthread_rwlock_unlock,"pthread_rwlock_unlock");

        dlclose(handle);
        LOGE("libc trace: %zu entries installed (once)",
             _g_libc_trace != nullptr ? _g_libc_trace->map.size() : 0);
    });
}

static void addJNItrace()
{
    //initJni失败时pJFunc为空，直接解引用会崩溃，这里必须判空
    if(pJFunc == nullptr)
    {
        LOGE("jni trace disabled: pJFunc is null");
        return;
    }
    /* 字符串相关 */
    addJNITrace((void*)pJFunc->NewStringUTF,"NewStringUTF",trace_NewStringUTF);
    addJNITrace((void*)pJFunc->GetStringUTFChars,"GetStringUTFChars",trace_GetStringUTFChars);
    addJNITrace((void*)pJFunc->ReleaseStringUTFChars,"ReleaseStringUTFChars",trace_StringFunc);
    addJNITrace((void*)pJFunc->NewString,"NewString",trace_NewString);
    addJNITrace((void*)pJFunc->GetStringLength,"GetStringLength",trace_StringLengthFunc);
    addJNITrace((void*)pJFunc->GetStringUTFLength,"GetStringUTFLength",trace_StringLengthFunc);
    addJNITrace((void*)pJFunc->GetStringChars,"GetStringChars",trace_StringFunc);
    addJNITrace((void*)pJFunc->ReleaseStringChars,"ReleaseStringChars",trace_StringFunc);
    addJNITrace((void*)pJFunc->GetStringRegion,"GetStringRegion",trace_StringFunc);
    addJNITrace((void*)pJFunc->GetStringUTFRegion,"GetStringUTFRegion",trace_StringFunc);

    /* 类/反射相关 */
    addJNITrace((void*)pJFunc->FindClass,"FindClass",trace_FindClass);
    addJNITrace((void*)pJFunc->GetObjectClass,"GetObjectClass",trace_GetObjectClass);
    addJNITrace((void*)pJFunc->GetSuperclass,"GetSuperclass",trace_ClassFunc);
    addJNITrace((void*)pJFunc->IsAssignableFrom,"IsAssignableFrom",trace_ClassFunc);
    addJNITrace((void*)pJFunc->IsInstanceOf,"IsInstanceOf",trace_ClassFunc);
    addJNITrace((void*)pJFunc->GetObjectRefType,"GetObjectRefType",trace_ClassFunc);

    /* 字段读写：Get/Set<Type>Field 与 Static 版本统一走 trace_GetField */
#define ADD_JNI_FIELD_TRACE(fn) addJNITrace((void*)pJFunc->fn, #fn, trace_GetField)
    ADD_JNI_FIELD_TRACE(GetObjectField);
    ADD_JNI_FIELD_TRACE(GetBooleanField);
    ADD_JNI_FIELD_TRACE(GetByteField);
    ADD_JNI_FIELD_TRACE(GetCharField);
    ADD_JNI_FIELD_TRACE(GetShortField);
    ADD_JNI_FIELD_TRACE(GetIntField);
    ADD_JNI_FIELD_TRACE(GetLongField);
    ADD_JNI_FIELD_TRACE(GetFloatField);
    ADD_JNI_FIELD_TRACE(GetDoubleField);
    ADD_JNI_FIELD_TRACE(SetObjectField);
    ADD_JNI_FIELD_TRACE(SetBooleanField);
    ADD_JNI_FIELD_TRACE(SetByteField);
    ADD_JNI_FIELD_TRACE(SetCharField);
    ADD_JNI_FIELD_TRACE(SetShortField);
    ADD_JNI_FIELD_TRACE(SetIntField);
    ADD_JNI_FIELD_TRACE(SetLongField);
    ADD_JNI_FIELD_TRACE(SetFloatField);
    ADD_JNI_FIELD_TRACE(SetDoubleField);
    ADD_JNI_FIELD_TRACE(GetStaticObjectField);
    ADD_JNI_FIELD_TRACE(GetStaticBooleanField);
    ADD_JNI_FIELD_TRACE(GetStaticByteField);
    ADD_JNI_FIELD_TRACE(GetStaticCharField);
    ADD_JNI_FIELD_TRACE(GetStaticShortField);
    ADD_JNI_FIELD_TRACE(GetStaticIntField);
    ADD_JNI_FIELD_TRACE(GetStaticLongField);
    ADD_JNI_FIELD_TRACE(GetStaticFloatField);
    ADD_JNI_FIELD_TRACE(GetStaticDoubleField);
    ADD_JNI_FIELD_TRACE(SetStaticObjectField);
    ADD_JNI_FIELD_TRACE(SetStaticBooleanField);
    ADD_JNI_FIELD_TRACE(SetStaticByteField);
    ADD_JNI_FIELD_TRACE(SetStaticCharField);
    ADD_JNI_FIELD_TRACE(SetStaticShortField);
    ADD_JNI_FIELD_TRACE(SetStaticIntField);
    ADD_JNI_FIELD_TRACE(SetStaticLongField);
    ADD_JNI_FIELD_TRACE(SetStaticFloatField);
    ADD_JNI_FIELD_TRACE(SetStaticDoubleField);
#undef ADD_JNI_FIELD_TRACE

    addJNITrace((void*)pJFunc->GetFieldID,"GetFieldID",trace_GetFieldID);
    addJNITrace((void*)pJFunc->GetMethodID,"GetMethodID",trace_GetMethodID);
    addJNITrace((void*)pJFunc->RegisterNatives,"RegisterNatives",trace_RegisterNatives);
    addJNITrace((void*)pJFunc->UnregisterNatives,"UnregisterNatives",trace_GenericJni);
    addJNITrace((void*)pJFunc->GetStaticMethodID,"GetStaticMethodID",trace_GetStaticMethodID);
    //Call*Method / CallStatic*Method 系列：统一由 trace_CallMethod 处理，函数名在注册时传入
#define ADD_JNI_CALL_TRACE(fn) addJNITrace((void*)pJFunc->fn, #fn, trace_CallMethod)
    ADD_JNI_CALL_TRACE(CallObjectMethod);
    ADD_JNI_CALL_TRACE(CallObjectMethodV);
    ADD_JNI_CALL_TRACE(CallObjectMethodA);
    ADD_JNI_CALL_TRACE(CallBooleanMethod);
    ADD_JNI_CALL_TRACE(CallBooleanMethodV);
    ADD_JNI_CALL_TRACE(CallBooleanMethodA);
    ADD_JNI_CALL_TRACE(CallByteMethod);
    ADD_JNI_CALL_TRACE(CallByteMethodV);
    ADD_JNI_CALL_TRACE(CallByteMethodA);
    ADD_JNI_CALL_TRACE(CallCharMethod);
    ADD_JNI_CALL_TRACE(CallCharMethodV);
    ADD_JNI_CALL_TRACE(CallCharMethodA);
    ADD_JNI_CALL_TRACE(CallShortMethod);
    ADD_JNI_CALL_TRACE(CallShortMethodV);
    ADD_JNI_CALL_TRACE(CallShortMethodA);
    ADD_JNI_CALL_TRACE(CallIntMethod);
    ADD_JNI_CALL_TRACE(CallIntMethodV);
    ADD_JNI_CALL_TRACE(CallIntMethodA);
    ADD_JNI_CALL_TRACE(CallLongMethod);
    ADD_JNI_CALL_TRACE(CallLongMethodV);
    ADD_JNI_CALL_TRACE(CallLongMethodA);
    ADD_JNI_CALL_TRACE(CallFloatMethod);
    ADD_JNI_CALL_TRACE(CallFloatMethodV);
    ADD_JNI_CALL_TRACE(CallFloatMethodA);
    ADD_JNI_CALL_TRACE(CallDoubleMethod);
    ADD_JNI_CALL_TRACE(CallDoubleMethodV);
    ADD_JNI_CALL_TRACE(CallDoubleMethodA);
    ADD_JNI_CALL_TRACE(CallVoidMethod);
    ADD_JNI_CALL_TRACE(CallVoidMethodV);
    ADD_JNI_CALL_TRACE(CallVoidMethodA);
    ADD_JNI_CALL_TRACE(CallStaticObjectMethod);
    ADD_JNI_CALL_TRACE(CallStaticObjectMethodV);
    ADD_JNI_CALL_TRACE(CallStaticObjectMethodA);
    ADD_JNI_CALL_TRACE(CallStaticBooleanMethod);
    ADD_JNI_CALL_TRACE(CallStaticBooleanMethodV);
    ADD_JNI_CALL_TRACE(CallStaticBooleanMethodA);
    ADD_JNI_CALL_TRACE(CallStaticByteMethod);
    ADD_JNI_CALL_TRACE(CallStaticByteMethodV);
    ADD_JNI_CALL_TRACE(CallStaticByteMethodA);
    ADD_JNI_CALL_TRACE(CallStaticCharMethod);
    ADD_JNI_CALL_TRACE(CallStaticCharMethodV);
    ADD_JNI_CALL_TRACE(CallStaticCharMethodA);
    ADD_JNI_CALL_TRACE(CallStaticShortMethod);
    ADD_JNI_CALL_TRACE(CallStaticShortMethodV);
    ADD_JNI_CALL_TRACE(CallStaticShortMethodA);
    ADD_JNI_CALL_TRACE(CallStaticIntMethod);
    ADD_JNI_CALL_TRACE(CallStaticIntMethodV);
    ADD_JNI_CALL_TRACE(CallStaticIntMethodA);
    ADD_JNI_CALL_TRACE(CallStaticLongMethod);
    ADD_JNI_CALL_TRACE(CallStaticLongMethodV);
    ADD_JNI_CALL_TRACE(CallStaticLongMethodA);
    ADD_JNI_CALL_TRACE(CallStaticFloatMethod);
    ADD_JNI_CALL_TRACE(CallStaticFloatMethodV);
    ADD_JNI_CALL_TRACE(CallStaticFloatMethodA);
    ADD_JNI_CALL_TRACE(CallStaticDoubleMethod);
    ADD_JNI_CALL_TRACE(CallStaticDoubleMethodV);
    ADD_JNI_CALL_TRACE(CallStaticDoubleMethodA);
    ADD_JNI_CALL_TRACE(CallStaticVoidMethod);
    ADD_JNI_CALL_TRACE(CallStaticVoidMethodV);
    ADD_JNI_CALL_TRACE(CallStaticVoidMethodA);
#undef ADD_JNI_CALL_TRACE

    //CallNonvirtual*Method 系列：参数布局不同(obj,clazz,methodID,...)
#define ADD_JNI_NONVIRTUAL_TRACE(fn) addJNITrace((void*)pJFunc->fn, #fn, trace_CallNonvirtualMethod)
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualObjectMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualObjectMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualObjectMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualBooleanMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualBooleanMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualBooleanMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualByteMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualByteMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualByteMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualCharMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualCharMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualCharMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualShortMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualShortMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualShortMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualIntMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualIntMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualIntMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualLongMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualLongMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualLongMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualFloatMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualFloatMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualFloatMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualDoubleMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualDoubleMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualDoubleMethodA);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualVoidMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualVoidMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualVoidMethodA);
#undef ADD_JNI_NONVIRTUAL_TRACE

    //构造对象
    addJNITrace((void*)pJFunc->NewObject,"NewObject",trace_NewObject);
    addJNITrace((void*)pJFunc->NewObjectV,"NewObjectV",trace_NewObject);
    addJNITrace((void*)pJFunc->NewObjectA,"NewObjectA",trace_NewObject);
    addJNITrace((void*)pJFunc->AllocObject,"AllocObject",trace_NewObject);

    addJNITrace((void*)pJFunc->GetStaticFieldID,"GetStaticFieldID",trace_GetStaticFieldID);
    addJNITrace((void*)pJFunc->GetByteArrayRegion,"GetByteArrayRegion",trace_GetByteArrayRegion);
    addJNITrace((void*)pJFunc->GetArrayLength,"GetArrayLength",trace_GetArrayLength);
    addJNITrace((void*)pJFunc->GetByteArrayElements,"GetByteArrayElements",trace_GetByteArrayElements);
    addJNITrace((void*)pJFunc->GetObjectArrayElement,"GetObjectArrayElement",trace_GetObjectArrayElement);

    //数组相关
#define ADD_JNI_ARRAY_TRACE(fn) addJNITrace((void*)pJFunc->fn, #fn, trace_ArrayFunc)
    ADD_JNI_ARRAY_TRACE(NewBooleanArray);
    ADD_JNI_ARRAY_TRACE(NewByteArray);
    ADD_JNI_ARRAY_TRACE(NewCharArray);
    ADD_JNI_ARRAY_TRACE(NewShortArray);
    ADD_JNI_ARRAY_TRACE(NewIntArray);
    ADD_JNI_ARRAY_TRACE(NewLongArray);
    ADD_JNI_ARRAY_TRACE(NewFloatArray);
    ADD_JNI_ARRAY_TRACE(NewDoubleArray);
    ADD_JNI_ARRAY_TRACE(NewObjectArray);
    ADD_JNI_ARRAY_TRACE(SetObjectArrayElement);
    ADD_JNI_ARRAY_TRACE(SetBooleanArrayRegion);
    ADD_JNI_ARRAY_TRACE(SetByteArrayRegion);
    ADD_JNI_ARRAY_TRACE(SetCharArrayRegion);
    ADD_JNI_ARRAY_TRACE(SetShortArrayRegion);
    ADD_JNI_ARRAY_TRACE(SetIntArrayRegion);
    ADD_JNI_ARRAY_TRACE(SetLongArrayRegion);
    ADD_JNI_ARRAY_TRACE(SetFloatArrayRegion);
    ADD_JNI_ARRAY_TRACE(SetDoubleArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetBooleanArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetCharArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetShortArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetIntArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetLongArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetFloatArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetDoubleArrayRegion);
    ADD_JNI_ARRAY_TRACE(GetBooleanArrayElements);
    ADD_JNI_ARRAY_TRACE(GetCharArrayElements);
    ADD_JNI_ARRAY_TRACE(GetShortArrayElements);
    ADD_JNI_ARRAY_TRACE(GetIntArrayElements);
    ADD_JNI_ARRAY_TRACE(GetLongArrayElements);
    ADD_JNI_ARRAY_TRACE(GetFloatArrayElements);
    ADD_JNI_ARRAY_TRACE(GetDoubleArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseBooleanArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseByteArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseCharArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseShortArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseIntArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseLongArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseFloatArrayElements);
    ADD_JNI_ARRAY_TRACE(ReleaseDoubleArrayElements);
#undef ADD_JNI_ARRAY_TRACE

    //引用管理
#define ADD_JNI_REF_TRACE(fn) addJNITrace((void*)pJFunc->fn, #fn, trace_ReferenceFunc)
    ADD_JNI_REF_TRACE(NewGlobalRef);
    ADD_JNI_REF_TRACE(NewLocalRef);
    ADD_JNI_REF_TRACE(DeleteGlobalRef);
    ADD_JNI_REF_TRACE(DeleteWeakGlobalRef);
    ADD_JNI_REF_TRACE(IsSameObject);
    ADD_JNI_REF_TRACE(EnsureLocalCapacity);
#undef ADD_JNI_REF_TRACE
    addJNITrace((void*)pJFunc->DeleteLocalRef,"DeleteLocalRef",trace_DeleteLocalRef);

    //异常相关
    addJNITrace((void*)pJFunc->ExceptionOccurred,"ExceptionOccurred",trace_ExceptionFunc);
    addJNITrace((void*)pJFunc->ExceptionCheck,"ExceptionCheck",trace_ExceptionFunc);
    addJNITrace((void*)pJFunc->ExceptionDescribe,"ExceptionDescribe",trace_ExceptionFunc);
    addJNITrace((void*)pJFunc->ExceptionClear,"ExceptionClear",trace_ExceptionFunc);
    addJNITrace((void*)pJFunc->Throw,"Throw",trace_ExceptionFunc);
    addJNITrace((void*)pJFunc->ThrowNew,"ThrowNew",trace_ExceptionFunc);

    //监视器
    addJNITrace((void*)pJFunc->MonitorEnter,"MonitorEnter",trace_MonitorFunc);
    addJNITrace((void*)pJFunc->MonitorExit,"MonitorExit",trace_MonitorFunc);

    //其他常用函数
    addJNITrace((void*)pJFunc->GetVersion,"GetVersion",trace_VersionFunc);
    addJNITrace((void*)pJFunc->GetJavaVM,"GetJavaVM",trace_VersionFunc);
    addJNITrace((void*)pJFunc->DefineClass,"DefineClass",trace_DefineClass);
    addJNITrace((void*)pJFunc->GetDirectBufferAddress,"GetDirectBufferAddress",trace_DirectBufferFunc);
    addJNITrace((void*)pJFunc->GetDirectBufferCapacity,"GetDirectBufferCapacity",trace_DirectBufferFunc);
}

/* trace环境初始化：只会在第一次调用 lingyi_vm_init / lingyi_vm_call 时执行一次 */
static std::once_flag g_trace_init_flag;

static void initTraceEnv()
{
    setBufferSize(0x1000000A);
    /*JNI Trace*/
    initJni();
    //添加监控的jni函数
    addJNItrace();

    /*libc Trace*/
    initLibcTrace();
    //添加监控的libc函数
    addLibctrace();
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
 * 只初始化 trace 环境（JNI/libc/hook 表），不执行 trace。
 * 方便先单独调用一次确认 hook 安装与日志路径是否正常，再调用 lingyi_vm_call。
 */
extern "C" __attribute__((visibility("default")))
int lingyi_vm_init(void)
{
    std::call_once(g_trace_init_flag, initTraceEnv);
    LOGE("lingyi_vm_init done");
    return 0;
}

/*
 * 诊断：打印 JNI trace 表里注册了什么、JNIEnv 函数表槽位里实际放的是什么。
 * 用来快速判断 "目标代码调到的地址" 和 "trace表里注册的地址" 是否一致
 * （不一致时日志里只会出现 "Call addr: 0x... [libnativelib.so!0x...]"，没有任何 [JNI] 行）。
 *
 * frida: var dump = new NativeFunction(mod.getExportByName("lingyi_vm_dump_jnitrace"), 'int', []);
 *        console.log("dump ret =", dump());
 * 日志用 logcat 看：adb logcat -s QTrace
 */
extern "C" __attribute__((visibility("default")))
int lingyi_vm_dump_jnitrace(void)
{
    if (pJFunc == nullptr)
    {
        LOGE("dump_jnitrace: pJFunc is null -> lingyi_vm_set_jnienv 没成功/还没调用");
        return -1;
    }
    LOGE("dump_jnitrace: jniTrace=%d, entries=%zu",
         is_jni_trace_enabled() ? 1 : 0,
         _g_jni_trace != nullptr ? _g_jni_trace->map.size() : 0);
    LOGE("dump_jnitrace: 函数表槽位 FindClass=%p, GetObjectClass=%p, GetMethodID=%p, GetFieldID=%p",
         (void *)pJFunc->FindClass, (void *)pJFunc->GetObjectClass,
         (void *)pJFunc->GetMethodID, (void *)pJFunc->GetFieldID);
    if (_g_jni_trace == nullptr)
    {
        LOGE("dump_jnitrace: trace表还没创建(setup_jfunc 没跑)");
        return -2;
    }
    const size_t findClassSlot = (size_t)pJFunc->FindClass;
    const size_t getObjectClassSlot = (size_t)pJFunc->GetObjectClass;
    const size_t getMethodIdSlot = (size_t)pJFunc->GetMethodID;
    int n = 0;
    for (auto& kv : _g_jni_trace->map)
    {
        const char* mark = "";
        if (kv.first == findClassSlot)
        {
            mark = "   <== 当前FindClass槽位";
        }
        else if (kv.first == getObjectClassSlot)
        {
            mark = "   <== 当前GetObjectClass槽位";
        }
        else if (kv.first == getMethodIdSlot)
        {
            mark = "   <== 当前GetMethodID槽位";
        }
        LOGE("dump_jnitrace:   [%d] %p %s%s", n++, (void *)kv.first,
             kv.second != nullptr && kv.second->name != nullptr ? kv.second->name : "?", mark);
    }
    return n;
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

    /*
     * 先保存"进入本次调用之前"的配置，再应用 flags。
     * 注意必须在 setBufferSize(flags) 之前取：
     * 旧代码是在应用 flags 之后才计算 savedConfig，结果保存下来的就是本次 flags，
     * 于是 restore 等于没恢复 —— 上一次调用如果没带 bit1/bit3，后续 flags=0 的调用
     * 就会一直沿用"jni/libc trace 关闭"的状态，表现为没有函数名/参数的 Call 行。
     */
    const uint32_t savedConfig = ((uint32_t)bufsize & 0xFFFFFF00u) |
                                 ((uint32_t)bufstate & 0xFFu);

    if (flags != LINGYI_VM_FLAG_NONE)
    {
        /*
         * flags 与 setBufferSize 使用同一套32位打包格式，用于按调用覆盖配置:
         *   bit7..bit0 : 配置状态
         *                bit0 逐指令日志
         *                bit1 jni trace
         *                bit2 jni obj类名解析(method/field名始终由hook记录)
         *                bit3 libc trace
         *                bit4 安全模式：目标代码要调用/跳进 ART(libart/libnativehelper)
         *                     或未知模块之前就停止trace
         *                     (加固so的VM调JNI时ART会解引用垃圾jmethodID/jobject，
         *                      报 "access violation accessing 0x7040xxxx"，打开它即可避免；
         *                      停止后调用方必须把真实函数原生再跑一遍)
         *   bit31..bit8: 累计写盘阈值，字节数 = flags & 0xFFFFFF00
         * 例如 0x1000000A = 256MB + jni trace + libc trace
         *      0x1000001A = 256MB + jni trace + libc trace + 安全模式
         * 传 0 表示沿用 initTraceEnv() 里 setBufferSize 配置的默认值
         */
        setBufferSize((int)flags);
        LOGI("lingyi_vm_call: apply packed flags 0x%x", flags);
    }
    else
    {
        LOGI("lingyi_vm_call: flags=0, keep config from initTraceEnv");
    }

    LOGI("lingyi_vm_call target:%p,arg_num:%u,log:%s", func_addr, arg_num,
         log_path != nullptr ? log_path : "default");

    /*
     * 每次trace前按JNIEnv函数表"当前内容"重新同步一次trace表：
     * 函数表槽位可能在首次注册之后才被patch(或加固进程自己还原过)，
     * 不同步就会出现"目标代码确实进了我们的hook，但trace表里没有这个地址"，
     * 日志里只剩一行 "Call addr: 0x... [libnativelib.so!0x...]"，没有任何 [JNI] 行。
     */
    setJNITraceQuiet(true);
    addJNItrace();
    setJNITraceQuiet(false);
    LOGE("lingyi_vm_call: jniTrace=%d, jniTraceEntries=%zu, pJFunc->FindClass=%p",
         is_jni_trace_enabled() ? 1 : 0,
         _g_jni_trace != nullptr ? _g_jni_trace->map.size() : 0,
         pJFunc != nullptr ? (void *)pJFunc->FindClass : nullptr);
    /*
     * libc trace表只在 initTraceEnv() 里安装一次，这里只打印当前状态，
     * 不会重新注册/覆盖回调。如果这里的 entries 和首次安装时的数量一致，
     * 就说明库函数钩子没有被重装，后续 trace 查表用的还是同一份地址->回调。
     */
    LOGE("lingyi_vm_call: libcTrace=%d, libcTraceEntries=%zu (installed once)",
         is_libc_trace_enabled() ? 1 : 0,
         _g_libc_trace != nullptr ? _g_libc_trace->map.size() : 0);
    if (!is_jni_trace_enabled())
    {
        LOGE("lingyi_vm_call: jni trace 未开启(flags低8位缺少bit1=0x2)，本次不会输出任何 [JNI] 行；"
             "需要JNI日志请传 0x1000000E(jni trace + 类名解析 + libc trace)");
    }
    if (!is_libc_trace_enabled())
    {
        LOGE("lingyi_vm_call: libc trace 未开启(flags低8位缺少bit3=0x8)，"
             "本次只会输出 \"Call addr: 0x...\" 而不会带函数名/参数；"
             "需要libc日志请传 0x1000000E 或 0x1000000A");
    }

    //flags 是本次trace的临时覆盖：执行完恢复"调用前"的配置，避免影响后续调用
    size_t ret = trace_call(func_addr, args, arg_num, log_path);
    if (flags != LINGYI_VM_FLAG_NONE)
    {
        setBufferSize((int)savedConfig);
        LOGI("lingyi_vm_call: restore config 0x%x (from call-entry config)", savedConfig);
    }
    return ret;
}

/*
 * 能力版本号：frida 侧用它确认设备上 push 的是不是新版 so。
 *   v2 = getInstAnalysis 修复 + bit4(TRACE_CFG_STOP_BEFORE_ART 安全模式)
 *   v3 = 支持同时/嵌套 trace 多个函数（去掉全局锁和同线程重入限制，状态按 trace 隔离）
 * 老 so 没有这个导出，脚本里 getExportByName 会直接抛错，从而避免"用旧 so 硬跑"再把 app 带崩。
 */
extern "C" __attribute__((visibility("default")))
int lingyi_vm_api_version(void)
{
    return 3;
}

// no auto trace after injection, call lingyi_vm_call from frida
__unused __attribute__((constructor)) void init_main() {
    LOGE("Injected! call lingyi_vm_call to start trace");
}