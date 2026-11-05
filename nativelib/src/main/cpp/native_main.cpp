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
    // TODO mmap
    // todo munmap
    // todo dlsym
    // todo strdup
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
    ADD_JNI_CALL_TRACE(CallBooleanMethod);
    ADD_JNI_CALL_TRACE(CallBooleanMethodV);
    ADD_JNI_CALL_TRACE(CallByteMethod);
    ADD_JNI_CALL_TRACE(CallByteMethodV);
    ADD_JNI_CALL_TRACE(CallCharMethod);
    ADD_JNI_CALL_TRACE(CallCharMethodV);
    ADD_JNI_CALL_TRACE(CallShortMethod);
    ADD_JNI_CALL_TRACE(CallShortMethodV);
    ADD_JNI_CALL_TRACE(CallIntMethod);
    ADD_JNI_CALL_TRACE(CallIntMethodV);
    ADD_JNI_CALL_TRACE(CallLongMethod);
    ADD_JNI_CALL_TRACE(CallLongMethodV);
    ADD_JNI_CALL_TRACE(CallFloatMethod);
    ADD_JNI_CALL_TRACE(CallFloatMethodV);
    ADD_JNI_CALL_TRACE(CallDoubleMethod);
    ADD_JNI_CALL_TRACE(CallDoubleMethodV);
    ADD_JNI_CALL_TRACE(CallVoidMethod);
    ADD_JNI_CALL_TRACE(CallVoidMethodV);
    ADD_JNI_CALL_TRACE(CallStaticObjectMethod);
    ADD_JNI_CALL_TRACE(CallStaticObjectMethodV);
    ADD_JNI_CALL_TRACE(CallStaticBooleanMethod);
    ADD_JNI_CALL_TRACE(CallStaticBooleanMethodV);
    ADD_JNI_CALL_TRACE(CallStaticByteMethod);
    ADD_JNI_CALL_TRACE(CallStaticByteMethodV);
    ADD_JNI_CALL_TRACE(CallStaticCharMethod);
    ADD_JNI_CALL_TRACE(CallStaticCharMethodV);
    ADD_JNI_CALL_TRACE(CallStaticShortMethod);
    ADD_JNI_CALL_TRACE(CallStaticShortMethodV);
    ADD_JNI_CALL_TRACE(CallStaticIntMethod);
    ADD_JNI_CALL_TRACE(CallStaticIntMethodV);
    ADD_JNI_CALL_TRACE(CallStaticLongMethod);
    ADD_JNI_CALL_TRACE(CallStaticLongMethodV);
    ADD_JNI_CALL_TRACE(CallStaticFloatMethod);
    ADD_JNI_CALL_TRACE(CallStaticFloatMethodV);
    ADD_JNI_CALL_TRACE(CallStaticDoubleMethod);
    ADD_JNI_CALL_TRACE(CallStaticDoubleMethodV);
    ADD_JNI_CALL_TRACE(CallStaticVoidMethod);
    ADD_JNI_CALL_TRACE(CallStaticVoidMethodV);
#undef ADD_JNI_CALL_TRACE

    //CallNonvirtual*Method 系列：参数布局不同(obj,clazz,methodID,...)
#define ADD_JNI_NONVIRTUAL_TRACE(fn) addJNITrace((void*)pJFunc->fn, #fn, trace_CallNonvirtualMethod)
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualObjectMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualObjectMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualBooleanMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualBooleanMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualByteMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualByteMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualCharMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualCharMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualShortMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualShortMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualIntMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualIntMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualLongMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualLongMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualFloatMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualFloatMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualDoubleMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualDoubleMethodV);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualVoidMethod);
    ADD_JNI_NONVIRTUAL_TRACE(CallNonvirtualVoidMethodV);
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
    // todo CallStaticObjectMethodA
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
        /*
         * flags 与 setBufferSize 使用同一套32位打包格式，用于按调用覆盖配置:
         *   bit7..bit0 : 配置状态
         *                bit0 逐指令日志
         *                bit1 jni trace
         *                bit2 jni 类名/方法名解析
         *                bit3 libc trace
         *   bit31..bit8: 累计写盘阈值，字节数 = flags & 0xFFFFFF00
         * 例如 0x1000000A = 256MB + jni trace + libc trace
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

    //flags 是本次trace的临时覆盖：执行完恢复原配置，避免影响后续调用
    const uint32_t savedConfig = ((uint32_t)bufsize & 0xFFFFFF00u) |
                                 ((uint32_t)bufstate & 0xFFu);
    size_t ret = trace_call(func_addr, args, arg_num, log_path);
    if (flags != LINGYI_VM_FLAG_NONE)
    {
        setBufferSize((int)savedConfig);
        LOGI("lingyi_vm_call: restore config 0x%x", savedConfig);
    }
    return ret;
}

// no auto trace after injection, call lingyi_vm_call from frida
__unused __attribute__((constructor)) void init_main() {
    LOGE("Injected! call lingyi_vm_call to start trace");
}