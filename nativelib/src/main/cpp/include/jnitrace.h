//
// Created by zgy on 2025/10/30.
//

#ifndef QBDI_JNITRACE_H
#define QBDI_JNITRACE_H
#include "vm.h"
#include <jni.h>
#include "unordered_map"

extern const JNINativeInterface* pJFunc;
extern JNIEnv * jniEnv;
void initJni();
void setup_jfunc(JNIEnv * jnienv);
/* 由外部(frida)直接传入JNIEnv，避免符号查找拿到无效地址 */
int setup_jni_env(void* env);
void enable_jni_trace_debug(bool enable);
/* 当前jni trace开关状态(由setBufferSize的bit1控制) */
bool is_jni_trace_enabled();
/* 是否允许记录类名（bit2）：和methodID/fieldID一样，在JNIEnv函数表上hook
 * (FindClass/GetObjectClass/Get*ID)把 jclass->类名、obj->jclass 缓存下来，
 * 供trace时直接查表。trace回调里不做任何JNI调用，避免ART在QBDI改写的栈上抛异常崩溃。 */
void enable_jni_resolve(bool enable);

struct JNITraceMap {
    std::unordered_map<size_t, TraceFunc*> map;
};

extern JNITraceMap* _g_jni_trace;
void addJNITrace(void* target,const char* funcname,TraceCallBack callback);
/* 加锁查 jni trace 表（多线程同时 trace 时用），未命中返回 nullptr */
TraceFunc* findJNITraceEntry(size_t target);
/* 重新注册trace表时静默(不打印"已注册"日志)，用于每次trace前的同步 */
void setJNITraceQuiet(bool quiet);

void trace_FindClass(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_NewStringUTF(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_NewString(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetMethodID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_RegisterNatives(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetStringUTFChars(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetFieldID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetLongField(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetStaticMethodID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetStaticFieldID(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetIntField(QBDI::VM *vm, QBDI::GPRState *gprState);
/* Get/Set<Type>Field 通用回调(含Static)，函数名由注册时传入 */
void trace_GetField(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetByteArrayRegion(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_CallStaticObjectMethodV(QBDI::VM *vm, QBDI::GPRState *gprState);
/* Call*Method / CallStatic*Method 通用回调，函数名由注册时传入 */
void trace_CallMethod(QBDI::VM *vm, QBDI::GPRState *gprState);
/* CallNonvirtual*Method 通用回调 */
void trace_CallNonvirtualMethod(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_DeleteLocalRef(QBDI::VM *vm, QBDI::GPRState *gprState);
/* 异常相关JNI函数通用回调(ExceptionOccurred/ExceptionCheck/ExceptionDescribe/
 * ExceptionClear/Throw/ThrowNew)，函数名由注册时传入 */
void trace_ExceptionFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetArrayLength(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetByteArrayElements(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetObjectArrayElement(QBDI::VM *vm, QBDI::GPRState *gprState);
/* 常用JNI函数通用回调 */
void trace_NewObject(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_ReferenceFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_StringLengthFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_StringFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_ArrayFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_MonitorFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetObjectClass(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_ClassFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_VersionFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_DefineClass(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_DirectBufferFunc(QBDI::VM *vm, QBDI::GPRState *gprState);
/* 未单独解析的JNI函数通用输出 */
void trace_GenericJni(QBDI::VM *vm, QBDI::GPRState *gprState);

#endif //QBDI_JNITRACE_H
