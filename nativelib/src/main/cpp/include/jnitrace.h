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

struct JNITraceMap {
    std::unordered_map<size_t, TraceFunc*> map;
};

extern JNITraceMap* _g_jni_trace;
void addJNITrace(void* target,const char* funcname,TraceCallBack callback);

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
void trace_GetByteArrayRegion(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_CallStaticObjectMethodV(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetArrayLength(QBDI::VM *vm, QBDI::GPRState *gprState);
void trace_GetByteArrayElements(QBDI::VM *vm, QBDI::GPRState *gprState);

#endif //QBDI_JNITRACE_H
