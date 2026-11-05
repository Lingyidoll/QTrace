//
// Created by fang on 23-12-19.
//

#ifndef QBDIRECORDER_VM_H
#define QBDIRECORDER_VM_H
#include "QBDI.h"
#include "QBDI/State.h"
#include "logger.h"
#include <cstddef>
#include <cstdint>
#include <sstream>

typedef void (*TraceCallBack)(QBDI::VM *vm, QBDI::GPRState *gprState);
typedef bool (*TraceFilter)(size_t regs[]);

struct TraceFunc {
    TraceCallBack callback;
    const char* name = nullptr;   // 注册时的函数名，供通用回调打印
};

class vm {
public:
    /**
     * 初始化QBDI VM并instrument目标模块
     * @param base   模块加载基址，用于计算trace日志里的模块内偏移
     * @param target 目标函数地址，用于定位需要instrument的模块
     */
    QBDI::VM init(size_t base, size_t target);
    size_t base;
private:

};

/* 当前trace目标的模块信息，jni/libc trace回调通过它计算模块内偏移 */
struct g_trace_data{
    size_t base;    // 模块加载基址
    size_t start;   // 模块起始地址
    size_t end;     // 模块结束地址
};

extern g_trace_data* _g_trace_data;
/* 最近一次延迟回调所对应调用的返回值(x0)，供jni/libc回调读取 */
extern size_t g_deferred_call_retval;
/* 最近一次延迟回调对应的函数名（注册时传入），供通用回调使用 */
extern const char* g_deferred_call_name;
/* 最近一次延迟回调所对应JNI调用的JNIEnv(x0)。
 * JNI局部引用与线程/env绑定，解析obj/method时必须用它，不能用初始化时保存的其他线程env */
extern void *g_deferred_call_env;
extern int bufsize ;
/* setBufferSize 低8位保存的配置状态，不参与写盘阈值计算 */
extern int bufstate;
extern bool debugInsn;
void setBufferSize(int);
void enableDebugInsn(bool);

/**
 * 在目标函数上执行一次QBDI trace
 * @param func_addr 目标函数地址
 * @param args      参数值数组（x0~x7），arg_num为0时可为nullptr
 * @param arg_num   参数个数，最大8个
 * @param log_path  trace日志路径，为空时使用默认路径
 * @return 目标函数返回值，失败返回0
 */
size_t trace_call(void *func_addr, const size_t *args, size_t arg_num, const char *log_path);

#endif //QBDIRECORDER_VM_H
