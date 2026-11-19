//
// Created by zgy on 2025/10/23.
//

#include "qbdihook.h"
#include "logger.h"
#include "HookUtils.h"
#include "jnitrace.h"
#include "TraceUtils.h"

QBDIHookData*  _g_hook_data = nullptr;


void hook_0x71DD54(QBDI::VM *vm, QBDI::GPRState *gprState)
{
    size_t input = QBDI_GPR_GET(gprState,3);
    size_t len = QBDI_GPR_GET(gprState,4);
    /*
     * 这是给其它app用的示例hook：把 (x3, x4) 当作 (ptr, len) 读原始数据。
     * 但这只是"猜测"的参数语义，实际不一定是合法指针/长度，在QBDI回调里直接解引用
     * 会把整个进程带崩。这里改成"先校验长度 + process_vm_readv 安全读"，
     * 读不到就跳过，绝不让日志hook成为崩溃点。
     */
    const size_t kMaxDump = 0x1000;
    if (input == 0 || len == 0 || len > kMaxDump)
    {
        LOGE("hook_0x71DD54: skip bad ptr/len: %p/0x%lx", (void*)input, (unsigned long)len);
        return;
    }
    uint8_t *raw = (uint8_t*)malloc(len);
    if (raw == nullptr)
    {
        return;
    }
    if (!safeReadMemory((uint64_t)input, raw, len))
    {
        LOGE("hook_0x71DD54: unreadable %p len 0x%lx", (void*)input, (unsigned long)len);
        free(raw);
        return;
    }
    char* hex = bytes_to_hex_string((char*)raw,len);
    char* base64 = (char*) malloc(2 * len);
    if (base64 != nullptr)
    {
        memset(base64,0,2*len);
        base64_encode(base64,raw,len);
    }
    const char* b64 = base64 != nullptr ? base64 : "";
    LOGE("base64:src:%p,raw:%s,res:%s",(void*)input,hex != nullptr ? hex : "",b64);
    appendlogendl();
    appendformat("base64:src:%p,raw:%s,res:%s",(void*)input,hex != nullptr ? hex : "",b64);
    appendlogendl();
    if (hex != nullptr)
    {
        free(hex);
    }
    if (base64 != nullptr)
    {
        free(base64);
    }
    free(raw);
}

void initHookData()
{
    _g_hook_data = new QBDIHookData();
    _g_hook_data->hookMap.reserve(10);
}

void addHook(size_t addr,TraceCallBack callback)
{
    auto* func_hook = new QBDIHookFunc();
    func_hook->callback = callback;
    func_hook->ignore = nullptr;
    addQBDIHook(addr,func_hook);
}

void addHook(size_t addr,TraceCallBack callback,const size_t * ignorefrom,int ignorenum)
{
    auto* func_hook = new QBDIHookFunc();
    func_hook->callback = callback;
    auto * ignores = (size_t *)malloc(sizeof(size_t)*ignorenum);
    for(int i=0;i<ignorenum;i++)
    {
        ignores[i] = ignorefrom[i];
    }
    func_hook->ignore = ignores;
    func_hook->ignorenum = ignorenum;
    addQBDIHook(addr,func_hook);
}

void addQBDIHook(size_t addr,QBDIHookFunc* callback)
{
    if(_g_hook_data == nullptr)
    {
        LOGE("qbdi hook: not init!");
        return;
    }
    auto it = _g_hook_data->hookMap.find(addr);
    if(it != _g_hook_data->hookMap.end())
    {
        LOGE("qbdi hook: %p has installed!",(void*)addr);
        return;
    }
    _g_hook_data->hookMap[addr] = callback;
    LOGE("qbdi hook: %p install",(void*)addr);
}
