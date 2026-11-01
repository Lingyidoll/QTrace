[中文版](README.md) | English

# QTrace
QBDI based Android arm64 trace tool,this is an android studio project.

# Features
* arm64 code Instrumentation,memory read/write monitor
* custome function monitor
* custome jni monitor
* custome libc monitor

# Usage

0.unzip libQBDI.zip under nativelib\src\main\cpp\qbdi-arm64\lib.Or download latest libQBDI.a from https://github.com/QBDI/QBDI/releases/ ,we use andorid-aarch64.then put libQBDI.a under nativelib\src\main\cpp\qbdi-arm64\lib

1.push your target so file to /data/local/tmp

2.under root ,run cmd: setenforce 0

3.modify initTraceEnv() in /nativelib/cpp/native_main.cpp for trace configuration

4.add custome function monitor in qbdihook.cpp，add custome libc function monitor in libctrace.cpp，add custome jni function monitoe in jnitrace.cpp

5.run Build-Generate Apks,push the output lib file: libnativelib.so , to /data/local/tmp

6.inject libnativelib.so into the target process ，you can use the frida script inject.js inside this project.After injection, libnativelib.so exports a C function which can be called by frida directly:

```c
// func_addr: target function address, args: argument values, arg_num: argument count(max 8)
// log_path: trace log path(NULL for default), flags: reserved, pass 0
size_t lingyi_vm_call(void *func_addr, size_t *args, uint32_t arg_num, const char *log_path, uint32_t flags);
```

```javascript
var vmCall = new NativeFunction(addr, 'pointer',
    ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);
var res = vmCall(targetFunc, argsPtr, argNum, logPathPtr, 0);
```

* libnativelib.so does NOT trace anything after injection, all traces are triggered by lingyi_vm_call
* memory pointed by args must be allocated by the caller, at most 8 register arguments(x0~x7)
* JNI/libc trace environment is initialized only once, on the first call
