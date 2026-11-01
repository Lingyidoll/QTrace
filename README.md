中文 | [English](README_en.md)

# QTrace
基于qbdi的安卓arm64真机trace工具,使用android studio构建

# Features
* arm64真机指令trace，内存读写监控
* 自定义函数监控
* 自定义jni函数监控
* 自定义libc函数监控

# Usage
0.将nativelib\src\main\cpp\qbdi-arm64\lib 目录下的libQBDI.zip解压出libQBDI.a，置于nativelib\src\main\cpp\qbdi-arm64\lib目录下。或去qbdi官方 https://github.com/QBDI/QBDI/releases/ 下载最新的libQBDI.a，注意选择andorid aarch64架构的,置于nativelib\src\main\cpp\qbdi-arm64\lib目录下

1.将trace的目标so push到/data/local/tmp目录下

2.root 环境下执行 setenforce 0

3.在 /nativelib/cpp/native_main.cpp 中，修改 initTraceEnv() 中的trace配置

4.在qbdihook.cpp中添加自定义hook，在libctrace.cpp中添加需要trace 的libc函数，在jnitrace.cpp中添加需要trace的jni函数

5.Build-Generate Apks,将自动生成libnativelib.so ,将其 push 到 /data/local/tmp目录下

6.使用第三方工具注入libnativelib.so 到目标进程，可使用项目自带的frida脚本inject.js，注入后libnativelib.so可以直接被frida调用：


```c
// libnativelib.so 对外导出的trace接口
// func_addr: 目标函数地址  args: 参数值数组  arg_num: 参数个数(最大8个)
// log_path: trace日志路径(传NULL使用默认路径)  flags: 保留参数，传0
size_t lingyi_vm_call(void *func_addr, size_t *args, uint32_t arg_num, const char *log_path, uint32_t flags);
```

```javascript
// frida中直接调用，不再需要shadowhook inline hook
var vmCall = new NativeFunction(addr, 'pointer',
    ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);
var res = vmCall(targetFunc, argsPtr, argNum, logPathPtr, 0);
```

* libnativelib.so 注入后不会自动trace，所有trace都由 lingyi_vm_call 触发
* args 中的字符串/内存数据需要调用方提前分配好，参数最多8个（x0~x7）
* JNI/libc trace环境只在首次调用时初始化，后续调用复用
* inject.js 中已包含 prepareArgs、hook目标so、rpc调用等完整示例



# 使用教程
[QTrace：基于QBDI的高稳定，高定制的trace工具](https://bbs.kanxue.com/thread-290574.htm)

# trace日志格式

```
0x743584a838	0x7838		ldr	x1, [x1, #1384]	;X1=0x7482a19bd8 -> 0x7482652404
0x743584a83c	0x783c		ldr	x8, [sp, #16]	;X8=0x744b07d200 -> 0x744b07ed18, SP=0x744b07d130
0x743584a850	0x7850		blr	x8	;X8=0x7482652404, SP=0x744b07d130, LR=0x743585b884 -> 0x743584a854
Call addr: 0x7482652404 [libart.so!0x652404]
  -> Entering system lib: libart.so
  <- Return to: 0x743584a854 (libGameVMP.so)

0x7435845bec	0x2bec		br	x17	;X17=0x7740f41540
Call addr: 0x7740f41540 strcmp
strcmp("java/lang/Class", "java/lang/String")
  <- Return to: 0x7435875e34 (unknown)

0x7435858910	0x15910		blr	x8	;X8=0x748284d50c, SP=0x744b078bc0, LR=0x743587c290 -> 0x7435858914
Call addr: 0x748284d50c [libart.so!0x84d50c]
  -> Entering system lib: libart.so
  [JNI] GetByteArrayRegion(env=0x7380016ac0, array=0x744b078c08, start=0x1, len=0x20, buf=0x744b078ba0)
   0x744b078ba0: 6d 69 63 72 6f 2d 74 65 73 74 2d 64 61 74 61  |micro-test-data|
  <- Return to: 0x7435858914 (libGameVMP.so)
```

* 第1列：指令绝对地址；第2列：模块内偏移；第3列：反汇编
* `;` 之后：写寄存器为 `before -> after`（值未变化时只输出一次），读寄存器输出当前值
* `bl/blr` 会额外输出 `SP`（调用时栈指针）和 `LR`（`before -> after`，after即返回地址）
* `Call addr / Entering system lib / Return to` 打印在分支指令**执行之后**（即下一行之前），
  能解析到导出符号时直接显示符号名，否则显示 `[模块名!偏移]`
* 只有**跨模块**调用（进入系统库/其他so）或已注册的 libc/jni 监控函数才打印 `Call addr` 块，
  目标 so 内部的 `bl`/`blr`（含 PLT 前的本地跳转）只保留指令行
* 已注册的 libc/jni 监控函数（如 `strcmp`）参数输出也在这之后
