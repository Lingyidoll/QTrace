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

   `setBufferSize` 参数是 32 位打包值：

   - `bit7~bit0`：配置状态，按 `enable_*` 调用顺序从 bit0 开始  
     `bit0` 逐指令日志(`enableDebugInsn`)、`bit1` jni trace、`bit2` jni 类名/方法名解析、`bit3` libc trace
   - `bit31~bit8`：累计写盘阈值，等价字节数 = `参数 & 0xFFFFFF00`；为 0 表示每 trace 一条指令就写盘
   - 例如 `0x1000000A` = 256MB + jni trace + libc trace（逐指令日志和jni解析关闭）


4.在qbdihook.cpp中添加自定义hook，在libctrace.cpp中添加需要trace 的libc函数，在jnitrace.cpp中添加需要trace的jni函数

5.Build-Generate Apks,将自动生成libnativelib.so ,将其 push 到 /data/local/tmp目录下

6.使用第三方工具注入libnativelib.so 到目标进程，可使用项目自带的frida脚本inject.js，注入后libnativelib.so可以直接被frida调用：


```c
// libnativelib.so 对外导出的trace接口
// func_addr: 目标函数地址  args: 参数值数组  arg_num: 参数个数(最大8个)
// log_path: trace日志路径(传NULL使用默认路径)
// flags: 32位打包配置，传0沿用 initTraceEnv() 的默认配置
//        低8位开关: bit0 逐指令日志 / bit1 jni trace / bit2 jni解析 / bit3 libc trace
//        高24位写盘阈值: 字节数 = flags & 0xFFFFFF00
//        例: 0x1000000A = 256MB写盘 + jni trace + libc trace
size_t lingyi_vm_call(void *func_addr, size_t *args, uint32_t arg_num, const char *log_path, uint32_t flags);
```

```javascript
// frida中直接调用，不再需要shadowhook inline hook
var vmCall = new NativeFunction(addr, 'pointer',
    ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);
// 沿用默认配置
var res = vmCall(targetFunc, argsPtr, argNum, logPathPtr, 0);
// 本次trace覆盖配置: 0x1000000A
var res2 = vmCall(targetFunc, argsPtr, argNum, logPathPtr, 0x1000000A);
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
0x743584a850	0x7850		blr	x8	;X8=0x7740f4d040, SP=0x744b07d130, LR=0x743585b884 -> 0x743584a854
Call addr: malloc(0x80)
       return x0 = 0x744b07ed10

0x7435845bec	0x2bec		br	x17	;X17=0x7740f41540
Call addr: strcmp("java/lang/Class", "java/lang/String")
       return x0 = 0x13

0x743584a8f0	0x78f0		blr	x8	;X8=0x7740f31678, SP=0x744b07d130, LR=0x743585b884 -> 0x743584a8f4
Call addr: 0x7740f31678 [libc.so!0x6d678]

0x7435858910	0x15910		blr	x8	;X8=0x748284d50c, SP=0x744b078bc0, LR=0x743587c290 -> 0x7435858914
  [JNI] CallObjectMethodV(env=0x7380016ac0, obj=0x74001234, methodID=0x6f914da8, args=[0x0, 0x1, 0x2, 0x3])
      jobject CallObjectMethodV(JNIEnv *env, jobject obj, jmethodID methodID, va_list args);
      obj = java.lang.String
      method = toString
      return x0 = 0x74005678 (java.lang.String)
```

* 第1列：指令绝对地址；第2列：模块内偏移；第3列：反汇编
* `;` 之后：写寄存器为 `before -> after`（值未变化时只输出一次），读寄存器输出当前值
* `bl/blr` 会额外输出 `SP`（调用时栈指针）和 `LR`（`before -> after`，after即返回地址）
* **已 hook 的函数**直接输出 `Call addr: 函数名(参数)`，下一行输出 `return x0 = ...`，
  不再带原始地址，也不再输出 `Entering system lib` / `Return to`
* **未 hook 的跨模块调用**输出 `Call addr: 0x地址 [模块名!偏移]`（能解析到符号时显示符号名），
  目标 so 内部的 `bl`/`blr`（含 PLT 前的本地跳转）只保留指令行
* JNI 函数统一输出 `[JNI] 函数名(参数)`，下一行输出该函数的 C 原型，再输出 `obj/clazz` 解析出的
  java 类名（如 `obj = java.lang.String`）、`method = 方法名` / `field = 字段名` 和
  `return x0 = ...`；`va_list` 只解析出前几个参数槽位，不再 hexdump
* `obj/clazz` 通过 `GetObjectClass + Class.getName()` 解析；`method` 优先用
  `GetMethodID/GetStaticMethodID` 的返回值建立 `methodID -> 方法名` 缓存（零额外开销），
  缓存未命中时再用 `Class.getDeclaredMethods()/getMethods()` + `FromReflectedMethod` 反查并缓存
  （最多 128 次，避免拖慢 trace）；`field` 同理来自 `GetFieldID/GetStaticFieldID`
* 解析失败时输出 `obj/clazz = <unknown>`（或 `<null>`）、`method/field = <unknown>`，不影响后续trace
* 解析 `obj/method` 使用的是被 trace 代码**本次 JNI 调用自己的 `JNIEnv*`（x0）**，
  不会混用初始化时保存的其它线程 env（JNI 局部引用与线程/env 绑定，混用会导致 ART 崩溃）
* `Call*Method` / `CallStatic*Method` / `CallNonvirtual*Method` 全系列（Object/Boolean/Byte/Char/
  Short/Int/Long/Float/Double/Void，含 `V` 版本），以及字段读写、数组、引用、字符串、异常、
  监视器等常用 JNI 函数都已注册（见 `native_main.cpp`）
* libc 侧已注册：内存/字符串/文件/线程/时钟/property 等常用函数（见 `libctrace.cpp`），
  bionic 内部实现（`__strlen_aarch64`、`__memset_aarch64`）在 `dlsym` 失败时会回退到 ELF 动态符号表解析

