//
// Created by fang on 2024/1/3.
//

#ifndef QBDI_HOOKUTILS_H
#define QBDI_HOOKUTILS_H
#include <string>
#define HOOK_DEF(ret, func, ...) \
  ret (*orig_##func)(__VA_ARGS__)=nullptr; \
  ret new_##func(__VA_ARGS__)
typedef size_t Size;
#define HEADSIZE 0x100
struct MapAddresInfo {
    /**
     * 函数的符号
     */
    char *sym = nullptr;
    /**
     * 函数在文件路径
     */
    char *fname = nullptr;

    /**
     * 所在函数的基地址
     */
    size_t sym_base = 0;
    /**
     * 文件基地址
     */
    size_t fbase = 0;

    /**
     * 传入地址,相对于so的偏移
     */
    size_t offset = 0;
};

struct MapItemInfo {
    size_t start;
    size_t end;
    //默认为end - start，但是也可以根据需要重新修改
    size_t size;
};

MapItemInfo getSoBaseAddress(const char *libpath, const char *name);
MapItemInfo getSoBaseAddressByNameAndAddr(const char *so_name, void* address);
MapItemInfo getSoBaseAddressFromAddress(void* address);

void callstackLogcat(const char* tag);
void callstackDump(std::string &dump);
void callstackDumpWithFilter(std::string &dump, const char** filter_strings, size_t filter_count);
void callstackLogcatWithFilter(const char* tag, const char** filter_strings, size_t filter_count);
char* getAppName();
char* getPrivatePath();
const char* getAddressInfo(void* address, char* buffer, size_t buffer_size);
size_t findSymbolInLibArt(const char * soname,const char * symname);
/* 通用ELF符号解析：在已加载的so中按名字查找导出/动态符号 */
size_t findSymbolInSo(const char * soname, const char * symname);
size_t getLibRXsize(const char * soname);
size_t base64_encode(char *out, const uint8_t *data, size_t len) ;
char* bytes_to_hex_string(char* bytes, size_t len) ;

uintptr_t get_current_x0();
uintptr_t get_current_x1();
uintptr_t get_current_x2();
uintptr_t get_current_x3();
uintptr_t get_current_x4();
uintptr_t get_current_x5();
uintptr_t get_current_x6();
uintptr_t get_current_x7();
uintptr_t get_current_x8();
uintptr_t get_current_x9();
uintptr_t get_current_x10();
uintptr_t get_current_x11();
uintptr_t get_current_x12();
uintptr_t get_current_x13();
uintptr_t get_current_x14();
uintptr_t get_current_x15();
uintptr_t get_current_x16();
uintptr_t get_current_x17();
uintptr_t get_current_x18();
uintptr_t get_current_x19();
uintptr_t get_current_x20();
uintptr_t get_current_x21();
uintptr_t get_current_x22();
uintptr_t get_current_x23();
uintptr_t get_current_x24();
uintptr_t get_current_x25();
uintptr_t get_current_x26();
uintptr_t get_current_x27();
uintptr_t get_current_x28();
uintptr_t get_current_x29();

bool isString(const char*,int);
#endif //QBDI_HOOKUTILS_H
