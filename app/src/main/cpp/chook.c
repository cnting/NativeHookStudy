//
// Created by cnting on 2023/11/16.
//

#include "chook.h"
#include <fcntl.h>
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <regex.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>

/**
 * hook操作，属于动态形式的内存操作，因此主要关心的是执行视图。
 * 执行视图，是以segment 为单位的数据组织形式。
 * 在执行视图中，总是会存在一个类型为 PT_DYNAMIC 的 segment，这个segment包含了.dynamic section的内容。
 * .dynamic section包含了ELF中其他各个section的内存位置等信息
 */

//取到systable的位置，r_info里两个值是通过&操作合成的，要分开
#if defined(__LP64__)
#define ELF_R_SYM(info) ELF64_R_SYM(info)
#else
#define ELF_R_SYM(info) ELF32_R_SYM(info)
#endif

#define PAGE_START(addr)(addr & PAGE_MASK)

///2.解析elf找到要hook的函数的地址，替换成指定的函数地址
//elf格式：https://www.51cto.com/article/663698.html，跟着这篇一起看，好理解点
void core_chook(const uintptr_t base_address, const char *symbol, void *new_function) {
    ///(1)找到 struct program_header_table
    //ElfW是个宏定义，会拼接成Elf32_Ehdr 或 Elf64_Ehdr
    ElfW(Ehdr) *elf_header = base_address;

    //e_phoff:program_header_table在elf文件中的偏移量
    ElfW(Phdr) *elf_program_header_table = base_address + elf_header->e_phoff;

    ///(2)遍历 elf_program_header_table
    //e_phnum:program_header_table中有多少个表项
    int elf_program_header_table_length = elf_header->e_phnum;

    //dynamic表地址
    uintptr_t dyn_address;
    //dynamic表大小
    unsigned int dyn_table_length;

    for (int i = 0; i < elf_program_header_table_length; i++) {
        //PT_DYNAMIC这个segment里包含了.dynamic section，这个section中其中包含了ELF中其他各个section的内存位置等信息
        //无论是执行hook操作时，还是动态链接器执行动态链接时，都需要通过 PT_DYNAMIC segment 来找到 .dynamic section 的内存位置，再进一步读取其他各项 section 的信息。
        if (elf_program_header_table[i].p_type == PT_DYNAMIC) {
            //p_vaddr:段加载到内存中的虚拟地址
            dyn_address = elf_program_header_table[i].p_vaddr + base_address;
            //p_memsz:段占据的字节数
            dyn_table_length = elf_program_header_table[i].p_memsz / sizeof(ElfW(Dyn));
            break;
        }
    }

    ///(3)遍历 dynamic 表
    ElfW(Dyn) *dyn_table = dyn_address;
    ElfW(Dyn) *dyn_table_end = dyn_table + dyn_table_length;
    uintptr_t rel_table_address;
    uintptr_t rel_table_length;
    uintptr_t sys_table_address;
    uintptr_t str_table_address;

    for (; dyn_table < dyn_table_end; dyn_table++) {
        switch (dyn_table->d_tag) {
            case DT_NULL:
                //读到结尾
                dyn_table_end = dyn_table;
                break;
            case DT_JMPREL:
                //.rela.plt表的位置
                rel_table_address = dyn_table->d_un.d_ptr + base_address;
                break;
            case DT_PLTRELSZ:
                //.rela.plt表的大小
                rel_table_length = dyn_table->d_un.d_val / sizeof(ElfW(Rela));
                break;
            case DT_SYMTAB:
                //symbol table表
                sys_table_address = dyn_table->d_un.d_ptr + base_address;
                break;
            case DT_STRTAB:
                str_table_address = dyn_table->d_un.d_ptr + base_address;
                break;
        }
    }
    //遍历.rela.plt表，这个就是PLT表
    //rel_table -> symbol表 -> str 表
    ElfW(Rela) *rel_table = rel_table_address;
    for (int i = 0; i < rel_table_length; i++) {
        //r_info存了两个信息，一个是symbol表的index,一个是type，是通过&操作合成一个值的，
        //拿到 sys table 的index
        int sys_table_index = ELF_R_SYM(rel_table[i].r_info);
        ElfW(Sym) *sys_item =
                sys_table_address + sys_table_index * sizeof(ElfW(Sym));

        //st_name就是方法名的偏移，注意存的是字符串表的位置，要再去字符串表里取字符串
        char *fun_name = sys_item->st_name + str_table_address;
        if (memcmp(symbol, fun_name, strlen(symbol)) == 0) {
            __android_log_print(ANDROID_LOG_ERROR, "TAG", "匹配:%s", fun_name);

            uintptr_t mem_page_start = rel_table[i].r_offset + base_address;

            //加载so后，linker会把地址改成不可写，一旦我们想去修改，会报错，所以要修改权限
            //PAGE_START要页对齐
            mprotect(PAGE_START(mem_page_start), getpagesize(), PROT_READ | PROT_WRITE);

            *(void **) (rel_table[i].r_offset + base_address) = new_function;

            //刷新
            __builtin___clear_cache(PAGE_START(mem_page_start),
                                    PAGE_START(mem_page_start) + getpagesize());
            break;
        }
    }
}

///1.读取 /proc/self/maps 内容，找到Android so基地址
void chook(const char *pathname_regex_str, const char *symbol, void *new_function) {
    FILE *maps_fp = fopen("/proc/self/maps", "r");
    char line[512];
    uintptr_t base_address;
    char permission[5];
    uintptr_t offset;
    int path_name_position;
    char *path_name;
    int path_name_len;
    regex_t path_name_regex;
    regcomp(&path_name_regex, pathname_regex_str, REG_NOSUB);

    while (fgets(line, sizeof(line), maps_fp)) {
        ///起始地址 - 结束地址      属性   偏移    设备号 inode号   映射的文件名
        ///70aca00000-70acb2a000 r--p 00000000 07:30 118      /apex/com.android.art/lib64/libart.so
        ///70acb2a000-70ad09f000 r-xp 0012a000 07:30 118      /apex/com.android.art/lib64/libart.so
//        __android_log_print(ANDROID_LOG_ERROR, "TAG", "line:%s", line);


        //https://cplusplus.com/reference/cstdio/scanf/
        //%"PRIxPTR"：PRIxPTR 64位是l，其他情况是ll，为了兼容系统，直接用%lx会有问题
        //%*lx：*表示忽略读到的内容，lx是unsigned long int*
        //%4s：读四个字符串
        //%*x:%*x：x表示(0-9, a-f, A-F)
        //%*d%n：%*d忽略读到的内容，%n计算从开始到这个位置读到的偏移，也就是从起始位置到inode号的偏移
        sscanf(line, "%"
                     PRIxPTR
                     "-%*lx %4s %lx %*x:%*x %*d%n", &base_address, permission,
               &offset,
               &path_name_position);

        if (permission[0] != 'r') {
            continue;
        }
        if (permission[3] != 'p') {
            continue;
        }
        //基地址 offset=0
        if (offset != 0) {
            continue;
        }
        //用正则来判断名字
        //把空格去掉
        while (isspace(line[path_name_position]) && path_name_position < sizeof(line) - 1) {
            path_name_position++;
        }
        if (path_name_position >= sizeof(line) + 1) {
            continue;
        }
        //获取文件路径
        path_name = line + path_name_position;
        path_name_len = strlen(path_name);
        if (path_name_len == 0) continue;
        //文件名最后解析出来有 \n
        if (path_name[path_name_len - 1] == '\n') {
            path_name[path_name_len - 1] = '\0';
            path_name_len -= 1;
        }
        //
        if ('[' == path_name[0] || 0 == path_name_len) {
            continue;
        }
        if (0 == regexec(&path_name_regex, path_name, 0, NULL, 0)) {
            __android_log_print(ANDROID_LOG_ERROR, "TAG", "找到===>%s", line);
            core_chook(base_address, symbol, new_function);
        }
    }
    fclose(maps_fp);
}
