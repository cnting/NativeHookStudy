//
// Created by cnting on 2023/11/16.
//

#ifndef NATIVEHOOKSTUDY_CHOOK_H
#define NATIVEHOOKSTUDY_CHOOK_H

#ifdef __cplusplus
extern "C"{
#endif

void chook(const char *pathname_regex_str, const char *symbol, void *new_function);

#ifdef _cplusplus
};
#endif


#endif //NATIVEHOOKSTUDY_CHOOK_H
