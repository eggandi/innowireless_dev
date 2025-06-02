/**
 * @file
 * @brief dot3 라이브러리 내부에서 사용되는 정보 정의 헤더파일
 * @date 2019-06-04
 * @author gyun
 */


#ifndef LIBDOT3_DOT3_INTERNAL_H
#define LIBDOT3_DOT3_INTERNAL_H


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-mib.h"
#include "dot3-internal-defines.h"
#include "dot3-internal-types.h"
#include "dot3-internal-funcs.h"


/*
 * 라이브러리 내부에서 사용되는 전역변수들
 */
extern Dot3LogLevel g_dot3_log;
extern struct Dot3MIB INTERNAL g_dot3_mib;
extern const char * g_dot3_rc_str[kDot3Result_Count];


#endif //LIBDOT3_DOT3_INTERNAL_H
