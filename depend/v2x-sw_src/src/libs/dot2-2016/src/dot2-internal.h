/** 
 * @file
 * @brief libdot2 내부에서 사용되는 기본 헤더 파일
 * @date 2020-02-18
 * @author gyun
 *
 * 라이브러리 내 다른 헤더 파일에서는 본 파일을 인클루드해서는 안된다. C 파일에서만 인클루드 가능하다.
 */


#ifndef V2X_SW_DOT2_INTERNAL_H
#define V2X_SW_DOT2_INTERNAL_H


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-defines.h"
#include "dot2-internal-types.h"
#include "dot2-internal-funcs.h"
#include "dot2-mib.h"


/*
 * 라이브러리 내부에서 사용되는 전역변수들
 */
extern Dot2LogLevel g_dot2_log;
extern struct Dot2MIB g_dot2_mib;


#endif //V2X_SW_DOT2_INTERNAL_H
