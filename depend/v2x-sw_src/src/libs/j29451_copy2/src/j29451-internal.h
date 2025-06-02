/** 
 * @file
 * @brief j29451 라이브러리 내부에서 사용되는 기본 헤더 파일
 * @date 2020-10-03
 * @author gyun
 */


#ifndef V2X_SW_J29451_INTERNAL_H
#define V2X_SW_J29451_INTERNAL_H


// 라이브러리 내부 헤더 파일
#include "j29451-internal-defines.h"
#include "j29451-internal-types.h"
#include "j29451-internal-funcs.h"
#include "j29451-mib.h"

/*
 * 라이브러리 내부에서 사용되는 전역변수들
 */
extern J29451LogLevel g_j29451_log;
extern struct J29451MIB g_j29451_mib;

#endif //V2X_SW_J29451_INTERNAL_H
