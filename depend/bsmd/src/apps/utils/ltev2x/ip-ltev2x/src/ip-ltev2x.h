/**
 * @file
 * @brief wsm-lte-v2x 어플리케이션 메인 헤더파일
 * @date 2021-02-24
 * @author gyun
 */

#ifndef V2X_WSM_LTEV2X_H
#define V2X_WSM_LTEV2X_H


// 시스템 헤더 파일
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

// 라이브러리 헤더 파일
#include "../../../../depend/include/ltev2x-hal/ltev2x-hal.h"
#include "../../../../depend/include/ffasn1c/ffasn1-dot3-2016.h"


/*
 * 입력 파라미터 기본값
 */
#define DEFAULT_DEV_NAME "/dev/spidev1.1"
#define DEFAULT_POWER 23
#define DEFAULT_PRIORITY 5
#define DEFAULT_DBG 1
#define DEFAULT_LIB_DBG 1

/*
 * 로그출력 매크로
 * 컴파일 시 "_DEBUG_*_"가 정의되지 않으면 로그출력 코드가 제거되어 컴파일된다.
 */
#if defined(_DEBUG_STDOUT_) || defined(_DEBUG_SYSLOG_)
/// 로그 출력 매크로
#define Log(l, f, a...) do { if (g_mib.dbg >= l) { IP_LTEV2X_PrintLog(__FUNCTION__, f, ## a); } } while(0)
/// 에러레벨 로그 출력 매크로
#define Err(f, a ...) do { if (g_mib.dbg >= kDbgMsgLevel_err) { IP_LTEV2X_PrintLog(__FUNCTION__,f,## a); } } while(0)
#else
#define Log(l, f, a ...) do {} while(0)
#define Err(f, a ...) do {} while(0)
#endif


/**
 * @brief 로그메시지 출력 레벨
 */
enum eDbgMsgLevel
{
  kDbgMsgLevel_None, ///< 미출력
  kDbgMsgLevel_Err, ///< 에러
  kDbgMsgLevel_Init, ///< 에러
  kDbgMsgLevel_Event, ///< 이벤트 출력
  kDbgMsgLevel_Dump, ///< 메시지 hexdump 출력
  kDbgMsgLevel_max = kDbgMsgLevel_Dump
};
typedef unsigned int DbgMsgLevel; ///< @ref eDbgMsgLevel


/**
 * @brief 어플리케이션 관리정보
 */
struct MIB
{
  char dev_name[256]; ///< LTE-V2X 통신 디바이스 이름
  DbgMsgLevel dbg; ///< 디버그 메시지 출력 레벨
  unsigned int lib_dbg; ///< V2X 라이브러리 디버그 메시지 출력 레벨
  LTEV2XHALPower tx_power; ///< WSM 송신 파워 (실제 전송에도 사용되며, WSM 확장 헤더에도 수납된다)
  LTEV2XHALPriority tx_priority; ///< WSM 송신에 사용되는 우선순위

  bool tx_running;
};


/*
 * 프로그램에서 사용되는 전역 변수 및 함수
 */
extern struct MIB g_mib;
void IP_LTEV2X_PrintLog(const char *func, const char *format, ...);
int IP_LTEV2X_ParsingInputParameters(int argc, char *argv[]);

#endif //V2X_WSM_LTEV2X_H
