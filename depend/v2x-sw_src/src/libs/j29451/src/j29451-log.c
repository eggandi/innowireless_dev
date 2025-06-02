/** 
 * @file
 * @brief j29451 라이브러리 로그 출력 기능 구현 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

// 라이브러리 헤더 파일
#include "j29451/j29451-types.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"


/// 로그레벨 저장 변수 - J29451_Init() API에서 설정/업데이트 된다.
J29451LogLevel INTERNAL g_j29451_log = kJ29451LogLevel_Event;


/**
 * @brief 로그메시지를 출력한다.
 * @param[in] func 로그 출력을 수행하는 함수명
 * @param[in] format 출력 라인
 * @param[in] ... 출력라인
 *
 * 본 함수는 직접 호출되지 않으며, 항상 Log() 및 Err() 매크로를 통해 간접 호출된다. \n
 * 전달된 출력문 앞에 라이브러리명(j29451)과 함수명이 추가되어 출력된다.
 */
void INTERNAL j29451_PrintLog(const char *func, const char *format, ...)
{
  va_list arg;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  struct tm tm_now;
  memset(&tm_now, 0, sizeof(struct tm));
  tzset();
  localtime_r((time_t *)&(ts.tv_sec), &tm_now);

#if defined(_DEBUG_STDOUT_)
  fprintf(stderr, "[%04u%02u%02u.%02u%02u%02u.%06ld]",
          tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday,
          tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000);

  fprintf(stderr, "[%s][%s] ", "j29451", func);
  va_start(arg, format);
  vfprintf(stderr, format, arg);
  va_end(arg);
#elif defined(_DEBUG_SYSLOG_)
  char log[255];
  sprintf(log, "[%06ld][%s] ", ts.tv_nsec / 1000, func);
  va_start(arg, format);
  vsprintf(log + strlen(log), format, arg);
  va_end(arg);
  syslog(LOG_INFO | LOG_LOCAL0, "%s", log);
#endif
}
