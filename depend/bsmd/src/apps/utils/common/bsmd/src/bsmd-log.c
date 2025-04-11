/**
 * @file
 * @brief 로그 출력 기능 구현
 * @date 2022-09-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

// 어플리케이션 헤더 파일
#include "include/bsmd.h"


/**
 * @brief 로그메시지를 출력한다.
 * @param[in] func 로그 출력을 수행하는 함수 이름
 * @param[in] format 출력 라인
 * @param[in] ... 출력 라인
 *
 * 본 함수는 직접 호출되지 않으며, 항상 Log() 및 Err() 매크로를 통해 간접 호출된다.
 * 전달된 출력문 앞에 어플리케이션명(BSMD)과 함수명이 추가되어 표준에러(stderr)로 출력된다.
 */
void BSMD_PrintLog(const char *func, const char *format, ...)
{
  va_list arg;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  struct tm tm_now;
  localtime_r((time_t *)&ts.tv_sec, &tm_now);

#if defined(_DEBUG_STDOUT_)
  fprintf(stderr, "[%04u%02u%02u.%02u%02u%02u.%06ld]", tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday,
          tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000);
  fprintf(stderr, "[%s][%s] ", "BSMD", func);
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


/**
 * @brief 패킷의 내용을 16진수로 출력한다.
 * @param[in] log_level 출력할 로그레벨
 * @param[in] pkt 출력할 패킷
 * @param[in] pkt_size 출력할 패킷의 길이
 */
void BSMD_PrintPacketDump(BSMDLogLevel log_level, const uint8_t *pkt, size_t pkt_size)
{
  if (g_bsmd_mib.log.bsmd < log_level) {
    return;
  }

  for (size_t i = 0; i < pkt_size; i++) {
    if ((i!=0) && (i%16==0)) {
      printf("\n");
    }
    printf("%02X ", pkt[i]);
  }
  printf("\n");
}
