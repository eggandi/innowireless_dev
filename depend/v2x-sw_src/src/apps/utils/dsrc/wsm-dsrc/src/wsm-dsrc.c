/**
 * @file
 * @brief wsm-dsrc 어플리케이션 구현 메인 파일
 * @date 2019-08-10
 * @author gyun
 *
 * 더미 WSM(1609.2 미적용)을 송수신하는 테스트 어플리케이션
 */


// 시스템 헤더 파일
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 어플리케이션 헤더 파일
#include "wsm-dsrc.h"


/// 어플리케이션 관리정보
struct MIB g_mib;
volatile bool g_loop = true;


/**
 * @brief 어플리케이션 사용법을 출력한다.
 * @param[in] app_filename 어플리케이션 실행파일명
 */
static void WSM_DSRC_Usage(char app_filename[])
{
  printf("\n\n Description: Sample application to transmit and receive WSMs on DSRC using v2x-sw libraries\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s trx|rx [OPTIONS]\n", app_filename);

  printf("\n OPTIONS for \"TRANSMIT AND RECEIVE\" operation\n");
  printf("  --if <if_idx>         Set interface index(0~n) to transmit. If not specified, set to %u\n", DEFAULT_IF_IDX);
  printf("  --psid <psid>         Set PSID(in decimal) to transmit or receive. If not specified, set to %u\n", DEFAULT_PSID);
  printf("  --chan <channel>      Set tx channel number. If not specified, set to %u\n", DEFAULT_CHAN_NUM);
  printf("  --rate <datarate>     Set tx datarate(in 500kbps). If not specified, set to %u(%uMbps)\n", DEFAULT_DATARATE, DEFAULT_DATARATE/2);
  printf("  --power <power>       Set tx power level(in dBm). If not specified, set to %d\n", DEFAULT_POWER);
  printf("  --prio <priority>     Set tx user priority(0~7). If not specified, set to %u\n", DEFAULT_PRIORITY);
  printf("  --dst <address>       Set tx destination MAC address. If not specified, set to broadcast(FF:FF:FF:FF:FF:FF)\n");
  printf("  --len <len>           Set tx WSM body length(in octet). If not specified, set to %u\n", DEFAULT_WSM_BODY_LEN);
  printf("  --interval <usec>     Set tx interval(in usec). If not specified, set to %u(%umsec)\n", DEFAULT_TX_INTERVAL, DEFAULT_TX_INTERVAL/1000);
  printf("  --dbg <level>         Set debug message print level. If not specified, set to %u\n", DEFAULT_DBG);
  printf("                            0: nothing, 1: event, 2: message hexdump\n");
  printf("  --libdbg <level>      Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                            0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"RECEIVE ONLY\" operation\n");
  printf("  --psid <psid>         Set PSID(in decimal) to receive. If not specified, set to %u\n", DEFAULT_PSID);
  printf("  --dbg <level>         Set debug message print level. If not specified, set to %u\n", DEFAULT_DBG);
  printf("                            0: nothing, 1: event, 2: message hexdump\n");
  printf("  --libdbg <level>      Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                            0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n Example\n");
  printf("  1) %s trx             Sending periodically and receiving test WSM(psid=%u)\n", app_filename, DEFAULT_PSID);
  printf("  2) %s rx              Receiving all WSMs in any interface/channel/timeslot\n", app_filename);
  printf("\n\n");
}


/**
 * @brief V2X 라이브러리들을 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int WSM_DSRC_InitV2XLibs(void)
{
  printf("Initialize V2X libraries\n");
  int ret;

  Dot3LogLevel dot3_log_level = g_mib.lib_dbg;
  WalLogLevel wal_log_level = g_mib.lib_dbg;

  /*
   * dot3 라이브러리를 초기화한다.
   */
  ret = Dot3_Init(dot3_log_level);
  if (ret < 0) {
    printf("Fail to Dot3_Init(): %d\n", ret);
    return -1;
  }
  printf("Success to initialize dot3 library\n");

  // 무선랜 접속계층 라이브러리를 오픈하고 패킷수신콜백함수를 등록한다.
  // WAL_Init()이 아닌 WAL_Open()을 호출하는 이유는, 본 프로그램 실행 전에 설정된 채널 접속이 유지되어야 하기 때문이다.
  ret = WAL_Open(wal_log_level);
  if (ret < 0) {
    printf("Fail to WAL_Open(): %d\n", ret);
    return -1;
  }
  g_mib.if_num = (unsigned int)ret;
  WAL_RegisterCallbackRxMPDU(WSM_DSRC_ProcessRxMPDUCallback);
  printf("Success to open wlanaccess library - %d interface supported\n", g_mib.if_num);

  return 0;
}


/**
 * @brief 종료 시그널 핸들러
 * @param signo 사용되지 않음
 */
static void WSM_DSRC_Signal(int signo)
{
  (void)signo;
  g_loop = false;
}


/**
 * @brief 어플리케이션 메인 함수
 * @param[in] argc 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 개수 (유틸리티 실행파일명 포함)
 * @param[in] argv 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (유틸리티 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int main(int argc, char *argv[])
{
  /*
   * 아무 파라미터 없이 실행하면 사용법을 출력한다.
   */
  if (argc < 2) {
    WSM_DSRC_Usage(argv[0]);
    return 0;
  }

  printf("Running WSM trx application..\n");

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  memset(&g_mib, 0, sizeof(g_mib));
  int ret = WSM_DSRC_ParsingInputParameters(argc, argv);
  if (ret < 0) {
    return -1;
  }

  /*
   * 종료 시그널 핸들러를 설정한다.
   */
  signal(SIGINT,  WSM_DSRC_Signal);
  signal(SIGTERM, WSM_DSRC_Signal);
  signal(SIGQUIT, WSM_DSRC_Signal);
  signal(SIGHUP,  WSM_DSRC_Signal);
  signal(SIGPIPE, WSM_DSRC_Signal);

  /*
   * V2X 라이브러리들을 초기화한다.
   */
  ret = WSM_DSRC_InitV2XLibs();
  if (ret < 0) {
    return -1;
  }

  /*
   * 각 인터페이스의 MAC 주소를 확인한다 (WSM MPDU의 MAC 헤더에 수납하기 위해)
   */
  for (unsigned int if_idx = 0; if_idx < g_mib.if_num; if_idx++) {
    ret = WAL_GetIfMACAddress(if_idx, g_mib.my_addr[if_idx]);
    if (ret < 0) {
      printf("Fail to WAL_GetIfMACAddress() for if[%u] - %d\n", if_idx, ret);
      goto out;
    }
    printf("Check if[%u] MAC address - "MAC_ADDR_FMT"\n", if_idx, MAC_ADDR_FMT_ARGS(g_mib.my_addr[if_idx]));
  }

  /*
   * WSM 수신을 위한 PSID를 등록한다.
   */
  ret = Dot3_AddWSR(g_mib.psid);
  if (ret < 0) {
    printf("Fail to add WSR(psid: %u) - %d\n", g_mib.psid, ret);
    goto out;
  }

  /*
   * 메시지 송신 루틴을 초기화한다.
   */
  if (g_mib.op == kOperationType_trx) {
    ret = WSM_DSRC_InitTxOperation(g_mib.tx_interval);
    if (ret < 0) {
      goto out;
    }
  }

  /*
   * 무한 루프
   *  - (송신 동작 시) WSM 송신 타이머 처리
   *  - WSM 수신 콜백 처리
   */
  while (g_loop == true) {
    usleep(1000000);
  }

  /*
   * 송신 동작을 종료한다.
   */
  if (g_mib.op == kOperationType_trx) {
    WSM_DSRC_ReleaseTxOperation();
  }

  printf("Exit program\n");
  ret = 0;

out:
  Dot3_Release();
  WAL_Close();
  return ret;
}


/**
 * @brief 로그 메시지를 출력한다.
 * @param[in] func 본 함수를 호출하는 함수의 이름
 * @param[in] format 출력 메시지 인자
 * @param[in] ... 출력 메시지 인자
 */
void WSM_DSRC_Print(const char *func, const char *format, ...)
{
  va_list arg;
  struct timespec ts;
  struct tm tm_now;

  clock_gettime(CLOCK_REALTIME, &ts);
  localtime_r((time_t *)&ts.tv_sec, &tm_now);
  fprintf(stderr, "[%04u%02u%02u.%02u%02u%02u.%06ld][%s] ", tm_now.tm_year+1900, tm_now.tm_mon+1, tm_now.tm_mday,
          tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ts.tv_nsec / 1000, func);
  va_start(arg, format);
  vprintf(format, arg);
  va_end(arg);
}

