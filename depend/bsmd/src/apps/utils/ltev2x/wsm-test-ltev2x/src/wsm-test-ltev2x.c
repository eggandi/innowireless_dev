/** 
 * @file
 * @brief LTE-V2X 기반 WSM 테스트 유틸리티 구현 메인 파일
 * @date 2021-02-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// 유틸리티 헤더 파일
#include "wsm-test-ltev2x.h"


/// 유틸리티 관리정보
struct MIB g_mib;
volatile bool g_loop = true;


/**
 * @brief 유틸리티 사용법을 출력한다.
 * @param[in] app_filename 어플리케이션 실행파일명
 */
static void WSM_TEST_LTEV2X_Usage(char app_filename[])
{
  printf("\n\n Description: WSM test utility using LTE-V2X\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s tx|rx [OPTIONS]\n", app_filename);

  printf("\n OPTIONS for \"TRANSMIT AND RECEIVE\" operation\n");
  printf("  --dev <dev_name>      Set device name to communication. If not specified, set to %s\n", DEFAULT_DEV_NAME);
  printf("  --if <if_idx>         Set interface index(0~n) to transmit. If not specified, set to %u\n", DEFAULT_IF_IDX);
  printf("  --flow <type>         Set tx flow type - \"sps\" or \"event\". If not specified, set to \"sps\"\n");
  printf("  --psid <psid>         Set PSID(in decimal) to transmit or receive. If not specified, set to %u\n", DEFAULT_PSID);
  printf("  --power <power>       Set tx power level(in dBm). If not specified, set to %d\n", DEFAULT_POWER);
  printf("  --prio <priority>     Set tx user priority(0~7). If not specified, set to %u\n", DEFAULT_PRIORITY);
  printf("  --len <len>           Set tx WSM body length(in octet). If not specified, set to %u\n", DEFAULT_WSM_BODY_LEN);
  printf("  --interval <usec>     Set tx interval(in usec). If not specified, set to %u(%umsec)\n", DEFAULT_TX_INTERVAL, DEFAULT_TX_INTERVAL/1000);
  printf("  --dbg 0|1             Set if print debug message. If not specified, set to %u\n", DEFAULT_DBG);
  printf("  --libdbg <level>      Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                            0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"RECEIVE ONLY\" operation\n");
  printf("  --psid <psid>         Set PSID(in decimal) to receive. If not specified, set to %u\n", DEFAULT_PSID);
  printf("  --dbg 0|1             Set if print debug message. If not specified, set to %u\n", DEFAULT_DBG);
  printf("  --libdbg <level>      Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                            0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n Example\n");
  printf("  1) %s tx              Sending test WSM(psid=%u) periodically\n", app_filename, DEFAULT_PSID);
  printf("  2) %s rx              Receiving test WSM(psid=%u) in any interface/channel/timeslot\n", app_filename, DEFAULT_PSID);
  printf("\n\n");
}


/**
 * @brief V2X 라이브러리들을 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int WSM_TEST_LTEV2X_InitV2XLibs(void)
{
  printf("Initialize V2X libraries\n");
  int ret;

  Dot3LogLevel dot3_log_level = g_mib.op.lib_dbg;
  LTEV2XHALLogLevel ltev2x_hal_log_level = g_mib.op.lib_dbg;

  /*
   * dot3 라이브러리를 초기화한다.
   */
  ret = Dot3_Init(dot3_log_level);
  if (ret < 0) {
    printf("Fail to Dot3_Init(): %d\n", ret);
    return -1;
  }
  printf("Success to Dot3_Init()\n");

  // LTE 접속계층 라이브러리를 초기화하고 패킷수신콜백함수를 등록한다.
  ret = LTEV2XHAL_Init(ltev2x_hal_log_level, g_mib.op.dev_name);
  if (ret < 0) {
    printf("Fail to LTEV2XHAL_Init(): %d\n", ret);
    return -1;
  }
  LTEV2XHAL_RegisterCallbackProcessMSDU(WSM_TEST_LTEV2X_ProcessRxMSDUCallback);
  printf("Success to initialize ltev2x-hal library\n");

  return 0;
}


/**
 * @brief 어플리케이션 종료 시에 호출되는 시그널 함수
 * @param[in] signum 시그널 번호
 *
 * 종료 시에 반드시 LAL_Close()가 호출되어야 한다. (소켓 재사용을 위해)
 */
static void WSM_TEST_LTEV2X_Terminate(int signum)
{
  (void)signum;
  LTEV2XHAL_Close();
  exit(0);
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
    WSM_TEST_LTEV2X_Usage(argv[0]);
    return 0;
  }

  printf("Running WSM trx on LTE-V2X application..\n");

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  memset(&g_mib, 0, sizeof(g_mib));
  int ret = WSM_TEST_LTEV2X_ParsingInputParameters(argc, argv);
  if (ret < 0) {
    return -1;
  }

  /*
   * GPS 정보데이터를 초기화한다 - 좌표 등의 정보를 획득하기 위해
   */
  ret = gps_open(GPSD_SHARED_MEMORY, 0, &(g_mib.status.gps_data));
  if (ret) {
    printf("Fail to gps_open(): %d(reason: %s)\n", ret, gps_errstr(ret));
    return -1;
  }
  printf("Success to gps_open()\n");

  /*
   * V2X 라이브러리들을 초기화한다.
   */
  ret = WSM_TEST_LTEV2X_InitV2XLibs();
  if (ret < 0) {
    return -1;
  }

  /*
   * 종료 시에 반드시 LAL_Close()가 호출되어야 하므로, 종료 시그널 핸들러를 등록한다.
   */
  struct sigaction sig_action;
  sig_action.sa_handler = WSM_TEST_LTEV2X_Terminate;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = 0;
  sigaction(SIGINT, &sig_action, NULL);
  sigaction(SIGHUP, &sig_action, NULL);
  sigaction(SIGTERM, &sig_action, NULL);
  sigaction(SIGSEGV, &sig_action, NULL);

  /*
   * WSM 수신을 위한 PSID를 등록한다.
   */
  ret = Dot3_AddWSR(g_mib.op.psid);
  if (ret < 0) {
    printf("Fail to add WSR(psid: %u) - %d\n", g_mib.op.psid, ret);
    goto out;
  }

  /*
   * 메시지 송신 루틴을 초기화한다.
   */
  if (g_mib.op.op == kOperationType_Tx) {
    ret = WSM_TEST_LTEV2X_InitTxOperation(g_mib.op.tx_interval);
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

  ret = 0;

out:
  LTEV2XHAL_Close();
  Dot3_Release();
  return ret;
}
