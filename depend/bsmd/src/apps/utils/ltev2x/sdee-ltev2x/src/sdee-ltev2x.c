/** 
 * @file
 * @brief sdee-lte-v2x 샘플 어플리케이션 메인 구현 파일
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

// 어플리케이션 헤더 파일
#include "sdee-ltev2x.h"

/// 어플리케이션 관리정보
struct MIB g_mib;
volatile bool g_loop = true;


/**
 * @brief sdee 샘플 어플리케이션의 사용법을 화면에 출력한다.
 * @param[in] app_filename 어플리케이션 실행파일명
 */
static void SDEE_LTEV2X_Usage(char *app_filename)
{
  printf("\n\n Description: Sample application to transmit and receive Ieee1609Dot2Data message on LTE-V2X\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s trx|rx|loopback [OPTIONS]\n", app_filename);

  printf("\n OPTIONS for \"TRANSMIT AND RECEIVE\" and \"LOOPBACK\" operation\n");
  printf("  --dev <dev_name>         Set device name to communication. If not specified, set to %s\n", DEFAULT_DEV_NAME);
  printf("  --type u|s               Set Ieee1609Dot2Data message type(u: unsecured, s: signed). If not specified, set to \"signed\"\n");
  printf("  --flow <type>            Set tx flow type - \"sps\" or \"event\". If not specified, set to \"sps\"\n");
  printf("  --psid <psid>            Set PSID(in decimal) to transmit/receive. If not specified, set to %u\n", DEFAULT_PSID);
  printf("  --len <len>              Set tx payload length(in octet). If not specified, set to %u(pre-defined BSM will be transmitted)\n", DEFAULT_PAYLOAD_SIZE);
  printf("  --interval <usec>        Set tx interval(in usec). If not specified, set to %u(%umsec)\n", DEFAULT_TX_INTERVAL, DEFAULT_TX_INTERVAL/1000);
  printf("  --lat <latitude>         Set my latitude. If not specified, set to %d\n", DEFAULT_LAT);
  printf("  --lon <longitude>        Set my longitude. If not specified, set to %d\n", DEFAULT_LON);
  printf("  --cmhf <CMHF dir>        Set my CMHF files directory. If not specified, set to %s\n", DEFAULT_CMHF_DIR);
  printf("  --rca <file path>        Set RCA certificate file path. If not specified, set to %s\n", DEFAULT_RCA_CERT_FILE);
  printf("  --ica <file path>        Set ICA certificate file path. If not specified, set to %s\n", DEFAULT_ICA_CERT_FILE);
  printf("  --pca <file path>        Set PCA certificate file path. If not specified, set to %s\n", DEFAULT_PCA_CERT_FILE);
  printf("  --dbg <level>            Set debug message print level. If not specified, set to %u\n", DEFAULT_DBG);
  printf("                             0: nothing, 1: event, 2: message hexdump\n");
  printf("  --libdbg <level>         Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                             0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"RECEIVE ONLY\" operation\n");
  printf("  --psid <psid>            Set PSID(in decimal) to receive. If not specified, set to %u\n", DEFAULT_PSID);
  printf("  --rca <file path>        Set RCA certificate file path. If not specified, set to %s\n", DEFAULT_RCA_CERT_FILE);
  printf("  --ica <file path>        Set ICA certificate file path. If not specified, set to %s\n", DEFAULT_ICA_CERT_FILE);
  printf("  --pca <file path>        Set PCA certificate file path. If not specified, set to %s\n", DEFAULT_PCA_CERT_FILE);
  printf("  --dbg <level>            Set debug message print level. If not specified, set to %d\n", DEFAULT_DBG);
  printf("                             0: nothing, 1: event, 2: message hexdump\n");
  printf("  --libdbg <level>         Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                             0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n Example\n");
  printf("  1) %s trx                Sending periodically and receiving sample message(psid=%u)\n", app_filename, DEFAULT_PSID);
  printf("  2) %s rx                 Receiving message\n", app_filename);
  printf("  3) %s loopback           Constructing and processing sample message in local device(No transmit)\n", app_filename);

  printf("\n NOTICE!!\n");
  printf("   1) CMHF files currently valid must be in %s\n", DEFAULT_CMHF_DIR);
  printf("      Or you can change your system time to use old CMHF files\n");
  printf("   2) This sample application send messages only on if[0]\n");
  printf("   3) Maximum payload size may be under 1202 when libdot3's wsm_max_len is 1400\n");
  printf("\n\n");
}


/**
 * @brief V2X 라이브러리들을 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int SDEE_LTEV2X_InitV2XLibs(void)
{
  printf("Initialize V2X libraries\n");
  int ret;

  Dot2LogLevel dot2_log_level = g_mib.lib_dbg;
  Dot3LogLevel dot3_log_level = g_mib.lib_dbg;
  LTEV2XHALLogLevel ltev2x_hal_log_level = g_mib.lib_dbg;

#ifndef _X64_
  if (g_mib.op != kOperationType_Loopback) {
    /*
     * LTE-V2X 접속계층 라이브러리를 초기화하고 패킷수신콜백함수를 등록한다.
     */
    ret = LTEV2XHAL_Init(ltev2x_hal_log_level, g_mib.dev_name);
    if (ret < 0) {
      printf("Fail to initialize ltev2x-hal library - LTEV2XHAL_Init() failed: %d\n", ret);
      return -1;
    }
    LTEV2XHAL_RegisterCallbackProcessMSDU(SDEE_LTEV2X_ProcessRxMSDUCallback);
    printf("Success to initialize ltev2x-hal library\n");
  }
#endif

  /*
   * dot2 라이브러리를 초기화하고 메시지처리 콜백함수를 등록한다.
   */
  ret = Dot2_Init(dot2_log_level, kDot2SigningParamsPrecomputeInterval_Default, "/dev/random", kDot2LeapSeconds_Default);
  if (ret < 0) {
    printf("Fail to initialize dot2 library - Dot2_Init() failed: %d\n", ret);
    return -1;
  }
  Dot2_RegisterProcessSPDUCallback(SDEE_LTEV2X_ProcessSPDUCallback);
  printf("Success to initialize dot2 library\n");

  /*
   * dot3 라이브러리를 초기화한다.
   */
  ret = Dot3_Init(dot3_log_level);
  if (ret < 0) {
    printf("Fail to initialize dot3 library - Dot3_Init() failed: %d\n", ret);
    return -1;
  }
  printf("Success to initialize dot3 library\n");

  return 0;
}


/**
 * @brief 어플리케이션 종료 시에 호출되는 시그널 함수
 * @param[in] signum 시그널 번호
 *
 * 종료 시에 반드시 LTEV2XHAL_Close()가 호출되어야 한다. (소켓 재사용을 위해)
 */
static void SDEE_LTEV2X_Terminate(int signum)
{
  (void)signum;
  LTEV2XHAL_Close();
  exit(0);
}


/**
 * @brief 어플리케이션 메인 함수
 * @param[in] argc 어플리케이션 실행 시 입력되는 명령줄 내 파라미터들의 개수 (어플리케이션 실행파일명 포함)
 * @param[in] argv 어플리케이션 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (어플리케이션 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int main(int argc, char *argv[])
{
  /*
   * 아무 파라미터 없이 실행하면 사용법을 출력한다.
   */
  if (argc < 2) {
    SDEE_LTEV2X_Usage(argv[0]);
    return 0;
  }

  printf("Running sdee sample application using LTE-V2X..\n");

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  memset(&g_mib, 0, sizeof(g_mib));
  int ret = SDEE_LTEV2X_ParsingInputParameters(argc, argv);
  if (ret < 0) {
    return -1;
  }

  /*
   * 종료 시에 반드시 LAL_Close()가 호출되어야 하므로, 종료 시그널 핸들러를 등록한다.
   */
  struct sigaction sig_action;
  sig_action.sa_handler = SDEE_LTEV2X_Terminate;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = 0;
  sigaction(SIGINT, &sig_action, NULL);
  sigaction(SIGHUP, &sig_action, NULL);
  sigaction(SIGTERM, &sig_action, NULL);
  sigaction(SIGSEGV, &sig_action, NULL);

  /*
   * V2X 라이브러리들을 초기화한다.
   */
  ret = SDEE_LTEV2X_InitV2XLibs();
  if (ret < 0) {
    return -1;
  }

  /*
   * 서명 메시지 생성/처리를 위한 인증서 관련 정보(CA 인증서 및 CMH)들을 등록한다.
   */
  if (g_mib.msg_type == kMsgType_Signed) {
    ret = SDEE_LTEV2X_RegisterCryptoMaterials();
    if (ret < 0) {
      goto out;
    }
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
   * 송신 동작을 초기화한다.
   */
  if ((g_mib.op == kOperationType_Trx) || (g_mib.op == kOperationType_Loopback)) {
    ret = SDEE_LTEV2X_InitTxOperation(g_mib.tx_interval);
    if (ret < 0) {
      goto out;
    }
  }

  /*
   * 무한 루프
   *  - (송신 동작 시) 메시지 송신 타이머 처리를 수행한다.
   *  - 메시지 수신 콜백 처리를 수행한다.
   */
  while (g_loop == true) {
    usleep(1000000);
  }

  ret = 0;

out:
#ifndef _X64_
  if (g_mib.op != kOperationType_Loopback) {
    LTEV2XHAL_Close();
  }
#endif
  Dot3_Release();
  Dot2_Release();
  return ret;
}


/**
 * @brief 로그 메시지를 출력한다.
 * @param[in] func 본 함수를 호출하는 함수의 이름
 * @param[in] format 출력 메시지 인자
 * @param[in] ... 출력 메시지 인자
 */
void SDEE_LTEV2X_Print(const char *func, const char *format, ...)
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
