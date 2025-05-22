/**
 * @file
 * @brief bsmd 메인 구현
 * @date 2022-09-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#include "j29451/j29451.h"
#if defined(_BSMD_DSRC_)
#include "wlanaccess/wlanaccess.h"
#elif defined(_BSMD_LTE_V2X_)
#include "ltev2x-hal/ltev2x-hal.h"
#endif

// 유틸리티 헤더 파일
#include "include/bsmd.h"


/// 어플리케이션 관리정보
struct BSMD_MIB g_bsmd_mib;


/**
 * @brief 어플리케이션 사용법을 화면에 출력한다.
 * @param app_filename 어플리케이션 실행파일명
 */
static void BSMD_Usage(const char *app_filename)
{
  printf("\n\n Description: bsmd application for DSRC/LTE-V2X\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s start [OPTIONS]\n", app_filename);

  printf("\n OPTIONS\n");
  printf("  --rx                         Activate Rx function\n");
#if defined(_BSMD_LTE_V2X_)
  printf("  --dev <dev_name>             Set device name to communication. If not specified, set to %s\n", DEFAULT_DEV_NAME);
#endif
  printf("  --dbg <level>                Set debug message print level. If not specified, set to %u\n", DEFAULT_BSMD_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: event, 3: detailed event, 4: message hexdump\n");
  printf("  --dot2dbg <level>            Set libdot2 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
  printf("  --dot3dbg <level>            Set libdot3 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
  printf("  --j29451dbg <level>          Set libj29451 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: event, 3: message hexdump\n");
#if defined(_BSMD_DSRC_)
  printf("  --wlandbg <level>            Set libwlanaccess debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
#elif defined(_BSMD_LTE_V2X_)
  printf("  --ltev2xdbg <level>          Set libltev2x-hal debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
#else
#error "Communication type is not defined"
#endif
  printf("\n");
}


/**
 * @brief V2X 라이브러리들을 초기화한다.
 * @param[out] 랜덤하게 생성된 V2V 인터페이스용 MAC 주소가 반환될 변수
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int BSMD_InitV2XLibs(uint8_t *v2v_if_mac_addr)
{
  Log(kBSMDLogLevel_Event, "Initialize v2x libraries\n");
  int ret;

  /*
   * 접속 계층 라이브러리를 초기화한다.
   * 수신기능은 사하지 않으므로 콜백함수는 등록하지 않는다.
   */
#if defined(_BSMD_DSRC_)
  // 무선랜 접속계층 라이브러리를 초기화한다.
  ret = WAL_Init(g_bsmd_mib.log.lib.wlanaccess);
  if (ret < 0) {
    Err("Fail to initialize wlanaccess library - WAL_Open() failed: %d\n", ret);
    return -1;
  }
  Log(kBSMDLogLevel_Event, "Success to initialize wlanaccess library\n");
  if (g_bsmd_mib.op == kBSMDOperation_TxRx) {
    WAL_RegisterCallbackRxMPDU(BSMD_DSRC_ProcessRxMPDUCallback);
  }
#elif defined(_BSMD_LTE_V2X_)
  // LTE 접속계층 라이브러리를 초기화하고 패킷수신콜백함수를 등록한다.
  ret = LTEV2XHAL_Init(g_bsmd_mib.log.lib.ltev2x_hal, g_bsmd_mib.dev_name);
  if (ret < 0) {
    Err("Fail to initialize ltev2x-hal library - LTEV2XHAL_Init() failed: %d\n", ret);
    return -1;
  }
  Log(kBSMDLogLevel_Event, "Success to initialize ltev2x-hal library\n");
  if (g_bsmd_mib.op == kBSMDOperation_TxRx) {
    LTEV2XHAL_RegisterCallbackProcessMSDU(BSMD_LTE_V2X_ProcessRxMSDUCallback);
  }
#else
#error "Communication type is not defined"
#endif

  /*
   * dot2 라이브러리를 초기화한다.
   * 수신기능은 사용하지 않으므로 콜백함수는 등록하지 않는다.
   */
  ret = Dot2_Init(g_bsmd_mib.log.lib.dot2,
                  kDot2SigningParamsPrecomputeInterval_Default,
                  "/dev/random",
                  kDot2LeapSeconds_Default);
  if (ret < 0) {
    Err("Fail to initialize dot2 library - Dot2_Init() failed: %d\n", ret);
    goto out;
  }
  Log(kBSMDLogLevel_Event, "Success to initialize dot2 library\n");
  if (g_bsmd_mib.op == kBSMDOperation_TxRx) {
    Dot2_RegisterProcessSPDUCallback(BSMD_ProcessSPDUCallback);
  }

  /*
   * dot3 라이브러리를 초기화한다.
   */
  ret = Dot3_Init(g_bsmd_mib.log.lib.dot3);
  if (ret < 0) {
    Err("Fail to initialize dot3 library - Dot3_Init() failed: %d\n", ret);
    goto out;
  }
  Log(kBSMDLogLevel_Event, "Success to initialize dot3 library\n");

  /*
   * j29451 라이브러리를 초기화하고 메시지처리 콜백함수를 등록한다.
   * 반환된 랜덤 MAC 주소를 저장한다(BSM MPDU 생성 시에 사용된다)
   */
  ret = J29451_Init(g_bsmd_mib.log.lib.j29451, v2v_if_mac_addr);
  if (ret < 0) {
    Err("Fail to initialize j29451 library - J29451_Init() failed: %d\n", ret);
    goto out;
  }
  J29451_RegisterBSMTransmitCallback(BSMD_BSMTransmitCallback);
  J29451_LoadPathInfoBackupFile("./bsm_path.history"); // 백업된 Path 정보 로딩
  Log(kBSMDLogLevel_Event, "Success to initialize j29451 libraries\n");
  return 0;

out:
#if defined(_BSMD_LTE_V2X_)
  LTEV2XHAL_Close();
#endif
  return -1;
}


#ifdef _SUPPORT_USER_POWER_OFF_
/**
 * @brief 종료신호 핸들러
 * @param signo 사용되지 않음.
 */
static void BSMD_SigHandler(int signo)
{
  (void)signo;
  Log(kBSMDLogLevel_Event, "Power off!!\n");
  g_bsmd_mib.power_off = true;
}
#endif


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
    BSMD_Usage(argv[0]);
    return 0;
  }

  printf("Running bsmd application...\n");

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  memset(&g_bsmd_mib, 0, sizeof(g_bsmd_mib));
  int ret = BSMD_ParseInputParameters(argc, argv);
  if (ret < 0) {
    return -1;
  }

#ifdef _SUPPORT_POWER_OFF_DETECT_
  /*
   * Power off 감지 기능을 초기화한다.
   */
  BSMD_InitPowerOffFunction();
#endif

#if defined(_BSMD_LTE_V2X_)
  /*
   * LTE-V2X의 경우 종료시그널 핸들러를 등록한다 - 어플리케이션 종료 시에 반드시 LAL_Close()가 호출되어야 한다.
   */
  BSMD_LTE_V2X_InitTerminateHandler();
#endif

  /*
   * v2x 라이브러리들을 초기화한다.
   * 랜덤하게 생성된 V2V 인터페이스 MAC 주소를 저장한다 -> MPDU 생성 시 사용된다.
   */
  ret = BSMD_InitV2XLibs(g_bsmd_mib.v2v_if_mac_addr);
  if (ret < 0) {
    return -1;
  }
  Log(kBSMDLogLevel_Event, "Store Random MAC address("MAC_ADDR_FMT") for V2V I/F\n",
      MAC_ADDR_FMT_ARGS(g_bsmd_mib.v2v_if_mac_addr));

  /*
   * 1609.2 보안 관련 정보를 초기화한다.
   */
  ret = BSMD_InitSecurity();
  if (ret < 0) {
    goto out;
  }

  /*
   * BSM 송신을 시작한다.
   */
  ret = BSMD_StartBSMTransmit();
  if (ret < 0) {
    goto out;
  }

#ifdef _SUPPORT_USER_POWER_OFF_
  /*
   * 종료 신호에 대한 핸들러를 등록한다.
   */
  signal(SIGINT, BSMD_SigHandler);
  signal(SIGTERM, BSMD_SigHandler);
  signal(SIGQUIT, BSMD_SigHandler);
  signal(SIGHUP, BSMD_SigHandler);
  signal(SIGPIPE, BSMD_SigHandler);
#endif

  /*
   * 루프
   */
  while (1) {
    sleep(1);
    if (g_bsmd_mib.power_off == true) {
      sleep(1);
      Log(kBSMDLogLevel_Event, "Program exit\n");
      break;
    }
  }

  ret = 0;

out:
#if defined(_BSMD_LTE_V2X_)
  LTEV2XHAL_Close();
#endif
  return ret;
}
