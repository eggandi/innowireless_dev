/**
 * @file
 * @brief tci application 구현 메인 파일
 * @date 2019-09-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot2-2016/dot2.h"
#else
#include "dot2/dot2.h"
#endif
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#include "j29451/j29451.h"
#if defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
#include "ltev2x-hal/ltev2x-hal.h"
#else
#include "lteaccess/lteaccess.h"
#endif
#endif
#if defined(_TCIA2023_DSRC_)
#include "wlanaccess/wlanaccess.h"
#endif

// 유틸리티 헤더 파일
#include "include/tcia2023.h"


/// 어플리케이션 관리정보
struct TCIA2023_MIB g_tcia_mib;


/**
 * @brief 어플리케이션 사용법을 화면에 출력한다.
 * @param app_filename 어플리케이션 실행파일명
 */
static void TCIA2023_Usage(const char *app_filename)
{
#if defined(_TCIA2023_DSRC_)
  printf("\n\n Description: TCI application for DSRC\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s start [OPTIONS]\n", app_filename);

  printf("\n OPTIONS\n");
  printf("  --port <number>              Set UDP port exchanging TCI message. If not specified, set to %u\n", DEFAULT_TCI_PORT);
  printf("  --addr0 <xx:xx:xx:xx:xx:xx>  Set MAC address for interface 0. If not specified, set to %s\n", DEFAULT_IF0_MAC_ADDR_STR);
  printf("  --addr1 <xx:xx:xx:xx:xx:xx>  Set MAC address for interface 1. If not specified, set to %s\n", DEFAULT_IF1_MAC_ADDR_STR);
  printf("  --rcpi0 <value>              (DEPRECATED) Set RCPI correction value for interface 0. If not specified, set to %u\n", DEFAULT_RCPI_CORRECTION);
  printf("  --rcpi1 <value>              (DEPRECATED) Set RCPI correction value for interface 1. If not specified, set to %u\n", DEFAULT_RCPI_CORRECTION);
  printf("  --lat <value>                (Only for RSU test) Set initial latitude of DUT. If not specified, set to %d\n", DEFAULT_INIT_LAT);
  printf("  --lon <value>                (Only for RSU test) Set initial longitude of DUT. If not specified, set to %d\n", DEFAULT_INIT_LON);
  printf("  --elev <value>               (Only for RSU test) Set initial elevation of DUT. If not specified, set to %d\n", DEFAULT_INIT_ELEV);
  printf("  --autobsm                    (Only for OBU test) Set to transmit BSM automatically\n");
  printf("  --replay                     (Only for OBU test) Set to handles duplication of BSM security profile\n");
  printf("  --cmhfdir <path>             Set CMHF directory. If not specified, set to %s\n", DEFAULT_OBU_CMHF_DIR);
  printf("  --rca <path>                 Set RCA certificate file path. If not specified, set to %s\n", DEFAULT_RCA_FILE);
  printf("  --ica <path>                 Set ICA certificate file path. If not specified, set to %s\n", DEFAULT_ICA_FILE);
  printf("  --pca <path>                 Set PCA certificate file path. If not specified, set to %s\n", DEFAULT_PCA_FILE);
  printf("  --dbg <level>                Set debug message print level. If not specified, set to %u\n", DEFAULT_TCIA2023_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: detailed event, 5: message hexdump\n");
  printf("  --tcidbg <level>             Set libcvcoctci debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: config, 4: event, 5: message hexdump\n");
  printf("  --dot2dbg <level>            Set libdot2 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
  printf("  --dot3dbg <level>            Set libdot3 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
  printf("  --j29451dbg <level>          Set libj29451 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: event, 3: message hexdump\n");
  printf("  --wlanaccessdbg <level>      Set libwlanaccess debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
#elif defined(_TCIA2023_LTE_V2X_)
  printf("\n\n Description: TCI application for LTE-V2X\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s start [OPTIONS]\n", app_filename);

  printf("\n OPTIONS\n");
  printf("  --dev <dev_name>         Set device name to communication. If not specified, set to %s\n", DEFAULT_DEV_NAME);
  printf("  --port <number>          Set UDP port exchanging TCI message. If not specified, set to %u\n", DEFAULT_TCI_PORT);
  printf("  --lat <value>            (Only for RSU test) Set initial latitude of DUT. If not specified, set to %d\n", DEFAULT_INIT_LAT);
  printf("  --lon <value>            (Only for RSU test) Set initial longitude of DUT. If not specified, set to %d\n", DEFAULT_INIT_LON);
  printf("  --elev <value>           (Only for RSU test) Set initial elevation of DUT. If not specified, set to %d\n", DEFAULT_INIT_ELEV);
  printf("  --autobsm                (Only for OBU test) Set to transmit BSM automatically\n");
  printf("  --replay                 (Only for OBU test) Set to handles duplication of BSM security profile\n");
  printf("  --cmhfdir <path>         Set CMHF directory. If not specified, set to %s\n", DEFAULT_OBU_CMHF_DIR);
  printf("  --rca <path>             Set RCA certificate file path. If not specified, set to %s\n", DEFAULT_RCA_FILE);
  printf("  --ica <path>             Set ICA certificate file path. If not specified, set to %s\n", DEFAULT_ICA_FILE);
  printf("  --pca <path>             Set PCA certificate file path. If not specified, set to %s\n", DEFAULT_PCA_FILE);
  printf("  --dbg <level>            Set debug message print level. If not specified, set to %u\n", DEFAULT_TCIA2023_LOG_LEVEL);
  printf("                             0: nothing, 1: err, 2: init, 3: event, 4: detailed event, 5: message hexdump\n");
  printf("  --tcidbg <level>             Set libcvcoctci debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: config, 4: event, 5: message hexdump\n");
  printf("  --dot2dbg <level>            Set libdot2 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
  printf("  --dot3dbg <level>            Set libdot3 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
  printf("  --j29451dbg <level>          Set libj29451 debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: event, 3: message hexdump\n");
  printf("  --lteaccessdbg <level>       Set liblteaccess debug message print level. If not specified, set to %u\n", DEFAULT_LIB_LOG_LEVEL);
  printf("                                 0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");
#else
#error "Communication type is not defined"
#endif
  printf("\n");
  printf("!!NOTICE!! This utility supports 1609.x and 2945/1 test ONLY with Spirent test system\n");
}


/**
 * @brief V2X 라이브러리들을 초기화한다.
 * @param[out] 랜덤하게 생성된 V2V 인터페이스용 MAC 주소가 반환될 변수
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_InitV2XLibs(uint8_t *v2v_if_mac_addr)
{
  Log(kTCIA3LogLevel_Init, "Initialize v2x libraries\n");
  int ret;

  /*
   * 접속 계층 라이브러리를 초기화한다.
   */
#if defined(_TCIA2023_DSRC_)
  // 무선랜 접속계층 라이브러리를 오픈하고 패킷수신콜백함수를 등록한다.
  ret = WAL_Init(g_tcia_mib.log.lib.wlanaccess);
  if (ret < 0) {
    Err("Fail to initialize wlanaccess library - WAL_Open() failed: %d\n", ret);
    return -1;
  }
  g_tcia_mib.v2x_if.if_num = (unsigned int)ret;
  WAL_RegisterCallbackRxMPDU(TCIA2023_DSRC_ProcessRxMPDUCallback);
  Log(kTCIA3LogLevel_Init, "Success to initialize wlanaccess libraries - %d interface are supported\n",
      g_tcia_mib.v2x_if.if_num);
#elif defined(_TCIA2023_LTE_V2X_)
  // LTE 접속계층 라이브러리를 초기화하고 패킷수신콜백함수를 등록한다.
#if defined(_LTEV2X_HAL_)
  ret = LTEV2XHAL_Init(g_tcia_mib.log.lib.lteaccess, g_tcia_mib.input_params.dev_name);
  if (ret < 0) {
    Err("Fail to initialize ltev2x-hal library - LTEV2XHAL_Init() failed: %d\n", ret);
    return -1;
  }

  g_tcia_mib.flow_info[0].type = kLTEV2XHALTxFlowType_SPS;
  g_tcia_mib.flow_info[0].index = kLTEV2XHALTxFLowIndex_Default;
  g_tcia_mib.flow_info[0].pppp = kLTEV2XHALPriority_Default;
  g_tcia_mib.flow_info[0].power = kLTEV2XHALPower_Default;
  g_tcia_mib.flow_info[0].interval = kLTEV2XHALTxFLowInterval_Default;
  g_tcia_mib.flow_info[0].size = kLTEV2XHALMSDUSize_None;
  LTEV2XHAL_RegisterCallbackProcessMSDU(TCIA2023_LTE_V2X_ProcessRxMSDUCallback);
  Log(kTCIA3LogLevel_Init, "Success to initialize ltev2x-hal library\n");
  g_tcia_mib.v2x_if.if_num = 1;
#else
  ret = LAL_Init(g_tcia_mib.log.lib.lteaccess);
  if (ret < 0) {
    Err("Fail to initialize lteaccess library - LAL_Init() failed: %d\n", ret);
    return -1;
  }
  LAL_RegisterCallbackRxMSDU(TCIA2023_LTE_V2X_ProcessRxMSDUCallback);
  Log(kTCIA3LogLevel_Init, "Success to initialize lteaccess library\n");
  g_tcia_mib.v2x_if.if_num = 1;
#endif
#else
#error "Communication type is not defined"
#endif

  /*
   * cvcoctci 라이브러리를 초기화한다.
   */
  Cvcoctci2023_Init(g_tcia_mib.log.lib.cvcoctci3);

  /*
   * dot2 라이브러리를 초기화하고 메시지처리 콜백함수를 등록한다.
   */
  ret = Dot2_Init(g_tcia_mib.log.lib.dot2,
                  kDot2SigningParamsPrecomputeInterval_Default,
                  "/dev/random",
                  kDot2LeapSeconds_Default);
  if (ret < 0) {
    Err("Fail to initialize dot2 library - Dot2_Init() failed: %d\n", ret);
    goto out;
  }
  Dot2_RegisterProcessSPDUCallback(TCIA2023_ProcessSPDUCallback);
  Log(kTCIA3LogLevel_Init, "Success to initialize dot2 libraries\n");

  /*
   * dot3 라이브러리를 초기화한다.
   */
  ret = Dot3_Init(g_tcia_mib.log.lib.dot3);
  if (ret < 0) {
    Err("Fail to initialize dot3 library - Dot3_Init() failed: %d\n", ret);
    goto out;
  }
  Log(kTCIA3LogLevel_Init, "Success to initialize dot3 libraries\n");

  /*
   * j29451 라이브러리를 초기화하고 메시지처리 콜백함수를 등록한다.
   * 반환된 랜덤 MAC 주소를 저장한다(BSM MPDU 생성 시에 사용된다)
   */
  ret = J29451_Init(g_tcia_mib.log.lib.j29451, v2v_if_mac_addr);
  if (ret < 0) {
    Err("Fail to initialize j29451 library - J29451_Init() failed: %d\n", ret);
    goto out;
  }
  J29451_RegisterBSMTransmitCallback(TCIA2023_BSMTransmitCallback);
  J29451_ActivateHardBrakingEventDecision(false);
  J29451_SetCertificationMode();
  Log(kTCIA3LogLevel_Init, "Success to initialize j29451 libraries\n");

#if 0
  /**
   * Update TCIv3 by young@KETI
   * Reset J29451 tx info
   * */
  Log(kTCIA3LogLevel_Event, "Initialize J29451 tx info\n");
  memset(&(g_tcia_mib.j29451_tx_info), 0, sizeof(struct TCIA3J29451TxInfo));

  g_tcia_mib.j29451_tx_info.enable_user_gnss_data = true;
  g_tcia_mib.j29451_tx_info.acc_lon = kJ29451Acceleration_Max;
  g_tcia_mib.j29451_tx_info.acc_lat = kJ29451Acceleration_Max;
  g_tcia_mib.j29451_tx_info.acc_vert = kJ29451VerticalAcceleration_Max;
  g_tcia_mib.j29451_tx_info.acc_yaw = kJ29451YawRate_Max;
  g_tcia_mib.j29451_tx_info.vehicle_width = kJ29451VehicleWidth_Max;
  g_tcia_mib.j29451_tx_info.vehicle_length = kJ29451VehicleLength_Max;
  g_tcia_mib.j29451_tx_info.lat = g_tcia_mib.input_params.lat;
  g_tcia_mib.j29451_tx_info.lon = g_tcia_mib.input_params.lon;
  g_tcia_mib.j29451_tx_info.elev = g_tcia_mib.input_params.elev;
  g_tcia_mib.j29451_tx_info.semi_major = kJ29451SemiMajorAxisAccuracy_Max;
  g_tcia_mib.j29451_tx_info.semi_minor = kJ29451SemiMinorAxisAccuracy_Max;
  g_tcia_mib.j29451_tx_info.semi_orien = kJ29451SemiMajorAxisOrientation_Max;
  g_tcia_mib.j29451_tx_info.speed = kJ29451Speed_Max;
  g_tcia_mib.j29451_tx_info.heading= kJ29451Heading_Max;

  Log(kTCIA3LogLevel_Init, "Success to initialize j29451 libraries\n");
#endif

  Log(kTCIA3LogLevel_Init, "Success to initialize v2x libraries\n");
  return 0;

out:
  J29451_Release();
  Dot3_Release();
  Dot2_Release();
#if defined(_TCIA_DSRC_)
  WAL_Close();
#elif defined(_TCIA_LTE_V2X_)
  LAL_Close();
#endif
  return -1;
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
    TCIA2023_Usage(argv[0]);
    return 0;
  }

  printf("Running TCI application...\n");

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  memset(&g_tcia_mib, 0, sizeof(g_tcia_mib));
  int ret = TCIA2023_ParseInputParameters(argc, argv);
  if (ret < 0) {
    return -1;
  }
  g_tcia_mib.testing.auto_bsm_tx = g_tcia_mib.input_params.auto_bsm_tx;

#if defined(_TCIA2023_LTE_V2X_)
  /*
   * LTE-V2X의 경우 종료시그널 핸들러를 등록한다 - 어플리케이션 종료 시에 반드시 LAL_Close()가 호출되어야 한다.
   */
  TCIA2023_LTE_V2X_InitTerminateHandler();
#endif

  /*
   * v2x 라이브러리들을 초기화한다.
   */
  uint8_t v2v_if_mac_addr[MAC_ALEN];
  ret = TCIA2023_InitV2XLibs(v2v_if_mac_addr);
  if (ret < 0) {
    return -1;
  }

#if defined(_TCIA2023_DSRC_)
  /*
   * DSRC의 경우 각 V2X 인터페이스의 초기 MAC 주소를 설정한다.
   */
  ret = TCIA2023_DSRC_SetInitialIfMACAddress();
  if (ret < 0) {
    goto out;
  }
#endif

  /*
   * 1609.2 보안 관련 정보를 초기화한다.
   */
  ret = TCIA2023_InitSecurity();
  if (ret < 0) {
    goto out;
  }

  /*
   * 차량 크기 정보를 초기화한다.
   */
  g_tcia_mib.vehicle_size.len = DEFAULT_INIT_VEHICLE_LENGTH;
  g_tcia_mib.vehicle_size.width = DEFAULT_INIT_VEHICLE_WIDTH;

  /*
   * V2V 통신 인터페이스용 랜덤 MAC 주소를 저장한다 (OBU 시험 시에만 사용된다)
   */
  memcpy(g_tcia_mib.v2x_if.mac_addr[V2V_IF_IDX], v2v_if_mac_addr, MAC_ALEN);
  Log(kTCIA3LogLevel_Init, "Store Random MAC address("MAC_ADDR_FMT") for if[%u]\n",
      MAC_ADDR_FMT_ARGS(g_tcia_mib.v2x_if.mac_addr[V2V_IF_IDX]), V2V_IF_IDX);

  /*
   * TS와의 인터페이스 기능을 초기화한다.
   */
  ret = TCIA2023_InitTestSystemInterfaceFunction(g_tcia_mib.input_params.tci_port);
  if (ret < 0) {
    goto out;
  }

  /*
   * 설정되었을 경우, BSM 송신을 시작한다.
   */
  if (g_tcia_mib.testing.auto_bsm_tx == true) {
    ret = TCIA2023_StartBSMTransmit();
    if (ret < 0) {
      goto out;
    }
  }

  /*
   * 루프
   */
  pthread_join(g_tcia_mib.ts_if_info.thread, NULL);

  ret = 0;

out:
  J29451_Release();
  Dot3_Release();
  Dot2_Release();
#if defined(_TCIA_DSRC_)
  WAL_Close();
#elif defined(_TCIA_LTE_V2X_)
  LAL_Close();
#endif
  return ret;
}
