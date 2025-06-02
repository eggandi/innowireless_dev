/** 
 * @file
 * @brief
 * @date 2021-03-08
 * @author gyun
 */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_ProcessParsedOption(int option)
{
  switch (option) {
    case 0: {
      g_tcia_mib.input_params.tci_port = (uint16_t)strtoul(optarg, 0, 10);
      break;
    }
    case 1: {
      strncpy(g_tcia_mib.input_params.mac_addr[0], optarg, sizeof(g_tcia_mib.input_params.mac_addr[0]) - 1);
      break;
    }
    case 2: {
      strncpy(g_tcia_mib.input_params.mac_addr[1], optarg, sizeof(g_tcia_mib.input_params.mac_addr[1]) - 1);
      break;
    }
    case 3: {
      g_tcia_mib.input_params.rcpi_correction[0] = strtol(optarg, 0, 10);
      break;
    }
    case 4: {
      g_tcia_mib.input_params.rcpi_correction[1] = strtol(optarg, 0, 10);
      break;
    }
    case 5: {
      g_tcia_mib.input_params.lat = (int32_t)strtol(optarg, 0, 10);
      break;
    }
    case 6: {
      g_tcia_mib.input_params.lon = (int32_t)strtol(optarg, 0, 10);
      break;
    }
    case 7: {
      g_tcia_mib.input_params.elev = (uint16_t)strtoul(optarg, 0, 10);
      break;
    }
    case 8: {
      g_tcia_mib.input_params.auto_bsm_tx = true;
      break;
    }
    case 9: {
      memset(g_tcia_mib.input_params.cmhf_dir, 0, sizeof(g_tcia_mib.input_params.cmhf_dir));
      strncpy(g_tcia_mib.input_params.cmhf_dir, optarg, sizeof(g_tcia_mib.input_params.cmhf_dir) - 1);
      break;
    }
    case 10: {
      memset(g_tcia_mib.input_params.rca_cert_file, 0, sizeof(g_tcia_mib.input_params.rca_cert_file));
      strncpy(g_tcia_mib.input_params.rca_cert_file, optarg, sizeof(g_tcia_mib.input_params.rca_cert_file) - 1);
      break;
    }
    case 11: {
      memset(g_tcia_mib.input_params.ica_cert_file, 0, sizeof(g_tcia_mib.input_params.ica_cert_file));
      strncpy(g_tcia_mib.input_params.ica_cert_file, optarg, sizeof(g_tcia_mib.input_params.ica_cert_file) - 1);
      break;
    }
    case 12: {
      memset(g_tcia_mib.input_params.pca_cert_file, 0, sizeof(g_tcia_mib.input_params.pca_cert_file));
      strncpy(g_tcia_mib.input_params.pca_cert_file, optarg, sizeof(g_tcia_mib.input_params.pca_cert_file) - 1);
      break;
    }
    case 13: {
      g_tcia_mib.log.tcia = (TCIALogLevel)strtoul(optarg, 0, 10);
      break;
    }
    case 14: {
      g_tcia_mib.log.lib.cvcoctci3 = strtoul(optarg, 0, 10);
      break;
    }
    case 15: {
      g_tcia_mib.log.lib.dot2 = strtoul(optarg, 0, 10);
      break;
    }
    case 16: {
      g_tcia_mib.log.lib.dot3 = strtoul(optarg, 0, 10);
      break;
    }
    case 17: {
      g_tcia_mib.log.lib.j29451 = strtoul(optarg, 0, 10);
      break;
    }
    case 18: {
      g_tcia_mib.log.lib.lteaccess = strtoul(optarg, 0, 10);
      break;
    }
    case 19: {
      g_tcia_mib.log.lib.wlanaccess = strtoul(optarg, 0, 10);
      break;
    }
    case 20: {
      g_tcia_mib.input_params.bsm_replay = true;
      break;
    }
    case 21: {
      memset(g_tcia_mib.input_params.dev_name, 0x00, sizeof(g_tcia_mib.input_params.dev_name));
      strncpy(g_tcia_mib.input_params.dev_name, optarg, sizeof(g_tcia_mib.input_params.dev_name) - 1);
      break;
    }
    default: {
      printf("Invalid option\n");
      return -1;
    }
  }
  return 0;
}


/**
 * @brief 어플리케이션 실행 시 함께 입력된 파라미터들을 파싱하여 관리정보에 저장한다.
 * @param[in] argc 어플리케이션 실행 시 입력되는 명령줄 내 파라미터들의 개수 (어플리케이션 실행파일명 포함)
 * @param[in] argv 어플리케이션 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (어플리케이션 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_ParseInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
  {"port", required_argument, 0, 0},
  {"addr0", required_argument, 0, 1},
  {"addr1", required_argument, 0, 2},
  {"rcpi0", required_argument, 0, 3},
  {"rcpi1", required_argument, 0, 4},
  {"lat", required_argument, 0, 5},
  {"lon", required_argument, 0, 6},
  {"elev", required_argument, 0, 7},
  {"autobsm", no_argument, 0, 8},
  {"cmhfdir", required_argument, 0, 9},
  {"rca", required_argument, 0, 10},
  {"ica", required_argument, 0, 11},
  {"pca", required_argument, 0, 12},
  {"dbg", required_argument, 0, 13},
  {"tcidbg", required_argument, 0, 14},
  {"dot2dbg", required_argument, 0, 15},
  {"dot3dbg", required_argument, 0, 16},
  {"j29451dbg", required_argument, 0, 17},
  {"lteaccessdbg", required_argument, 0, 18},
  {"wlanaccessdbg", required_argument, 0, 19},
  {"replay", no_argument, 0, 20},
  {"dev", required_argument, 0, 21},
  {0, 0, 0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 파라미터 기본 값을 설정한다.
   */
  g_tcia_mib.input_params.tci_port = DEFAULT_TCI_PORT;
  strncpy(g_tcia_mib.input_params.mac_addr[0], DEFAULT_IF0_MAC_ADDR_STR, sizeof(g_tcia_mib.input_params.mac_addr[0]) - 1);
  strncpy(g_tcia_mib.input_params.mac_addr[1], DEFAULT_IF1_MAC_ADDR_STR, sizeof(g_tcia_mib.input_params.mac_addr[1]) - 1);
  g_tcia_mib.input_params.rcpi_correction[0] = DEFAULT_RCPI_CORRECTION;
  g_tcia_mib.input_params.rcpi_correction[1] = DEFAULT_RCPI_CORRECTION;
  g_tcia_mib.input_params.lat = DEFAULT_INIT_LAT;
  g_tcia_mib.input_params.lon = DEFAULT_INIT_LON;
  g_tcia_mib.input_params.elev = DEFAULT_INIT_ELEV;
  g_tcia_mib.input_params.auto_bsm_tx = DEFAULT_BSM_AUTO_TX;
  g_tcia_mib.input_params.bsm_replay = false;
  strncpy(g_tcia_mib.input_params.cmhf_dir, DEFAULT_OBU_CMHF_DIR, sizeof(g_tcia_mib.input_params.cmhf_dir) - 1);
  strncpy(g_tcia_mib.input_params.rca_cert_file, DEFAULT_RCA_FILE, sizeof(g_tcia_mib.input_params.rca_cert_file) - 1);
  strncpy(g_tcia_mib.input_params.ica_cert_file, DEFAULT_ICA_FILE, sizeof(g_tcia_mib.input_params.ica_cert_file) - 1);
  strncpy(g_tcia_mib.input_params.pca_cert_file, DEFAULT_PCA_FILE, sizeof(g_tcia_mib.input_params.pca_cert_file) - 1);
  g_tcia_mib.log.tcia = DEFAULT_TCIA2023_LOG_LEVEL;
  g_tcia_mib.log.lib.cvcoctci3 = DEFAULT_LIB_LOG_LEVEL;
  g_tcia_mib.log.lib.dot2 = DEFAULT_LIB_LOG_LEVEL;
  g_tcia_mib.log.lib.dot3 = DEFAULT_LIB_LOG_LEVEL;
  g_tcia_mib.log.lib.j29451 = DEFAULT_LIB_LOG_LEVEL;
  g_tcia_mib.log.lib.lteaccess = DEFAULT_LIB_LOG_LEVEL;
  g_tcia_mib.log.lib.wlanaccess = DEFAULT_LIB_LOG_LEVEL;
  strncpy(g_tcia_mib.input_params.dev_name, DEFAULT_DEV_NAME, sizeof(g_tcia_mib.input_params.dev_name) - 1);

  /*
   * 파라미터들을 파싱 및 저장한다.
   */
  int ret;
  while(1)
  {
    // 옵션 파싱
    c = getopt_long(argc, argv, "", options, &option_idx);
    if (c == -1) {  // 모든 파라미터 파싱 완료
      break;
    }

    // 파싱된 옵션 처리
    ret = TCIA2023_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 파싱된 파라미터 내용 출력
   */
  Log(kTCIA3LogLevel_Init, "\tTCI port: %u, CMHF dir: %s, RCA: %s, ICA: %s, PCA: %s, dbg: %u\n",
      g_tcia_mib.input_params.tci_port, g_tcia_mib.input_params.cmhf_dir, g_tcia_mib.input_params.rca_cert_file,
      g_tcia_mib.input_params.ica_cert_file, g_tcia_mib.input_params.pca_cert_file, g_tcia_mib.log.tcia);
  Log(kTCIA3LogLevel_Init, "\tlat: %d, lon: %d, elev: %u, BSM auto tx: %u, BSM replay: %u\n",
      g_tcia_mib.input_params.lat, g_tcia_mib.input_params.lon, g_tcia_mib.input_params.elev,
      g_tcia_mib.input_params.auto_bsm_tx, g_tcia_mib.input_params.bsm_replay);
  Log(kTCIA3LogLevel_Init, "\tlib dbg - cvcoctci3: %u, dot2: %u, dot3: %u, j29451: %u\n",
      g_tcia_mib.log.lib.cvcoctci3, g_tcia_mib.log.lib.dot2, g_tcia_mib.log.lib.dot3, g_tcia_mib.log.lib.j29451);
#if defined(_TCIA2023_DSRC_)
  Log(kTCIA3LogLevel_Init, "\tMAC address[0]: %s, MAC address[1]: %s\n",
      g_tcia_mib.input_params.mac_addr[0], g_tcia_mib.input_params.mac_addr[1]);
      Log(kTCIA3LogLevel_Init, "\tRCPI[0] correction: %d, RCPI[1] correction: %d, libwlanaccess dbg: %u\n",
      g_tcia_mib.input_params.rcpi_correction[0], g_tcia_mib.input_params.rcpi_correction[1],
      g_tcia_mib.log.lib.wlanaccess);
#elif defined(_TCIA2023_LTE_V2X_)
  Log(kTCIA3LogLevel_Init, "\tliblteaccess dbg: %u\n", g_tcia_mib.log.lib.lteaccess);
#endif

  return 0;
}
