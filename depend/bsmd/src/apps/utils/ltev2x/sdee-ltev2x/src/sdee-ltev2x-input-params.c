/** 
 * @file
 * @brief sdee-lte-v2x 샘플 어플리케이션 실행 시 함께 입력되는 파라미터들을 파싱/처리하는 기능 구현 파일
 * @date 2021-02-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 어플리케이션 헤더 파일
#include "sdee-ltev2x.h"


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int SDEE_LTEV2X_ProcessParsedOption(int option)
{
  switch (option) {
    case 0: {
      if (*optarg == 'u') {
        g_mib.msg_type = kMsgType_Unsecured;
      } else if (*optarg == 's') {
        g_mib.msg_type = kMsgType_Signed;
      } else {
        printf("Invalid msg type option - %c\n", *optarg);
        return -1;
      }
      break;
    }
    case 1: {
      if (memcmp(optarg, "event", 5) == 0) {
        g_mib.tx_flow_type = kLTEV2XHALTxFlowType_Ad_Hoc;
      } else {
        g_mib.tx_flow_type = kLTEV2XHALTxFlowType_SPS;
      }
      break;
    }
    case 2: {
      g_mib.psid = (Dot2PSID)strtoul(optarg, 0, 10);
      break;
    }
    case 3: {
      g_mib.payload_size = (size_t)strtoul(optarg, 0, 10);
      break;
    }
    case 4: {
      g_mib.tx_interval = (uint32_t)strtoul(optarg, 0, 10);
      break;
    }
    case 5: {
      g_mib.lat = (int32_t)strtol(optarg, 0, 10);
      break;
    }
    case 6: {
      g_mib.lon = (int32_t)strtol(optarg, 0, 10);
      break;
    }
    case 7: {
      memset(g_mib.cmhf_dir, 0, sizeof(g_mib.cmhf_dir));
      memcpy(g_mib.cmhf_dir, optarg, strlen(optarg));
      break;
    }
    case 8: {
      memset(g_mib.rca_cert_file_path, 0, sizeof(g_mib.rca_cert_file_path));
      memcpy(g_mib.rca_cert_file_path, optarg, strlen(optarg));
      break;
    }
    case 9: {
      memset(g_mib.ica_cert_file_path, 0, sizeof(g_mib.ica_cert_file_path));
      memcpy(g_mib.ica_cert_file_path, optarg, strlen(optarg));
      break;
    }
    case 10: {
      memset(g_mib.pca_cert_file_path, 0, sizeof(g_mib.pca_cert_file_path));
      memcpy(g_mib.pca_cert_file_path, optarg, strlen(optarg));
      break;
    }
    case 11: {
      g_mib.dbg = strtoul(optarg, 0, 10);
      break;
    }
    case 12: {
      g_mib.lib_dbg = strtoul(optarg, 0, 10);
      break;
    }
    case 13: {
      memcpy(g_mib.dev_name, optarg, strlen(optarg));
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
int SDEE_LTEV2X_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
    {"type", required_argument, 0, 0/*=getopt_long() 호출 시 option_idx 에 반환되는 값*/},
    {"flow", required_argument, 0, 1},
    {"psid", required_argument, 0, 2},
    {"len", required_argument, 0, 3},
    {"interval", required_argument, 0, 4},
    {"lat", required_argument, 0, 5},
    {"lon", required_argument, 0, 6},
    {"cmhf", required_argument, 0, 7},
    {"rca", required_argument, 0, 8},
    {"ica", required_argument, 0, 9},
    {"pca", required_argument, 0, 10},
    {"dbg", required_argument, 0, 11},
    {"libdbg", required_argument, 0, 12},
    {"dev", required_argument, 0, 13},
    {0, 0, 0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 기본 파라미터를 파싱 및 저장한다.
   */
  if (!memcmp(argv[1], "trx", 3)) {
    g_mib.op = kOperationType_Trx;
#ifdef _X64_
    printf("TRX operation in x64 system is not supported\n");
    return -1;
#endif
  } else if (!memcmp(argv[1], "rx", 2)) {
    g_mib.op = kOperationType_RxOnly;
#ifdef _X64_
    printf("TRX operation in x64 system is not supported\n");
    return -1;
#endif
  } else if (!memcmp(argv[1], "loopback", 8)) {
    g_mib.op = kOperationType_Loopback;
  } else {
    printf("Invalid operation - %s\n", argv[1]);
    return -1;
  }

  /*
   * 파라미터 기본 값을 설정한다.
   */
  memcpy(g_mib.dev_name, DEFAULT_DEV_NAME, strlen(DEFAULT_DEV_NAME));
  g_mib.msg_type = kMsgType_Signed;
  g_mib.tx_flow_type = DEFAULT_TX_FLOW_TYPE;
  g_mib.psid = DEFAULT_PSID;
  g_mib.payload_size = DEFAULT_PAYLOAD_SIZE;
  g_mib.tx_interval = DEFAULT_TX_INTERVAL;
  g_mib.lat = DEFAULT_LAT,
  g_mib.lon = DEFAULT_LON,
  g_mib.dbg = DEFAULT_DBG;
  g_mib.lib_dbg = DEFAULT_LIB_DBG;
  memcpy(g_mib.cmhf_dir, DEFAULT_CMHF_DIR, strlen(DEFAULT_CMHF_DIR));
  memcpy(g_mib.rca_cert_file_path, DEFAULT_RCA_CERT_FILE, strlen(DEFAULT_RCA_CERT_FILE));
  memcpy(g_mib.ica_cert_file_path, DEFAULT_ICA_CERT_FILE, strlen(DEFAULT_ICA_CERT_FILE));
  memcpy(g_mib.pca_cert_file_path, DEFAULT_PCA_CERT_FILE, strlen(DEFAULT_PCA_CERT_FILE));

  /*
   * 파라미터들을 파싱 및 저장한다.
   */
  while(1)
  {
    // 옵션 파싱
    c = getopt_long(argc, argv, "", options, &option_idx);
    if (c == -1) {  // 모든 파라미터 파싱 완료
      break;
    }

    // 파싱된 옵션 처리
    int ret = SDEE_LTEV2X_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 파싱된 파라미터 내용 출력
   */
  printf("  dev: %s\n", g_mib.dev_name);
  printf("  op: %u(0:rx,1:trx,2:loopback), tx_flow_type: %u(0:event, 1:SPS), PSID: %u, RCA: %s, ICA: %s, PCA: %s, dbg:%u, lib dbg: %u\n",
         g_mib.op, g_mib.tx_flow_type, g_mib.psid, g_mib.rca_cert_file_path, g_mib.ica_cert_file_path,
         g_mib.pca_cert_file_path, g_mib.dbg, g_mib.lib_dbg);
  if ((g_mib.op == kOperationType_Trx) || (g_mib.op == kOperationType_Loopback)) {
    printf("  msg_type: %u(0:unsecured,1:signed), len: %zu, interval: %uusec, lat: %d, lon: %d, CMHF dir: %s\n",
           g_mib.msg_type, g_mib.payload_size, g_mib.tx_interval, g_mib.lat, g_mib.lon, g_mib.cmhf_dir);
  }

  return 0;
}
