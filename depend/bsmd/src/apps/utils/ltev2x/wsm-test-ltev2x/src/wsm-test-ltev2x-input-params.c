/** 
 * @file
 * @brief wsm 테스트 유틸리티 실행 시 함께 입력되는 파라미터들을 처리하는 기능을 구현한 파일
 * @date 2021-02-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "v2x-sw.h"

// 유틸리티 헤더 파일
#include "wsm-test-ltev2x.h"


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int WSM_TEST_LTEV2X_ProcessParsedOption(int option)
{
  switch (option) {
    case 0: {
      g_mib.op.tx_if_idx = (unsigned int)strtoul(optarg, 0, 10);
      break;
    }
    case 1: {
      if (memcmp(optarg, "event", 5) == 0) {
        g_mib.op.tx_flow_type = kLTEV2XHALTxFlowType_Ad_Hoc;
      } else {
        g_mib.op.tx_flow_type = kLTEV2XHALTxFlowType_SPS;
      }
      break;
    }
    case 2: {
      g_mib.op.psid = (Dot3PSID)strtol(optarg, 0, 10);
      break;
    }
    case 3: {
      g_mib.op.tx_power = (Dot3Power)strtol(optarg, 0, 10);
      break;
    }
    case 4: {
      g_mib.op.tx_priority = (Dot3Priority)strtoul(optarg, 0, 10);
      break;
    }
    case 6: {
      g_mib.op.tx_wsm_body_len = (Dot3WSMPayloadSize)strtoul(optarg, 0, 10);
      break;
    }
    case 7: {
      g_mib.op.tx_interval = (unsigned int)strtoul(optarg, 0, 10);
      break;
    }
    case 8: {
      g_mib.op.dbg = strtoul(optarg, 0, 10);
      break;
    }
    case 9: {
      g_mib.op.lib_dbg = strtoul(optarg, 0, 10);
      break;
    }
    case 10: {
      memcpy(g_mib.op.dev_name, optarg, strlen(optarg));
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
 * @param[in] argc 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 개수 (유틸리티 실행파일명 포함)
 * @param[in] argv 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (유틸리티 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int WSM_TEST_LTEV2X_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
    {"if", required_argument, 0, 0/*=getopt_long() 호출 시 option_idx 에 반환되는 값*/},
    {"flow", required_argument, 0, 1},
    {"psid", required_argument, 0, 2},
    {"power", required_argument, 0, 3},
    {"prio", required_argument, 0, 4},
    {"len", required_argument, 0, 6},
    {"interval", required_argument, 0, 7},
    {"dbg", required_argument, 0, 8},
    {"libdbg", required_argument, 0, 9},
    {"dev", required_argument, 0, 10},
    {0, 0, 0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 기본 파라미터 파싱 및 저장
   */
  if (!memcmp(argv[1], "tx", 2)) {
    g_mib.op.op = kOperationType_Tx;
  } else if (!memcmp(argv[1], "rx", 2)) {
    g_mib.op.op = kOperationType_Rx;
  } else {
    printf("Invalid operation - %s\n", argv[1]);
    return -1;
  }

  /*
   * 파라미터 기본 값 설정
   */
  memcpy(g_mib.op.dev_name, DEFAULT_DEV_NAME, strlen(DEFAULT_DEV_NAME));
  g_mib.op.tx_if_idx = DEFAULT_IF_IDX;
  g_mib.op.tx_flow_type = DEFAULT_TX_FLOW_TYPE;
  g_mib.op.psid = DEFAULT_PSID;
  g_mib.op.tx_power = DEFAULT_POWER;
  g_mib.op.tx_priority = DEFAULT_PRIORITY;
  g_mib.op.tx_wsm_body_len = DEFAULT_WSM_BODY_LEN;
  g_mib.op.tx_interval = DEFAULT_TX_INTERVAL;
  g_mib.op.dbg = DEFAULT_DBG;
  g_mib.op.lib_dbg = DEFAULT_DBG;

  /*
   * 파라미터 파싱 및 저장
   */
  while(1) {

    /*
     * 옵션 파싱
     */
    c = getopt_long(argc, argv, "", options, &option_idx);
    if (c == -1) {  // 모든 파라미터 파싱 완료
      break;
    }

    /*
     * 파싱된 옵션 처리
     */
    int ret = WSM_TEST_LTEV2X_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 입력된 WSM body 길이가 테스트 정보를 담을 수 없을만큼 작으면 실패를 반환한다.
   */
  if (g_mib.op.tx_wsm_body_len < sizeof(struct TestMessageHeader)) {
    printf("Too short WSM body length: %zu (It must be same or greater than %zu\n",
           g_mib.op.tx_wsm_body_len, sizeof(struct TestMessageHeader));
    return -1;
  }

  /*
   * 파싱된 파라미터 내용 출력
   */
  printf("  dev: %s\n", g_mib.op.dev_name);
  printf("  op: %u(0:rx,1:tx), tx_flow_type: %u(0:event, 1:SPS), PSID: %u, dbg: %u, lib dbg: %u\n",
         g_mib.op.op, g_mib.op.tx_flow_type, g_mib.op.psid, g_mib.op.dbg, g_mib.op.lib_dbg);
  if (g_mib.op.op == kOperationType_Tx) {
    printf("  if_idx: %u\n", g_mib.op.tx_if_idx);
    printf("  power: %ddBm, priority: %u, body len: %zu, interval: %u(usec)\n",
           g_mib.op.tx_power, g_mib.op.tx_priority, g_mib.op.tx_wsm_body_len, g_mib.op.tx_interval);
  }
  return 0;
}
