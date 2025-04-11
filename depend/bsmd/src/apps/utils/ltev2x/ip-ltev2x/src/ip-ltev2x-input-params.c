/**
 * @file
 * @brief wsm-lte-v2x 어플리케이션 실행 시 함께 입력되는 파라미터들을 처리하는 기능을 구현한 파일
 * @date 2021-02-24
 * @author gyun
 */

// 시스템 헤더 파일
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 어플리케이션 헤더 파일
#include "ip-ltev2x.h"


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int IP_LTEV2X_ProcessParsedOption(int option)
{
  switch (option) {
    case 1: {
      g_mib.tx_power = (LTEV2XHALPower) strtol(optarg, 0, 10);
      break;
    }
    case 2: {
      g_mib.tx_priority = (LTEV2XHALPriority) strtoul(optarg, 0, 10);
      break;
    }
    case 3: {
      g_mib.dbg = strtoul(optarg, 0, 10);
      break;
    }
    case 4: {
      g_mib.lib_dbg = strtoul(optarg, 0, 10);
      break;
    }
    case 5: {
      strcpy(g_mib.dev_name, optarg);
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
int IP_LTEV2X_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
    {"power", required_argument, 0, 1},
    {"prio", required_argument, 0, 2},
    {"dbg", required_argument, 0, 3},
    {"libdbg", required_argument, 0, 4},
    {"dev", required_argument, 0, 5},
    {0, 0, 0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 파라미터 기본 값 설정
   */
  strcpy(g_mib.dev_name, DEFAULT_DEV_NAME);
  g_mib.tx_power = DEFAULT_POWER;
  g_mib.tx_priority = DEFAULT_PRIORITY;
  g_mib.dbg = DEFAULT_DBG;
  g_mib.lib_dbg = DEFAULT_LIB_DBG;

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
    int ret = IP_LTEV2X_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 파싱된 파라미터 내용 출력
   */
  printf("  power: %ddBm, priority: %u\n", g_mib.tx_power, g_mib.tx_priority);
  printf("  dbg: %u, lib dbg: %u\n", g_mib.dbg, g_mib.lib_dbg);
  return 0;
}
