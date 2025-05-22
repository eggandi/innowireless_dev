/**
 * @file
 * @brief 입력 파라미터 처리 기능
 * @date 2022-09-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 어플리케이션 헤더 파일
#include "include/bsmd.h"


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int BSMD_ProcessParsedOption(int option)
{
  switch (option) {
    case 0: {
      g_bsmd_mib.op = kBSMDOperation_TxRx;
      break;
    }
    case 1: {
      g_bsmd_mib.log.bsmd = (BSMDLogLevel)strtoul(optarg, 0, 10);
      break;
    }
    case 2: {
      g_bsmd_mib.log.lib.dot2 = strtoul(optarg, 0, 10);
      break;
    }
    case 3: {
      g_bsmd_mib.log.lib.dot3 = strtoul(optarg, 0, 10);
      break;
    }
    case 4: {
      g_bsmd_mib.log.lib.j29451 = strtoul(optarg, 0, 10);
      break;
    }
    case 5: {
      g_bsmd_mib.log.lib.wlanaccess = strtoul(optarg, 0, 10);
      break;
    }
    case 6: {
      g_bsmd_mib.log.lib.ltev2x_hal = strtoul(optarg, 0, 10);
      break;
    }
    case 7: {
      memcpy(g_bsmd_mib.dev_name, optarg, strlen(optarg));
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
int BSMD_ParseInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
    {"rx", no_argument, 0, 0},
    {"dbg", required_argument, 0, 1},
    {"dot2dbg", required_argument, 0, 2},
    {"dot3dbg", required_argument, 0, 3},
    {"j29451dbg", required_argument, 0, 4},
    {"wlandbg", required_argument, 0, 5},
    {"ltev2xdbg", required_argument, 0, 6},
    {"dev", required_argument, 0, 7},
    {0, 0, 0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 파라미터 기본 값을 설정한다.
   */
  g_bsmd_mib.op = kBSMDOperation_TxOnly;
  memcpy(g_bsmd_mib.dev_name, DEFAULT_DEV_NAME, strlen(DEFAULT_DEV_NAME));
  g_bsmd_mib.log.bsmd = DEFAULT_BSMD_LOG_LEVEL;
  g_bsmd_mib.log.lib.dot2 = DEFAULT_LIB_LOG_LEVEL;
  g_bsmd_mib.log.lib.dot3 = DEFAULT_LIB_LOG_LEVEL;
  g_bsmd_mib.log.lib.j29451 = DEFAULT_LIB_LOG_LEVEL;
  g_bsmd_mib.log.lib.wlanaccess = DEFAULT_LIB_LOG_LEVEL;
  g_bsmd_mib.log.lib.ltev2x_hal = DEFAULT_LIB_LOG_LEVEL;

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
    ret = BSMD_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 파싱된 파라미터 내용 출력
   */
  Log(kBSMDLogLevel_Event, "\top: %u(0:TxOnly, 1:TxRx), dbg: %u, dot2dbg: %u, dot3dbg: %u, j29451dbg: %u, ",
      g_bsmd_mib.op, g_bsmd_mib.log.bsmd, g_bsmd_mib.log.lib.dot2, g_bsmd_mib.log.lib.dot3, g_bsmd_mib.log.lib.j29451);
#if defined(_BSMD_DSRC_)
  Log(kBSMDLogLevel_Event, "wlandbg: %u\n", g_bsmd_mib.log.lib.wlanaccess);
#elif defined(_BSMD_LTE_V2X_)
  Log(kBSMDLogLevel_Event, "dev_name: %s, ltev2xdbg: %u\n", g_bsmd_mib.dev_name, g_bsmd_mib.log.lib.ltev2x_hal);
#endif

  return 0;
}
