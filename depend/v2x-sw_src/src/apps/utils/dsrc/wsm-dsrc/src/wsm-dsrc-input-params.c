/**
 * @file
 * @brief wsm-dsrc 어플리케이션 실행 시 함께 입력되는 파라미터들을 처리하는 기능을 구현한 파일
 * @date 2019-08-10
 * @author gyun
 */

// 시스템 헤더 파일
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 어플리케이션 헤더 파일
#include "wsm-dsrc.h"


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int WSM_DSRC_ProcessParsedOption(int option)
{
  switch (option) {
    case 0: {
      g_mib.tx_if_idx = (unsigned int)strtoul(optarg, 0, 10);
      break;
    }
    case 1: {
      g_mib.psid = (Dot3PSID)strtol(optarg, 0, 10);
      break;
    }
    case 2: {
      g_mib.tx_chan_num = (Dot3ChannelNumber)strtol(optarg, 0, 10);
      break;
    }
    case 3: {
      g_mib.tx_datarate = (Dot3DataRate)strtoul(optarg, 0, 10);
      break;
    }
    case 4: {
      g_mib.tx_power = (Dot3Power)strtol(optarg, 0, 10);
      break;
    }
    case 5: {
      g_mib.tx_priority = (Dot3Priority)strtoul(optarg, 0, 10);
      break;
    }
    case 6: {
      WAL_ConvertMACAddressStrToOctets(optarg, g_mib.tx_dst_mac_addr);
      break;
    }
    case 7: {
      g_mib.tx_wsm_body_len = (Dot3WSMPayloadSize)strtoul(optarg, 0, 10);
      break;
    }
    case 8: {
      g_mib.tx_interval = (unsigned int)strtoul(optarg, 0, 10);
      break;
    }
    case 9: {
      g_mib.dbg = strtoul(optarg, 0, 10);
      break;
    }
    case 10: {
      g_mib.lib_dbg = strtoul(optarg, 0, 10);
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
int WSM_DSRC_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
    {"if", required_argument, 0, 0/*=getopt_long() 호출 시 option_idx 에 반환되는 값*/},
    {"psid", required_argument, 0, 1},
    {"chan", required_argument, 0, 2},
    {"rate", required_argument, 0, 3},
    {"power", required_argument, 0, 4},
    {"prio", required_argument, 0, 5},
    {"dst", required_argument, 0, 6},
    {"len", required_argument, 0, 7},
    {"interval", required_argument, 0, 8},
    {"dbg", required_argument, 0, 9},
    {"libdbg", required_argument, 0, 10},
    {0, 0, 0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 기본 파라미터 파싱 및 저장
   */
  if (!memcmp(argv[1], "trx", 3)) {
    g_mib.op = kOperationType_trx;
  } else if (!memcmp(argv[1], "rx", 2)) {
    g_mib.op = kOperationType_rx_only;
  } else {
    printf("Invalid operation - %s\n", argv[1]);
    return -1;
  }

  /*
   * 파라미터 기본 값 설정
   */
  g_mib.tx_if_idx = DEFAULT_IF_IDX;
  g_mib.psid = DEFAULT_PSID;
  g_mib.tx_chan_num = DEFAULT_CHAN_NUM;
  g_mib.tx_datarate = DEFAULT_DATARATE;
  g_mib.tx_power = DEFAULT_POWER;
  g_mib.tx_priority = DEFAULT_PRIORITY;
  g_mib.tx_wsm_body_len = DEFAULT_WSM_BODY_LEN;
  g_mib.tx_interval = DEFAULT_TX_INTERVAL;
  g_mib.dbg = DEFAULT_DBG;
  g_mib.lib_dbg = DEFAULT_LIB_DBG;
  memset(g_mib.tx_dst_mac_addr, 0xff, MAC_ALEN);

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
    int ret = WSM_DSRC_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 파싱된 파라미터 내용 출력
   */
  printf("  op: %u(0:rx,1:trx), PSID: %u, dbg: %u, lib dbg: %u\n", g_mib.op, g_mib.psid, g_mib.dbg, g_mib.lib_dbg);
  if (g_mib.op == kOperationType_trx) {
    printf("  if_idx: %u, chan: %u\n", g_mib.tx_if_idx, g_mib.tx_chan_num);
    printf("  datarate: %u*500kbps, power: %ddBm, priority: %u, dst: "MAC_ADDR_FMT"\n",
           g_mib.tx_datarate, g_mib.tx_power, g_mib.tx_priority, MAC_ADDR_FMT_ARGS(g_mib.tx_dst_mac_addr));
    printf("  body len: %zu, interval: %u(usec)\n", g_mib.tx_wsm_body_len, g_mib.tx_interval);
  }

  return 0;
}
