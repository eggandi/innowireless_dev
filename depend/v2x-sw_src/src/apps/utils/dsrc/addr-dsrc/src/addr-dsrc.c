/**
 * @file
 * @brief addr-dsrc 유틸리티 구현 메인 파일
 * @date 2020-01-16
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "wlanaccess/wlanaccess.h"


/// 장치가 지원하는 통신인터페이스 개수
int g_if_num;


/**
 * @brief 유틸리티 사용법을 화면에 출력한다.
 * @param[in] app_filename 어플리케이션 실행파일명
 */
static void ADDR_DSRC_Usage(char app_filename[])
{
  printf("\n\n Description: Utility to check and configure DSRC MAC address using v2x-sw libraries\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s set|get <if_idx> [address]\n\n", app_filename);
  printf("          set: set MAC address of interface whose index is \"if_idx\". \"address\" must be specified\n");
  printf("          get: get MAC address of interface whose index is \"if_idx\"\n");
  printf("\n\n");
}


/**
 * @brief 유틸리티 메인 함수
 * @param[in] argc 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 개수 (유틸리티 실행파일명 포함)
 * @param[in] argv 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (유틸리티 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int main(int argc, char *argv[])
{
  /*
   * 파라미터가 부족하면 사용법을 출력한다.
   */
  if (argc < 3) {
    ADDR_DSRC_Usage(argv[0]);
    return 0;
  }

  printf("Running addr utility..\n");

  /*
   * 접속계층라이브러리를 초기화한다.
   */
  int ret = WAL_Open(kWalLogLevel_Err);
  if (ret < 0) {
    printf("Fail to open wlanaccess library - %d\n", ret);
    return -1;
  }
  g_if_num = ret;
  printf("Success to open wlanaccess library - %d interface supported\n", g_if_num);

  /*
   * 입력된 통신인터페이스 식별번호의 유효성을 확인한다.
   */
  uint8_t if_idx = (uint8_t)strtoul(argv[2], NULL, 10);
  if (if_idx >= g_if_num) {
    printf("Invalid if_idx %u\n", if_idx);
    goto out;
  }

  /*
   * MAC 주소를 설정한다.
   */
  uint8_t addr[6];
  if (memcmp(argv[1], "set", 3) == 0) {
    WAL_ConvertMACAddressStrToOctets(argv[3], addr);
    ret = WAL_SetIfMACAddress(if_idx, addr);
    if (ret < 0) {
      printf("Fail to set MAC address for if[%u] as %02X:%02X:%02X:%02X:%02X:%02X - ret: %d\n",
        if_idx, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], ret);
    } else {
      printf("Success to set MAC address for if[%u] as %02X:%02X:%02X:%02X:%02X:%02X\n",
             if_idx, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    }
  }
  /*
   * MAC 주소를 확인한다.
   */
  else {
    ret = WAL_GetIfMACAddress(if_idx, addr);
    if (ret < 0) {
      printf("Fail to get MAC address for if[%u] - ret: %d\n", if_idx, ret);
    } else {
      printf("Success to get MAC address for if[%u] - %02X:%02X:%02X:%02X:%02X:%02X\n",
        if_idx, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    }
  }

  ret = 0;

out:
  /*
   * 접속계층 라이브러리를 해제한다.
   */
  WAL_Close();

  return ret;
}
