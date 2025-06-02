/** 
 * @file
 * @brief init-dsrc 유틸리티 구현 메인 파일
 * @date 2020-02-29
 * @author gyun
 *
 * 플랫폼 부팅 후 최초 1회 실행하여, 하드웨어 및 디바이스 드라이버를 초기화한다.
 */


// 시스템 헤더 파일
#include <stdio.h>

// 라이브러리 헤더 파일
#include "wlanaccess/wlanaccess.h"


/**
 * @brief init 유틸리티 메인 함수
 * @retval 0: 성공
 * @retval -1: 실패
 */
int main(void)
{
  printf("Initialize device hardware and device driver\n");

  /*
   * WLAN 접속계층 라이브러리 초기화 API 를 호출하여 디바이스를 초기화한다.
   */
  int ret = WAL_Init(kWalLogLevel_Err);
  if (ret < 0) {
    printf("Fail to initialize device - %d\n", ret);
    return -1;
  }

  /*
   * 라이브러리를 해제한다.
   */
  WAL_Close();

  printf("Success to initialize device\n");
  return 0;
}
