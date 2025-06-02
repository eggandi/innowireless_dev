/**
 * @file
 * @brief IPv6 주소 설정/확인 등의 기능을 구현한 파일
 * @date 2019-11-10
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 랜덤한 링크로컬 IPv6 주소를 네트워크인터페이스에 설정한다.
 * @param[in] if_idx 주소를 설정할 인터페이스 식별번호
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_SetRandomLinkLocalAddress(unsigned int if_idx)
{
  uint8_t ipv6_addr[IPv6_ALEN];
  const uint8_t ll_prefix[8] = { 0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00 };

  Log(kTCIA3LogLevel_Event, "Set random link local address\n");

  /*
   * 랜덤한 링크로컬 주소를 생성한다.
   */
  memcpy(ipv6_addr, ll_prefix, sizeof(ll_prefix));
  for (int i = 0; i < 8; i++) {
    *(ipv6_addr + 8 + i) = (uint8_t)rand();
  }
  ipv6_addr[8] |= (1 << 1);  /* U/L bit 역전 */

#if defined(_TCIA2023_DSRC_)
  int ret = WAL_SetIPv6Address(if_idx, ipv6_addr, 64);
  if (ret < 0) {
    Err("Fail to set random link local address - WAL_SetIPv6Address() failed: %m\n");
    return -1;
  }
#elif defined(_TCIA2023_LTE_V2X_)
  (void)if_idx;
#endif

  Log(kTCIA3LogLevel_Event, "Success to set random link local address\n");
  return 0;
}


/**
 * @brief 특정 네트워크인터페이스에 할당된 모든 IPv6 주소를 삭제한다.
 * @param[in] if_idx 네트워크인터페이스 식별번호
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_DeleteAllIPv6Address(unsigned int if_idx)
{
  Log(kTCIA3LogLevel_Event, "Delete all IPv6 addresses on if[%u]\n", if_idx);

  /*
   * 기존에 설정되어 있는 모든 주소들을 확인하여 삭제한다.
   */
#if defined(_TCIA2023_DSRC_)
  struct WalIPv6AddressSet get_ipv6_addr_set;
  int ret = WAL_GetIPv6Addresses(if_idx, &get_ipv6_addr_set);
  if (ret < 0) {
    Err("Fail to delete all IPv6 addresses - WAL_GetIPv6Addresses() failed: %d\n", ret);
    return ret;
  }
  for (unsigned int cnt = 0; cnt < get_ipv6_addr_set.num; cnt++) {
    ret = WAL_DeleteIPv6Address(if_idx, get_ipv6_addr_set.addr[cnt].addr, get_ipv6_addr_set.addr[cnt].prefix_len);
    if (ret < 0) {
      Err("Fail to delete all IPv6 addresses - WAL_DeleteIPv6Address() failed: %d\n", ret);
      return ret;
    }
  }
#endif

  Log(kTCIA3LogLevel_Event, "Success to delete all IPv6 addresses\n");
  return 0;
}
