/**
 * @file
 * @date 2019-11-09
 * @author gyun
 * @brief 시스템의 네트워크 인터페이스 정보를 구성하는 기능을 구현한 파일
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
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/// 문자열 버퍼 최대길이
#define MAXLINE 255

/* from include/uapi/linux/route.h */
#ifndef RTF_UP
#define RTF_UP 0x0001	/* route usable                 */
#define RTF_GATEWAY 0x0002	/* destination is a gateway     */
#define RTF_HOST 0x0004	/* host entry (net otherwise)   */
#define RTF_REINSTATE 0x0008	/* reinstate route after tmout  */
#define RTF_DYNAMIC 0x0010	/* created dyn. (by redirect)   */
#define RTF_MODIFIED 0x0020	/* modified dyn. (by redirect)  */
#define RTF_MTU 0x0040	/* specific MTU for this route  */
#ifndef RTF_MSS
#define RTF_MSS RTF_MTU	/* Compatibility :-(            */
#endif
#define RTF_WINDOW 0x0080	/* per route window clamping    */
#define RTF_IRTT 0x0100	/* Initial round trip time      */
#define RTF_REJECT 0x0200	/* Reject route                 */
#define RTF_NONEXTHOP 0x00200000 /* route with no nexthop	*/
#endif

/// DNS 설정 파일 경로
const char *dns_file_path = "/etc/resolv.conf";
/// 라우팅 정보 시스템 파일 경로
const char *route_file_path = "/proc/net/ipv6_route";


/**
 * @brief 특정 네트워크인터페이스 식별번호를 갖는 인터페이스의 인터페이스명을 반환한다.
 * @param[in] if_idx 네트워크인터페이스 식별번호
 * @param[in] if_name 인터페이스명이 저장되어 반환될 버퍼
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_GetInterfaceNameForIndex(unsigned int if_idx, char *if_name)
{
  if (if_idx >= g_tcia_mib.v2x_if.if_num) {
    Err("Fail to get interface name for if[%u]\n", if_idx);
    return -1;
  }

  // Condor5x 용 IPv6 인터페이스 이름
  const char *if_name_defined[V2X_IF_MAX_NUM] = {
    "llc-cch-ipv6",
    "llc-sch-ipv6"
  };

  memcpy(if_name, if_name_defined[if_idx], strlen(if_name_defined[if_idx]));
  Log(kTCIA3LogLevel_Event, "Success to get interface name \"%s\" for if[%u]\n", if_name, if_idx);
  return 0;
}


#if defined(_TCIA2023_DSRC_)
/**
 * @brief 인터페이스의 gateway mac 주소를 획득한다.
 * @param[out] gw_mac_addr gateway mac 주소가 반환될 버퍼
 * @return gateway mac 주소 반환 여부
 *
 * gateway MAC 주소는 tcia MIB에 저장되어 있다.
 */
static bool TCIA2023_GetGatewayMACAddress(uint8_t gw_mac_addr[MAC_ALEN])
{
  if (g_tcia_mib.ip_net_info.gw_mac_addr_configured == true) {
    memcpy(gw_mac_addr, g_tcia_mib.ip_net_info.gw_mac_addr, MAC_ALEN);
    Log(kTCIA3LogLevel_Event, "Success to get gateway mac address - %02X:%02X:%02X:%02X:%02X:%02X\n",
        gw_mac_addr[0], gw_mac_addr[1], gw_mac_addr[2], gw_mac_addr[3], gw_mac_addr[4], gw_mac_addr[5]);
    return true;
  }
  Log(kTCIA3LogLevel_Event, "Fail to get gateway mac address - no entry\n");
  return false;
}
#endif


/**
 * @brief 시스템의 인터페이스 정보를 획득하여 반환한다.
 * @param[in] radio_idx 요청된 인터페이스 식별번호
 * @param[out] infos 획득된 인터페이스 정보가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_GetInterfaceInfo(Cvcoctci2023Radio radio_idx, struct Cvcoctci2023IPv6InterfaceInfos *infos)
{
  Log(kTCIA3LogLevel_Event, "Get interface info for if%d\n", radio_idx);

#if defined(_TCIA2023_DSRC_)

  int ret;
  char ipv6_addr_str[IPv6_ADDR_STR_MAX_LEN+1];

  /*
   * 인터페이스 MAC 주소를 획득한다.
   */
  uint8_t mac_addr[MAC_ALEN];
  ret = WAL_GetIfMACAddress(radio_idx, mac_addr);
  if (ret < 0) {
    Err("Fail to get interface mac address - %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to get mac address - %02X:%02X:%02X:%02X:%02X:%02X\n",
    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

  /*
   * 인터페이스 IPv6 주소들을 획득한다.
   */
  struct WalIPv6AddressSet get_ipv6_addr_set;
  ret = WAL_GetIPv6Addresses(radio_idx, &get_ipv6_addr_set);
  if (ret < 0) {
    Err("Fail to get interface ipv6 address - WAL_GetIPv6Addresses() failed: %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to get %u IPv6 addresses\n", get_ipv6_addr_set.num);
  for (unsigned int cnt = 0; cnt < get_ipv6_addr_set.num; cnt++) {
    Log(kTCIA3LogLevel_Event, "  [%u]. %s/%u\n", cnt,
        inet_ntop(AF_INET6, get_ipv6_addr_set.addr[cnt].addr, ipv6_addr_str, sizeof(ipv6_addr_str)),
        get_ipv6_addr_set.addr[cnt].prefix_len);
  }

  /*
   * Default gateway IPv6 주소를 획득한다.
   */
  bool default_gw_ipv6_addr_present;
  uint8_t default_gw_ipv6_addr[IPv6_ALEN];
  ret = WAL_GetDefaultGatewayIPv6Address(radio_idx, default_gw_ipv6_addr);
  if (ret < 0) {
    Err("Fail to get default gateway ipv6 address - WAL_GetDefaultGatewayIPv6Address() failed: %d\n", ret);
    default_gw_ipv6_addr_present = false;
  } else {
    memset(ipv6_addr_str, 0, sizeof(ipv6_addr_str));
    Log(kTCIA3LogLevel_Event, "Success to get default gateway IPv6 address(%s)\n",
        inet_ntop(AF_INET6, default_gw_ipv6_addr, ipv6_addr_str, sizeof(ipv6_addr_str)));
    default_gw_ipv6_addr_present = true;
  }

  /*
   * DNS IPv6 주소를 획득한다.
   */
  uint8_t primary_dns_ipv6_addr[IPv6_ALEN], secondary_dns_ipv6_addr[IPv6_ALEN];
  bool primary_dns_ipv6_addr_present, secondary_dns_ipv6_addr_present;
  ret = WAL_GetDNSIPv6Address(primary_dns_ipv6_addr, &secondary_dns_ipv6_addr_present, secondary_dns_ipv6_addr);
  if (ret < 0) {
    Err("Fail to get DNS IPv6 address - WAL_GetDNSIPv6Address() failed: %m\n", ret);
    primary_dns_ipv6_addr_present = false;
    secondary_dns_ipv6_addr_present = false;
  } else {
    Log(kTCIA3LogLevel_Event, "Success to get DNS IPv6 address\n");
    memset(ipv6_addr_str, 0, sizeof(ipv6_addr_str));
    Log(kTCIA3LogLevel_Event, "   Primary DNS: %s\n",
        inet_ntop(AF_INET6, primary_dns_ipv6_addr, ipv6_addr_str, sizeof(ipv6_addr_str)));
    primary_dns_ipv6_addr_present = true;
    if (secondary_dns_ipv6_addr_present == true) {
      memset(ipv6_addr_str, 0, sizeof(ipv6_addr_str));
      Log(kTCIA3LogLevel_Event, "   Secondary DNS: %s\n",
          inet_ntop(AF_INET6, secondary_dns_ipv6_addr, ipv6_addr_str, sizeof(ipv6_addr_str)));
    }
  }

  /*
   * Gateway MAC 주소를 획득한다.
   */
  uint8_t gw_mac_addr[MAC_ALEN];
  bool gw_mac_addr_present = TCIA2023_GetGatewayMACAddress(gw_mac_addr);

  /*
   * 반환 파라미터에 정보를 채운다.
   */
  infos->info_cnt = 1;
  struct Cvcoctci2023IPv6InterfaceInfo *info = &(infos->info[0]);
  memset(info, 0, sizeof(*info));
  snprintf(info->if_name, sizeof(info->if_name), "wave%d", radio_idx);
  info->ip_addr_list.cnt = get_ipv6_addr_set.num;
  for(int i = 0; i < info->ip_addr_list.cnt; i++) {
    memcpy(info->ip_addr_list.addr[i], get_ipv6_addr_set.addr[i].addr, sizeof(info->ip_addr_list.addr[i]));
  }
  memcpy(info->mac_addr, mac_addr, sizeof(info->mac_addr));
  if (default_gw_ipv6_addr_present) {
    info->options.default_gw = true;
    memcpy(info->default_gw, default_gw_ipv6_addr, sizeof(info->default_gw));
  }
  if (primary_dns_ipv6_addr_present) {
    info->options.primary_dns = true;
    memcpy(info->primary_dns, primary_dns_ipv6_addr, sizeof(info->primary_dns));
  }
  if (gw_mac_addr_present) {
    info->options.gw_mac_addr = true;
    memcpy(info->gw_mac_addr, gw_mac_addr, sizeof(info->gw_mac_addr));
  }
#elif defined(_TCIA2023_LTE_V2X_)
  infos->info_cnt = 0;
#else
#error "Communication type is not defined"
#endif

  Log(kTCIA3LogLevel_Event, "Success to get interface info\n");
  return 0;
}
