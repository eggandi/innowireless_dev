/** 
 * @file
 * @brief WRA 수신 처리 관련 기능을 구현한 파일
 * @date 2020-06-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

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


/**
 * @brief 수신된 WRA를 처리한다.
 * @param[in] if_idx WRA가 수신된 인터페이스 식별번호
 * @param[in] wra 수신된 WRA 정보
 * @retval 0: 성공
 * @retval -1: 실패
 *
 * V2X 인터페이스의 IP 주소, Default gateway, DNS 주소 등을 설정한다.
 */
int TCIA2023_ProcessRxWRA(unsigned int if_idx, struct Dot3WRA *wra)
{
  /*
   * 로그 출력
   */
  Log(kTCIA3LogLevel_Event, "Process rx WRA\n");
  char ipv6_addr_str[IPv6_ADDR_STR_MAX_LEN];
  Log(kTCIA3LogLevel_Event, "  Router lifetime: %u\n", wra->router_lifetime);
  inet_ntop(AF_INET6, wra->ip_prefix, ipv6_addr_str, sizeof(ipv6_addr_str));
  Log(kTCIA3LogLevel_Event, "  IP prefix: %s/%u\n", ipv6_addr_str, wra->ip_prefix_len);
  inet_ntop(AF_INET6, wra->default_gw, ipv6_addr_str, sizeof(ipv6_addr_str));
  Log(kTCIA3LogLevel_Event, "  Default gateway: %s\n", ipv6_addr_str);
  inet_ntop(AF_INET6, wra->primary_dns, ipv6_addr_str, sizeof(ipv6_addr_str));
  Log(kTCIA3LogLevel_Event, "  Primary DNS: %s\n", ipv6_addr_str);
  if (wra->present.secondary_dns == true) {
    inet_ntop(AF_INET6, wra->secondary_dns, ipv6_addr_str, sizeof(ipv6_addr_str));
    Log(kTCIA3LogLevel_Event, "  Secondary DNS: %s\n", ipv6_addr_str);
  }
  if (wra->present.gateway_mac_addr == true) {
    Log(kTCIA3LogLevel_Event, "  Gateway MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
        wra->gateway_mac_addr[0], wra->gateway_mac_addr[1], wra->gateway_mac_addr[2],
        wra->gateway_mac_addr[3], wra->gateway_mac_addr[4], wra->gateway_mac_addr[5]);
  }

#if defined(_TCIA2023_DSRC_)
  /*
   * WRA 정보를 이용하여 IPv6 주소를 설정한다.
   */
  uint8_t ipv6_addr[IPv6_ALEN];
  int ret = WAL_SetIPv6AddressWithPrefixInfo(if_idx, wra->ip_prefix, wra->ip_prefix_len, ipv6_addr);
  if (ret < 0) {
    Err("Fail to process WRA - WAL_SetIPv6AddressWithPrefixInfo() failed: %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to set IPv6 address with prefix info\n");

  /*
   * WRA 정보를 이용하여 Default gateway IPv6 주소를 설정한다.
   */
  ret = WAL_SetDefaultGatewayIPv6Address(if_idx, wra->default_gw);
  if (ret < 0) {
    Err("Fail to process WRA - WAL_SetDefaultGatewayIPv6Address() failed: %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to set default gateway IPv6 address\n");

  /*
   * WRA 정보를 이용하여 DNS 서버 IPv6 주소를 설정한다.
   */
  ret = WAL_SetDNSIPv6Address(wra->primary_dns, wra->present.secondary_dns, wra->secondary_dns);
  if (ret < 0) {
    Err("Fail to process WRA - WAL_SetDnsIPv6Address() failed: %d\n", ret);
  } else {
    Log(kTCIA3LogLevel_Event, "Success to set DNS server IPv6 address\n");
  }
#endif

  /*
   * WRA 정보를 이용하여 Gateway MAC 주소를 설정한다.
   */
  if (wra->present.gateway_mac_addr) {
    memcpy(g_tcia_mib.ip_net_info.gw_mac_addr, wra->gateway_mac_addr, MAC_ALEN);
    g_tcia_mib.ip_net_info.gw_mac_addr_configured = true;
    char line[500];
    memset(line, 0, 500);
    char addr_str[IPv6_ADDR_STR_MAX_LEN+1];
    char if_name[IF_NAME_MAX_SIZE+1] = {0};
    TCIA2023_GetInterfaceNameForIndex(if_idx, if_name);
    sprintf(line, "ip -6 neigh add %s lladdr %02x:%02x:%02x:%02x:%02x:%02x dev %s",
            inet_ntop(AF_INET6, wra->default_gw, addr_str, sizeof(addr_str)),
            wra->gateway_mac_addr[0], wra->gateway_mac_addr[1], wra->gateway_mac_addr[2],
            wra->gateway_mac_addr[3], wra->gateway_mac_addr[4], wra->gateway_mac_addr[5],
            if_name);
    Log(kTCIA3LogLevel_Event, "Set gateway MAC address - %s\n", line);
    system(line);
  }

  Log(kTCIA3LogLevel_Event, "Success to process WRA\n");
  return 0;
}
