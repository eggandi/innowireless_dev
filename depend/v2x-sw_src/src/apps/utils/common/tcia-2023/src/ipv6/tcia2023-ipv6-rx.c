/** 
 * @file
 * @brief IPv6 수신 기능을 구현한 파일
 * @date 2020-08-21
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"

/// 이더넷 헤더 길이
#ifndef ETH_HLEN
#define ETH_HLEN (14)
#endif

/// 이더넷 주소 길이
#ifndef ETH_ALEN
#define ETH_ALEN (6)
#endif

/// 이더넷 FCS 필드 길이
#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN (4)
#endif

/// IPv6 EtherType
#define ETHERTYPE_IPv6 (0x86DD)

/**
 * @brief IPv6 패킷 헤더 형식 (next_hdr 값을 살펴 UDP 패킷만 골라 내는데 사용된다)
 */
struct IPv6Header
{
  uint32_t ver_tc_flow;
  uint16_t payload_len;
  uint8_t next_hdr;
  uint8_t hop_limit;
  uint8_t src_addr[IPv6_ALEN];
  uint8_t dst_addr[IPv6_ALEN];
} __attribute__((packed));


/**
 * @brief IPv6 수신 정보
 */
struct IPv6RxInfo
{
  unsigned int if_idx; /// 수신 인터페이스 식별번호
  uint16_t listen_port; /// 수신 포트번호
  int sock; ///< 수신 소켓
  pthread_t thread; ///< 수신 쓰레드
  volatile bool rxing; ///< 수신 중인지 여부
};
struct IPv6RxInfo g_ip_rx_info;


/**
 * @brief UDP 수신 소켓을 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_InitUDPRxSocket(void)
{
  Log(kTCIA3LogLevel_Event, "Initialize UDP rx socket\n");

  /*
   * 수신 소켓을 연다 - TS로 UDP 헤더까지 함께 전달해야 하므로 UDP 소켓이 아닌 Raw 소켓을 사용한다.
   */
  g_ip_rx_info.sock = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPv6));
  if (g_ip_rx_info.sock < 0) {
    Err("Fail to initialize UDP rx socket - socket() failed: %m\n");
    return -1;
  }

  /*
   * 수신을 위한 정보를 수신소켓에 바인드한다.
   */
  char if_name[IFNAMSIZ] = {0};
  int ret = TCIA2023_GetInterfaceNameForIndex(g_ip_rx_info.if_idx, if_name);
  if (ret < 0) {
    Err("Fail to initialize UDP rx socket - cannot find interface name for if_idx %d\n", g_ip_rx_info.if_idx);
    close(g_ip_rx_info.sock);
    return -1;
  }
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(addr));
  addr.sll_family		=	PF_PACKET;
  addr.sll_protocol	=	htons(ETHERTYPE_IPv6);
  addr.sll_halen		=	ETH_ALEN;
  addr.sll_ifindex	=	if_nametoindex(if_name);
  ret = bind(g_ip_rx_info.sock, (struct sockaddr *)&addr, sizeof(addr));
  if (ret) {
    Err("Fail to initialize UDP rx socket - bind() failed: %m\n");
    close(g_ip_rx_info.sock);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to bind() - ifindex: %d\n", addr.sll_ifindex);

  Log(kTCIA3LogLevel_Event, "Success to initialize UDP rx socket\n");
  return 0;
}


/**
 * @brief UDP 패킷 송신 쓰레드
 * @param none 사용되지 않음
 * @return NULL
 */
uint8_t g_udp_rx_buf[1500];
static void * TCIA2023_UDPRxThread(void *none)
{
  (void)none;
  unsigned int rx_cnt = 0;

  Log(kTCIA3LogLevel_Event, "Success to create UDP rx thread\n");
  g_ip_rx_info.rxing = true;

  /*
   * UDP 패킷을 수신하면 TS로 전달한다.
   */
  int rx_pkt_size;
  socklen_t addr_len;
  struct sockaddr_in6 remote;
  uint8_t ind_pkt[1000];
  int ind_pkt_size;
  uint8_t *src_ipv6_addr;
  do
  {
    // 패킷 수신 - Raw 소켓을 사용하므로, 수신되는 패킷은 이더넷 MPDU이다.
    rx_pkt_size = recvfrom(g_ip_rx_info.sock,
                           g_udp_rx_buf,
                           sizeof(g_udp_rx_buf),
                           MSG_TRUNC,
                           (struct sockaddr *)&remote,
                           &addr_len);

    if (g_ip_rx_info.rxing == false) {
      break;
    }

    if (rx_pkt_size <= 0) {
      Err("Fail to receive UDP packet - recvfrom() failed: %m\n");
      continue;
    }

    uint8_t *ip_pkt = g_udp_rx_buf + ETH_HLEN;
    struct IPv6Header *ip_hdr = (struct IPv6Header *)ip_pkt;
    uint8_t *ip_payload = ip_pkt + sizeof(struct IPv6Header);
    size_t ip_payload_size = rx_pkt_size - (ETH_HLEN + sizeof(struct IPv6Header));
    src_ipv6_addr = remote.sin6_addr.s6_addr;

    switch (ip_hdr->next_hdr) {
      // UDP 패킷에 대한 Indication 생성
      case 17:
        ind_pkt_size = TCIA2023_ConstructIndication_UDPPktRx(g_ip_rx_info.if_idx,
                                                         src_ipv6_addr,
                                                         ip_payload,
                                                         ip_payload_size,
                                                         ind_pkt,
                                                         sizeof(ind_pkt));
        break;

        // ICMPv6 패킷에 대한 Indication 생성
      case 58:
        ind_pkt_size = TCIA2023_ConstructIndication_ICMPv6PktRx(g_ip_rx_info.if_idx,
                                                            src_ipv6_addr,
                                                            ip_payload,
                                                            ip_payload_size,
                                                            ind_pkt,
                                                            sizeof(ind_pkt));
        break;

      default:
        Err("Not supported IPv6 packet - Next Hdr in IPv6 header is %u\n", ip_hdr->next_hdr);
        continue;
    }

    // TS로 Indication 송신
    if (ind_pkt_size > 0) {
      TCIA2023_SendTCIMessagePacket(ind_pkt, (size_t)ind_pkt_size);
      ++rx_cnt;
      if ((rx_cnt % 10) == 1) {
        Log(kTCIA3LogLevel_Event, "Success to send %u-th IPv6(UDP/ICMPv6) pkt indication\n", rx_cnt);
      } else {
        Log(kTCIA3LogLevel_DetailedEvent, "Success to send %u-th IPv6(UDP/ICMPv6) pkt indication\n", rx_cnt);
      }
    }
  } while(1);

  return NULL;
}


/**
 * @brief UDP 수신 동작을 시작한다.
 * @param[in] data TS로부터 수신된 StartIPv6Rx 메시지 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_StartUDPRxOperation(const struct Cvcoctci2023StartIPv6Rx *data)
{
  Log(kTCIA3LogLevel_Event, "Start UDP rx operation\n");

  /*
   * 수신 동작이 이미 수행 중이면 실패를 반환한다.
   */
  if (g_ip_rx_info.rxing == true) {
    Err("Fail to start UDP rx operation - already running\n");
    return -1;
  }

  /*
   * 수신 정보를 저장한다.
   */
  g_ip_rx_info.if_idx = data->radio.radio;
  g_ip_rx_info.listen_port = data->listen_port;

  /*
   * 수신 소켓을 초기화한다.
   */
  int ret = TCIA2023_InitUDPRxSocket();
  if (ret < 0) {
    return -1;
  }


  /*
   * 수신 쓰레드를 생성한다.
   */
  ret = pthread_create(&(g_ip_rx_info.thread), NULL, TCIA2023_UDPRxThread, NULL);
  if (ret < 0) {
    Err("Fail to start UDP rx operation - pthread_create() failed: %m\n");
    return -1;
  }
  while(g_ip_rx_info.rxing == false) {
    usleep(10);
  }
  pthread_detach(g_ip_rx_info.thread);

  Log(kTCIA3LogLevel_Event, "Success to start UDP rx operation\n");
  return 0;
}


/**
 * @brief UDP 수신 동작을 중지한다.
 */
void TCIA2023_StopUDPRxOperation(void)
{
  Log(kTCIA3LogLevel_Event, "Stop UDP rx operation\n");

  if (g_ip_rx_info.rxing == true) {
    pthread_cancel(g_ip_rx_info.thread);
    close(g_ip_rx_info.sock);
    g_ip_rx_info.rxing = false;
  }
}


/**
 * @brief IPv6 수신 동작을 시작한다.
 * @param[in] data TS로부터 수신된 StartIPv6Rx 메시지 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_StartIPv6RxOperation(const struct Cvcoctci2023StartIPv6Rx *data)
{
  Log(kTCIA3LogLevel_Event, "Start IPv6 rx operation\n");

  /*
   * 프로토콜 별로 IP 수신 동작을 시작한다.
   *  - 현재 Rx 동작은 UDP만 지원하면 된다.
   */
  int ret;
  switch(data->protocol) {
    case kCvcoctci2023Protocol_udp:
      ret = TCIA2023_StartUDPRxOperation(data);
      break;
    default:
      Err("Fail to start IPv6 tx operation - invalid protocol %d\n", data->protocol);
      return -1;
  }

  if (ret < 0) {
    Err("Fail to start IPv6 rx operation\n");
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to start IPv6 rx operation\n");
  return 0;
}


/**
 * @brief IPv6 수신 동작을 중지한다.
 * @param[in] data TS로부터 수신된 StartIPv6Rx 메시지 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_StopIPv6RxOperation(const struct Cvcoctci2023StopIPv6Rx *data)
{
  Log(kTCIA3LogLevel_Event, "Stop IPv6 rx operation\n");

  /*
   * 프로토콜 별로 IP 수신 동작을 중지한다.
   *  - 현재 Rx 동작은 UDP만 지원하면 된다.
   */
  int ret = 0;
  switch(data->protocol) {
    case kCvcoctci2023Protocol_udp:
      TCIA2023_StopUDPRxOperation();
      break;
    default:
      Err("Fail to stop IPv6 tx operation - invalid protocol %d\n", data->protocol);
      return -1;
  }

  if (ret < 0) {
    Err("Fail to stop IPv6 rx operation\n");
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to stop IPv6 rx operation\n");
  return 0;
}

