/** 
 * @file
 * @brief
 * @date 2020-06-24
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
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


/// 이더넷 헤더 길이
#ifndef ETH_HLEN
#define ETH_HLEN (14)
#endif
/// 이더넷 FCS 필드 길이
#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN (4)
#endif
/// 이더넷 주소 길이
#ifndef ETH_ALEN
#define ETH_ALEN (6)
#endif
/// IPv6 EtherType
#define ETHERTYPE_IPv6 (0x86DD)

/// IPv6 헤더 길이
#ifndef IPv6_HLEN
#define IPv6_HLEN (40)
#endif
/// IPv6 헤더 내 송신지 주소 필드 오프셋
#define	IPv6_HDR_SA_OFFSET	(8)
/// ICMPv6 Echo request 메시지 식별자
#define ICMPv6_ECHO_REQUEST (128)
/// ICMPv6 Echo reply 메시지 식별자
#define ICMPv6_ECHO_REPLY (129)


/**
 * @brief Ping 송신정보
 */
struct IPv6PingInfo
{
  // 전송 파라미터
  //  - TS 로부터 수신된 정보로 채워지며, 해당 정보를 이용하여 IPv6 통신이 수행된다.
  unsigned int if_idx;
  uint8_t dst_ipv6_addr[IPv6_ALEN];

  pthread_t thread; ///< 송신 쓰레드
  timer_t timer; ///< 송신 타이머
  pthread_mutex_t timer_mtx; ///< 송신타이머 뮤텍스
  pthread_cond_t timer_sig; ///< 송신타이머 시그널
  volatile bool thread_running; ///< 송신쓰레드가 동작 중인지 여부

  int tx_sock; ///< Ping request 송신 소켓
  int rx_sock; ///< Ping reply 수신 소켓

  uint8_t ping_pkt[200]; ///< Ping 패킷 버퍼
  size_t ping_pkt_size; ///< Ping 패킷 길이

  struct sockaddr_in6 remote; ///< Ping request 패킷 목적지 정보

  volatile bool running; ///< Ping 송신 동작 중인지 여부
};

static struct IPv6PingInfo g_ping_info;


/**
 * @brief ICMPv6 패킷 형식
 */
struct ICMPv6Pkt
{
  uint8_t type;
  uint8_t code;
  uint16_t chk_sum;
  uint16_t id;
  uint16_t seq;
  uint8_t body[100];
}  __attribute__ ((packed));


/**
 * @brief Ping 송신 타이머 만기 시 실행되는 쓰레드 함수 -> Ping request를 송신하고 reply를 수신하여 TS로 Indication한다.
 * @param arg 사용되지 않음
 */
static void TCIA2023_PingTxTimerThread(union sigval arg)
{
  (void)arg;

  char ipv6_addr_str[IPv6_ADDR_STR_MAX_LEN+1];
  inet_ntop(AF_INET6, g_ping_info.remote.sin6_addr.s6_addr, ipv6_addr_str, sizeof(ipv6_addr_str));
  Log(kTCIA3LogLevel_Event, "Send Ping request to %s\n", ipv6_addr_str);
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, g_ping_info.ping_pkt, g_ping_info.ping_pkt_size);

  /*
   * 미리 만들어 둔 Ping request 패킷을 송신한다.
   */
  int ret = sendto(g_ping_info.tx_sock,
                   g_ping_info.ping_pkt,
                   g_ping_info.ping_pkt_size,
                   0,
                   (struct sockaddr *)&(g_ping_info.remote),
                   sizeof(g_ping_info.remote));
  if (ret != sizeof(struct ICMPv6Pkt)) {
    Err("Fail to send Ping request - sendto() failed: %m\n");
    return;
  }
  Log(kTCIA3LogLevel_Event, "Success to send Ping request\n");

  /*
   * Ping reply 패킷을 수신한다 - 수신되는 패킷은 {이더넷 MAC헤더 + IPv6 헤더 + ICMPv6 헤더&바디} 형태를 갖는다.
   */
  struct sockaddr_ll from;
  socklen_t from_len = sizeof(from);
  int len = recvfrom(g_ping_info.rx_sock,
                     g_ping_info.ping_pkt,
                     sizeof(g_ping_info.ping_pkt),
                     MSG_TRUNC,
                     (struct sockaddr *)&from,
                     &from_len);
  if (len <= 0) {
    Err("Fail to receive Ping reply - recvfrom() failed: %m\n");
    return;
  }

  uint8_t *ip_pkt = g_ping_info.ping_pkt + ETH_HLEN;
  struct ICMPv6Pkt *icmp_pkt = (struct ICMPv6Pkt *)(ip_pkt + IPv6_HLEN);
  size_t icmp_pkt_len = len - ETH_HLEN - IPv6_HLEN;

  /*
   * Ping reply 패킷이 수신되었으면, TS로 Indication 메시지를 전달한다.
   * Indication에 수납되는 PDU는 MAC/IPv6 헤더를 제외한 ICMPv6 reply 패킷(헤더 및 바디 포함)이다
   */
  if (icmp_pkt->type == ICMPv6_ECHO_REPLY) {
    uint8_t *src_ipv6_addr = (ip_pkt + IPv6_HDR_SA_OFFSET);
    inet_ntop(AF_INET6, src_ipv6_addr, ipv6_addr_str, sizeof(ipv6_addr_str));
    Log(kTCIA3LogLevel_Event, "Ping reply is received form %s\n", ipv6_addr_str);
    uint8_t ind_pkt[1000];
    int ind_pkt_size = TCIA2023_ConstructIndication_ICMPv6PktRx(g_ping_info.if_idx,
                                                             src_ipv6_addr,
                                                             (uint8_t *)icmp_pkt,
                                                             icmp_pkt_len,
                                                             ind_pkt,
                                                             (size_t)sizeof(ind_pkt));
    if (ind_pkt_size > 0) {
      TCIA2023_SendTCIMessagePacket(ind_pkt, ind_pkt_size);
    }
  } else {
    Err("ICMPv6 type %d is received(not expected reply)\n", icmp_pkt->type);
  }
}


/**
 * @brief Ping 송신 타이머를 초기화한다.
 * @param[in] msec 타이머 주기
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_InitPingTxTimer(uint32_t msec)
{
  Log(kTCIA3LogLevel_Event, "Initialize Ping tx timer - duration: %umsec\n", msec);

  /*
   * 타이머 만기 시에 TCIA2023_PingTxTimerThread() 쓰레드가 생성되도록 설정한다.
   */
  struct sigevent se;
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_value.sival_ptr = &(g_ping_info.timer);
  se.sigev_notify_function = TCIA2023_PingTxTimerThread;
  se.sigev_notify_attributes = NULL;
  int ret = timer_create(CLOCK_MONOTONIC, &se, &(g_ping_info.timer));
  if (ret) {
    Err("Fail to initialize Ping tx timer - timer_create() failed - %m\n");
    return -1;
  }

  /*
   * 타이머 주기를 설정한다.
   */
  struct itimerspec ts;
  ts.it_value.tv_sec = 0;
  ts.it_value.tv_nsec = 1000;
  ts.it_interval.tv_sec = msec / 1000;
  ts.it_interval.tv_nsec = (msec % 1000) * 1000000;
  ret = timer_settime(g_ping_info.timer, 0, &ts, 0);
  if (ret) {
    Err("Fail to initialize Ping tx timer - timer_settime() failed - %m\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to initialize Ping tx timer.\n");
  return 0;
}


/**
 * @brief Ping request 패킷을 생성한다.
 * @param[out] outbuf 생성된 패킷이 저장될 버퍼
 * @return 생성된 패킷의 길이
 */
static size_t TCIA2023_ConstructPingRequest(uint8_t *outbuf)
{
  Log(kTCIA3LogLevel_Event, "Construct Ping request packet\n");
  struct ICMPv6Pkt *icmp_pkt = (struct ICMPv6Pkt *)outbuf;
  icmp_pkt->type = ICMPv6_ECHO_REQUEST;
  icmp_pkt->code = 0;
  icmp_pkt->chk_sum = htons(0x6a13); // 더미 데이터
  icmp_pkt->id = htons(0x0001); // 더미 데이터
  icmp_pkt->seq = htons(0x0002); // 더미 데이터
  for (int i = 0; i < 100; i++) { // 더미 데이터
    icmp_pkt->body[i] = (uint8_t)i;
  }
  return sizeof(struct ICMPv6Pkt);
}


/**
 * @brief Ping 송신을 위한 준비를 수행한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_PreparePingTx(void)
{
  int ret;
  Log(kTCIA3LogLevel_Event, "Prepare Ping tx\n");

  /*
   * 송신소켓과 수신소켓을 생성한다.
   */
  g_ping_info.tx_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (g_ping_info.tx_sock < 0) {
    Err("Fail to prepare Ping tx - socket(tx_sock) failed: %m\n");
    return -1;
  }
  g_ping_info.rx_sock = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPv6));
  if (g_ping_info.rx_sock < 0) {
    Err("Fail to prepare Ping tx - socket(rx_sock) failed: %m\n");
    close(g_ping_info.tx_sock);
    return -1;
  }

  /*
   * Ping 패킷을 구성한다.
   */
  g_ping_info.ping_pkt_size = TCIA2023_ConstructPingRequest(g_ping_info.ping_pkt);

  /*
   * 목적지 IPv6 주소를 설정한다 - TS로부터 전달받은 정보를 사용한다.
   */
  memset(&(g_ping_info.remote), 0, sizeof(g_ping_info.remote));
  g_ping_info.remote.sin6_family = AF_INET6;
  memcpy(g_ping_info.remote.sin6_addr.s6_addr, g_ping_info.dst_ipv6_addr, IPv6_ALEN);

  /*
   * Ping request 패킷을 전송할 V2X 인터페이스의 링크로컬 IPv6 주소를 송신소켓에 바인드한다.
   */
  struct sockaddr_in6 local;
  memset(&local, 0, sizeof(local));
  local.sin6_family = AF_INET6;
  char if_name[IF_NAME_MAX_SIZE+1] = {0};
  TCIA2023_GetInterfaceNameForIndex(g_ping_info.if_idx, if_name);
  local.sin6_scope_id = if_nametoindex(if_name);
#if defined(_TCIA2023_DSRC_)
  ret = WAL_GetLinkLocalIPv6Address(g_ping_info.if_idx, local.sin6_addr.s6_addr);
  if (ret < 0) {
    Err("Fail to prepare Ping tx - WAL_GetLinkLocalIPv6Address() failed: %d\n", ret);
    close(g_ping_info.tx_sock);
    close(g_ping_info.rx_sock);
    return -1;
  }
#endif
  char ip_addr_str[IPv6_ADDR_STR_MAX_LEN+1];
  inet_ntop(AF_INET6, local.sin6_addr.s6_addr, ip_addr_str, sizeof(ip_addr_str));
  Log(kTCIA3LogLevel_Event, "Success to get link local IPv6 address - %s\n", ip_addr_str);
  ret = bind(g_ping_info.tx_sock, (struct sockaddr *)&local, sizeof(local));
  if (ret) {
    Err("Fail to prepare Ping tx - bind(tx_sock) failed: %m\n");
    close(g_ping_info.tx_sock);
    close(g_ping_info.rx_sock);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to bind(tx_sock) - ifindex: %d\n", local.sin6_scope_id);

  /*
   * 수신을 위한 정보를 수신소켓에 바인드한다.
   */
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(addr));
  addr.sll_family		=	PF_PACKET;
  addr.sll_protocol	=	htons(ETHERTYPE_IPv6);
  addr.sll_halen		=	ETH_ALEN;
  addr.sll_ifindex	=	if_nametoindex(if_name);
  ret = bind(g_ping_info.rx_sock, (struct sockaddr *)&addr, sizeof(addr));
  if (ret) {
    Err("Fail to prepare Ping tx - bind(rx_sock) failed: %m\n");
    close(g_ping_info.tx_sock);
    close(g_ping_info.rx_sock);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to bind(rx_sock) - ifindex: %d\n", addr.sll_ifindex);

  Log(kTCIA3LogLevel_Event, "Success to prepare Ping tx\n");
  return 0;
}


/**
 * @brief Ping 송신 동작을 시작한다.
 * @param[in] data TS 로부터 수신된 StartIPv6Ping 메시지 정보
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_StartPingTxOperation(const struct Cvcoctci2023StartIPv6Ping *data)
{
  Log(kTCIA3LogLevel_Event, "Start Ping tx operation\n");

  int ret;

  /*
   * 이미 송신 중이면 실패를 반환한다.
   */
  if (g_ping_info.running == true) {
    Err("Fail to start Ping tx operation - already sending\n");
    return -1;
  }

  /*
   * Ping 송신정보를 초기화한다.
   */
  memset(&g_ping_info, 0, sizeof(g_ping_info));
  pthread_mutex_init(&(g_ping_info.timer_mtx), NULL);
  pthread_cond_init(&(g_ping_info.timer_sig), NULL);

  /*
   * TS가 전송한 정보로부터 Ping 송신 인터페이스, 목적지 IPv6 주소를 저장한다.
   */
  g_ping_info.if_idx = data->radio.radio;
  memcpy(g_ping_info.dst_ipv6_addr, data->dst_ip_addr, sizeof(g_ping_info.dst_ipv6_addr));

  /*
   * TS가 전송한 정보로부터 송신주기를 설정한다. 전달된 주기가 없거나, 0일 경우 임의로 1초로 설정한다.
   */
  int tx_interval_msec = -1;
  if (data->options.repeat_rate && data->repeat_rate) {
    tx_interval_msec = 5000 / data->repeat_rate;
  }
  if (tx_interval_msec <= 0) {
    tx_interval_msec = 1000;
  }

  /*
   * Ping 전송을 준비한다.
   */
  ret = TCIA2023_PreparePingTx();
  if (ret < 0) {
    return -1;
  }

  /*
   * 송신 타이머를 시작한다.
   */
  ret = TCIA2023_InitPingTxTimer(tx_interval_msec);
  if (ret < 0) {
    close(g_ping_info.tx_sock);
    close(g_ping_info.rx_sock);
    return -1;
  }

  g_ping_info.running = true;
  Log(kTCIA3LogLevel_Event, "Success to start Ping tx operation\n");
  return 0;
}


/**
 * @brief Ping 송신 동작을 중지한다.
 */
void TCIA2023_StopPingTxOperation(void)
{
  Log(kTCIA3LogLevel_Event, "Stop Ping tx operation\n");

  if (g_ping_info.running == false) {
    return;
  }

  /*
   * 송신 타이머를 제거한다.
   */
  timer_delete(g_ping_info.timer);

  /*
   * 소켓을 닫는다.
   */
  close(g_ping_info.tx_sock);
  close(g_ping_info.rx_sock);

  g_ping_info.running = false;
}
