/**
 * @file
 * @brief IPv6 통신 기능을 구현한 파일
 * @date 2019-11-10
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <net/if.h>
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


/**
 * @brief IPv6 송신 정보
 */
struct IPv6TxInfo
{
  /*
   * 전송 파라미터
   *  - TS 로부터 수신된 정보로 채워지며, 해당 정보를 이용하여 IPv6 통신이 수행된다.
   */
  int if_idx;
  uint8_t dst_ipv6_addr[IPv6_ALEN];
  uint16_t dst_port;
  uint16_t payload_size;
  uint8_t payload[MAX_PDU_SIZE];

  /*
   * 송신 관련 상태변수
   */
  pthread_t thread;
  timer_t timer;
  pthread_mutex_t timer_mtx;
  pthread_cond_t timer_cond;

  bool txing; ///< 송신 중인지 여부
};

struct IPv6TxInfo g_tx_info;


/**
 * @brief IPv6 송신 타이머를 해제한다.
 */
static void TCIA2023_ReleaseIPv6TxTimer(void)
{
  Log(kTCIA3LogLevel_Event, "Release IPv6 tx timer\n");

  /*
   * 타이머가 없으면...
   */
  if (g_tx_info.timer == 0) {
    Err("Fail to release IPv6 tx timer - no timer\n");
    return;
  }

  /*
   * 타이머 제거
   */
  int ret = timer_delete(g_tx_info.timer);
  if (ret) {
    Err("Fail to release IPv6 tx timer - timer_delete() failed - %m\n");
  }
  g_tx_info.timer = 0;
}


/**
 * @brief IPv6 송신 쓰레드를 해제한다.
 */
static void TCIA2023_ReleaseIPv6TxThread(void)
{
  Log(kTCIA3LogLevel_Event, "Releasing IPv6 tx thread\n");

  if (g_tx_info.thread) {
    pthread_mutex_lock(&(g_tx_info.timer_mtx));
    g_tx_info.txing = false;
    pthread_cond_signal(&(g_tx_info.timer_cond));
    pthread_mutex_unlock(&(g_tx_info.timer_mtx));
    pthread_cancel(g_tx_info.thread);
    g_tx_info.thread = 0;
  }
}


/**
 * @brief IPv6 송신 동작을 초기화(해제)한다.
 */
void TCIA2023_InitIPv6TxOperation(void)
{
  Log(kTCIA3LogLevel_Event, "Initializing(Releasing) IPv6 tx operation\n");
  g_tx_info.txing = false;
  TCIA2023_ReleaseIPv6TxTimer();
  TCIA2023_ReleaseIPv6TxThread();
}


/**
 * @brief UDP 송신 쓰레드
 * @param none 사용되지 않음
 * @return
 */
static void* TCIA2023_UDPTxThread(void *none)
{
  (void)none;
  int ret;
  Log(kTCIA3LogLevel_Event, "Start UDP tx thread...\n");

  /*
   * 소켓을 연다
   */
  int sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) {
    Err("Fail to start UDP tx thread - socket() failed - %m\n");
    return NULL;
  }
  Log(kTCIA3LogLevel_Event, "Success to create socket().\n");

  /*
   * 목적지 정보 설정
   */
  struct sockaddr_in6 remote;
  memset(&remote, 0, sizeof(struct sockaddr_in6));
  remote.sin6_family = AF_INET6;
  remote.sin6_port = htons(g_tx_info.dst_port);
  memcpy(remote.sin6_addr.s6_addr, g_tx_info.dst_ipv6_addr, sizeof(g_tx_info.dst_ipv6_addr));

  /*
   * 소켓을 네트워크 인터페이스에 bind() 한다.
   */
  char if_name[IFNAMSIZ] = {0};
  ret = TCIA2023_GetInterfaceNameForIndex(g_tx_info.if_idx, if_name);
  if (ret < 0) {
    Err("Fail to start UDP tx thread - cannot find interface name for if_idx %d\n", g_tx_info.if_idx);
    close(sock);
    return NULL;
  }
  struct ifreq ifr;
  memset(ifr.ifr_name, 0, IFNAMSIZ);
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s", if_name);
  ret = ioctl(sock, SIOGIFINDEX, &ifr);
  if (ret < 0) {
    Err("Fail to start UDP tx thread - ioctl(SIOGIFINDEX) failed - %m\n");
    close(sock);
    return NULL;
  }
  Log(kTCIA3LogLevel_Event, "Success to ioctl(sock) - ifindex = %d\n", ifr.ifr_ifindex);
  if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
    Err("Fail to start UDP tx thread - setsockopt(txsock) failed to bind to interface - %m\n");
    close(sock);
    return NULL;
  }
  Log(kTCIA3LogLevel_Event, "Success to setsockopt(SO_BINDTODEVICE)\n");

  /*
   * 패킷을 주기적으로 송신한다.
   */
  uint32_t tx_cnt = 0;
  do {

    /* 타이머가 터질 때까지 대기한다. */
    pthread_mutex_lock(&(g_tx_info.timer_mtx));
    pthread_cond_wait(&(g_tx_info.timer_cond), &(g_tx_info.timer_mtx));
    pthread_mutex_unlock(&(g_tx_info.timer_mtx));

    /* 종료 */
    if(g_tx_info.txing) {
      break;
    }

    /* UDP 패킷을 전송한다. */
    ret = sendto(sock, g_tx_info.payload, g_tx_info.payload_size, 0, (struct sockaddr *) &remote, sizeof(remote));
    if(ret != g_tx_info.payload_size) {
      Err("Fail to send %d-bytes UDP packet - %m\n", g_tx_info.payload_size);
    } else {
      tx_cnt++;
      if((tx_cnt % 10) == 1) {
        Log(kTCIA3LogLevel_Event, "Success to send %d-th UDP packet (Len: %d)\n", tx_cnt, g_tx_info.payload_size);
      } else {
        Log(kTCIA3LogLevel_DetailedEvent, "Success to send %d-th UDP packet (Len: %d)\n", tx_cnt, g_tx_info.payload_size);
      }
    }
  } while(1);

  close(sock);
  return	NULL;
}


/**
 * @brief IPv6 송신 타이머가 터질 때마다 실행되는 쓰레드함수
 * @param arg 사용되지 않음
 */
static void TCIA2023_IPv6TxTimerThread(union sigval arg)
{
  (void)arg;
  pthread_mutex_lock(&(g_tx_info.timer_mtx));
  pthread_cond_signal(&(g_tx_info.timer_cond));
  pthread_mutex_unlock(&(g_tx_info.timer_mtx));
}


/**
 * @brief IPv6 송신 타이머를 초기화한다.
 * @param[in] msec 타이머 주기
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_InitIPv6TxTimer(const uint32_t msec)
{
  Log(kTCIA3LogLevel_Event, "Initialize IPv6 tx timer - duration: %umsec\n", msec);

 /*
  * 타이머 만기 시에 TCIA2023_IPv6TxTimerThread() 쓰레드가 생성되도록 설정한다.
  */
  struct sigevent se;
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_value.sival_ptr = &(g_tx_info.timer);
  se.sigev_notify_function = TCIA2023_IPv6TxTimerThread;
  se.sigev_notify_attributes = NULL;
  int ret = timer_create(CLOCK_MONOTONIC, &se, &(g_tx_info.timer));
  if (ret) {
    Err("Fail to initialize IPv6 tx timer - timer_create() failed - %m\n");
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
  ret = timer_settime(g_tx_info.timer, 0, &ts, 0);
  if (ret) {
    Err("Fail to initialize IPv6 tx timer - timer_settime() failed - %m\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to initialize IPv6 tx timer.\n");
  return 0;
}


/**
 * @brief UDP 송신 쓰레드를 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_InitUdpTxThread(void)
{
  Log(kTCIA3LogLevel_Event, "Initialize UDP tx thread\n");
  int ret = pthread_create(&(g_tx_info.thread), NULL, TCIA2023_UDPTxThread, NULL);
  if(ret) {
    Err("Fail to initialize UDP tx thread - pthread_create() failed - %m\n");
    return -1;
  }
  pthread_detach(g_tx_info.thread);
  Log(kTCIA3LogLevel_Event, "Success to initialize UDP tx thread\n");
  return 0;
}


/**
 * @brief UDP 송신 동작을 시작한다.
 * @param[in] data TS 로부터 수신된 StartIPv6Tx 메시지 정보
 * @param[in] payload TS 로부터 수신된 payload
 * @param[in] payload_size payload_size 의 길이
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_StartUDPTxOperation(const struct Cvcoctci2023StartIPv6Tx *data, const uint8_t *payload, size_t payload_size)
{
  Log(kTCIA3LogLevel_Event, "Starting UDP tx operation\n");

  int ret;

  /*
   * 이미 송신 중이면 실패
   */
  if (g_tx_info.txing) {
    Err("Fail to start UDP tx operation - already sending\n");
    return -1;
  }

  /*
   * IP 통신 관련 정보 저장
   *  - 네트워크인터페이스 식별번호, 목적지 IPv6 주소, 목적지 포트(옵션), 페이로드(옵션), 전송주기(옵션)
   */
  memset(&g_tx_info, 0, sizeof(g_tx_info));
  g_tx_info.if_idx = data->radio.radio;
  memcpy(g_tx_info.dst_ipv6_addr, data->dst_ip_addr, sizeof(g_tx_info.dst_ipv6_addr));
  if (data->options.dst_port) {
    g_tx_info.dst_port = data->dst_port;
  } else {
    Err("Fail to start UDP tx operation - dst_port is not specified\n");
    return -1;
  }
  // 전송 페이로드를 저장한다. 전달된 페이로드가 없을 경우 임의로 10바이트로 설정한다.
  if (payload && (payload_size > 0)) {
    if (payload_size > sizeof(g_tx_info.payload)) {
      Err("Fail to start UDP tx operation - too long payload %d > %d\n", payload_size, sizeof(g_tx_info.payload));
      return -1;
    }
    g_tx_info.payload_size = payload_size;
    memcpy(g_tx_info.payload, payload, g_tx_info.payload_size);
  } else {
    g_tx_info.payload_size = 10;
  }
  // 송신주기를 설정한다. 전달된 주기가 없거나, 0일 경우 임의로 1초로 설정한다.
  int tx_interval_msec = -1;
  if (data->options.repeat_rate && data->repeat_rate) {
    tx_interval_msec = 5000 / data->repeat_rate;
  }
  if (tx_interval_msec <= 0) {
    tx_interval_msec = 1000;
  }

  /*
   * 송신 관련 초기화
   */
  pthread_mutex_init(&(g_tx_info.timer_mtx), NULL);
  pthread_cond_init(&(g_tx_info.timer_cond), NULL);

  /*
   * 송신 쓰레드를 생성한다.
   */
  ret = TCIA2023_InitUdpTxThread();
  if (ret < 0) {
    Err("Fail to start UDP tx operation\n");
    goto release;
  }

  /*
   * 송신 타이머를 시작한다.
   */
  ret = TCIA2023_InitIPv6TxTimer(tx_interval_msec);
  if (ret < 0) {
    Err("Fail to start UDP tx operation\n");
    goto release;
  }

  Log(kTCIA3LogLevel_Event, "Success to start UDP tx operation\n");
  return 0;

release:
  TCIA2023_InitIPv6TxOperation();
  return -1;
}


/**
 * @brief UDP 송신 동작을 중지한다.
 */
void TCIA2023_StopUDPTxOperation(void)
{
  Log(kTCIA3LogLevel_Event, "Stopping UDP tx operation\n");
  TCIA2023_InitIPv6TxOperation();
}


/**
 * @brief IPv6 송신 동작을 시작한다.
 * @param[in] data TS 로부터 수신된 StartIPv6Tx 메시지 정보
 * @param[in] payload TS 로부터 수신된 payload
 * @param[in] payload_size payload_size 의 길이
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_StartIPv6TxOperation(const struct Cvcoctci2023StartIPv6Tx *data, const uint8_t *payload, size_t payload_size)
{
  Log(kTCIA3LogLevel_Event, "Starting IPv6 tx operation\n");

  /*
   * 프로토콜 별로 IP 송신 동작을 시작한다.
   */
  int ret = -1;
  switch(data->protocol) {
    case kCvcoctci2023Protocol_tcp:
      break;
    case kCvcoctci2023Protocol_udp:
      ret = TCIA2023_StartUDPTxOperation(data, payload, payload_size);
      break;
    case kCvcoctci2023Protocol_icmpv6:
      ret = TCIA2023_StartPingTxOperation(data);
      break;
    default:
      Err("Fail to start IPv6 tx operation - invalid protocol %d\n", data->protocol);
      ret = -1;
  }

  if (ret < 0) {
    Err("Fail to start IPv6 tx operation\n");
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to start IPv6 tx operation\n");
  return 0;
}


/**
 * @brief IPv6 송신 동작을 중지한다.
 * @param[in] data TS 로부터 수신된 StopIPv6Tx 메시지 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_StopIPv6TxOperation(const struct Cvcoctci2023StopIPv6Tx *data)
{
  Log(kTCIA3LogLevel_Event, "Stop IPv6 tx operation\n");

  /*
   * 프로토콜 별로 IP 송신 동작을 중지한다.
   */
  int ret = 0;
  switch(data->protocol) {
    case kCvcoctci2023Protocol_tcp:
      break;
    case kCvcoctci2023Protocol_udp:
      TCIA2023_StopUDPTxOperation();
      break;
    case kCvcoctci2023Protocol_icmpv6:
      TCIA2023_StopPingTxOperation();
      break;
    default:
      Err("Fail to stop IPv6 tx operation - invalid protocol %d\n", data->protocol);
      return -1;
  }

  if (ret < 0) {
    Err("Fail to stop IPv6 tx operation\n");
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to stop IPv6 tx operation\n");
  return 0;
}

