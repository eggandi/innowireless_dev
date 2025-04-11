/** 
 * @file
 * @brief WSM 송신 관련 기능을 구현한 파일
 * @date 2021-02-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// 유틸리티 헤더 파일
#include "wsm-test-ltev2x.h"


/// 송신타이머
timer_t g_tx_timer;

/// 송신 페이로드
uint8_t g_payload[kDot3WSMPayloadSize_Max];


/**
 * @brief 송신할 테스트 메시지를 생성한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int WSM_TEST_LTEV2X_ConstructTestMessage(void)
{
  /*
   * 현재 시각을 가져 온다.
   */
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm *ptm;
  ptm = localtime(&(ts.tv_sec));

  /*
   * GPS 정보를 가져 온다.
   */
  struct gps_data_t *gps_data = &(g_mib.status.gps_data);
  int ret = gps_read(gps_data, NULL, 0);
  if (ret < 0) {
    printf("Fail to gps_read()\n");
    return -1;
  }
  int32_t lat = LATITUDE_UNAVAILABLE;
  int32_t lon = LONGITUDE_UNAVAILABLE;
  uint16_t speed = SPEED_UNAVAILABLE;
  if ((gps_data->fix.mode >= MODE_2D) && (isnan(gps_data->fix.latitude) == 0)) {
    lat = (int32_t)(gps_data->fix.latitude * 1e7);
  }
  if ((gps_data->fix.mode >= MODE_2D) && (isnan(gps_data->fix.longitude) == 0)) {
    lon = (int32_t)(gps_data->fix.longitude * 1e7);
  }
  if ((gps_data->fix.mode >= MODE_2D) && (isnan(gps_data->fix.track) == 0)) {
    speed = (int16_t)(gps_data->fix.speed);
  }

  /*
   * 페이로드 및 헤더를 설정한다.
   */
  for (size_t i = 0; i < g_mib.op.tx_wsm_body_len; i++) {
    g_payload[i] = (uint8_t)i;
  }
  struct TestMessageHeader *hdr = (struct TestMessageHeader *)g_payload;
  hdr->seq = htonl(g_mib.seq++);
  hdr->lat = htonl(lat);
  hdr->lon = htonl(lon);
  hdr->speed = htons(speed);
  hdr->year = htons(ptm->tm_year + 1900);
  hdr->month = ptm->tm_mon + 1;
  hdr->day = ptm->tm_mday;
  hdr->hour = ptm->tm_hour;
  hdr->minute = ptm->tm_min;
  hdr->second = ptm->tm_sec;
  hdr->msecond = htons(ts.tv_nsec / 1000000);

  return 0;
}


/**
 * @brief LTE-V2X MPDU를 생성하여 전송한다.
 * @param[in] wsdu 전송할 WSDU (=WSM body에 수납되는 페이로드)
 * @param[in] wsdu_size 전송할 WSDU의 크기
 */
static void WSM_TEST_LTEV2X_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size)
{
  int ret;
  if (g_mib.op.dbg) {
    printf("Sending LTE-V2X WSM\n");
  }

  /*
   * WSM을 생성한다.
   */
  uint8_t *wsm;
  size_t wsm_size;
  struct Dot3WSMConstructParams dot3_params;
  dot3_params.chan_num = kDot3ChannelNumber_NA; // WSMP 확장헤더에 채널번호 정보를 수납하지 않음
  dot3_params.datarate = kDot3DataRate_NA; // WSMP 확장헤더에 데이터레이트 정보를 수납하지 않음
  dot3_params.transmit_power = g_mib.op.tx_power; // WSMP 확장헤더에 송신파워 정보 수납
  dot3_params.psid = g_mib.op.psid;
  wsm = Dot3_ConstructWSM(&dot3_params, wsdu, wsdu_size, &wsm_size, &ret);
  if (wsm == NULL) {
    printf("Fail to Dot3_ConstructWSM() - %d\n", ret);
    return;
  }
  if (g_mib.op.dbg) {
    printf("Success to construct %zu-bytes LTE-V2X WSM\n", wsm_size);
  }

  /*
   * WSM을 전송한다.
   */
  struct LTEV2XHALMSDUTxParams tx_params;
  memset(&tx_params, 0, sizeof(struct LTEV2XHALTxProfile));
  tx_params.tx_flow_type = g_mib.op.tx_flow_type;
  tx_params.tx_flow_index = kLTEV2XHALTxFLowIndex_Default;
  tx_params.tx_power = g_mib.op.tx_power;
  tx_params.priority = g_mib.op.tx_priority;
  tx_params.dst_l2_id = kLTEV2XHALL2ID_Broadcast;

  ret = LTEV2XHAL_TransmitMSDU(wsm, wsm_size, tx_params);
  if (ret < 0) {
    printf("Fail to LTEV2XHAL_TransmitMSDU() - ret: %d\n", ret);
  } else {
    if (g_mib.op.dbg) {
      printf("Success to LTEV2XHAL_TransmitMSDU()\n");
    }
  }

  /*
   * 생성된 WSM을 해제한다.
   */
  free(wsm);
}


/**
 * @brief WSM 송신타이머 만기 쓰레드. 송신타이머 만기 시마다 호출된다.
 * @param[in] arg 사용되지 않음
 */
static void WSM_TEST_LTEV2X_TxTimerThread(union sigval arg)
{
  (void)arg;

  if (g_mib.op.dbg) {
    printf("Sending Test message\n");
  }

  /*
   * 테스트 메시지를 생성한다.
   */
  int ret = WSM_TEST_LTEV2X_ConstructTestMessage();
  if (ret < 0) {
    return;
  }

  WSM_TEST_LTEV2X_TransmitWSM(g_payload, g_mib.op.tx_wsm_body_len);
}


/**
 * @brief WSM 송신타이머를 초기화한다.
 * @param[in] interval 송신주기(usec)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int WSM_TEST_LTEV2X_InitTxTimer(unsigned int interval)
{
  int ret;
  struct itimerspec ts;
  struct sigevent se;

  printf("Initialize tx timer - interval: %uusec\n", interval);

  /*
   * 송신타이머 만기 시 송신타이머쓰레드(V2X_WSM_TxTimerThread)가 생성되도록 설정한다.
   */
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_value.sival_ptr = &g_tx_timer;
  se.sigev_notify_function = WSM_TEST_LTEV2X_TxTimerThread;
  se.sigev_notify_attributes = NULL;

  ts.it_value.tv_sec = 0;
  ts.it_value.tv_nsec = 1000000;  // 최초타이머 주기 = 1msec
  ts.it_interval.tv_sec = (time_t)(interval / 1000000);
  ts.it_interval.tv_nsec = (long)((interval % 1000000) * 1000);

  /*
   * 송신타이머를 생성한다.
   */
  ret = timer_create(CLOCK_REALTIME, &se, &g_tx_timer);
  if (ret) {
    perror("Fail to cerate timer: ");
    return -1;
  }

  /*
   * 송신타이머 주기를 설정한다.
   */
  ret = timer_settime(g_tx_timer, 0, &ts, 0);
  if (ret) {
    perror("Fail to set timer: ");
    return -1;
  }

  printf("Success to initialize tx timer.\n");
  return 0;
}


/**
 * @brief WSM 송신동작을 초기화한다.
 * @param[in] timer_interval 송신타이머 주기(usec 단위)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int WSM_TEST_LTEV2X_InitTxOperation(unsigned int interval)
{
  printf("Initialize WSM tx operation\n");

  /*
   * 송신 플로우를 등록한다.
   */
  struct LTEV2XHALTxFlowParams flow_params;
  memset(&flow_params, 0, sizeof(struct LTEV2XHALTxFlowParams));
  flow_params.index = kLTEV2XHALTxFLowIndex_Default;
  flow_params.priority = g_mib.op.tx_priority;
  flow_params.size = g_mib.op.tx_wsm_body_len + 25;
  flow_params.interval = g_mib.op.tx_interval / 1000;

  int ret = LTEV2XHAL_RegisterTransmitFlow(flow_params);
  if (ret < 0) {
    printf("Fail to initialize WSM tx operation - LTEV2XHAL_RegisterTransmitFlow() failed: %d\n", ret);
    return -1;
  }

  /*
   * 송신 타이머를 생성한다.
   */
  ret = WSM_TEST_LTEV2X_InitTxTimer(interval);
  if (ret < 0) {
    return -1;
  }

  printf("Success to initialize tx operation\n");
  return 0;
}


/**
 * @brief WSM 송신 동작을 해제한다.
 */
void WSM_TEST_LTEV2X_ReleaseTxOperation(void)
{
  printf("Release WSM tx operation\n");

  /*
   * 송신 타이머를 제거한다.
   */
  timer_delete(g_tx_timer);

  /*
   * GPS 인터페이스를 닫는다.
   */
  gps_close(&(g_mib.status.gps_data));
}
