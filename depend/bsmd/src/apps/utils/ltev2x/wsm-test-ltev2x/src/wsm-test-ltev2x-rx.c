/** 
 * @file
 * @brief WSM 수신 처리 기능을 구현한 파일
 * @date 2021-02-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <math.h>
#include <stdio.h>

// 라이브러리 헤더 파일
#include "v2x-sw.h"

// 유틸리티 헤더 파일
#include "wsm-test-ltev2x.h"


/**
 * @brief LTE-V2X로 수신된 테스트 메시지를 처리한다.
 * @param[in] msg 테스트 메시지
 * @param[in] msg_size 테스트 메시지 길이
 */
static void WSM_TEST_LTEV2X_ProcessRxTestMessage(const uint8_t *msg, size_t msg_size)
{
  if (g_mib.op.dbg) {
    printf("Process rx Test message\n");
  }

  unsigned int rx_if_idx = 0;

  /*
   * 현재 시각을 가져온다.
   */
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm *ptm = localtime(&(ts.tv_sec));

  /*
   * GPS 정보를 읽어 온다.
   */
  struct gps_data_t *gps_data = &(g_mib.status.gps_data);
  int ret = gps_read(gps_data, NULL, 0);
  if (ret < 0) {
    printf("Fail to gps_read()\n");
    return;
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

  struct TestMessageHeader *hdr = (struct TestMessageHeader *)msg;

  // 수신시각, 수신인터페이스 식별번호, 수신장치위도, 수신장치경도, 수신장치속도
  printf("%04u%02u%02u.%02u%02u%02u.%03lu,%u,%d,%d,%u,",
         ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
         ptm->tm_hour, ptm->tm_min, ptm->tm_sec, ts.tv_nsec / 1000000,
         rx_if_idx, lat, lon, speed);

  // 송신시각
  printf("%04u%02u%02u.%02u%02u%02u.%03u,",
         ntohs(hdr->year), hdr->month, hdr->day, hdr->hour, hdr->minute, hdr->second, ntohs(hdr->msecond));
  // 송신장치위도, 송신장치경도, 송신장치속도
  printf("%d,%d,%u,", ntohl(hdr->lat), ntohl(hdr->lon), ntohs(hdr->speed));
  // 메시지 순서번호, 메시지 길이
  printf("%u,%zu\n", ntohl(hdr->seq), msg_size);
}


/**
 * @brief 수신된 LTE-V2X WSDU를 처리한다.
 * @param[in] wsdu 수신된 WSDU
 * @param[in] wsdu_size 수신된 WSDU의 크기
 * @param[in] params WSM 헤더 파싱정보
 * @param[in] interested_psid 관심 PSID인지 여부
 */
static void WSM_TEST_LTEV2X_ProcessRxWSDU(
  const uint8_t *wsdu,
  size_t wsdu_size,
  struct Dot3WSMParseParams *params,
  bool interested_psid)
{
  /*
   * 관심있는 서비스를 처리한다.
   */
  if (interested_psid == true) {
    if (g_mib.op.dbg) {
      printf("Process interested rx %zu-bytes LTE-V2X WSDU\n", wsdu_size);
      printf("    WSM header - PSID: %u, power: %ddBm\n", params->psid, params->transmit_power);
    }
    WSM_TEST_LTEV2X_ProcessRxTestMessage(wsdu, wsdu_size);
  }
  /*
   * 관심 없는 서비스에 대한 WSDU는 처리하지 않는다.
   */
  else {
    if (g_mib.op.dbg) {
      printf("NOT process WSM - not intersted PSID %u\n", params->psid);
    }
  }
}


/**
 * @brief LTE-V2X MSDU 수신처리 콜백함수. lteaccess 라이브러리에서 호출된다.
 * @param[in] msdu 수신된 MSDU
 * @param[in] msdu_size 수신된 MSDU의 크기
 */
void WSM_TEST_LTEV2X_ProcessRxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_param)
{
  if (g_mib.op.dbg) {
    printf("Process rx LTE-V2X MSDU\n");
  }

  /*
   * WSM MSDU를 파싱한다.
   */
  int ret;
  struct Dot3WSMParseParams params;
  size_t wsdu_size;
  bool wsr_registered;
  uint8_t *wsdu = Dot3_ParseWSM(msdu, msdu_size, &params, &wsdu_size, &wsr_registered, &ret);
  if (wsdu == NULL) {
    printf("Fail to process rx C-V2X MSDU - Dot3_ParseWSM() failed: %d\n", ret);
    return;
  }

  /*
   * 페이로드를 처리한다.
   */
  WSM_TEST_LTEV2X_ProcessRxWSDU(wsdu, wsdu_size, &params, wsr_registered);
}
