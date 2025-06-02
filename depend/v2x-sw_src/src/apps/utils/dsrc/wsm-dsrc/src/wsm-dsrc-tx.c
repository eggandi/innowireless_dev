/**
 * @file
 * @brief WSM 송신 관련 기능을 구현한 파일
 * @date 2019-08-12
 * @author gyun
 */

// 시스템 헤더 파일
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// 어플리케이션 헤더 파일
#include "wsm-dsrc.h"


/// 송신타이머
timer_t g_tx_timer;

/// 송신 페이로드
uint8_t g_payload[kDot3WSMPayloadSize_Max];


/**
 * @brief WAVE MPDU를 생성하여 전송한다.
 * @param[in] wsdu 전송할 WSDU
 * @param[in] wsdu_size 전송할 WSDU의 크기
 */
static void WSM_DSRC_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size)
{
  int ret;
  if (g_mib.dbg >= kDbgMsgLevel_event) {
    WSM_DSRC_Print(__FUNCTION__, "Sending WAVE WSM\n");
  }

  /*
   * WSM MPDU를 생성한다.
   */
  uint8_t *mpdu;
  size_t mpdu_size;
  struct Dot3MACAndWSMConstructParams dot3_params;
  dot3_params.wsm.chan_num = g_mib.tx_chan_num;
  dot3_params.wsm.datarate = g_mib.tx_datarate;
  dot3_params.wsm.transmit_power = g_mib.tx_power;
  dot3_params.mac.priority = g_mib.tx_priority;
  dot3_params.wsm.psid = g_mib.psid;
  memcpy(dot3_params.mac.dst_mac_addr, g_mib.tx_dst_mac_addr, MAC_ALEN);
  memcpy(dot3_params.mac.src_mac_addr, g_mib.my_addr[g_mib.tx_if_idx], MAC_ALEN);
  mpdu = Dot3_ConstructWSMMPDU(&dot3_params, wsdu, wsdu_size, &mpdu_size, &ret);
  if (mpdu == NULL) {
    WSM_DSRC_Print(__FUNCTION__, "Fail to Dot3_ConstructWSMMPDU() - %d\n", ret);
    return;
  }
  if (g_mib.dbg >= kDbgMsgLevel_event) {
    WSM_DSRC_Print(__FUNCTION__, "Success to construct %d-bytes WSM MPDU\n", mpdu_size);
    if (g_mib.dbg >= kDbgMsgLevel_msgdump) {
      for (size_t i = 0; i < mpdu_size; i++) {
        if ((i!=0) && (i%16==0)) {
          printf("\n");
        }
        printf("%02X ", mpdu[i]);
      }
      printf("\n");
    }
  }

  /*
   * WSM MPDU를 전송한다.
   */
  struct WalMPDUTxParams wal_tx_params;
  wal_tx_params.chan_num = (WalChannelNumber)(g_mib.tx_chan_num);
  wal_tx_params.datarate = (WalDataRate)(g_mib.tx_datarate);
  wal_tx_params.expiry = 0;
  wal_tx_params.tx_power = g_mib.tx_power;
  ret = WAL_TransmitMPDU(g_mib.tx_if_idx, mpdu, mpdu_size, &wal_tx_params);
  if (ret < 0) {
    WSM_DSRC_Print(__FUNCTION__, "Fail to WAL_TransmitMPDU() - ret: %d\n", ret);
  } else {
    if (g_mib.dbg >= kDbgMsgLevel_event) {
      WSM_DSRC_Print(__FUNCTION__, "Success to WAL_TransmitMPDU()\n");
    }
  }

  /*
   * 생성된 MPDU를 해제한다.
   */
  free(mpdu);

}


/**
 * @brief WSM 송신타이머 만기 쓰레드. 송신타이머 만기 시마다 호출된다.
 * @param[in] arg 사용되지 않음
 */
static void WSM_DSRC_TxTimerThread(union sigval arg)
{
  (void)arg;

  // 페이로드 더미 데이터를 설정한다.
  for (size_t i = 0; i < g_mib.tx_wsm_body_len; i++) {
    g_payload[i] = (uint8_t)i;
  }

  // WSM을 생성하여 전송한다.
  WSM_DSRC_TransmitWSM(g_payload, g_mib.tx_wsm_body_len);
}


/**
 * @brief WSM 송신타이머를 초기화한다.
 * @param[in] interval 송신주기(usec)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int WSM_DSRC_InitTxTimer(unsigned int interval)
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
  se.sigev_notify_function = WSM_DSRC_TxTimerThread;
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
int WSM_DSRC_InitTxOperation(unsigned int interval)
{
  printf("Initialize WSM tx operation\n");
  int ret = WSM_DSRC_InitTxTimer(interval);
  if (ret < 0) {
    return -1;
  }
  printf("Success to initialize tx operation\n");
  return 0;
}


/**
 * @brief WSM 송신동작을 종료한다.
 */
void WSM_DSRC_ReleaseTxOperation(void)
{
  timer_delete(g_tx_timer);
}
