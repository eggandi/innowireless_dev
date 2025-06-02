/** 
 * @file
 * @brief IEEE 1609.2 메시지 생성 및 송신 기능 구현 파일
 * @date 2020-05-26
 * @author gyun
 */


// 시스템 헤더 파일
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "sdee-dsrc.h"


/*
 * 송신 관련 전역 변수
 */
timer_t g_tx_timer; ///< 송신타이머
uint8_t g_payload[] = { ///< 샘플 페이로드(실행파라미터로 길이값이 입력되지 않았을 때 사용되는 페이로드) - BSM 메시지
  0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00,
  0x07, 0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63,
  0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F,
  0xF0, 0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1,
  0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00
};


/**
 * @brief DSRC MPDU를 생성하여 전송한다.
 * @param[in] wsdu 전송할 WSDU
 * @param[in] wsdu_size 전송할 WSDU의 크기
 */
static void SDEE_DSRC_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size)
{
  int ret;
  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_DSRC_Print(__FUNCTION__, "Sending DSRC WSM\n");
  }

  /*
   * WSM MPDU를 생성한다.
   */
  struct Dot3MACAndWSMConstructParams dot3_params;
  dot3_params.wsm.chan_num = (Dot3ChannelNumber)(g_mib.chan[0]);
  dot3_params.wsm.datarate = DEFAULT_DATARATE;
  dot3_params.wsm.transmit_power = DEFAULT_POWER;
  dot3_params.mac.priority = DEFAULT_PRIORITY;
  dot3_params.wsm.psid = g_mib.psid;
  memset(dot3_params.mac.dst_mac_addr, 0xff, MAC_ALEN);
  memcpy(dot3_params.mac.src_mac_addr, g_mib.mac_addr, MAC_ALEN);
  size_t mpdu_size;
  uint8_t *mpdu = Dot3_ConstructWSMMPDU(&dot3_params, wsdu, (Dot3WSMPayloadSize)wsdu_size, &mpdu_size, &ret);
  if (mpdu == NULL) {
    SDEE_DSRC_Print(__FUNCTION__, "Fail to transmit SPDU - Dot3_ConstructWSMMPDU() failed: %d\n", ret);
    return;
  }
  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_DSRC_Print(__FUNCTION__, "Success to construct %d-bytes WSM MPDU\n", mpdu_size);
    if (g_mib.dbg >= kDbgMsgLevel_MsgDump) {
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
   * 루프백 테스트 수행 시, 패킷을 전송하지 않고 바로 수신콜백함수를 호출하여 스스로 처리한다.
   */
  if (g_mib.op == kOperationType_Loopback) {
    struct WalMPDURxParams rx_params;
    memset(&rx_params, 0, sizeof(rx_params));
    SDEE_DSRC_ProcessRxMPDUCallback(mpdu, mpdu_size, &rx_params);
  }
#ifndef _X64_
  /*
   * WSM MPDU를 전송한다.
   */
  else {
    struct WalMPDUTxParams wal_tx_params;
    wal_tx_params.chan_num = g_mib.chan[0]; // 현재 접속 중인 채널
    wal_tx_params.datarate = DEFAULT_DATARATE;
    wal_tx_params.expiry = 0;
    wal_tx_params.tx_power = DEFAULT_POWER;
    ret = WAL_TransmitMPDU(DEFAULT_IF_IDX, mpdu, mpdu_size, &wal_tx_params);
    if (ret < 0) {
      SDEE_DSRC_Print(__FUNCTION__, "Fail to WAL_TransmitMPDU() - ret: %d\n", ret);
    } else {
      if (g_mib.dbg >= kDbgMsgLevel_Event) {
        SDEE_DSRC_Print(__FUNCTION__, "Success to WAL_TransmitMPDU()\n");
      }
    }
  }
#endif

  /*
   * 생성된 MPDU를 해제한다.
   */
  free(mpdu);
}


/**
 * @brief 송신타이머 만기 쓰레드 함수
 * @param not_used 사용되지 않음
 *
 * 송신타이머 만기 시마다 호출되며, 송신타이머 컨디션 시그널을 전송하여 송신쓰레드가 깨어나도록 한다.
 */
static void SDEE_DSRC_TxTimerThread(union sigval not_used)
{
  (void)not_used;

  uint8_t payload[kDot2MsgSize_Max];

  /*
   * 프로그램 실행파라미터로 길이값이 지정되지 않았을 경우, 사전에 정의된 페이로드가 전송된다.
   */
  if (g_mib.payload_size == 0) {
    memcpy(payload, g_payload, sizeof(g_payload));
    g_mib.payload_size = sizeof(g_payload);
  }

  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_DSRC_Print(__FUNCTION__, "Transmit SPDU\n");
  }

  /*
   * SPDU(IEEE 1609.2 메시지)를 생성한다.
   *  - 입력 파라미터에 따라 SignedData 또는 UnsecuredData 메시지를 생성한다.
   */
  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;
  memset(&params, 0, sizeof(params));
  if (g_mib.msg_type == kMsgType_Signed) {
    params.type = kDot2SPDUConstructType_Signed;
    params.signed_data.psid = g_mib.psid;
    params.signed_data.signer_id_type = kDot2SignerId_Profile;
    params.signed_data.gen_location.lat = g_mib.lat;
    params.signed_data.gen_location.lon = g_mib.lon;
    params.signed_data.gen_location.elev = 0;
    res = Dot2_ConstructSPDU(&params, payload, g_mib.payload_size);
    if (res.ret < 0) {
      SDEE_DSRC_Print(__FUNCTION__, "Fail to generate SPDU - Dot2_ConstructSPDU() failed: %d\n", res.ret);
      return;
    }
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_DSRC_Print(__FUNCTION__, "Success to generate %d-bytes SPDU(Signed)\n", res.ret);
    }
  } else {
    params.type = kDot2SPDUConstructType_Unsecured;
    res = Dot2_ConstructSPDU(&params, payload, g_mib.payload_size);
    if (res.ret < 0) {
      SDEE_DSRC_Print(__FUNCTION__, "Fail to transmit SPDU - Dot2_ConstructSPDU() failed: %d\n", res.ret);
      return;
    }
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_DSRC_Print(__FUNCTION__, "Success to generate %d-bytes SPDU(Unsecured)\n",  res.ret);
    }
  }

  // WSM을 생성하여 전송한다.
  SDEE_DSRC_TransmitWSM(res.spdu,  res.ret);
  free(res.spdu);
}


/**
 * @brief 송신타이머를 초기화한다.
 * @param[in] interval 송신주기(usec)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int SDEE_DSRC_InitTxTimer(unsigned int interval)
{
  int ret;
  struct itimerspec ts;
  struct sigevent se;

  printf("Initialize tx timer - interval: %uusec\n", interval);

  /*
   * 송신타이머 만기 시 송신타이머쓰레드(SDEE_TxTimerThread)가 생성되도록 설정한다.
   */
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_value.sival_ptr = &g_tx_timer;
  se.sigev_notify_function = SDEE_DSRC_TxTimerThread;
  se.sigev_notify_attributes = NULL;

  ts.it_value.tv_sec = 0;
  ts.it_value.tv_nsec = 1000000;  // 최초타이머 주기 = 1msec
  ts.it_interval.tv_sec = (time_t)(interval / 1000000);
  ts.it_interval.tv_nsec = (long)((interval % 1000000) * 1000);

  /*
   * 송신타이머 생성
   */
  ret = timer_create(CLOCK_REALTIME, &se, &g_tx_timer);
  if (ret) {
    perror("Fail to cerate timer: ");
    return -1;
  }

  /*
   * 송신타이머 주기 설정
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
 * @brief 송신 동작에 관련된 초기화를 수행한다.
 * @param[in] interval 송신주기(usec 단위)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int SDEE_DSRC_InitTxOperation(unsigned int interval)
{
  printf("Initialize tx operation\n");

  /*
   * 송신 타이머를 생성한다.
   */
  int ret = SDEE_DSRC_InitTxTimer(interval);
  if (ret < 0) {
    return -1;
  }

  printf("Success to initialize tx operation\n");
  return 0;
}
