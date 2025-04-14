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

// 어플리케이션 헤더 파일
#include "sdee-ltev2x.h"


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
 * @brief LTE-V2X MSDU를 생성하여 전송한다.
 * @param[in] wsdu 전송할 WSDU (=WSM body에 수납되는 페이로드)
 * @param[in] wsdu_size 전송할 WSDU의 크기
 */
static void SDEE_LTEV2X_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size)
{
  int ret;
  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Sending LTE-V2X WSM\n");
  }

  /*
   * WSM을 생성한다.
   */
  uint8_t *wsm;
  size_t wsm_size;
  struct Dot3WSMConstructParams dot3_params;
  dot3_params.psid = g_mib.psid;
  dot3_params.chan_num = kDot3ChannelNumber_NA; // WSMP 확장헤더에 채널번호 정보를 수납하지 않음
  dot3_params.datarate = kDot3DataRate_NA; // WSMP 확장헤더에 데이터레이트 정보를 수납하지 않음
  dot3_params.transmit_power = kDot3Power_NA; // WSMP 확장헤더에 송신파워 정보를 수납하지 않음
  wsm = Dot3_ConstructWSM(&dot3_params, wsdu, wsdu_size, &wsm_size, &ret);
  if (wsm == NULL) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Fail to Dot3_ConstructWSM() - %d\n", ret);
    return;
  }
  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Success to construct %d-bytes LTE-V2X WSM\n", wsm_size);
    if (g_mib.dbg >= kDbgMsgLevel_MsgDump) {
      for (size_t i = 0; i < wsm_size; i++) {
        if ((i!=0) && (i%16==0)) {
          printf("\n");
        }
        printf("%02X ", wsm[i]);
      }
      printf("\n");
    }
  }

  /*
   * 루프백 테스트 수행 시, 패킷을 전송하지 않고 바로 수신콜백함수를 호출하여 스스로 처리한다.
   */
  if (g_mib.op == kOperationType_Loopback) {
    struct LTEV2XHALMSDURxParams rx_params;
    memset(&rx_params, 0x00, sizeof(struct LTEV2XHALMSDURxParams));
    SDEE_LTEV2X_ProcessRxMSDUCallback(wsm, wsm_size, rx_params);
  }
#ifndef _X64_
  /*
   * WSM을 전송한다.
   */
  else {
    struct LTEV2XHALMSDUTxParams tx_params;
    memset(&tx_params, 0x00, sizeof(struct LTEV2XHALMSDUTxParams));
    tx_params.tx_flow_type = g_mib.tx_flow_type;
    tx_params.tx_flow_index = kLTEV2XHALTxFLowIndex_Default;
    tx_params.tx_power = DEFAULT_POWER;
    tx_params.priority= DEFAULT_PRIORITY;
    tx_params.dst_l2_id = kLTEV2XHALL2ID_Broadcast;

    ret = LTEV2XHAL_TransmitMSDU(wsm, wsm_size, tx_params);
    if (ret < 0) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Fail to LTEV2XHAL_TransmitMSDU() - ret: %d\n", ret);
    } else {
      if (g_mib.dbg >= kDbgMsgLevel_Event) {
        SDEE_LTEV2X_Print(__FUNCTION__, "Success to LTEV2XHAL_TransmitMSDU()\n");
      }
    }
  }
#endif

  /*
   * 생성된 WSM을 해제한다.
   */
  free(wsm);
}


/**
 * @brief 송신타이머 만기 쓰레드 함수
 * @param arg 사용되지 않음
 */
static void SDEE_LTEV2X_TxTimerThread(union sigval arg)
{
  (void)arg;

  uint8_t payload[kDot2MsgSize_Max];

  /*
   * 프로그램 실행파라미터로 길이값이 지정되지 않았을 경우, 사전에 정의된 페이로드가 전송된다.
   */
  if (g_mib.payload_size == 0) {
    memcpy(payload, g_payload, sizeof(g_payload));
    g_mib.payload_size = sizeof(g_payload);
  }

  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Transmit SPDU\n");
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
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = g_mib.lat;
    params.signed_data.gen_location.lon = g_mib.lon;
    params.signed_data.gen_location.elev = 0;
    res = Dot2_ConstructSPDU(&params, payload, g_mib.payload_size);
    if (res.ret < 0) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Fail to generate SPDU - Dot2_ConstructSPDU() failed: %d\n", res.ret);
      return;
    }
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Success to generate %d-bytes SPDU(Signed)\n", res.ret);
    }
  } else {
    params.type = kDot2SPDUConstructType_Unsecured;
    res = Dot2_ConstructSPDU(&params, payload, g_mib.payload_size);
    if (res.ret < 0) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Fail to transmit SPDU - Dot2_ConstructSPDU() failed: %d\n", res.ret);
      return;
    }
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Success to generate %d-bytes SPDU(Unsecured)\n", res.ret);
    }
  }

  // WSM을 생성하여 전송한다.
  SDEE_LTEV2X_TransmitWSM(res.spdu, res.ret);
  free(res.spdu);
}


/**
 * @brief 송신타이머를 초기화한다.
 * @param[in] interval 송신주기(usec)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int SDEE_LTEV2X_InitTxTimer(unsigned int interval)
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
  se.sigev_notify_function = SDEE_LTEV2X_TxTimerThread;
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
int SDEE_LTEV2X_InitTxOperation(unsigned int interval)
{
  printf("Initialize tx operation\n");
  int ret;

#ifndef _X64_
  if (g_mib.op != kOperationType_Loopback) {

    // 송신 플로우를 등록한다.
    struct LTEV2XHALTxFlowParams flow_params;
    memset(&flow_params, 0, sizeof(struct LTEV2XHALTxFlowParams));
    flow_params.index = kLTEV2XHALTxFLowIndex_Default;
    flow_params.priority = DEFAULT_PRIORITY;
    flow_params.size = g_mib.payload_size + 300;
    flow_params.interval = g_mib.tx_interval / 1000;

    ret = LTEV2XHAL_RegisterTransmitFlow(flow_params);
    if (ret < 0) {
      printf("Fail to initialize WSM tx operation - LTEV2XHAL_RegisterTransmitFlow() failed: %d\n", ret);
      return -1;
    }
  }
#endif

  /*
   * 송신 타이머를 생성한다.
   */
  ret = SDEE_LTEV2X_InitTxTimer(interval);
  if (ret < 0) {
    return -1;
  }

  printf("Success to initialize tx operation\n");
  return 0;
}
