/**
 * @file
 * @brief WSM 관련 기능을 구현한 파일
 * @date 2019-09-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#if defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
#include "ltev2x-hal/ltev2x-hal.h"
#else
#include "lteaccess/lteaccess.h"
#endif
#endif
#if defined(_TCIA2023_DSRC_)
#include "wlanaccess/wlanaccess.h"
#endif

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief WSM 송신 쓰레드 함수
 * @param[in] arg 시간슬롯 번호
 * @return NULL (프로그램 종료시에만 리턴됨)
 *
 * 대기하고 있다가, 송신타이머쓰레드로부터 컨디션 시그널을 수신하면, WSM 을 송신한다.
 */
static void * TCIA2023_WSMTxThread(void *arg)
{
  Dot3TimeSlot timeslot = *(Dot3TimeSlot *)arg;
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  struct TCIA3WSATxInfo *wsa_tx_info = &(wsa_info->tx_info);
  struct TCIA3WSAHdrInfo *wsa_hdr_info = &(wsa_info->hdr_info);
  Log(kTCIA3LogLevel_Event, "WSMTxThread for timeslot[%u] is created\n", timeslot);
  wsm_tx_info->txing = true;

  int pdu_size;

  do {
    /*
     * 송신타이머로부터 시그널이 올때 때까지 대기한다.
     * 	- 송신타이머 주기마다 시그널이 수신되어 깨어난다.
     */
    pthread_mutex_lock(&(wsm_tx_info->tx_timer.mtx));
    pthread_cond_wait(&(wsm_tx_info->tx_timer.cond), &(wsm_tx_info->tx_timer.mtx));
    pthread_mutex_unlock(&(wsm_tx_info->tx_timer.mtx));

    if (wsm_tx_info->txing == false) {
      Log(kTCIA3LogLevel_Event, "Stop WSM tx thread for timeslot[%u]\n", timeslot);
      break;
    }

    pdu_size = wsm_tx_info->pdu_size;

    struct Dot2SPDUConstructParams params;
    struct Dot2SPDUConstructResult res = { 0, NULL, false };
    memset(&params, 0, sizeof(params));

    if (wsm_tx_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_Unsecure) {
      params.type = kDot2SPDUConstructType_Unsecured;
    }
    else if (wsm_tx_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_UseSecProfilePerContentType) {
      params.type = kDot2SPDUConstructType_Signed;
      params.signed_data.signer_id_type = kDot2SignerId_Profile;
    }
    else if (wsm_tx_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_SignIncludeCertificate) {
      params.type = kDot2SPDUConstructType_Signed;
      params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    }
    else if (wsm_tx_info->sec_info.signer_id_type == kCvcoctci2023SignerIdentifierType_SignIncludeDigest) {
      params.type = kDot2SPDUConstructType_Signed;
      params.signed_data.signer_id_type = kDot2SignerId_Digest;
    }
    params.signed_data.psid = wsm_tx_info->psid;
    params.signed_data.gen_location.lat = wsa_hdr_info->latitude;
    params.signed_data.gen_location.lon = wsa_hdr_info->longitude;
    params.signed_data.gen_location.elev = wsa_hdr_info->elevation;

    switch(g_tcia_mib.testing.test_protocol)
    {
      case kTCIA3TestProtocol_80211:
      case kTCIA3TestProtocol_16094:
        Log(kTCIA3LogLevel_DetailedEvent, "Constructing %s Ieee1609Dot2Data\n", params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured");
        res = Dot2_ConstructSPDU(&params, wsm_tx_info->pdu, pdu_size);
        if (res.ret < 0) {
          Err("Fail to construct %s Ieee1609Dot2Data - Dot2_ConstructSPDU() failed: %d\n", params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured", res.ret);
          continue;
        }
        Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes %s Ieee1609Dot2Data\n", res.ret, params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured");
        break;

      case kTCIA3TestProtocol_16093dsrc:
        Log(kTCIA3LogLevel_DetailedEvent, "Constructing %s Ieee1609Dot2Data\n", params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured");
        res = Dot2_ConstructSPDU(&params, wsm_tx_info->pdu, pdu_size);
        if (res.ret < 0) {
          Err("Fail to construct %s Ieee1609Dot2Data - Dot2_ConstructSPDU() failed: %d\n", params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured", res.ret);
          continue;
        }
        Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes %s Ieee1609Dot2Data\n", res.ret, params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured");
        break;

      case kTCIA3TestProtocol_16093pc5:
        Log(kTCIA3LogLevel_DetailedEvent, "Constructing %s Ieee1609Dot2Data\n", params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured");
        res = Dot2_ConstructSPDU(&params, wsm_tx_info->pdu, pdu_size);
        if (res.ret < 0) {
          Err("Fail to construct %s Ieee1609Dot2Data - Dot2_ConstructSPDU() failed: %d\n", params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured", res.ret);
          continue;
        }
        Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes %s Ieee1609Dot2Data\n", res.ret, params.type == kDot2SPDUConstructType_Signed ? "signed" : "unsecured");
        break;
      default:
        break;
    }

#if defined(_TCIA2023_DSRC_)
    TCIA2023_DSRC_TransmitWSM(res.spdu, (size_t)res.ret, timeslot);
#elif defined(_TCIA2023_LTE_V2X_)
    TCIA2023_LTE_V2X_TransmitWSM(res.spdu, (size_t)res.ret, timeslot);
#else
#error "Communication type is not defined"
#endif
    if (res.spdu) {
      free(res.spdu);
    }

  } while(1);

  return NULL;
}


/**
 * @brief TimeSlot0 WSM 송신타이머 만기 쓰레드. 송신타이머 만기 시마다 호출된다.
 * @param arg 사용되지 않음
 *
 * 송신타이머 컨디션 시그널을 전송하여 송신쓰레드가 깨어나도록 한다.
 */
static void TCIA2023_WSMTxTimerThreadForTimeSlot0(union sigval arg)
{
  (void)arg;
  if (g_tcia_mib.wsm_trx_info[0].tx_timer.cnt++ == g_tcia_mib.wsm_trx_info[0].packet_count && g_tcia_mib.wsm_trx_info[0].packet_count != 0) {
    TCIA2023_StopWSMTransmit(0);
  }
  pthread_mutex_lock(&(g_tcia_mib.wsm_trx_info[0].tx_timer.mtx));
  pthread_cond_signal(&(g_tcia_mib.wsm_trx_info[0].tx_timer.cond));
  pthread_mutex_unlock(&(g_tcia_mib.wsm_trx_info[0].tx_timer.mtx));
}


/**
 * @brief TimeSlot1 WSM 송신타이머 만기 쓰레드. 송신타이머 만기 시마다 호출된다.
 * @param arg 사용되지 않음
 *
 * 송신타이머 컨디션 시그널을 전송하여 송신쓰레드가 깨어나도록 한다.
 */
static void TCIA2023_WSMTxTimerThreadForTimeSlot1(union sigval arg)
{
  (void)arg;
  if (g_tcia_mib.wsm_trx_info[1].tx_timer.cnt++ == g_tcia_mib.wsm_trx_info[1].packet_count && g_tcia_mib.wsm_trx_info[1].packet_count != 0) {
    TCIA2023_StopWSMTransmit(1);
  }
  pthread_mutex_lock(&(g_tcia_mib.wsm_trx_info[1].tx_timer.mtx));
  pthread_cond_signal(&(g_tcia_mib.wsm_trx_info[1].tx_timer.cond));
  pthread_mutex_unlock(&(g_tcia_mib.wsm_trx_info[1].tx_timer.mtx));
}


/**
 * @brief Continuous WSM 송신타이머 만기 쓰레드. 송신타이머 만기 시마다 호출된다.
 * @param arg 사용되지 않음
 *
 * 송신타이머 컨디션 시그널을 전송하여 송신쓰레드가 깨어나도록 한다.
 */
static void TCIA2023_WSMTxTimerThreadForContinuous(union sigval arg)
{
  (void)arg;
  pthread_mutex_lock(&(g_tcia_mib.wsm_trx_info[2].tx_timer.mtx));
  pthread_cond_signal(&(g_tcia_mib.wsm_trx_info[2].tx_timer.cond));
  pthread_mutex_unlock(&(g_tcia_mib.wsm_trx_info[2].tx_timer.mtx));
}


/**
 * @brief WSM 송신타이머를 초기화한다.
 * @param[in] timeslot WSM 송신 TimeSlot
 * @param[in] interval 송신주기(usec 단위)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int  TCIA2023_InitWSMTxTimer(Dot3TimeSlot timeslot, unsigned int interval)
{
  int ret;
  struct itimerspec ts;
  struct sigevent se;

  Log(kTCIA3LogLevel_Event, "Initialize WSM tx timer on timeslot[%u] - interval: %u msec\n", timeslot, interval);

  /*
   * 송신타이머 만기 시 송신타이머쓰레드(TCIA2023_TxTimerThread)가 생성되도록 설정한다.
   */
  se.sigev_notify = SIGEV_THREAD;
  se.sigev_value.sival_ptr = NULL;
  if (timeslot == kDot3TimeSlot_0) {
    se.sigev_notify_function = TCIA2023_WSMTxTimerThreadForTimeSlot0;
  } else if (timeslot == kDot3TimeSlot_1) {
    se.sigev_notify_function = TCIA2023_WSMTxTimerThreadForTimeSlot1;
  } else {
    se.sigev_notify_function = TCIA2023_WSMTxTimerThreadForContinuous;
  }
  se.sigev_notify_attributes = NULL;

  ts.it_value.tv_sec = 1;     // 최초타이머 주기 = 1 sec
  ts.it_value.tv_nsec = 0;  // 최초타이머 주기 = 100usec
  ts.it_interval.tv_sec = interval / 1000;
  ts.it_interval.tv_nsec = (interval % 1000) * 1000000;

  /*
   * 송신타이머 생성
   */
  ret = timer_create(CLOCK_MONOTONIC, &se, &(g_tcia_mib.wsm_trx_info[timeslot].tx_timer.timer));
  if (ret) {
    Err("Fail to create timer: %m\n");
    return -1;
  }

  /*
   * 송신타이머 주기 설정
   */
  ret = timer_settime(g_tcia_mib.wsm_trx_info[timeslot].tx_timer.timer, 0, &ts, 0);
  if (ret) {
    Err("Fail to set timer: %m\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to initialize tx timer.\n");
  return 0;
}


/**
 * @brief WSM 전송을 시작한다.
 * @param[in] timeslot WSM을 전송할 TimeSlot
 * @retval 0: 성공
 * @retval -1: 실패
 *
 * WSM 전송 쓰레드와 타이머를 생성하여 주기적으로 전송한다.
 */
int TCIA2023_StartWSMTransmit(Dot3TimeSlot timeslot)
{
  Log(kTCIA3LogLevel_Event, "Start WSM transmit on timeslot[%u]\n", timeslot);

  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);
#if defined(_LTEV2X_HAL_)
  struct TCIA3FlowInfo *flow_info = &(g_tcia_mib.flow_info[wsm_tx_info->flow_id]);
#endif
  /*
   * 전송 주기 계산
   */
  unsigned int tx_interval_msec;
  if (g_tcia_mib.wsm_trx_info[timeslot].repeat_rate > 0) {
    tx_interval_msec = 5000 / wsm_tx_info->repeat_rate;
#if defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
    if (tx_interval_msec > flow_info->interval && flow_info->interval != kLTEV2XHALTxFLowInterval_None) {
      tx_interval_msec = flow_info->interval;
    }
#endif
#endif
  } else {
    //    tx_interval_msec = 100; // 기본값
    tx_interval_msec = 10000 /* 10 sec */ / g_tcia_mib.wsm_trx_info[timeslot].packet_count;
  }

  /*
   * 송신 타이머 관련 뮤텍스, 컨디션시그널 초기화
   */
  pthread_mutex_init(&(wsm_tx_info->tx_timer.mtx), NULL);
  pthread_cond_init(&(wsm_tx_info->tx_timer.cond), NULL);

  /*
   * 송신 쓰레드 생성
   */
  Log(kTCIA3LogLevel_Event, "Create WSM tx thread\n");
  int ret = pthread_create(&(wsm_tx_info->tx_timer.thread), NULL, TCIA2023_WSMTxThread, &timeslot);
  if (ret < 0) {
    Err("Fail to create WSM tx thread - %m\n");
    return -1;
  }
  pthread_detach(wsm_tx_info->tx_timer.thread);
  Log(kTCIA3LogLevel_Event, "Success to create WSM tx thread\n");

#if defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
  if (flow_info->size == kLTEV2XHALMSDUSize_None) {
    flow_info->size = wsm_tx_info->pdu_size;
  }
  if (flow_info->type == kLTEV2XHALTxFlowType_SPS) {
    ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(flow_info->index, flow_info->pppp, flow_info->interval, flow_info->size);
    if (ret < 0) {
      return -1;
    }
  }
#else
  ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(wsm_tx_info->psid, wsm_tx_info->tx_power, wsm_tx_info->priority, tx_interval_msec);
  if (ret < 0) {
    return -1;
  }
#endif
#endif

  /*
   * 송신 타이머 생성
   */
  ret = TCIA2023_InitWSMTxTimer(timeslot, tx_interval_msec);
  if (ret < 0) {
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to start WSM transmit\n");\
  return 0;
}


/**
 * @brief WSM 전송을 종료한다.
 * @param[in] timeslot 전송을 종료할 TimeSlot
 *
 * WSM 전송 쓰레드와 타이머를 종료한다.
 */
void TCIA2023_StopWSMTransmit(Dot3TimeSlot timeslot)
{
  Log(kTCIA3LogLevel_Event, "Stop WSM transmit on timeslot %d\n", timeslot);

  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);

  /*
   * 전송 중이면 전송 동작을 중지한다.
   *  - 전송 쓰레드, 타이머 등을 제거한다.
   *  - 전송 큐를 비운다.
   */
  if (wsm_tx_info->txing == true) {
    Log(kTCIA3LogLevel_Event, "Destroy tx thread, timer, condition, mutex\n");
    pthread_cancel(wsm_tx_info->tx_timer.thread);
    timer_delete(wsm_tx_info->tx_timer.timer);    
    usleep(500000);
    pthread_cond_destroy(&(wsm_tx_info->tx_timer.cond));
    pthread_mutex_destroy(&(wsm_tx_info->tx_timer.mtx));
    wsm_tx_info->txing = false;
    Log(kTCIA3LogLevel_Event, "Flush transmit queues\n");
#if defined(_TCIA2023_DSRC_)
    WAL_FlushTransmitQueue(wsm_tx_info->if_idx, kWalTimeSlot_0, 5);
    WAL_FlushTransmitQueue(wsm_tx_info->if_idx, kWalTimeSlot_1, 5);
#endif
  }

  Log(kTCIA3LogLevel_Event, "Success to stop WSM transmit\n");
}


/**
 * @brief 특정 TimeSlot에서 WSM 수신을 시작한다.
 * @param[in] timeslot 수신을 시작할 TimeSlot
 */
void TCIA2023_StartWSMReceive(Dot3TimeSlot timeslot)
{
  Log(kTCIA3LogLevel_Event, "Start WSM receive on timeslot[%u]\n", timeslot);
  (void)timeslot;
}


/**
 * @brief 특정 TimeSlot에서 WSM 수신을 종료한다.
 * @param[in] timeslot 수신을 종료할 TimeSlot
 */
void TCIA2023_StopWSMReceive(Dot3TimeSlot timeslot)
{
  Log(kTCIA3LogLevel_Event, "Stop WSM receive on timeslot[%u]\n", timeslot);
  (void)timeslot;
}

