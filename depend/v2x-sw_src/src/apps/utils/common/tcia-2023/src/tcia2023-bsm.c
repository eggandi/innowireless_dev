/**
 * @file v2x-tcia-bsm.c
 * @brief BSM 관련 기능을 구현한 파일
 * @date 2019-09-28
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#include "j29451/j29451.h"
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief BSM 전송을 시작한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_StartBSMTransmit(void)
{
  int ret;
  Log(kTCIA3LogLevel_Event, "Start BSM transmit\n");

  /*
   * BSM 전송 정보를 저장한다.
   */
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[kDot3TimeSlot_Continuous]);
#if defined(_TCIA2023_DSRC_)
  wsm_tx_info->if_idx = V2V_IF_IDX;
#elif defined(_TCIA2023_LTE_V2X_)
  wsm_tx_info->if_idx = V2I_V2V_IF_IDX;
#else
#error "Communication type is not defined"
#endif
  wsm_tx_info->psid = DEFAULT_BSM_PSID;
  wsm_tx_info->chan_num = DEFAULT_BSM_CHANNEL;
  wsm_tx_info->timeslot = kDot3TimeSlot_0;
  wsm_tx_info->datarate = DEFAULT_DATARATE;
  wsm_tx_info->tx_power = DEFAULT_TX_POWER;
  wsm_tx_info->priority = kDot3Priority_Max;
  memset(wsm_tx_info->dst_mac_addr, 0xff, MAC_ALEN);

  J29451BSMTxInterval tx_interval = kJ29451BSMTxInterval_Default;

#if defined(_TCIA2023_DSRC_)
  /*
   * BSM 전송채널에 접속한다.
   */
  ret = TCIA2023_DSRC_AccessChannel(wsm_tx_info->if_idx, wsm_tx_info->chan_num, wsm_tx_info->chan_num);
  if (ret < 0) {
    return -1;
  }
#elif defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
  struct TCIA3FlowInfo *flow_info = &(g_tcia_mib.flow_info[wsm_tx_info->flow_id]);
  if (flow_info->type == kLTEV2XHALTxFlowType_SPS) {
    ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(flow_info->index, flow_info->pppp, flow_info->interval, 0);
    if (ret < 0) {
      return -1;
    }
  }
#else
  /*
   * 전송 플로우를 등록한다.
   */
  ret = TCIA2023_LTE_V2X_RegisterTransmitFlow(wsm_tx_info->psid, wsm_tx_info->tx_power, wsm_tx_info->priority, tx_interval);
  if (ret < 0) {
    return -1;
  }
#endif
#else
#error "Communication type is not defined"
#endif

  /*
   * BSM 필수정보를 설정한다.
   */
  ret = J29451_SetVehicleSize(g_tcia_mib.vehicle_size.width, g_tcia_mib.vehicle_size.len);
  if (ret < 0) {
    Err("Fail to start BSM transmit - J29451_SetVehicleSize() failed: %d\n", ret);
    return -1;
  }

  /*
   * 29451 라이브러리에 BSM 전송 시작을 요청한다.
   */
  Log(kTCIA3LogLevel_Event, "Start BSM transmit\n");
  ret = J29451_StartBSMTransmit(tx_interval);
  if (ret < 0) {
    Err("Fail to start BSM transmit - J29451_StartBSMTransmit() failed: %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to start BSM transmit\n");

  return 0;
}


/**
 * @brief j29451 라이브러리가 호출하는 BSM 송신 콜백함수
 * @param[in] bsm BSM 메시지 UPER 인코딩 바이트열
 * @param[in] bsm_size BSM 메시지의 길이
 * @param[in] event 이벤트 발생 여부
 * @param[in] cert_sign 인증서로 서명해야 하는지 여부
 * @param[in] id_change ID/인증서 변경 필요 여부
 * @param[in] addr 랜덤하게 생성된 MAC 주소. id_change=true일 경우 본 MAC 주소를 장치에 설정해야 한다.
 */
void
TCIA2023_BSMTransmitCallback(const uint8_t *bsm, size_t bsm_size, bool event, bool cert_sign, bool id_change, uint8_t *addr)
{
  Log(kTCIA3LogLevel_DetailedEvent, "BSM tx callback - event: %u, cert_sign: %u, id_change: %u\n",
      event, cert_sign, id_change);

  Dot3TimeSlot timeslot = kDot3TimeSlot_Continuous;
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);

  /*
   * 필요 시 MAC 주소를 변경한다.
   */
  if (id_change == true) {
    Log(kTCIA3LogLevel_Event, "BSM tx callback - id changed is needed - new MAC addr: "MAC_ADDR_FMT"\n",
        MAC_ADDR_FMT_ARGS(addr));
    memcpy(g_tcia_mib.v2x_if.mac_addr[wsm_tx_info->if_idx], addr, MAC_ALEN);

#if defined(_LTEV2X_HAL_)
    /*
     * J2945에서 만든 MAC 주소를 기반으로 L2ID를 설정한다.
     */
    int ret;
    uint32_t l2_id = (addr[5]) | (addr[4] << 8) | (addr[3] << 16);
    ret = LTEV2XHAL_SetL2ID(l2_id);
    if (ret < 0) {
      Err("Fail to set L2 ID - new L2 ID: %02X:%02X:%02X\n", addr[3], addr[4], addr[5]);
      return;
    }
#endif
  }

  /*
   * Signed 메시지를 생성한다.
   */
  Dot2SignerIdType signer_id;
  if (cert_sign == true) {
    Log(kTCIA3LogLevel_Event, "BSM tx callback - Force to sign with certificate\n");
    signer_id = kDot2SignerId_Certificate;
  } else {
    signer_id = kDot2SignerId_Profile;
  }
  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Signed;
  params.signed_data.psid = 32;
  params.signed_data.signer_id_type = signer_id;
  params.signed_data.cmh_change = id_change;
  res = Dot2_ConstructSPDU(&params, bsm, bsm_size);
  if (res.ret < 0) {
    Err("BSM tx callback - Dot2_ConstructSPDU() failed: %d\n", res.ret);
    return;
  }

#if defined(_TCIA2023_DSRC_)
  TCIA2023_DSRC_TransmitWSM(res.spdu, (size_t)res.ret, timeslot);
#elif defined(_TCIA2023_LTE_V2X_)
#if defined(_LTEV2X_HAL_)
  TCIA2023_LTE_V2X_TransmitBSM(res.spdu, (size_t)res.ret, timeslot, event);
#else
  TCIA2023_LTE_V2X_TransmitWSM(res.spdu, (size_t)res.ret, timeslot);
#endif
#else
#error "Communication type is not defined"
#endif
  free(res.spdu);

  // 현재 인증서가 이미 만기되었거나 다음번 BSM 서명 시에 만기될 경우에는, BSM ID 변경을 요청한다.
  // 다음번 BSM 콜백함수가 호출될 때, id_change=true, cert_sign=true 가 전달된다.
  if (res.cmh_expiry == true) {
    Log(kTCIA3LogLevel_Event, "BSM tx callback - Certificate will be expired. Request to change BSM ID\n");
    J29451_RequestBSMIDChange();
  }
}
