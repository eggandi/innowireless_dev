/** 
 * @file
 * @brief DSRC 관련 구현
 * @date 2022-09-17
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/bsmd.h"


/**
 * @brief DSRC WSM을 생성하여 전송한다.
 * @param[in] wsdu WSM에 수납될 WSDU
 * @param[in] wsdu_size WSM에 수납될 WSDU의 길이
 * @param[in] priority 전송 우선순위
 */
void BSMD_DSRC_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, WalPriority priority)
{
  /*
   * WSM MPDU를 생성한다.
   */
  int ret;
  struct Dot3MACAndWSMConstructParams wsm_params;
  memset(&wsm_params, 0, sizeof(wsm_params));
  wsm_params.wsm.chan_num = kDot3ChannelNumber_NA;
  wsm_params.wsm.datarate = kDot3DataRate_NA;
  wsm_params.wsm.transmit_power = kDot3Power_NA;
  wsm_params.wsm.psid = BSM_PSID;
  wsm_params.mac.priority = priority;
  memset(wsm_params.mac.dst_mac_addr, 0xff, MAC_ALEN);
  memcpy(wsm_params.mac.src_mac_addr, g_bsmd_mib.v2v_if_mac_addr, MAC_ALEN);
  Log(kBSMDLogLevel_DetailedEvent, "Construct DSRC WSM MPDU\n");
  size_t mpdu_size;
  uint8_t *mpdu = Dot3_ConstructWSMMPDU(&wsm_params, wsdu, wsdu_size, &mpdu_size, &ret);
  if (mpdu == NULL) {
    Err("Fail to construct DSRC WSM MPDU - Dot3_ConstructWSMMPDU() failed - %d\n", ret);
    return;
  }
  Log(kBSMDLogLevel_DetailedEvent, "Success to construct %d-bytes DSRC WSM MPDU\n", mpdu_size);
  BSMD_PrintPacketDump(kBSMDLogLevel_PktDump, mpdu, mpdu_size);

  /*
   * WSM MPDU를 전송한다.
   */
  struct WalMPDUTxParams wal_params;
  memset(&wal_params, 0, sizeof(wal_params));
  wal_params.chan_num = V2V_CHAN_NUM;
  wal_params.datarate = BSM_DATARATE;
  wal_params.expiry = 0;
  wal_params.tx_power = BSM_TX_POWER;
  Log(kBSMDLogLevel_DetailedEvent, "Transmit WAVE WSM MPDU\n");
  ret = WAL_TransmitMPDU(V2V_IF_IDX, mpdu, mpdu_size, &wal_params);
  if (ret < 0) {
    Err("Fail to transmit DSRC WSM MPDU - WAL_TransmitMPDU() failed - %d\n", ret);
  } else {
    Log(kBSMDLogLevel_DetailedEvent, "Success to transmit DSRC WSM MPDU\n");
  }

  free(mpdu);
}


/**
 * @brief DSRC MPDU 수신콜백함수
 * @param[in] mpdu 수신된 MPDU 데이터
 * @param[in] mpdu_size 수신된 MPDU 데이터 길이
 * @param[in] rx_params 수신 파라미터 정보
 */
void BSMD_DSRC_ProcessRxMPDUCallback(
  const uint8_t *mpdu,
  WalMPDUSize mpdu_size,
  const struct WalMPDURxParams *mpdu_rx_params)
{
  Log(kBSMDLogLevel_Event, "Proces %u-bytes rx MPDU\n", mpdu_size);

  /*
   * 패킷파싱데이터를 할당한다.
   */
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(mpdu, mpdu_size, mpdu_rx_params);
  if (parsed == NULL) {
    Err("Fail to process rx MPDU - V2X_AllocateDSRCPacketParseData() failed\n");
    return;
  }

  /*
   * WSM MPDU를 파싱한다.
   */
  int ret;
  parsed->wsdu = Dot3_ParseWSMMPDU(parsed->pkt,
                                   parsed->pkt_size,
                                   &(parsed->mac_wsm),
                                   &(parsed->wsdu_size),
                                   &(parsed->interested_psid),
                                   &ret);
  if (parsed->wsdu == NULL) {
    Err("Fail to process rx MPDU - Dot3_ParseWSMMPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * SPDU를 처리한다 - 결과는 콜백함수를 통해 전달된다.
   */
  struct Dot2SPDUProcessParams params;
  memset(&params, 0, sizeof(params));
  params.rx_psid = parsed->mac_wsm.wsm.psid;
  params.rx_pos.lat = kDot2Latitude_Unavailable; ///< don't care
  params.rx_pos.lon = kDot2Longitude_Unavailable; ///< don't care
  ret = Dot2_ProcessSPDU(parsed->wsdu, parsed->wsdu_size, &params, parsed);
  if (ret < 0) {
    Err("Fail to process rx MPDU - Dot2_ProcessSPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
}
