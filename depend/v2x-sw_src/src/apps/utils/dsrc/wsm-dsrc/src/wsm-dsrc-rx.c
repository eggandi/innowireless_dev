/**
 * @file
 * @brief WSM 수신 처리 기능을 구현한 파일
 * @date 2019-08-12
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdio.h>

// 어플리케이션 헤더 파일
#include "wsm-dsrc.h"


/**
 * @brief 수신된 WSDU를 처리한다.
 * @param[in] wsdu 수신된 WSDU (= WSM body)
 * @param[in] wsdu_size 수신된 WSDU의 크기
 * @param[in] hdr_params WSM/MAC 헤더 파싱정보
 * @param[in] rx_params 수신파라미터 정보
 * @param[in] interested_psid 관심 PSID인지 여부
 */
static void WSM_DSRC_ProcessRxWSDU(
  const uint8_t *wsdu,
  size_t wsdu_size,
  struct Dot3MACAndWSMParseParams *hdr_params,
  const struct WalMPDURxParams *rx_params,
  bool interested_psid)
{
  if (g_mib.dbg >= kDbgMsgLevel_event)
  {
    /*
     * 관심 있는 서비스에 대한 WSDU를 처리한다.
     */
    if (interested_psid == true)
    {
      WSM_DSRC_Print(__FUNCTION__, "Process interested rx %u-bytes WAVE WSDU\n", wsdu_size);

      // 수신 파라미터 정보
      WSM_DSRC_Print(__FUNCTION__,
                "    Rx info - if: %u, timeslot: %u, chan: %u, rx power: %ddBm, rcpi: %u, datarate: %u*500kbps\n",
                rx_params->if_idx, rx_params->timeslot, rx_params->chan_num,
                rx_params->rx_power, rx_params->rcpi, rx_params->datarate);

      // MAC 및 WSM 헤더 정보
      WSM_DSRC_Print(__FUNCTION__, "    MAC header - dst: "MAC_ADDR_FMT", src: "MAC_ADDR_FMT", priority: %u\n",
                     MAC_ADDR_FMT_ARGS(hdr_params->mac.dst_mac_addr), MAC_ADDR_FMT_ARGS(hdr_params->mac.src_mac_addr),
                     hdr_params->mac.priority);
      WSM_DSRC_Print(__FUNCTION__, "    WSM header - PSID: %u, chan: %u, datarate: %u*500kbps, power: %ddBm\n",
                     hdr_params->wsm.psid, hdr_params->wsm.chan_num,
                     hdr_params->wsm.datarate, hdr_params->wsm.transmit_power);

      // WSDU
      if (g_mib.dbg >= kDbgMsgLevel_msgdump) {
        for (size_t i = 0; i < wsdu_size; i++) {
          if ((i != 0) && (i % 16 == 0)) { printf("\n"); }
          printf("%02X ", wsdu[i]);
        }
        printf("\n");
      }
    }

    /*
     * 관심 없는 서비스에 대한 WSDU는 처리하지 않는다.
     */
    else
    {
      WSM_DSRC_Print(__FUNCTION__, "NOT process WSM - not intersted PSID %u\n", hdr_params->wsm.psid);
    }
  }
}


/**
 * @brief WAVE MPDU 수신처리 콜백함수. wlanacces 라이브러리에서 호출된다.
 * @param[in] mpdu 수신된 MPDU
 * @param[in] mpdu_size 수신된 MPDU의 크기
 * @param[in] rx_params 수신 파라미터 정보
 */
void WSM_DSRC_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *rx_params)
{
  if (g_mib.dbg >= kDbgMsgLevel_event) {
    WSM_DSRC_Print(__FUNCTION__, "Process rx WAVE MPDU\n");
  }

  /*
   * WSM MPDU를 파싱한다.
   */
  int ret;
  struct Dot3MACAndWSMParseParams params;
  size_t wsdu_size;
  bool wsr_registered;
  uint8_t *wsdu = Dot3_ParseWSMMPDU(mpdu, mpdu_size, &params, &wsdu_size, &wsr_registered, &ret);
  if (wsdu == NULL) {
    if (g_mib.dbg >= kDbgMsgLevel_event) {
      WSM_DSRC_Print(__FUNCTION__, "Fail to process rx WAVE MPDU - Dot3_ParseWSMMPDU() failed: %d\n", ret);
    }
    return;
  }

  /*
   * 페이로드를 처리한다.
   */
  WSM_DSRC_ProcessRxWSDU(wsdu, wsdu_size, &params, rx_params, wsr_registered);
}
