/** 
 * @file
 * @brief IEEE 1609.2 메시지 생성 및 송신 기능 구현 파일
 * @date 2020-05-26
 * @author gyun
 */


// 시스템 헤더 파일
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#include "wlanaccess/wlanaccess.h"
#include "v2x-sw.h"

// 어플리케이션 헤더 파일
#include "sdee-dsrc.h"


/**
 * @brief SPDU 처리 콜백함수. dot2 라이브러리에서 호출된다.
 * @param[in] result 처리결과
 * @param[in] priv 패킷파싱데이터
 */
void SDEE_DSRC_ProcessSPDUCallback(Dot2ResultCode result, void *priv)
{
  struct V2XPacketParseData *parsed = (struct V2XPacketParseData *)priv;
  struct Dot2SPDUParseData *dot2_parsed = &(parsed->spdu);

  if (result != kDot2Result_Success) {
    SDEE_DSRC_Print(__FUNCTION__, "Fail to process SPDU. result is %d\n", result);
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * UnsecuredData 형식의 dot2 메시지 처리 결과를 출력한다.
   */
  if (dot2_parsed->content_type == kDot2Content_UnsecuredData) {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_DSRC_Print(__FUNCTION__, "Success to process UNSECURED SPDU. Payload size is %u\n", parsed->ssdu_size);
    }
  }

  /*
   * SignedData 형식의 SPDU 처리 결과를 출력한다.
   */
  else if (dot2_parsed->content_type == kDot2Content_SignedData) {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_DSRC_Print(__FUNCTION__, "Success to process/verify SIGNED SPDU. Payload size is %u\n",
                      parsed->ssdu_size);
      SDEE_DSRC_Print(__FUNCTION__, "    content_type: %u, signer_id_type: %u, PSID: %u\n",
                      dot2_parsed->content_type, dot2_parsed->signed_data.signer_id_type, dot2_parsed->signed_data.psid);
      if (dot2_parsed->signed_data.gen_time_present == true) {
        SDEE_DSRC_Print(__FUNCTION__, "    gen_time: %"PRIu64"\n", dot2_parsed->signed_data.gen_time);
      }
      if (dot2_parsed->signed_data.expiry_time_present == true) {
        SDEE_DSRC_Print(__FUNCTION__, "    exp_time: %"PRIu64"\n", dot2_parsed->signed_data.expiry_time);
      }
      if (dot2_parsed->signed_data.gen_location_present == true) {
        SDEE_DSRC_Print(__FUNCTION__, "    gen_lat: %d, gen_lon: %d, gen_elev: %u\n",
                        dot2_parsed->signed_data.gen_location.lat, dot2_parsed->signed_data.gen_location.lon,
                        dot2_parsed->signed_data.gen_location.elev);
      }
    }
  }
  else {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_DSRC_Print(__FUNCTION__, "Success to process SPDU(content_type: %u). Payload size is %u\n",
                      dot2_parsed->content_type, parsed->ssdu_size);
    }
  }

  if (parsed->ssdu_size > 0) {
    if (g_mib.dbg >= kDbgMsgLevel_MsgDump) {
      SDEE_DSRC_Print(__FUNCTION__, "    payload: ");
      for (size_t i = 0; i < parsed->ssdu_size; i++) {
        printf("%02X", *(parsed->ssdu + i));
      }
      printf("\n");
    }
  }

  V2X_FreePacketParseData(parsed);
}


/**
 * @brief DSRC MPDU 수신처리 콜백함수. wlanaccess 라이브러리에서 호출된다.
 * @param[in] mpdu 수신된 MPDU
 * @param[in] mpdu_size 수신된 MPDU의 크기
 * @param[in] rx_params 수신 파라미터 정보
 */
void SDEE_DSRC_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *rx_params)
{
  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_DSRC_Print(__FUNCTION__, "Process rx DSRC MPDU\n");
  }

  /*
   * 패킷파싱데이터를 할당한다.
   */
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(mpdu, mpdu_size, rx_params);
  if (parsed == NULL) {
    SDEE_DSRC_Print(__FUNCTION__, "Fail to process rx DSRC MPDU - V2X_AllocateDSRCPacketParseData() failed\n");
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
    SDEE_DSRC_Print(__FUNCTION__, "Fail to process rx DSRC MPDU - Dot3_ParseWSMMPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * 관심 없는 PSID에 대한 WSM일 경우 로그만 출력하고 종료한다.
   */
  if (parsed->interested_psid == false) {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_DSRC_Print(__FUNCTION__, "Not interested(PSID:%u) DSRC WSM is received\n", parsed->mac_wsm.wsm.psid);
    }
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * SPDU를 처리한다 - 결과는 콜백함수를 통해 전달된다.
   */
  struct Dot2SPDUProcessParams params;
  memset(&params, 0, sizeof(params));
  params.rx_time = 0;
  params.rx_psid = parsed->mac_wsm.wsm.psid;
  params.rx_pos.lat = DEFAULT_LAT;
  params.rx_pos.lon = DEFAULT_LON;
  ret = Dot2_ProcessSPDU(parsed->wsdu, parsed->wsdu_size, &params, parsed);
  if (ret < 0) {
    SDEE_DSRC_Print(__FUNCTION__, "Fail to process rx DSRC MPDU - Dot2_ProcessSPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_DSRC_Print(__FUNCTION__, "Success to request to process dot2 msg\n");
  }
}
