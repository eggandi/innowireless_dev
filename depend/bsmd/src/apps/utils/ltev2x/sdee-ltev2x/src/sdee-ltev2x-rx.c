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

// 어플리케이션 헤더 파일
#include "sdee-ltev2x.h"


/**
 * @brief SPDU 처리 콜백함수. dot2 라이브러리에서 호출된다.
 * @param[in] result 처리결과
 * @param[in] priv 패킷파싱데이터
 */
void SDEE_LTEV2X_ProcessSPDUCallback(Dot2ResultCode result, void *priv)
{
  struct V2XPacketParseData *parsed = (struct V2XPacketParseData *)priv;
  struct Dot2SPDUParseData *dot2_parsed = &(parsed->spdu);

  if (result != kDot2Result_Success) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Fail to process SPDU. result is %d\n", result);
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * UnsecuredData 형식의 dot2 메시지 처리 결과를 출력한다.
   */
  if (dot2_parsed->content_type == kDot2Content_UnsecuredData) {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Success to process UNSECURED SPDU. Payload size is %u\n", parsed->ssdu_size);
    }
  }

  /*
   * SignedData 형식의 SPDU 처리 결과를 출력한다.
   */
  else if (dot2_parsed->content_type == kDot2Content_SignedData) {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Success to process/verify SIGNED SPDU. Payload size is %u\n",
                      parsed->ssdu_size);
      SDEE_LTEV2X_Print(__FUNCTION__, "    content_type: %u, signer_id_type: %u, PSID: %u\n",
                      dot2_parsed->content_type, dot2_parsed->signed_data.signer_id_type, dot2_parsed->signed_data.psid);
      if (dot2_parsed->signed_data.gen_time_present == true) {
        SDEE_LTEV2X_Print(__FUNCTION__, "    gen_time: %"PRIu64"\n", dot2_parsed->signed_data.gen_time);
      }
      if (dot2_parsed->signed_data.expiry_time_present == true) {
        SDEE_LTEV2X_Print(__FUNCTION__, "    exp_time: %"PRIu64"\n", dot2_parsed->signed_data.expiry_time);
      }
      if (dot2_parsed->signed_data.gen_location_present == true) {
        SDEE_LTEV2X_Print(__FUNCTION__, "    gen_lat: %d, gen_lon: %d, gen_elev: %u\n",
                        dot2_parsed->signed_data.gen_location.lat, dot2_parsed->signed_data.gen_location.lon,
                        dot2_parsed->signed_data.gen_location.elev);
      }
    }
  }
  else {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Success to process SPDU(content_type: %u). Payload size is %u\n",
                 dot2_parsed->content_type, parsed->ssdu_size);
    }
  }

  if (parsed->ssdu_size > 0) {
    if (g_mib.dbg >= kDbgMsgLevel_MsgDump) {
      SDEE_LTEV2X_Print(__FUNCTION__, "    payload: ");
      for (size_t i = 0; i < parsed->ssdu_size; i++) {
        printf("%02X", *(parsed->ssdu + i));
      }
      printf("\n");
    }
  }

  V2X_FreePacketParseData(parsed);
}


/**
 * @brief LTE-V2X MSDU 수신처리 콜백함수. lteaccess 라이브러리에서 호출된다.
 * @param[in] msdu 수신된 MSDU (= WSM 헤더 + WSM body)
 * @param[in] msdu_size 수신된 MSDU의 크기
 */
void SDEE_LTEV2X_ProcessRxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_param)
{
  if (g_mib.dbg >= kDbgMsgLevel_Event) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Process rx LTE-V2X MSDU\n");
  }

  /*
   * 패킷파싱데이터를 할당한다.
   */
  struct V2XPacketParseData *parsed = V2X_AllocateCV2XPacketParseData(msdu, msdu_size);
  if (parsed == NULL) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Fail to process rx LTE-V2X MSDU - V2X_AllocateCV2XPacketParseData() failed\n");
    return;
  }

  /*
   * WSM MSDU를 파싱한다.
   */
  int ret;
  parsed->wsdu = Dot3_ParseWSM(parsed->pkt,
                               parsed->pkt_size,
                               &(parsed->mac_wsm.wsm),
                               &(parsed->wsdu_size),
                               &(parsed->interested_psid),
                               &ret);
  if (parsed->wsdu == NULL) {
    SDEE_LTEV2X_Print(__FUNCTION__, "Fail to process rx LTE-V2X MSDU - Dot3_ParseWSM() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * 관심 없는 PSID에 대한 WSM일 경우 로그만 출력하고 종료한다.
   */
  if (parsed->interested_psid == false) {
    if (g_mib.dbg >= kDbgMsgLevel_Event) {
      SDEE_LTEV2X_Print(__FUNCTION__, "Not interested(PSID:%u) LTE-V2X WSM is received\n", parsed->mac_wsm.wsm.psid);
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
    SDEE_LTEV2X_Print(__FUNCTION__, "Fail to process rx LTE-V2X MSDU - Dot2_ProcessSPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
  SDEE_LTEV2X_Print(__FUNCTION__, "Success to request to process SPDU\n");
}
