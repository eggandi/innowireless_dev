/**
 * @file
 * @brief ffasn1c 라이브러리를 이용하여 WSM 을 디코딩하는 기능을 구현한 파일
 * @date 2019-08-09
 * @author gyun
 */

// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "ffasn1-dot3-2016.h"

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-ffasn1c.h"
#include "dot3-internal.h"


/**
 * @brief 디코딩된 WSM-N-Header 필수필드를 파싱한다.
 * @param[in] wsm_msg 파싱할 asn.1 정보구조체의 주소를 전달한다.
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 주소를 전달한다.
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int
dot3_ffasn1c_ParseWSMPNHdrMandatory(struct dot3ShortMsgNpdu *wsm_msg, struct Dot3WSMParseParams *params)
{
  Log(kDot3LogLevel_Event, "Parse WSMP-N-header mandatory fields\n");

  /*
   * subtype 필드 파싱
   */
  if (wsm_msg->subtype.choice != dot3ShortMsgSubtype_nullNetworking) {
    Err("Fail to parse WSMP-N-Header mandatory fields - invalid subtype: %d\n", wsm_msg->subtype.choice);
    return -kDot3Result_InvalidWSMPNHeaderSubType;
  }

  /*
   * WSMP version 필드 파싱
   */
  if (wsm_msg->subtype.u.nullNetworking.version != kShortMsgVersionNo) {
    Err("Fail to parse WSMP-N-Header mandatory fields - invalid version: %d\n",
        wsm_msg->subtype.u.nullNetworking.version);
    return -kDot3Result_InvalidWSMPNHeaderWSMPVersion;
  }
  params->version = (Dot3ProtocolVersion)(wsm_msg->subtype.u.nullNetworking.version);

  Log(kDot3LogLevel_Event, "Success to parse WSMP-N-header mandatory fields\n");
  return kDot3Result_Success;
}


/**
 * @brief 디코딩된 WSM-N-Header ChannelNumber 확장필드를 파싱한다.
 * @param[in] ext 파싱할 ChannelNumber 확장필드 정보구조체
 * @param[out] chan_num 파싱된 ChannelNumber 정보가 저장될 변수의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSMPHdrChannelNumberExtension(const void *ext, Dot3ChannelNumber *chan_num)
{
  Log(kDot3LogLevel_Event, "Parse WSMP-N-header ChannelNumber extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  *chan_num = *(Dot3ChannelNumber *)ext;
  Log(kDot3LogLevel_Event, "Success to parse WSMP-N-header ChannelNumber extension\n");
  return kDot3Result_Success;
}


/**
 * @brief 디코딩된 WSM-N-Header DataRate 확장필드를 파싱한다.
 * @param[in] ext 파싱할 DataRate 확장필드 정보구조체
 * @param[out] datarate 파싱된 DataRate 정보가 저장될 변수의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSMPHdrDataRateExtension(const void *ext, Dot3DataRate *datarate)
{
  Log(kDot3LogLevel_Event, "Parse WSMP-N-header DataRate extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  *datarate = *(Dot3DataRate *)ext;
  Log(kDot3LogLevel_Event, "Success to parse WSMP-N-header DataRate extension\n");
  return kDot3Result_Success;
}


/**
 * @brief 디코딩된 WSM-N-Header TransmitPowerUsed 확장필드를 파싱한다.
 * @param[in] ext 파싱할 TransmitPowerUsed 확장필드 정보구조체
 * @param[out] power 파싱된 TransmitPowerUsed 정보가 저장될 변수의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSMPHdrTransmitPowerUsedExtension(const void *ext, Dot3Power *power)
{
  Log(kDot3LogLevel_Event, "Parse WSMP-N-header TransmitPowerUsed extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  *power = *(int *)ext;
  Log(kDot3LogLevel_Event, "Success to parse WSMP-N-header TransmitPowerUsed extension\n");
  return kDot3Result_Success;
}


/**
 * @brief 디코딩된 WSM-N-Header 확장필드들을 파싱한다.
 * @param[in] wsm_msg 파싱할 확장필드 구조체들의 주소를 전달한다.
 * @param[out] params 파싱된 정보가 저장될 정보 구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSMPNHdrExtensions(
  const struct dot3ShortMsgNextensions *exts, struct Dot3WSMParseParams *params)
{
  Log(kDot3LogLevel_Event, "Parse WSMP-N-header extensions\n");

  if (exts->tab == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }

  /*
   * 각 확장필드들을 파싱한다.
   *  - ChannelNumber, DataRate, TransmitPowerUsed
   */
  struct dot3ShortMsgNextension *ext;
  int ret;
  for (uint32_t i = 0; i < exts->count; i++) {
    ext = exts->tab + i;
    if (ext == NULL) { return -kDot3Result_Asn1AbnormalOp; }
    switch (ext->extensionId) {
      case kDot3ExtensionID_ChannelNumber80211:
        ret = dot3_ffasn1c_ParseWSMPHdrChannelNumberExtension(ext->value.u.data, &params->chan_num);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_DataRate80211:
        ret = dot3_ffasn1c_ParseWSMPHdrDataRateExtension(ext->value.u.data, &params->datarate);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_TxPowerUsed80211:
        ret = dot3_ffasn1c_ParseWSMPHdrTransmitPowerUsedExtension(ext->value.u.data, &params->transmit_power);
        if (ret < 0) {
          return ret;
        }
        break;
      default:
        Err("Fail to parse WSMP-N-Header extensions - invalid extension id %d\n", ext->extensionId);
        return -kDot3Result_InvalidWSMPNHeaderExtensionID;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSMP-N-header extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief 디코딩된 WSM-N-Header 정보를 파싱한다.
 * @param[in] wsm_msg 파싱할 asn.1 정보구조체의 주소를 전달한다.
 * @param[out] params 파싱된 정보가 저장될 구조체의 주소를 전달한다.
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSMPNHdr(struct dot3ShortMsgNpdu *wsm_msg, struct Dot3WSMParseParams *params)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSMP-N-header\n");

  /*
   * 필수필드를 파싱한다.
   */
  ret = dot3_ffasn1c_ParseWSMPNHdrMandatory(wsm_msg, params);
  if (ret < 0) {
    return ret;
  }

  /*
   * 확장필드가 없을 때의 기본값을 설정한다.
   */
  params->chan_num = kDot3ChannelNumber_NA;
  params->datarate = kDot3DataRate_NA;
  params->transmit_power = kDot3Power_NA;

  /*
   * (존재하는 경우) 확장필드를 파싱한다.
   */
  if (wsm_msg->subtype.u.nullNetworking.nExtensions_option) {
    struct dot3ShortMsgNextensions *exts = &(wsm_msg->subtype.u.nullNetworking.nExtensions);
    ret = dot3_ffasn1c_ParseWSMPNHdrExtensions(exts, params);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * TPID 필수필드를 파싱한다.
   */
  if (wsm_msg->transport.choice != dot3ShortMsgTpdus_bcMode) {
    Err("Fail to parse WSMP-N-Header - invalid TPID: %d\n", wsm_msg->transport.choice);
    return -kDot3Result_InvalidWSMPNHeaderTPID;
  }

  Log(kDot3LogLevel_Event, "Success to parse WSMP-N-Header - chan: %d, datarate: %d, power: %d\n",
      params->chan_num, params->datarate, params->transmit_power);
  return kDot3Result_Success;
}


/**
 * @brief 디코딩된 WSMP-T-Header 정보구조체에서 PSID, 페이로드길이(=WSM body length) 정보를 파싱하여 반환한다.
 * @param[in] wsm_msg 파싱할 WSMP-T-Header 정보구조체의 주소를 전달한다.
 * @param[out] params 파싱된 PSID 정보가 저장될 정보구조체의 주소를 전달한다.
 * @retval 0 이상: 파싱된 페이로드의 길이
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * 현재 버전의 1609.3 표준(2016)에서 \n
 *  - TPID=0일 때 WSM-T-Header 는 PSID 와 WSM Length 필드를 가진다. \n
 *  - TPID=1일 때 WSM-T-Header 는 확장필드를 가진다고 되어 있으나, 현재 정의되어 있는 확장필드는 없다.
 */
static int dot3_ffasn1c_ParseWSMPTHdr(const struct dot3ShortMsgNpdu *wsm_msg, struct Dot3WSMParseParams *params)
{
  Log(kDot3LogLevel_Event, "Parse WSMP-T-header\n");

  /*
   * PSID 파싱
   */
  int ret = dot3_ffasn1c_ParseVarLengthNumber(&wsm_msg->transport.u.bcMode.destAddress);
  if (ret < 0) {
    return ret;
  }
  if (dot3_IsValidPSID((Dot3PSID)ret) == false) {
    Err("Fail to parse WSMP-T-Header - invalid PSID %d\n", ret);
    return -kDot3Result_InvalidPSID;
  }
  params->psid = (Dot3PSID)ret;

  /*
   * 페이로드길이 파싱
   *  - 허용길이를 초과하면 에러를 반환한다.
   */
  int payload_size = (int)wsm_msg->body.len;
  if (payload_size > kDot3WSMPayloadSize_Max) {
    Err("Fail to parse WSMP-T-Header - too long payload %u > %u\n", payload_size, kDot3WSMPayloadSize_Max);
    return -kDot3Result_InvalidWSMPayloadSize;
  }

  Log(kDot3LogLevel_Event, "Success to parse WSM-T-Header - psid: %u, payload_size: %u\n", params->psid, payload_size);
  return payload_size;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 WSM을 UPER 디코딩한다.
 * @param[in] wsm 파싱할 WSM이 저장된 버퍼
 * @param[in] wsm_size wsm 버퍼에 담긴 WSM의 크기
 * @param[out] payload_size 반환되는 페이로드의 길이가 저장될 변수의 포인터
 * @param[out] params WSMP 헤더정보가 저장될 구조체의 포인터
 * @param[out] ret 처리결과코드(Dot3ResultCode)가 반환될 변수 포인터
 * @retval WSM body에 수납되어 있는 페이로드: 성공
 * @retval NULL: WSM body가 비어 있는 경우 또는 실패
 */
uint8_t INTERNAL * dot3_ffasn1c_DecodeWSM(
  const uint8_t *wsm,
  Dot3WSMSize wsm_size,
  size_t *payload_size,
  struct Dot3WSMParseParams *params,
  int *ret)
{
  struct dot3ShortMsgNpdu *wsm_msg = NULL;
  Log(kDot3LogLevel_Event, "Decode WSM\n");

  /*
   * WSM 디코딩
   */
  ASN1Error asn1_err;
  asn1_ssize_t decoded_size = asn1_uper_decode((void **)&wsm_msg, asn1_type_dot3ShortMsgNpdu, wsm, wsm_size, &asn1_err);
  if ((decoded_size < 0) || (wsm_msg == NULL)) {
    Err("Fail to decode WSM - fail to asn1_uper_decode() - decoded_size %d\n", decoded_size);
    *ret = -kDot3Result_Asn1Decode;
    return NULL;
  }

  /*
   * WSM-N-Header 필드의 정보를 파싱하여 반환정보에 저장한다.
   */
  *ret = dot3_ffasn1c_ParseWSMPNHdr(wsm_msg, params);
  if (*ret < 0) {
    asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);
    return NULL;
  }

  /*
   * WSM-T-Header 필드의 정보를 파싱하여 반환정보에 저장한다.
   */
  *ret = dot3_ffasn1c_ParseWSMPTHdr(wsm_msg, params);
  if (*ret < 0) {
    asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);
    return NULL;
  }
  *payload_size = (size_t)(*ret);

  /*
   * WSM body를 파싱하여 반환정보에 저장한다.
   */
  uint8_t *payload = NULL;
  if (*payload_size) {
    payload = calloc(1, *payload_size);
    if (payload == NULL) {
      Err("Fail to decode WSM - calloc() failed\n");
      asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);
      *ret = -kDot3Result_NoMemory;
      return NULL;
    }
    memcpy(payload, wsm_msg->body.buf, *payload_size);
  }

  /*
   * asn.1 정보구조체를 해제한다.
   */
  asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);

  Log(kDot3LogLevel_Event, "Success to decode WSM - payload has %u bytes size\n", *payload_size);
  *ret = kDot3Result_Success;
  return payload;
}
