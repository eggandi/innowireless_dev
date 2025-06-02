/**
 * @file
 * @brief ffasn1c 라이브러리를 이용하여 WSM 을 인코딩하는 기능을 구현한 파일
 * @date 2019-08-02
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


const int kShortMsgVersionNo = 3; ///< WSMP version = 3


/**
 * @brief UPER 인코딩을 위해 asn.1 정보구조체의 WSM-N-Header 필수필드를 채운다.
 * @param[out] wsm_msg 정보를 채울 정보구조체의 포인터
 */
static void dot3_ffasn1c_FillWSMPNHdrMandatory(dot3ShortMsgNpdu *wsm_msg)
{
  Log(kDot3LogLevel_Event, "Fill WSMP-N-header mandatory fields\n");
  wsm_msg->subtype.choice = dot3ShortMsgSubtype_nullNetworking;
  wsm_msg->subtype.u.nullNetworking.version = kShortMsgVersionNo;
}


/**
 * @brief uper 인코딩을 위해 asn.1 정보구조체의 WSM-N-Header ChannelNumber 확장필드를 채운다.
 * @param[in] chan_num 채널번호
 * @param[out] ext 정보를 채울 확장필드 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSMPNHdrChannelNumberExtension(Dot3ChannelNumber chan_num, struct dot3ShortMsgNextension *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSMP-N-header ChannelNumber extension\n");

  ext->extensionId = kDot3ExtensionID_ChannelNumber80211;
  ext->value.type = (ASN1CType *)asn1_type_dot3ChannelNumber80211;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3ChannelNumber80211);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = (int)chan_num;

  Log(kDot3LogLevel_Event, "Success to fill WSMP-N-header ChannelNumber extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 asn.1 정보구조체의 WSM-N-Header DataRate 확장필드를 채운다.
 * @param[in] datarate 데이터레이트
 * @param[out] ext 정보를 채울 확장필드 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSMPNHdrDataRateExtension(Dot3DataRate datarate, struct dot3ShortMsgNextension *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSMP-N-header DataRate extension\n");

  ext->extensionId = kDot3ExtensionID_DataRate80211;
  ext->value.type = (ASN1CType *)asn1_type_dot3DataRate80211;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3DataRate80211);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = (int)datarate;

  Log(kDot3LogLevel_Event, "Success to fill WSMP-N-header DataRate extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 asn.1 정보구조체의 WSM-N-Header TransmitPowerUsed 확장필드를 채운다.
 * @param[in] transmit_power 전송파워
 * @param[out] ext 정보를 채울 확장필드 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int
dot3_ffasn1c_FillWSMPNHdrTransmitPowerUsedExtension(Dot3Power transmit_power, struct dot3ShortMsgNextension *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSMP-N-header TransmitPowerUsed extension\n");

  ext->extensionId = kDot3ExtensionID_TxPowerUsed80211;
  ext->value.type = (ASN1CType *)asn1_type_dot3TXpower80211;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3TXpower80211);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = transmit_power;

  Log(kDot3LogLevel_Event, "Success to fill WSMP-N-header TransmitPowerUsed extension\n");
  return kDot3Result_Success;
}


/**
 * @brief UPER 인코딩을 위해 asn.1 정보구조체의 WSM-N-Header 확장필드들을 채운다.
 * @param[in] params WSM 생성 정보
 * @param[out] exts 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * 표준 상 각 확장필드는 어떤 순서로 추가되어도 상관 없지만, 단위테스트 결과와의 비교를 위해
 * 채널번호, 데이터레이터, 전송파워 순서대로 추가한다.
 */
static int dot3_ffasn1c_FillWSMPNHdrExtensions(
  struct Dot3WSMConstructParams *params, struct dot3ShortMsgNextensions *exts)
{
  Log(kDot3LogLevel_Event, "Fill WSMP-N-header extensions\n");

  /*
   * 확장필드들을 채우기 위한 메모리를 할당한다.
   */
  exts->tab = (dot3ShortMsgNextension *)asn1_mallocz(
    (size_t)asn1_get_size(asn1_type_dot3ShortMsgNextension) * exts->count);
  if (exts->tab == NULL) {
    return -kDot3Result_NoMemory;
  }
  uint8_t *ptr = (uint8_t *)(exts->tab);

  /*
   * 각 확장필드들을 채운다.
   *  - ChannelNumber, DataRate, TransmitPowerUsed
   */
  int ret;
  if (params->chan_num != kDot3ChannelNumber_NA) {
    struct dot3ShortMsgNextension *ext = (struct dot3ShortMsgNextension *)ptr;
    ret = dot3_ffasn1c_FillWSMPNHdrChannelNumberExtension(params->chan_num, ext);
    if (ret < 0) {
      return ret;
    }
    ptr += asn1_get_size(asn1_type_dot3ShortMsgNextension);
  }
  if (params->datarate != kDot3DataRate_NA) {
    struct dot3ShortMsgNextension *ext = (struct dot3ShortMsgNextension *)ptr;
    ret = dot3_ffasn1c_FillWSMPNHdrDataRateExtension(params->datarate, ext);
    if (ret < 0) {
      return ret;
    }
    ptr += asn1_get_size(asn1_type_dot3ShortMsgNextension);
  }
  if (params->transmit_power != kDot3Power_NA) {
    struct dot3ShortMsgNextension *ext = (struct dot3ShortMsgNextension *)ptr;
    ret = dot3_ffasn1c_FillWSMPNHdrTransmitPowerUsedExtension(params->transmit_power, ext);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to fill WSMP-N-header extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief UPER 인코딩을 위해 asn.1 정보구조체의 WSM-N-Header 정보를 채운다.
 * @param[in] params WSM 생성 정보
 * @param[out] wsm_msg 정보를 채울 asn.1 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSMPNHdr(struct Dot3WSMConstructParams *params, dot3ShortMsgNpdu *wsm_msg)
{
  int ret;
  Log(kDot3LogLevel_Event, "Fill WSMP-N-header\n");

  /*
   * 필수필드를 채운다
   */
  dot3_ffasn1c_FillWSMPNHdrMandatory(wsm_msg);

  /*
   * (존재하는 경우) 확장필드를 채운다.
   */
  size_t count = 0;
  if (kDot3ChannelNumber_NA != params->chan_num) {
    count++;
  }
  if (kDot3DataRate_NA != params->datarate) {
    count++;
  }
  if (kDot3Power_NA != params->transmit_power) {
    count++;
  }
  if (count != 0) {
    wsm_msg->subtype.u.nullNetworking.nExtensions_option = true;
    struct dot3ShortMsgNextensions *exts = &(wsm_msg->subtype.u.nullNetworking.nExtensions);
    exts->count = count;
    ret = dot3_ffasn1c_FillWSMPNHdrExtensions(params, exts);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to fill WSM-N-header\n");
  return kDot3Result_Success;
}


/**
 * @brief UPER 인코딩을 위해 asn.1 정보구조체 내의 WSM-T-Header 정보 구조체를 채운다.
 * @param[in] params WSM 생성 정보
 * @param[in] payload_size 페이로드 길이
 * @param[out] wsm_msg 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * 현재 버전의 1609.3 표준(2016)에서 \n
 *  - TPID = 0일 때 WSM-T-Header 는 PSID 와 WSM Length 필드를 가진다. \n
 *  - TPID = 1일 때 WSM-T-Header 는 확장필드를 가진다고 되어 있으나, 현재 정의되어 있는 확장필드는 없다.
 */
static int dot3_ffasn1c_FillWSMPTHdr(
  struct Dot3WSMConstructParams *params,
  Dot3WSMPayloadSize payload_size,
  dot3ShortMsgNpdu *wsm_msg)
{
  int ret;
  Log(kDot3LogLevel_Event, "Fill WSMP-T-header - Psid: %u, WSM length: %u\n", params->psid, payload_size);

  /*
   * 표준 상 TPID 는 엄밀하게는 N 헤더에 포함되어 있지만 구현의 편의성을 위해 본 함수에서 채운다.
   */
  wsm_msg->transport.choice = dot3ShortMsgTpdus_bcMode; // TPID = 0
  wsm_msg->transport.u.bcMode.tExtensions_option = false; // 표준에 따르면, 아직까지는 T-헤더에 확장필드는 없다.

  /*
   * Psid 필드를 채운다.
   */
  ret = dot3_ffasn1c_FillVarLengthNumber(params->psid, &wsm_msg->transport.u.bcMode.destAddress);
  if (ret < 0) {
    return ret;
  }

  /*
   * WSM Length 필드를 채운다.
   */
  wsm_msg->body.len = payload_size;

  Log(kDot3LogLevel_Event, "Success to fill WSMP-T-header\n");
  return kDot3Result_Success;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 WSM 을 UPER 인코딩한다.
 * @param[in] params WSM 헤더구성정보
 * @param[in] payload 상위계층 페이로드
 * @param[in] payload_size 상위계층 페이로드 길이
 * @param[out] wsm_size 생성된 WSM의 길이가 반환될 변수 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @retval 생성된 WSM: 성공
 * @retval NULL: 실패
 *
 * 함수 호출자는 반환된 WSM을 free() 해줘야 한다.
 */
uint8_t INTERNAL * dot3_ffasn1c_EncodeWSM(
  struct Dot3WSMConstructParams *params,
  const uint8_t *payload,
  Dot3WSMPayloadSize payload_size,
  size_t *wsm_size,
  int *err)
{
  Log(kDot3LogLevel_Event, "Encode WSM\n");

  /*
   * 인코딩을 위한 asn.1 정보구조체를 할당하고 초기화한다.
   */
  struct dot3ShortMsgNpdu *wsm_msg = (struct dot3ShortMsgNpdu *)asn1_mallocz_value(asn1_type_dot3ShortMsgNpdu);
  if (wsm_msg == NULL) {
    Err("Fail to encode WSM - fail to asn1_mallocz_value(ShortMsgNpdu)\n");
    *err = -kDot3Result_Asn1Encode;
    return NULL;
  }

  /*
   * asn.1 정보구조체의 WSM-N-Header 필드를 채운다.
   */
  *err = dot3_ffasn1c_FillWSMPNHdr(params, wsm_msg);
  if (*err < 0) {
    asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);
    return NULL;
  }

  /*
   * asn.1 정보구조체의 WSM-T-Header 필드를 채운다.
  */
  *err = dot3_ffasn1c_FillWSMPTHdr(params, payload_size, wsm_msg);
  if (*err < 0) {
    asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);
    return NULL;
  }

  /*
   * asn.1 정보구조체의 body 필드를 채운다.
   *  body 필드의 len 필드는 FFAsn1c_FillWSMPTHeader()에서 이미 채워졌다.
   */
  if ((payload != NULL) && (payload_size > 0)) {
    wsm_msg->body.buf = (uint8_t *)asn1_mallocz(payload_size);
    if (wsm_msg->body.buf == NULL) {
      Err("Fail to encode WSM - fail to asn1_mallocz(payload)\n");
      asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);
      return NULL;
    }
    wsm_msg->body.len = payload_size;
    memcpy(wsm_msg->body.buf, payload, payload_size);
  } else {
    wsm_msg->body.len = 0;
  }

  /*
   * WSM을 인코딩한다.
   */
  uint8_t *buf;
  *wsm_size = (size_t)asn1_uper_encode(&buf, asn1_type_dot3ShortMsgNpdu, wsm_msg);
  if (buf == NULL) {
    Err("Fail to encode WSM - fail to asn1_uper_encode()\n");
    asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);
    *err = -kDot3Result_Asn1Encode;
    return NULL;
  }

  /*
   * asn.1 정보구조체 및 인코딩 버퍼 메모리를 해제한다.
   */
  asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm_msg);

  Log(kDot3LogLevel_Event, "Success to encode %u-bytes WSM\n", *wsm_size);
  return buf;
}
