/**
 * @file
 * @brief ffasn1c 라이브러리를 이용하여 WSA 를 인코딩하는 기능을 구현한 파일
 * @date 2019-08-17
 * @author gyun
 */

// 시스템 헤더 파일
#include <pthread.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-ffasn1c.h"
#include "dot3-internal.h"


const int kSrvAdvMsgVersionNo = 3; ///< WSA version = 3


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보구조체 내 헤더의 필수필드를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] wsa_msg 정보를 채울 정보구조체의 포인터
 */
static void dot3_ffasn1c_FillWSAHdrMandatory(const struct Dot3ConstructWSAParams *params, struct dot3SrvAdvMsg *wsa_msg)
{
  Log(kDot3LogLevel_Event, "Fill WSA header mandatory fields\n");
  wsa_msg->version.messageID = dot3SrvAdvMessageType_saMessage;
  wsa_msg->version.rsvAdvPrtVersion = kSrvAdvMsgVersionNo;
  wsa_msg->body.changeCount.saID = (dot3SrvAdvID)(params->hdr.wsa_id);
  wsa_msg->body.changeCount.contentCount = (dot3SrvAdvContentCount)(params->hdr.content_count);
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보구조체 내 헤더의 RepeatRate 확장필드를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] ext 확장필드정보를 채울 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSAHdrRepeatRateExtension(
  const struct Dot3ConstructWSAParams *params,
  struct dot3SrvAdvMsgHeaderExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA header RepeatRate extension\n");

  ext->extensionId = kDot3ExtensionID_RepeatRate;
  ext->value.type = (ASN1CType *)asn1_type_dot3RepeatRate;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3RepeatRate);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = (int)(params->hdr.repeat_rate);

  Log(kDot3LogLevel_Event, "Success to fill WSA header RepeatRate extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보구조체 내 헤더의 TwoDLocation 확장필드를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] ext 확장필드정보를 채울 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSAHdrTwoDLocationExtension(
  const struct Dot3ConstructWSAParams *params,
  struct dot3SrvAdvMsgHeaderExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA header TwoDLocation extension\n");

  ext->extensionId = kDot3ExtensionID_2DLocation;
  ext->value.type = (ASN1CType *)asn1_type_dot3TwoDLocation;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3TwoDLocation);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  struct dot3TwoDLocation *location = (struct dot3TwoDLocation *)(ext->value.u.data);
  location->latitude.fill.len = 1;
  location->latitude.fill.buf = asn1_mallocz(1);
  if (location->latitude.fill.buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(location->latitude.fill.buf) = 0 << 7;
  location->latitude.lat = params->hdr.twod_location.latitude;
  location->longitude = params->hdr.twod_location.longitude;

  Log(kDot3LogLevel_Event, "Success to fill WSA header TwoDLocation extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보구조체 내 헤더의 ThreeDLocation 확장필드를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] ext 확장필드정보를 채울 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSAHdrThreeDLocationExtension(
  const struct Dot3ConstructWSAParams *params,
  struct dot3SrvAdvMsgHeaderExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA header ThreeDLocation extension\n");

  ext->extensionId = kDot3ExtensionID_3DLocation;
  ext->value.type = (ASN1CType *)asn1_type_dot3ThreeDLocation;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3ThreeDLocation);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  struct dot3ThreeDLocation *location = (struct dot3ThreeDLocation *)(ext->value.u.data);

  location->latitude.fill.len = 1;
  location->latitude.fill.buf = asn1_mallocz(1);
  if (location->latitude.fill.buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(location->latitude.fill.buf) = 0 << 7;
  location->latitude.lat = params->hdr.threed_location.latitude;
  location->longitude = params->hdr.threed_location.longitude;
  location->elevation = params->hdr.threed_location.elevation;

  Log(kDot3LogLevel_Event, "Success to fill WSA header ThreeDLocation extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보구조체 내 헤더의 AdvertiserId 확장필드를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] ext 확장필드정보를 채울 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSAHdrAdvertiserIDExtension(
  const struct Dot3ConstructWSAParams *params,
  struct dot3SrvAdvMsgHeaderExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA header AdvertiserId extension\n");

  ext->extensionId = kDot3ExtensionID_AdvertiserID;
  ext->value.type = (ASN1CType *)asn1_type_dot3AdvertiserIdentifier;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3AdvertiserIdentifier);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  struct ASN1String *adv_id = (struct ASN1String *)(ext->value.u.data);
  adv_id->len = params->hdr.advertiser_id.len;
  adv_id->buf = asn1_mallocz(adv_id->len);
  if (adv_id->buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(adv_id->buf, params->hdr.advertiser_id.id, adv_id->len);

  Log(kDot3LogLevel_Event, "Success to fill WSA header AdvertiserId extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보구조체 내 헤더의 확장필드들을 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] wsa_msg 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSAHdrExtensions(const struct Dot3ConstructWSAParams *params, struct dot3SrvAdvMsg *wsa_msg)
{
  Log(kDot3LogLevel_Event, "Fill WSA header extensions\n");

  /*
   * 확장필드 저장 메모리를 할당한다.
   */
  wsa_msg->body.extensions_option = true;
  wsa_msg->body.extensions.tab = (struct dot3SrvAdvMsgHeaderExt *)asn1_mallocz(
    (size_t)asn1_get_size(asn1_type_dot3SrvAdvMsgHeaderExt) * wsa_msg->body.extensions.count);
  if (wsa_msg->body.extensions.tab == NULL) {
    return -kDot3Result_NoMemory;
  }
  uint8_t *ptr = (uint8_t *)(wsa_msg->body.extensions.tab);

  /*
   * 각 확장필드 정보를 채운다.
   *  RepeatRate, TwoDLocation, ThreeDLocation, AdvertiserId
   */
  int ret;
  if (params->hdr.extensions.repeat_rate == true) {
    struct dot3SrvAdvMsgHeaderExt *ext = (struct dot3SrvAdvMsgHeaderExt *)ptr;
    ret = dot3_ffasn1c_FillWSAHdrRepeatRateExtension(params, ext);
    if (ret < 0) {
      return ret;
    }
    ptr += asn1_get_size(asn1_type_dot3SrvAdvMsgHeaderExt);
  }
  if (params->hdr.extensions.twod_location == true) {
    struct dot3SrvAdvMsgHeaderExt *ext = (struct dot3SrvAdvMsgHeaderExt *)ptr;
    ret = dot3_ffasn1c_FillWSAHdrTwoDLocationExtension(params, ext);
    if (ret < 0) {
      return ret;
    }
    ptr += asn1_get_size(asn1_type_dot3SrvAdvMsgHeaderExt);
  }
  if (params->hdr.extensions.threed_location == true) {
    struct dot3SrvAdvMsgHeaderExt *ext = (struct dot3SrvAdvMsgHeaderExt *)ptr;
    ret = dot3_ffasn1c_FillWSAHdrThreeDLocationExtension(params, ext);
    if (ret < 0) {
      return ret;
    }
    ptr += asn1_get_size(asn1_type_dot3SrvAdvMsgHeaderExt);
  }
  if (params->hdr.extensions.advertiser_id == true) {
    struct dot3SrvAdvMsgHeaderExt *ext = (struct dot3SrvAdvMsgHeaderExt *)ptr;
    ret = dot3_ffasn1c_FillWSAHdrAdvertiserIDExtension(params, ext);
    if (ret < 0) {
      return ret;
    }
  }
  Log(kDot3LogLevel_Event, "Success to fill WSA header extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보구조체 내 헤더의 정보를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] wsa_msg 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSAHdr(const struct Dot3ConstructWSAParams *params, struct dot3SrvAdvMsg *wsa_msg)
{
  Log(kDot3LogLevel_Event, "Fill WSA header\n");
  int ret;

  /*
   * 필수필드를 채운다.
   */
  dot3_ffasn1c_FillWSAHdrMandatory(params, wsa_msg);

  /*
   * (존재하는 경우) 확장필드를 채운다.
   */
  size_t count = 0;
  if (params->hdr.extensions.repeat_rate) {
    count++;
  }
  if (params->hdr.extensions.twod_location) {
    count++;
  }
  if (params->hdr.extensions.threed_location) {
    count++;
  }
  if (params->hdr.extensions.advertiser_id) {
    count++;
  }
  if (count) {
    wsa_msg->body.extensions_option = true;
    wsa_msg->body.extensions.count = count;
    ret = dot3_ffasn1c_FillWSAHdrExtensions(params, wsa_msg);
    if (ret < 0) {
      return ret;
    }
  } else {
    wsa_msg->body.extensions.count = 0;
    wsa_msg->body.extensions_option = false;
  }

  Log(kDot3LogLevel_Event, "Success to fill WSA header\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 필수필드를 채운다.
 * @param[in] entry PSR 정보 테이블 엔트리
 * @param[out] wsi 정보를 채울 service info 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSIMandatory(const struct Dot3PSRTableEntry *entry, struct dot3ServiceInfo *wsi)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info mandatory fields\n");

  /*
   * PSID 필수필드를 채운다.
   */
  int ret = dot3_ffasn1c_FillVarLengthNumber(entry->psr.psid, &(wsi->serviceID));
  if (ret < 0) {
    return ret;
  }

  /*
   * Channel Index 필수필드는 나중에 채워진다.
   */

  Log(kDot3LogLevel_Event, "Success to fill WSA service info mandatory fields\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 PSC 확장필드를 채운다.
 * @param[in] psc PSC
 * @param[out] ext 정보를 채울 service info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSIPSCExtension(struct Dot3PSC *psc, struct dot3ServiceInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info Psc extension\n");

  ext->extensionId = kDot3ExtensionID_PSC;
  ext->value.type = (ASN1CType *)asn1_type_dot3ProviderServiceContext;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3ProviderServiceContext);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  struct dot3ProviderServiceContext *psc_to_fill = (struct dot3ProviderServiceContext *)ext->value.u.data;
  psc_to_fill->fillBit.len = 3;
  psc_to_fill->fillBit.buf = asn1_mallocz(psc_to_fill->fillBit.len);
  if (psc_to_fill->fillBit.buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(psc_to_fill->fillBit.buf) = (0 << 7) | (0 << 6) | (0 << 5);
  psc_to_fill->psc.len = psc->len;
  psc_to_fill->psc.buf = asn1_mallocz(psc->len);
  if (psc_to_fill->psc.buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(psc_to_fill->psc.buf, psc->psc, psc->len);

  Log(kDot3LogLevel_Event, "Success to fill WSA service info Psc extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 IPv6Address 확장필드를 채운다.
 * @param[in] ipv6_address IPv6Address
 * @param[out] ext 정보를 채울 service info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSIIPv6AddressExtension(Dot3IPv6Address ipv6_address, struct dot3ServiceInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info IPv6Address extension\n");

  ext->extensionId = kDot3ExtensionID_IPv6Address;
  ext->value.type = (ASN1CType *)asn1_type_dot3IPv6Address;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3IPv6Address);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  ASN1String *addr = (struct ASN1String *)ext->value.u.data;
  addr->len = IPv6_ALEN;
  addr->buf = asn1_mallocz(IPv6_ALEN);
  if (addr->buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(addr->buf, ipv6_address, IPv6_ALEN);
  Log(kDot3LogLevel_Event, "Success to fill WSA service info IPv6Address extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 ServicePort 확장필드를 채운다.
 * @param[in] service_port ServicePort
 * @param[out] ext 정보를 채울 service info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSIServicePortExtension(uint16_t service_port, struct dot3ServiceInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info ServicePort extension\n");

  ext->extensionId = kDot3ExtensionID_ServicePort;
  ext->value.type = (ASN1CType *)asn1_type_dot3ServicePort;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3ServicePort);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = service_port;

  Log(kDot3LogLevel_Event, "Success to fill WSA service info ServicePort extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 ProviderMacAddress 확장필드를 채운다.
 * @param[in] provider_mac_address ProviderMacAddress
 * @param[out] ext 정보를 채울 service info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int
dot3_ffasn1c_FillWSIProviderMACAddressExtension(Dot3MACAddress provider_mac_address, struct dot3ServiceInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info ProviderMacAddress extension\n");

  ext->extensionId = kDot3ExtensionID_ProviderMACAddress;
  ext->value.type = (ASN1CType *)asn1_type_dot3ProviderMacAddress;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3ProviderMacAddress);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  ASN1String *addr = (struct ASN1String *)ext->value.u.data;
  addr->len = MAC_ALEN;
  addr->buf = asn1_mallocz(MAC_ALEN);
  if (addr->buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(addr->buf, provider_mac_address, MAC_ALEN);

  Log(kDot3LogLevel_Event, "Success to fill WSA service info ProviderMacAddress extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 RcpiThreshold 확장필드를 채운다.
 * @param[in] rcpi_threshold RcpiThreshold
 * @param[out] ext 정보를 채울 service info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSIRCPIThresholdExtension(Dot3RCPI rcpi_threshold, struct dot3ServiceInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info RcpiThreshold extension\n");

  ext->extensionId = kDot3ExtensionID_RCPIThreshold;
  ext->value.type = (ASN1CType *)asn1_type_dot3RcpiThreshold;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3RcpiThreshold);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = (int)(rcpi_threshold);

  Log(kDot3LogLevel_Event, "Success to fill WSA service info RcpiThreshold extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 WsaCntThreshold 확장필드를 채운다.
 * @param[in] wsa_cnt_threshold WsaCntThreshold
 * @param[out] ext 정보를 채울 service info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int
dot3_ffasn1c_FillWSIWSACntThresholdExtension(Dot3WSACountThreshold wsa_cnt_threshold, struct dot3ServiceInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info WsaCntThreshold extension\n");

  ext->extensionId = kDot3ExtensionID_WSACountThreshold;
  ext->value.type = (ASN1CType *)asn1_type_dot3WsaCountThreshold;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3WsaCountThreshold);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = (int)wsa_cnt_threshold;

  Log(kDot3LogLevel_Event, "Success to fill WSA service info WsaCntThreshold extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 WsaCntThresholdInterval 확장필드를 채운다.
 * @param[in] wsa_cnt_threshold_interval WsaCntThresholdInterval
 * @param[out] ext 정보를 채울 service info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSIWSACntThresholdIntervalExtension(
  Dot3WSACountThreshold wsa_cnt_threshold_interval,
  struct dot3ServiceInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info WsaCntThresholdInterval extension\n");

  ext->extensionId = kDot3ExtensionID_WSACountThresholdInterval;
  ext->value.type = (ASN1CType *)asn1_type_dot3WsaCountThresholdInterval;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3WsaCountThresholdInterval);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = (int)wsa_cnt_threshold_interval;

  Log(kDot3LogLevel_Event, "Success to fill WSA service info WsaCntThresholdInterval extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Service info instance 의 확장필드들을 채운다.
 * @param[in] entry PSR 정보 테이블 엔트리
 * @param[out] wsi 정보를 채울 service info 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSIExtensions(struct Dot3PSRTableEntry *entry, struct dot3ServiceInfo *wsi)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info extensions\n");

  wsi->chOptions.extensions_option = true;
  struct dot3ServiceInfoExts *exts = &(wsi->chOptions.extensions);
  exts->count = entry->option_cnt;

  /*
   * 확장필드를 채우기 위한 메모리 할당.
   */
  exts->tab = (struct dot3ServiceInfoExt *)asn1_mallocz(sizeof(struct dot3ServiceInfoExt) * exts->count);
  if (exts->tab == NULL) {
    return -kDot3Result_NoMemory;
  }

  /*
   * 각 확장필드를 채운다.
   *  - Psc, Ipv6Address, ServicePort, ProviderMacAddress, RcpiThreshold, WsaCountThreshold, WsaCountThresholdInterval
   */
  int cnt = 0, ret;
  if (entry->psr.present.psc == true) {
    struct dot3ServiceInfoExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWSIPSCExtension(&entry->psr.psc, ext);
    if (ret < 0) {
      return ret;
    }
  }
  if (entry->psr.ip_service == true) {
    struct dot3ServiceInfoExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWSIIPv6AddressExtension(entry->psr.ipv6_address, ext);
    if (ret < 0) {
      return ret;
    }
    ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWSIServicePortExtension(entry->psr.service_port, ext);
    if (ret < 0) {
      return ret;
    }
  }
  if (entry->psr.present.provider_mac_addr == true) {
    struct dot3ServiceInfoExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWSIProviderMACAddressExtension(entry->psr.provider_mac_addr, ext);
    if (ret < 0) {
      return ret;
    }
  }
  if (entry->psr.present.rcpi_threshold == true) {
    struct dot3ServiceInfoExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWSIRCPIThresholdExtension(entry->psr.rcpi_threshold, ext);
    if (ret < 0) {
      return ret;
    }
  }
  if (entry->psr.present.wsa_cnt_threshold == true) {
    struct dot3ServiceInfoExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWSIWSACntThresholdExtension(entry->psr.wsa_cnt_threshold, ext);
    if (ret < 0) {
      return ret;
    }
  }
  if (entry->psr.present.wsa_cnt_threshold_interval == true) {
    struct dot3ServiceInfoExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWSIWSACntThresholdIntervalExtension(entry->psr.wsa_cnt_threshold_interval, ext);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to fill WSA service info extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 하나의 Service info instance 의 내용을 추가한다.
 * @param[in] entry PSR 정보 테이블 엔트리
 * @param[out] wsi 정보를 채울 service info 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_AddWSIInstance(struct Dot3PSRTableEntry *entry, struct dot3ServiceInfo *wsi)
{
  Log(kDot3LogLevel_Event, "Add WSA service info instance for psid %u\n", entry->psr.psid);
  int ret;

  /*
   * 필수필드를 채운다.
   */
  ret = dot3_ffasn1c_FillWSIMandatory(entry, wsi);
  if (ret < 0) {
    return ret;
  }

  /*
   * 확장 필드를 채운다.
   */
  if (entry->option_cnt) {
    ret = dot3_ffasn1c_FillWSIExtensions(entry, wsi);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to add WSA service info instance\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체 내에 수납되어 있는 Channel info 중 특정 채널을 갖는 channel info 의 index를 반환한다.
 * @param[in] infos WSA asn.1 정보구조체의 Channel info 들의 리스트 포인터
 * @param[in] info_count 현재 WSA asn.1 정보구조체에 저장되어 있는 Channel info 의 수
 * @param[in] chan_num 찾고자 하는 채널번호
 * @retval 1 이상: Channel info 의 인덱스(표준에 따라 1번부터 시작)
 * @retval 0: 해당되는 정보가 없음
 */
static unsigned int dot3_ffasn1c_GetWCIIndexWithChannelNumber(
  struct dot3ChannelInfo *infos,
  unsigned int info_count,
  Dot3ChannelNumber chan_num)
{
  struct dot3ChannelInfo *cinfo = NULL;
  unsigned int count = (info_count > kDot3WCINum_Max) ? kDot3WCINum_Max : info_count;
  for (unsigned int i = 0; i < count; i++) {
    cinfo = (struct dot3ChannelInfo *)(infos + i);
    if (cinfo->channelNumber == (int)chan_num) {
      return i + 1;
    }
  }
  return 0;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 channel info 의 필수필드를 추가한다.
 * @param[in] entry PCI 엔트리 포인터
 * @param[out] wci 정보를 채울 WSA Channel info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWCIMandatory(struct Dot3PCITableEntry *entry, struct dot3ChannelInfo *wci)
{
  Log(kDot3LogLevel_Event, "Fill WSA Channel Info mandatory fields\n");

  const struct Dot3PCI *const pci = &(entry->pci);
  wci->operatingClass = (dot3OperatingClass80211)(pci->operating_class);
  wci->channelNumber = (dot3ChannelNumber80211)(pci->chan_num);
  wci->powerLevel = (dot3TXpower80211)(pci->transmit_power_level);
  wci->dataRate.dataRate = (int)(pci->datarate);
  wci->dataRate.adaptable.len = 1;
  wci->dataRate.adaptable.buf = asn1_mallocz(1);
  if (wci->dataRate.adaptable.buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(wci->dataRate.adaptable.buf) = (uint8_t)((pci->adaptable_datarate) << 7);

  Log(kDot3LogLevel_Event, "Success to fill WSA Channel Info mandatory fields\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Channel info instance 의 EdcaParameterSet 확장필드를 채운다.
 * @param[in] edca_param_set EdcaParameterSet
 * @param[out] ext 정보를 채울 channel info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWCIEDCAParameterSetExtension(
  struct Dot3EDCAParameterSet *edca_param_set,
  struct dot3ChannelInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA channel info EdcaParameterSet extension\n");

  ext->extensionId = kDot3ExtensionID_EDCAParameterSet;
  ext->value.type = (ASN1CType *)asn1_type_dot3EdcaParameterSet;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3EdcaParameterSet);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }

  struct dot3EdcaParameterSet *set = (struct dot3EdcaParameterSet *)(ext->value.u.data);
  set->acbeRecord.aci = (int)(edca_param_set->record[0].aci);
  set->acbeRecord.acm = (int)(edca_param_set->record[0].acm);
  set->acbeRecord.aifsn = (int)(edca_param_set->record[0].aifsn);
  set->acbeRecord.ecwMax = (int)(edca_param_set->record[0].ecwmax);
  set->acbeRecord.ecwMin = (int)(edca_param_set->record[0].ecwmin);
  set->acbeRecord.txopLimit = (int)(edca_param_set->record[0].txoplimit);
  set->acbkRecord.aci = (int)(edca_param_set->record[1].aci);
  set->acbkRecord.acm = (int)(edca_param_set->record[1].acm);
  set->acbkRecord.aifsn = (int)(edca_param_set->record[1].aifsn);
  set->acbkRecord.ecwMax = (int)(edca_param_set->record[1].ecwmax);
  set->acbkRecord.ecwMin = (int)(edca_param_set->record[1].ecwmin);
  set->acbkRecord.txopLimit = (int)(edca_param_set->record[1].txoplimit);
  set->acviRecord.aci = (int)(edca_param_set->record[2].aci);
  set->acviRecord.acm = (int)(edca_param_set->record[2].acm);
  set->acviRecord.aifsn = (int)(edca_param_set->record[2].aifsn);
  set->acviRecord.ecwMax = (int)(edca_param_set->record[2].ecwmax);
  set->acviRecord.ecwMin = (int)(edca_param_set->record[2].ecwmin);
  set->acviRecord.txopLimit = (int)(edca_param_set->record[2].txoplimit);
  set->acvoRecord.aci = (int)(edca_param_set->record[3].aci);
  set->acvoRecord.acm = (int)(edca_param_set->record[3].acm);
  set->acvoRecord.aifsn = (int)(edca_param_set->record[3].aifsn);
  set->acvoRecord.ecwMax = (int)(edca_param_set->record[3].ecwmax);
  set->acvoRecord.ecwMin = (int)(edca_param_set->record[3].ecwmin);
  set->acvoRecord.txopLimit = (int)(edca_param_set->record[3].txoplimit);

  Log(kDot3LogLevel_Event, "Success to fill WSA channel info EdcaParameterSet extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Channel info instance 의 ChannelAccess 확장필드를 채운다.
 * @param[in] chan_access ChannelAccess
 * @param[out] ext 정보를 채울 channel info 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWCIChannelAccess(Dot3ProviderChannelAccess chan_access, struct dot3ChannelInfoExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WSA channel info ChannelAccess extension\n");

  ext->extensionId = kDot3ExtensionID_ChannelAccess;
  ext->value.type = (ASN1CType *)asn1_type_dot3ChannelAccess80211;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3ChannelAccess80211);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  *(int *)(ext->value.u.data) = (int)chan_access;
  Log(kDot3LogLevel_Event, "Success to fill WSA channel info ChannelAccess extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 Channel info instance 의 확장필드들을 채운다.
 * @param[in] entry PCI(Provider Channel Info) 엔트리 (채울 정보)
 * @param[out] wci 정보를 채울 WSA Channel info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWCIExtensions(struct Dot3PCITableEntry *entry, struct dot3ChannelInfo *wci)
{
  Log(kDot3LogLevel_Event, "Fill WSA channel info extensions\n");

  wci->extensions.extensions_option = true;
  struct dot3ChannelInfoExts *exts = &(wci->extensions.extensions);
  exts->count = entry->option_cnt;

  /*
   * 확장필드를 채우기 위한 메모리 할당.
   */
  exts->tab = (struct dot3ChannelInfoExt *)asn1_mallocz(sizeof(struct dot3ChannelInfoExt) * exts->count);
  if (exts->tab == NULL) {
    return -kDot3Result_NoMemory;
  }

  /*
   * 각 확장필드를 채운다.
   *  - EDCA Parameter Set, Channel access
   */
  int cnt = 0, ret;
  if (entry->pci.present.chan_access == true) {
    struct dot3ChannelInfoExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWCIChannelAccess(entry->pci.chan_access, ext);
    if (ret < 0) {
      return ret;
    }
  }
  if (entry->pci.present.edca_param_set == true) {
    struct dot3ChannelInfoExt *ext = exts->tab + cnt;
    ret = dot3_ffasn1c_FillWCIEDCAParameterSetExtension(&(entry->pci.edca_param_set), ext);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to fill WSA channel info extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 하나의 Channel info instance 를 추가한다.
 * @param[in] psr_entry PSR 엔트리
 * @param[out] wci 추가할 Channel info instance 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_AddWCIInstance(struct Dot3PSRTableEntry *psr_entry, struct dot3ChannelInfo *wci)
{
  Log(kDot3LogLevel_Event, "Add WSA channel info instance for channel %d\n", psr_entry->psr.service_chan_num);

  struct Dot3PCITableEntry *pci_entry = psr_entry->pci_entry;
  if (pci_entry == NULL) {
    Err("Fail to add WSA channel info instance - there is no channel info referenced by PSR\n");
    return -kDot3Result_NoRelatedChannelInfo;
  }

  int ret;

  /*
   * 필수필드를 채운다.
   */
  ret = dot3_ffasn1c_FillWCIMandatory(pci_entry, wci);
  if (ret < 0) {
    return ret;
  }

  /*
   * 확장필드를 채운다.
   */
  if (pci_entry->option_cnt) {
    ret = dot3_ffasn1c_FillWCIExtensions(pci_entry, wci);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to add WSA channel info instance\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 WSA Service info segment 와 Channel info segment 정보를 채운다.
 * @param[in] pinfo provider info MIB
 * @param[in] params WSA 생성 정보
 * @param[out] wsa_msg 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWSAServiceInfoSegmentAndChannelInfoSegment(
  struct Dot3ProviderInfo *pinfo,
  const struct Dot3ConstructWSAParams *params,
  struct dot3SrvAdvMsg *wsa_msg)
{
  Log(kDot3LogLevel_Event, "Fill WSA service info segment and channel info segment\n");

  /*
   * 일단 PSR 개수 또는 WSA 최대수납가능수 만큼의 Service Info, Channel Info 메모리를 할당한다.
   */
  unsigned int max_num = (pinfo->psr_table.num > kDot3WSINum_Max) ? kDot3WSINum_Max:pinfo->psr_table.num;
  wsa_msg->body.serviceInfos.tab = (struct dot3ServiceInfo *)asn1_mallocz(
    (size_t)asn1_get_size(asn1_type_dot3ServiceInfo) * max_num);
  if (wsa_msg->body.serviceInfos.tab == NULL) {
    return -kDot3Result_NoMemory;
  }
  wsa_msg->body.channelInfos.tab = (struct dot3ChannelInfo *)asn1_mallocz(
    (size_t)asn1_get_size(asn1_type_dot3ChannelInfo) * max_num);
  if (wsa_msg->body.channelInfos.tab == NULL) {
    return -kDot3Result_NoMemory;
  }

  /*
   * PSR 테이블을 탐색하며 wsa_id 가 동일한 PSR에 대한 정보를 WSA 정보구조체에 채운다.
   *  WSA 정보구조체 내에 Service Info 를 추가한다.
   *  WSA 정보구조체 내에 Channel Info 를 추가한다.
   */
  struct Dot3PSRTableEntry *psr_entry;
  struct dot3ServiceInfo *service_info_instance;
  int ret;
  unsigned int service_info_cnt = 0, chan_info_cnt = 0;
  TAILQ_FOREACH(psr_entry, &(pinfo->psr_table.head), entries)
  {
    if (psr_entry->psr.wsa_id != params->hdr.wsa_id) {
      continue;
    }

    // Service info instance 의 주요필드 및 옵션필드를 채운다.
    service_info_instance = (struct dot3ServiceInfo *)(wsa_msg->body.serviceInfos.tab + service_info_cnt);
    ret = dot3_ffasn1c_AddWSIInstance(psr_entry, service_info_instance);
    if (ret < 0) {
      return ret;
    }
    service_info_cnt++;

    // PSR의 채널번호와 동일한 channel info instance 가 이미 채워져 있는지 확인하여,
    //  - 채워져 있는 경우(!0), 해당 channel info instance 의 index 를 service info instance 의 channel index 값으로 설정한다.
    //  - 채워져 있지 않은 경우(0), 새로운 channel info instance 를 추가하고, service info instance 의 channel index 값을 설정한다.
    unsigned int chan_index = dot3_ffasn1c_GetWCIIndexWithChannelNumber(wsa_msg->body.channelInfos.tab,
                                                                        chan_info_cnt,
                                                                        psr_entry->psr.service_chan_num);
    if (chan_index) {
      service_info_instance->channelIndex = (int)chan_index;
    } else {
      ret = dot3_ffasn1c_AddWCIInstance(psr_entry, (wsa_msg->body.channelInfos.tab + chan_info_cnt));
      if (ret < 0) {
        return ret;
      }
      chan_info_cnt++;
      service_info_instance->channelIndex = (int)chan_info_cnt;
    }

    // 각 instance 가 WSA 에 실을 수 있는 개수를 초과하면 중단한다.
    if ((service_info_cnt >= kDot3WSINum_Max) || (chan_info_cnt >= kDot3WCINum_Max)) {
      break;
    }
  }

  if (service_info_cnt) {
    wsa_msg->body.serviceInfos_option = true;
    wsa_msg->body.serviceInfos.count = (size_t)service_info_cnt;
  }
  if (chan_info_cnt) {
    wsa_msg->body.channelInfos_option = true;
    wsa_msg->body.channelInfos.count = (size_t)chan_info_cnt;
  }

  Log(kDot3LogLevel_Event, "Success to fill WSA %d service info segment and %d channel info segment\n",
      wsa_msg->body.serviceInfos.count, wsa_msg->body.channelInfos.count);
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 WRA 의 필수필드를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] wra 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWRAMandatory(const struct Dot3ConstructWSAParams *params, struct dot3RoutingAdvertisement *wra)
{
  Log(kDot3LogLevel_Event, "Fill WRA mandatory fields\n");

  wra->lifetime = (dot3RouterLifetime)(params->wra.router_lifetime);
  wra->ipPrefix.len = IPv6_ALEN;
  wra->ipPrefix.buf = asn1_mallocz(IPv6_ALEN);
  if (wra->ipPrefix.buf == NULL) {
    return -kDot3Result_NoMemory;
  }

  memcpy(wra->ipPrefix.buf, params->wra.ip_prefix, IPv6_ALEN);
  wra->ipPrefixLength = (dot3IpV6PrefixLength)(params->wra.ip_prefix_len);
  wra->defaultGateway.len = IPv6_ALEN;
  wra->defaultGateway.buf = asn1_mallocz(IPv6_ALEN);
  if (wra->defaultGateway.buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(wra->defaultGateway.buf, params->wra.default_gw, IPv6_ALEN);
  wra->primaryDns.len = IPv6_ALEN;
  wra->primaryDns.buf = asn1_mallocz(IPv6_ALEN);
  if (wra->primaryDns.buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(wra->primaryDns.buf, params->wra.primary_dns, IPv6_ALEN);

  Log(kDot3LogLevel_Event, "Success to fill WRA mandatory field\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 WRA 의 Secondary DNS 확장필드를 채운다.
 * @param[in] secondary_dns Secondary DNS
 * @param[out] ext 정보를 채울 WRA 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWRASecondaryDNSExtension(const Dot3IPv6Address secondary_dns, struct dot3RoutAdvertExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WRA SecondaryDns extension\n");

  ext->extensionId = kDot3ExtensionID_SecondaryDNS;
  ext->value.type = (ASN1CType *)asn1_type_dot3SecondaryDns;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3SecondaryDns);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }

  ASN1String *addr = (struct ASN1String *)(ext->value.u.data);
  addr->len = IPv6_ALEN;
  addr->buf = asn1_mallocz(IPv6_ALEN);
  if (addr->buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(addr->buf, secondary_dns, IPv6_ALEN);
  Log(kDot3LogLevel_Event, "Success to fill WRA SecondaryDns extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 WRA 의 GatewayMacAddress 확장필드를 채운다.
 * @param[in] gw_mac_addr GatewayMacAddress
 * @param[out] ext 정보를 채울 WRA 확장필드 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWRAGatewayMACAddressExtension(const Dot3MACAddress gw_mac_addr, struct dot3RoutAdvertExt *ext)
{
  Log(kDot3LogLevel_Event, "Fill WRA GatewayMacAddress extension\n");

  ext->extensionId = kDot3ExtensionID_GatewayMACAddress;
  ext->value.type = (ASN1CType *)asn1_type_dot3GatewayMacAddress;
  ext->value.u.data = asn1_mallocz_value(asn1_type_dot3GatewayMacAddress);
  if (ext->value.u.data == NULL) {
    return -kDot3Result_NoMemory;
  }
  ASN1String *addr = (struct ASN1String *)(ext->value.u.data);
  addr->len = MAC_ALEN;
  addr->buf = asn1_mallocz(MAC_ALEN);
  if (addr->buf == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(addr->buf, gw_mac_addr, MAC_ALEN);
  Log(kDot3LogLevel_Event, "Success to fill WRA GatewayMacAddress extension\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 WRA 의 확장필드들을 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] wra 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int
dot3_ffasn1c_FillWRAExtensions(const struct Dot3ConstructWSAParams *params, struct dot3RoutingAdvertisement *wra)
{
  Log(kDot3LogLevel_Event, "Fill WRA extensions\n");

  struct dot3RoutAdvertExts *exts = &(wra->extensions);
  exts->count = 0;
  if (params->wra.present.secondary_dns) {
    exts->count++;
  }
  if (params->wra.present.gateway_mac_addr) {
    exts->count++;
  }

  /*
   * 확장필드를 채우기 위한 메모리를 할당한다.
   */
  exts->tab = (struct dot3RoutAdvertExt *)asn1_mallocz((size_t)asn1_get_size(asn1_type_dot3RoutAdvertExt) * exts->count);
  if (exts->tab == NULL) {
    return -kDot3Result_NoMemory;
  }

  /*
   * 각 확장필드를 채운다.
   *  - Secondary DNS, Gateway Mac Address
   */
  int cnt = 0, ret;
  if (params->wra.present.secondary_dns == true) {
    struct dot3RoutAdvertExt *ext = exts->tab + cnt++;
    ret = dot3_ffasn1c_FillWRASecondaryDNSExtension(params->wra.secondary_dns, ext);
    if (ret < 0) {
      return ret;
    }
  }
  if (params->wra.present.gateway_mac_addr == true) {
    struct dot3RoutAdvertExt *ext = exts->tab + cnt;
    ret = dot3_ffasn1c_FillWRAGatewayMACAddressExtension(params->wra.gateway_mac_addr, ext);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to fill WRA extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief uper 인코딩을 위해 WSA asn.1 정보 구조체 내 WRA 를 채운다.
 * @param[in] params WSA 생성 정보
 * @param[out] wsa_msg 정보를 채울 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_FillWRA(const struct Dot3ConstructWSAParams *params, struct dot3SrvAdvMsg *wsa_msg)
{
  Log(kDot3LogLevel_Event, "Fill WRA\n");

  int ret;
  wsa_msg->body.routingAdvertisement_option = true;

  /*
   * 필수필드를 채운다.
   */
  ret = dot3_ffasn1c_FillWRAMandatory(params, &wsa_msg->body.routingAdvertisement);
  if (ret < 0) {
    return ret;
  }

  /*
   * 확장필드를 채운다.
   */
  if (params->present.wra == true) {
    ret = dot3_ffasn1c_FillWRAExtensions(params, &wsa_msg->body.routingAdvertisement);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to fill WRA\n");
  return kDot3Result_Success;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 WSA 를 인코딩한다.
 * @param[in] params WSA 헤더구성정보
 * @param[out] wsa_size 생성된 WSA의 길이가 반환될 변수의 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수의 포인터
 * @retval 생성된 WSA: 성공
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot3_ffasn1c_EncodeWSA(const struct Dot3ConstructWSAParams *params, size_t *wsa_size, int *err)
{
  Log(kDot3LogLevel_Event, "Encode WSA\n");

  /*
   * 인코딩을 위한 WSA asn.1 정보구조체를 할당하고 초기화한다.
   */
  struct dot3SrvAdvMsg *wsa_msg = (struct dot3SrvAdvMsg *)asn1_mallocz_value(asn1_type_dot3SrvAdvMsg);
  if (!wsa_msg) {
    *err = -kDot3Result_NoMemory;
    return NULL;
  }

  /*
   * WSA asn.1 정보구조체의 헤더를 채운다.
   *  - version, change count, extensions 까지.
   */
  *err = dot3_ffasn1c_FillWSAHdr(params, wsa_msg);
  if (*err < 0) {
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    return NULL;
  }

  /*
   * asn.1 정보 구조체의 Service info segment 와 Channel info segment 를 채운다.
   */
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  *err = dot3_ffasn1c_FillWSAServiceInfoSegmentAndChannelInfoSegment(pinfo, params, wsa_msg);
  pthread_mutex_unlock(&(pinfo->mtx));
  if (*err < 0) {
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    return NULL;
  }

  /*
   * asn.1 정보 구조체의 WRA 필드를 채운다.
   */
  if (params->present.wra == true) {
    *err = dot3_ffasn1c_FillWRA(params, wsa_msg);
    if (*err < 0) {
      asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
      return NULL;
    }
  }

  /*
   * WSA를 인코딩한다.
   */
  uint8_t *buf;
  *wsa_size = (size_t)asn1_uper_encode(&buf, asn1_type_dot3SrvAdvMsg, wsa_msg);
  if (buf == NULL) {
    Err("Fail to encode WSA - fail to asn1_uper_encode()\n");
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    *err = -kDot3Result_Asn1Encode;
    return NULL;
  }

  /*
   * asn.1 정보구조체 메모리를 해제한다.
   */
  asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);

  Log(kDot3LogLevel_Event, "Success to encode %u-bytes WSA\n", *wsa_size);
  return buf;
}
