/**
 * @file
 * @brief ffasn1c 라이브러리를 이용하여 WSA 를 디코딩하는 기능을 구현한 파일
 * @date 2019-08-19
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
 * @brief WSA asn.1 정보구조체로부터 WSA 헤더의 필수필드를 파싱하여 저장한다.
 * @param[in] wsa_msg 디코딩된 WSA asn.1 정보구조체
 * @param[out] hdr 파싱된 헤더 정보가 저장될 구조체 포인터
 */
static void dot3_ffasn1c_ParseWSAHdrMandatory(struct dot3SrvAdvMsg *wsa_msg, struct Dot3WSAHdr *hdr)
{
  Log(kDot3LogLevel_Event, "Parse WSA header mandatory fields\n");
  hdr->msg_id = (Dot3SrvAdvMessageType)(wsa_msg->version.messageID);
  hdr->version = (Dot3WSAVersion)(wsa_msg->version.rsvAdvPrtVersion);
  hdr->wsa_id = (Dot3WSAIdentifier)(wsa_msg->body.changeCount.saID);
  hdr->content_count = (Dot3WSAContentCount)(wsa_msg->body.changeCount.contentCount);
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA 헤더의 RepeatRate 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 RepeatRate extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA 헤더 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSAHdrRepeatRateExtension(void *ext, struct Dot3WSAHdr *hdr)
{
  Log(kDot3LogLevel_Event, "Parse WSA header RepeatRate extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  hdr->repeat_rate = *(uint8_t *)ext;
  hdr->extensions.repeat_rate = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA header RepeatRate extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA 헤더의 2DLocation 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 2DLocation extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA 헤더 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSAHdrTwoDLocationExtension(void *ext, struct Dot3WSAHdr *hdr)
{
  Log(kDot3LogLevel_Event, "Parse WSA header 2DLocation extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  struct dot3TwoDLocation *location = (struct dot3TwoDLocation *)ext;
  hdr->twod_location.latitude = location->latitude.lat;
  hdr->twod_location.longitude = location->longitude;
  hdr->extensions.twod_location = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA header 2DLocation extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA 헤더의 3DLocation 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 3DLocation extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA 헤더 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSAHdrThreeDLocationExtension(void *ext, struct Dot3WSAHdr *hdr)
{
  Log(kDot3LogLevel_Event, "Parse WSA header 3DLocation extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  struct dot3ThreeDLocation *location = (struct dot3ThreeDLocation *)ext;
  hdr->threed_location.latitude = location->latitude.lat;
  hdr->threed_location.longitude = location->longitude;
  hdr->threed_location.elevation = location->elevation;
  hdr->extensions.threed_location = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA header 3DLocation extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA 헤더의 AdvertiserId 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 AdvertiserId extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA 헤더 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSAHdrAdvertiserIdExtension(void *ext, struct Dot3WSAHdr *hdr)
{
  Log(kDot3LogLevel_Event, "Parse WSA header AdvertiserId extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  ASN1String *adv_id = (struct ASN1String *)ext;
  if (adv_id->buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  if ((adv_id->len < kDot3WSAAdvertiserIDLen_Min) ||
      (adv_id->len > kDot3WSAAdvertiserIDLen_Max)) {
    Err("Fail to parse WSA header AdvertiserId extension - invalid length: %zu\n", adv_id->len);
    return -kDot3Result_InvalidAdvertiserIDLen;
  }
  hdr->advertiser_id.len = adv_id->len;
  memcpy(hdr->advertiser_id.id, adv_id->buf, hdr->advertiser_id.len);
  hdr->extensions.advertiser_id = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info AdvertiserId extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA 헤더의 확장필드를 파싱하여 저장한다.
 * @param[in] wsa_msg 디코딩된 WSA asn.1 정보구조체
 * @param[out] hdr 파싱된 헤더 정보가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSAHdrExtensions(struct dot3SrvAdvMsg *wsa_msg, struct Dot3WSAHdr *hdr)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSA header extensions\n");

  struct dot3SrvAdvMsgHeaderExts *exts = &(wsa_msg->body.extensions);
  struct dot3SrvAdvMsgHeaderExt *ext;

  for (size_t j = 0; j < exts->count; j++) {
    ext = exts->tab + j;
    if (ext == NULL) {
      return -kDot3Result_Asn1AbnormalOp;
    }
    switch (ext->extensionId) {
      case kDot3ExtensionID_RepeatRate:
        ret = dot3_ffasn1c_ParseWSAHdrRepeatRateExtension(ext->value.u.data, hdr);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_2DLocation: {
        ret = dot3_ffasn1c_ParseWSAHdrTwoDLocationExtension(ext->value.u.data, hdr);
        if (ret < 0) {
          return ret;
        }
        break;
      }
      case kDot3ExtensionID_3DLocation: {
        ret = dot3_ffasn1c_ParseWSAHdrThreeDLocationExtension(ext->value.u.data, hdr);
        if (ret < 0) {
          return ret;
        }
        break;
      }
      case kDot3ExtensionID_AdvertiserID: {
        ret = dot3_ffasn1c_ParseWSAHdrAdvertiserIdExtension(ext->value.u.data, hdr);
        if (ret < 0) {
          return ret;
        }
        break;
      }
      default:
        Err("Fail to parse WSA header extensions - invalid extension ID: %d\n", ext->extensionId);
        return -kDot3Result_InvalidWSAHdrExtensionID;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA header extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA 헤더를 파싱하여 저장한다.
 * @param[in] wsa_msg 디코딩된 WSA asn.1 정보구조체
 * @param[out] hdr 파싱된 헤더 정보가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSAHdr(struct dot3SrvAdvMsg *wsa_msg, struct Dot3WSAHdr *hdr)
{
  Log(kDot3LogLevel_Event, "Parse WSA header\n");

  /*
   * 필수필드를 파싱한다.
   */
  dot3_ffasn1c_ParseWSAHdrMandatory(wsa_msg, hdr);

  /*
   * (존재하는 경우) 확장필드를 파싱한다.
   */
  if (wsa_msg->body.extensions_option == true) {
    int ret = dot3_ffasn1c_ParseWSAHdrExtensions(wsa_msg, hdr);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA header\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 필수필드를 파싱하여 저장한다.
 * @param[in] service_info 파싱할 WSA Service info asn.1 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIMandatory(struct dot3ServiceInfo *service_info, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info mandatory fields\n");

  int ret = dot3_ffasn1c_ParseVarLengthNumber(&(service_info->serviceID));
  if (ret < 0) {
    return ret;
  }
  wsi->psid = (Dot3PSID)ret;
  wsi->channel_index = (Dot3WSAChannelIndex)(service_info->channelIndex);
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info mandatory fields\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 PSC 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 PSC extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIPSCExtension(void *ext, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info PSC extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  struct dot3ProviderServiceContext *psc = (struct dot3ProviderServiceContext *)ext;
  if (psc->psc.buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  if (psc->psc.len > kDot3PSCLen_Max) {
    Err("Fail to parse WSA Service Info PSC extension - invalid length: %zu\n", psc->psc.len);
    return -kDot3Result_InvalidPSCLen;
  }
  wsi->psc.len = psc->psc.len;
  memcpy(wsi->psc.psc, psc->psc.buf, wsi->psc.len);
  wsi->psc.psc[wsi->psc.len] = 0;
  wsi->extensions.psc = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info PSC extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 IPv6Address 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 IPv6Address extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIIPv6AddressExtension(void *ext, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info IPv6Address extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  ASN1String *addr = (struct ASN1String *)ext;
  if (addr->buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  memcpy(wsi->ipv6_address, addr->buf, (addr->len > IPv6_ALEN) ? IPv6_ALEN : addr->len);
  wsi->extensions.ipv6_address = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info IPv6Address extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 ServicePort 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 ServicePort extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIServicePortExtension(void *ext, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info ServicePort extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  wsi->service_port = *(uint16_t *)ext;
  wsi->extensions.service_port = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info ServicePort extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 ProviderMacAddress 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 ProviderMacAddress extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIProviderMACAddressExtension(void *ext, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info ProviderMacAddress extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  ASN1String *addr = (struct ASN1String *)ext;
  if (addr->buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  memcpy(wsi->provider_mac_address, addr->buf, (addr->len > MAC_ALEN) ? MAC_ALEN : addr->len);
  wsi->extensions.provider_mac_address = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info ProviderMacAddress extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 RcpiThreshold 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 RcpiThreshold extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIRCPIThresholdExtension(void *ext, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info RcpiThreshold extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  wsi->rcpi_threshold = *(uint8_t *)ext;
  wsi->extensions.rcpi_threshold = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info RcpiThreshold extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 WsaCountThreshold 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 WsaCountThreshold extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIWSACountThresholdExtension(void *ext, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info WsaCountThreshold extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  wsi->wsa_cnt_threshold = *(uint8_t *)ext;
  wsi->extensions.wsa_cnt_threshold = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info WsaCountThreshold extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 WsaCountThresholdInterval 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 WsaCountThresholdInterval extension 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIWSACountThresholdIntervalExtension(void *ext, struct Dot3WSI *wsi)
{
  Log(kDot3LogLevel_Event, "Parse WSA Service Info WsaCountThresholdInterval extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  wsi->wsa_cnt_threshold_interval = *(uint8_t *)ext;
  wsi->extensions.wsa_cnt_threshold_interval = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info WsaCountThresholdInterval extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 의 확장필드를 파싱하여 저장한다.
 * @param[in] service_info 파싱할 WSA Service info asn.1 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIExtensions(struct dot3ServiceInfo *service_info, struct Dot3WSI *wsi)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSA Service Info extensions\n");

  struct dot3ServiceInfoExts *exts = &(service_info->chOptions.extensions);
  struct dot3ServiceInfoExt *ext;

  for (size_t j = 0; j < exts->count; j++) {
    ext = exts->tab + j;
    if (ext == NULL) {
      return -kDot3Result_Asn1AbnormalOp;
    }
    switch (ext->extensionId) {
      case kDot3ExtensionID_PSC:
        ret = dot3_ffasn1c_ParseWSIPSCExtension(ext->value.u.data, wsi);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_IPv6Address:
        ret = dot3_ffasn1c_ParseWSIIPv6AddressExtension(ext->value.u.data, wsi);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_ServicePort:
        ret = dot3_ffasn1c_ParseWSIServicePortExtension(ext->value.u.data, wsi);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_ProviderMACAddress:
        ret = dot3_ffasn1c_ParseWSIProviderMACAddressExtension(ext->value.u.data, wsi);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_RCPIThreshold:
        ret = dot3_ffasn1c_ParseWSIRCPIThresholdExtension(ext->value.u.data, wsi);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_WSACountThreshold:
        ret = dot3_ffasn1c_ParseWSIWSACountThresholdExtension(ext->value.u.data, wsi);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_WSACountThresholdInterval:
        ret = dot3_ffasn1c_ParseWSIWSACountThresholdIntervalExtension(ext->value.u.data, wsi);
        if (ret < 0) {
          return ret;
        }
        break;
      default:
        Err("Fail to parse WSA Service Info extension - invalid extensionId %d\n", ext->extensionId);
        return -kDot3Result_InvalidWSIExtensionID;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info를 파싱하여 저장한다.
 * @param[in] service_info 파싱할 WSA Service info asn.1 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Service Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSI(struct dot3ServiceInfo *service_info, struct Dot3WSI *wsi)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSA Service Info\n");

  /*
   * 필수필드를 파싱한다.
   */
  ret = dot3_ffasn1c_ParseWSIMandatory(service_info, wsi);
  if (ret < 0) {
    return ret;
  }

  /*
   * (존재하는 경우) 확장필드를 파싱한다.
   */
  if (service_info->chOptions.extensions_option == true) {
    ret = dot3_ffasn1c_ParseWSIExtensions(service_info, wsi);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA Service Info\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Service Info 들을 파싱하여 저장한다.
 * @param[in] wsa_msg 디코딩된 WSA asn.1 정보구조체
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWSIs(struct dot3SrvAdvMsg *wsa_msg, struct Dot3ParseWSAParams *params)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSA Service Infos\n");

  /*
   * WSA 내에 WSA Service Info가 하나도 없으면 그대로 종료한다.
   */
  if (wsa_msg->body.serviceInfos_option == false) {
    Log(kDot3LogLevel_Event, "Success to parse WSA Service Infos - no WSA Service Info\n");
    return kDot3Result_Success;
  }

  struct dot3ServiceInfos *service_infos = &(wsa_msg->body.serviceInfos);

  /*
   * WSA 내에 수납되어 있는 WSA Service info 개수를 확인한다.
   *  - WSA 내에 수납되어 있는 WSA Service Info의 수가 시스템이 지원하는 수보다 클 경우, 시스템이 지원하는 수까지만 파싱한다.
   */
  params->wsi_num = (Dot3WSINum)(service_infos->count);
  if (params->wsi_num > kDot3WSINum_Max) {
    params->wsi_num = kDot3WSINum_Max;
    Log(kDot3LogLevel_Event, "WAVE Service Info count is adjusted from %u to %u\n",
        service_infos->count, params->wsi_num);
  } else {
    Log(kDot3LogLevel_Event, "%u service info exists\n", params->wsi_num);
  }

  /*
   * 각 WSA Service Info 를 파싱하여 저장한다.
   */
  struct dot3ServiceInfo *service_info;
  for (unsigned int i = 0; i < params->wsi_num; i++) {
    service_info = service_infos->tab + i;
    if (service_info == NULL) {
      return -kDot3Result_Asn1AbnormalOp;
    }
    ret = dot3_ffasn1c_ParseWSI(service_info, &(params->wsis[i]));
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA Service Infos - %u WSA Service Info are parsed\n", params->wsi_num);
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Channel Info 의 필수필드를 파싱하여 저장한다.
 * @param[in] chan_info 파싱할 WSA Channel info asn.1 정보구조체
 * @param[out] wsi 파싱된 정보가 저장될 WSA Channel Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWCIMandatory(struct dot3ChannelInfo *chan_info, struct Dot3WCI *wci)
{
  Log(kDot3LogLevel_Event, "Parse WSA Channel Info mandatory fields\n");
  if (chan_info->dataRate.adaptable.buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  wci->operating_class = (Dot3OperatingClass)(chan_info->operatingClass);
  wci->chan_num = (Dot3ChannelNumber)(chan_info->channelNumber);
  wci->transmit_power_level = chan_info->powerLevel;
  wci->adaptable_datarate = *(chan_info->dataRate.adaptable.buf);
  wci->datarate = (Dot3DataRate)(chan_info->dataRate.dataRate);
  Log(kDot3LogLevel_Event, "Success to parse WSA Channel Info mandatory fields\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Channel Info 의 EdcaParameterSet 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 EdcaParameterSet extension 정보구조체
 * @param[out] wci 파싱된 정보가 저장될 WSA Channel Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWCIEDCAParameterSetExtension(void *ext, struct Dot3WCI *wci)
{
  Log(kDot3LogLevel_Event, "Parse WSA Channel Info EdcaParameterSet extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }

  struct dot3EdcaParameterSet *from = (struct dot3EdcaParameterSet *)ext;
  struct Dot3EDCAParameterSet *to = &(wci->edca_param_set);
  to->record[0].aci = (Dot3ACI)(from->acbeRecord.aci);
  to->record[0].acm = from->acbeRecord.acm;
  to->record[0].aifsn = (Dot3AIFSN)(from->acbeRecord.aifsn);
  to->record[0].ecwmax = (Dot3ECW)(from->acbeRecord.ecwMax);
  to->record[0].ecwmin = (Dot3ECW)(from->acbeRecord.ecwMin);
  to->record[0].txoplimit = (Dot3TXOPLimit)(from->acbeRecord.txopLimit);
  to->record[1].aci = (Dot3ACI)(from->acbkRecord.aci);
  to->record[1].acm = from->acbkRecord.acm;
  to->record[1].aifsn = (Dot3AIFSN)(from->acbkRecord.aifsn);
  to->record[1].ecwmax = (Dot3ECW)(from->acbkRecord.ecwMax);
  to->record[1].ecwmin = (Dot3ECW)(from->acbkRecord.ecwMin);
  to->record[1].txoplimit = (Dot3TXOPLimit)(from->acbkRecord.txopLimit);
  to->record[2].aci = (Dot3ACI)(from->acviRecord.aci);
  to->record[2].acm = from->acviRecord.acm;
  to->record[2].aifsn = (Dot3AIFSN)(from->acviRecord.aifsn);
  to->record[2].ecwmax = (Dot3ECW)(from->acviRecord.ecwMax);
  to->record[2].ecwmin = (Dot3ECW)(from->acviRecord.ecwMin);
  to->record[2].txoplimit = (Dot3TXOPLimit)(from->acviRecord.txopLimit);
  to->record[3].aci = (Dot3ACI)(from->acvoRecord.aci);
  to->record[3].acm = from->acvoRecord.acm;
  to->record[3].aifsn = (Dot3AIFSN)(from->acvoRecord.aifsn);
  to->record[3].ecwmax = (Dot3ECW)(from->acvoRecord.ecwMax);
  to->record[3].ecwmin = (Dot3ECW)(from->acvoRecord.ecwMin);
  to->record[3].txoplimit = (Dot3TXOPLimit)(from->acvoRecord.txopLimit);
  wci->extension.edca_param_set = true;

  Log(kDot3LogLevel_Event, "Success to parse WSA Channel Info EdcaParameterSet extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Channel Info 의 ChannelAccess 확장필드를 파싱하여 저장한다.
 * @param[in] ext 파싱할 ChannelAccess extension 정보구조체
 * @param[out] wci 파싱된 정보가 저장될 WSA Channel Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWCIChannelAccessExtension(void *ext, struct Dot3WCI *wci)
{
  Log(kDot3LogLevel_Event, "Parse WSA Channel Info ChannelAccess extension\n");
  if (ext == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  wci->chan_access = *(uint8_t *)ext;
  wci->extension.chan_access = true;
  Log(kDot3LogLevel_Event, "Success to parse WSA Channel Info ChannelAccess extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Channel Info 의 확장필드를 파싱하여 저장한다.
 * @param[in] chan_info 파싱할 WSA Channel info asn.1 정보구조체
 * @param[out] wci 파싱된 정보가 저장될 WSA Channel Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWCIExtensions(struct dot3ChannelInfo *chan_info, struct Dot3WCI *wci)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSA Channel Info extensions\n");

  struct dot3ChannelInfoExts *exts = &(chan_info->extensions.extensions);
  struct dot3ChannelInfoExt *ext;

  for (size_t j = 0; j < exts->count; j++) {
    ext = exts->tab + j;
    if (ext == NULL) {
      return -kDot3Result_Asn1AbnormalOp;
    }
    switch (ext->extensionId) {
      case kDot3ExtensionID_EDCAParameterSet:
        ret = dot3_ffasn1c_ParseWCIEDCAParameterSetExtension(ext->value.u.data, wci);
        if (ret < 0) {
          return ret;
        }
        break;
      case kDot3ExtensionID_ChannelAccess:
        ret = dot3_ffasn1c_ParseWCIChannelAccessExtension(ext->value.u.data, wci);
        if (ret < 0) {
          return ret;
        }
        break;
      default:
        Err("Fail to parse WSA Channel Info extension - invalid extensionId %d\n", ext->extensionId);
        return -kDot3Result_InvalidWCIExtensionID;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA Channel Info extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Channel Info를 파싱하여 저장한다.
 * @param[in] chan_info 파싱할 WSA Channel info asn.1 정보구조체
 * @param[out] wci 파싱된 정보가 저장될 WSA Channel Info 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWCI(struct dot3ChannelInfo *chan_info, struct Dot3WCI *wci)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSA Channel Info\n");

  /*
   * 필수필드를 파싱한다.
   */
  ret = dot3_ffasn1c_ParseWCIMandatory(chan_info, wci);
  if (ret < 0) {
    return ret;
  }

  /*
   * (존재하는 경우) 확장필드를 파싱한다.
   */
  if (chan_info->extensions.extensions_option == true) {
    ret = dot3_ffasn1c_ParseWCIExtensions(chan_info, wci);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA Channel Info\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WSA Channel Info 들을 파싱하여 저장한다.
 * @param[in] wsa_msg WSA asn.1 정보구조체
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWCIs(struct dot3SrvAdvMsg *wsa_msg, struct Dot3ParseWSAParams *params)
{
  int ret;
  Log(kDot3LogLevel_Event, "Parse WSA Channel Infos\n");

  /*
   * WSA 내에 WSA Channel Info 가 하나도 없으면 그대로 종료한다.
   */
  if (wsa_msg->body.channelInfos_option == false) {
    Log(kDot3LogLevel_Event, "There is no WSA Channel Info\n");
    return kDot3Result_Success;
  }

  const struct dot3ChannelInfos *chan_infos = &(wsa_msg->body.channelInfos);

  /*
   * WSA 내에 수납되어 있는 개수를 확인한다.
   *  - WSA 내에 수납되어 있는 WSA Channel Info의 수가 시스템이 지원하는 수보다 클 경우, 시스템이 지원하는 수까지만 파싱한다.
   */
  params->wci_num = (Dot3WCINum)(chan_infos->count);
  if (params->wci_num > kDot3WCINum_Max) {
    params->wci_num = kDot3WCINum_Max;
    Log(kDot3LogLevel_Event, "Wci number is adjusted from %u to %u\n", chan_infos->count, params->wci_num);
  } else {
    Log(kDot3LogLevel_Event, "%u channel info exists\n", params->wci_num);
  }

  /*
   * 각 WSA Channel Info를 파싱하여 저장한다.
   */
  struct dot3ChannelInfo *chan_info;
  for (unsigned int i = 0; i < params->wci_num; i++) {
    chan_info = chan_infos->tab + i;
    if (chan_info == NULL) { return -kDot3Result_Asn1AbnormalOp; }
    ret = dot3_ffasn1c_ParseWCI(chan_info, &(params->wcis[i]));
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WSA Channel Infos - %u WSA Channel Info are parsed\n", params->wci_num);
  return kDot3Result_Success;
}


/**
 * @brief WRA asn.1 정보구조체 내 SecondaryDns 확장필드를 파싱하여 저장한다.
 * @param[in] from  WRA asn.1 정보구조체 내 SecondaryDns 확장필드
 * @param[out] to 파싱된 정보가 저장될 버퍼
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWRASecondaryDNSExtension(dot3IPv6Address *from, Dot3IPv6Address to)
{
  Log(kDot3LogLevel_Event, "Parse WRA Secondary DNS extension\n");
  if (from == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  memcpy(to, from->buf, (from->len > IPv6_ALEN) ? IPv6_ALEN: (unsigned int)(from->len));
  Log(kDot3LogLevel_Event, "Success to parse WRA Secondary DNS extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WRA asn.1 정보구조체 내 Gateway Mac address 확장필드를 파싱하여 저장한다.
 * @param[in] from  WRA asn.1 정보구조체 내 Gateway Mac address 확장필드
 * @param[out] to 파싱된 정보가 저장될 버퍼
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWRAGatewayMACAddressExtension(dot3MACaddress *from, Dot3MACAddress to)
{
  Log(kDot3LogLevel_Event, "Parse WRA Gateway MAC address extension\n");
  if (from == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  memcpy(to, from->buf, (from->len > IPv6_ALEN) ? IPv6_ALEN: (unsigned int)(from->len));
  Log(kDot3LogLevel_Event, "Success to parse WRA Gateway MAC address extension\n");
  return kDot3Result_Success;
}


/**
 * @brief WRA asn.1 정보구조체로부터 WRA의 필수필드를 파싱하여 저장한다.
 * @param[in] routing_adv 파싱할 WRA asn.1 정보구조체
 * @param[out] wra 파싱된 정보가 저장될 WRA 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWRAMandatory(struct dot3RoutingAdvertisement *routing_adv, struct Dot3WRA *wra)
{
  Log(kDot3LogLevel_Event, "Parse WRA mandatory fields\n");

  if (routing_adv->ipPrefix.buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  if (routing_adv->defaultGateway.buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  if (routing_adv->primaryDns.buf == NULL) {
    return -kDot3Result_Asn1AbnormalOp;
  }
  wra->router_lifetime = (Dot3WRARouterLifetime)(routing_adv->lifetime);
  unsigned int len = (routing_adv->ipPrefix.len > IPv6_ALEN) ? IPv6_ALEN : (unsigned int)(routing_adv->ipPrefix.len);
  memcpy(wra->ip_prefix, routing_adv->ipPrefix.buf, len);
  wra->ip_prefix_len = (Dot3IPv6PrefixLen)(routing_adv->ipPrefixLength);
  len = (routing_adv->defaultGateway.len > IPv6_ALEN) ? IPv6_ALEN : (unsigned int)(routing_adv->defaultGateway.len);
  memcpy(wra->default_gw, routing_adv->defaultGateway.buf, len);
  len = (routing_adv->primaryDns.len > IPv6_ALEN) ? IPv6_ALEN: (unsigned int)(routing_adv->primaryDns.len);
  memcpy(wra->primary_dns, routing_adv->primaryDns.buf, len);

  Log(kDot3LogLevel_Event, "Success to parse WRA mandatory field\n");
  return kDot3Result_Success;
}


/**
 * @brief WRA asn.1 정보구조체로부터 WRA의 확장필드를 파싱하여 저장한다.
 * @param[in] routing_adv 파싱할 WRA asn.1 정보구조체
 * @param[out] wra 파싱된 정보가 저장될 WRA 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWRAExtensions(struct dot3RoutingAdvertisement *routing_adv, struct Dot3WRA *wra)
{
  Log(kDot3LogLevel_Event, "Parse WRA extensions\n");

  dot3RoutAdvertExts *exts = &(routing_adv->extensions);
  dot3RoutAdvertExt *ext;

  int ret;
  for (size_t i = 0; i < exts->count; i++) {
    ext = exts->tab + i;
    switch (ext->extensionId) {
      case kDot3ExtensionID_SecondaryDNS:
        ret = dot3_ffasn1c_ParseWRASecondaryDNSExtension((dot3IPv6Address *)(ext->value.u.data), wra->secondary_dns);
        if (ret < 0) {
          return ret;
        }
        wra->present.secondary_dns = true;
        break;
      case kDot3ExtensionID_GatewayMACAddress:
        ret = dot3_ffasn1c_ParseWRAGatewayMACAddressExtension((dot3MACaddress *)(ext->value.u.data),
                                                              wra->gateway_mac_addr);
        if (ret < 0) {
          return ret;
        }
        wra->present.gateway_mac_addr = true;
        break;
      default:
        Err("Fail to parse WRA extensions - invalid extensionId: %d\n", ext->extensionId);
        return -kDot3Result_InvalidWCIExtensionID;
    }
  }

  Log(kDot3LogLevel_Event, "Success to parse WRA extensions\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA asn.1 정보구조체로부터 WRA 을 파싱하여 저장한다.
 * @param[in] wsa_msg WSA asn.1 정보구조체
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_ffasn1c_ParseWRA(struct dot3SrvAdvMsg *wsa_msg, struct Dot3ParseWSAParams *params)
{
  Log(kDot3LogLevel_Event, "Parse WRA\n");

  /*
   * WSA 내에 WRA가 없으면 그대로 종료한다.
   */
  if (wsa_msg->body.routingAdvertisement_option == false) {
    Log(kDot3LogLevel_Event, "There is no WRA\n");
    return kDot3Result_Success;
  }

  params->present.wra = true;

  struct dot3RoutingAdvertisement *routing_adv = &(wsa_msg->body.routingAdvertisement);

  /*
   * 필수 필드를 파싱한다.
   */
  int ret = dot3_ffasn1c_ParseWRAMandatory(routing_adv, &(params->wra));
  if (ret < 0) {
    return ret;
  }

  /*
   * 확장필드를 파싱한다.
   */
  ret = dot3_ffasn1c_ParseWRAExtensions(routing_adv, &(params->wra));
  if (ret < 0) {
    return ret;
  }

  Log(kDot3LogLevel_Event, "Success to parse WRA\n");
  return kDot3Result_Success;
}


/**
 * @brief WSA를 ffasn1c 라이브러리를 이용하여 파싱한다.
 * @param[in] wsa 파싱할 WSA (UPER 인코딩 된 상태)
 * @param[in] wsa_size WSA의 길이
 * @param[out] params 파싱된 정보가 저장될 정보구조체의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_ffasn1c_DecodeWSA(const uint8_t *wsa, size_t wsa_size, struct Dot3ParseWSAParams *params)
{
  int ret;
  struct dot3SrvAdvMsg *wsa_msg = NULL;
  Log(kDot3LogLevel_Event, "Decode %u-bytes WSA\n", wsa_size);

  /*
   * WSA를 UPER 디코딩한다.
   */
  ASN1Error err;
  asn1_ssize_t decoded_size = asn1_uper_decode((void **)&wsa_msg, asn1_type_dot3SrvAdvMsg, wsa, wsa_size, &err);
  if ((wsa_msg == NULL) || (decoded_size < 0)) {
    Err("Fail to decode WSA - asn1_uper_decode() failed\n");
    return -kDot3Result_Asn1Decode;
  }

  /*
   * 디코딩된 정보에 대해 constraint check를 수행한다.
   */
  if (asn1_check_constraints(asn1_type_dot3SrvAdvMsg, wsa_msg, &err) == false) {
    Err("Fail to decode WSA - asn1_check_constraints() failed: %s/%s\n", err.type_path, err.msg);
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    return -kDot3Result_Asn1Decode;
  }


  /*
   * 헤더 asn.1 정보를 파싱하여 반환정보에 저장한다.
   */
  ret = dot3_ffasn1c_ParseWSAHdr(wsa_msg, &(params->hdr));
  if (ret < 0) {
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    return ret;
  }

  /*
   * WSA Service Infos asn.1 정보를 파싱하여 반환정보에 저장한다.
   */
  ret = dot3_ffasn1c_ParseWSIs(wsa_msg, params);
  if (ret < 0) {
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    return ret;
  }

  /*
   * WSA Channel Infos asn.1 정보를 파싱하여 반환정보에 저장한다.
   */
  ret = dot3_ffasn1c_ParseWCIs(wsa_msg, params);
  if (ret < 0) {
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    return ret;
  }

  /*
   * WRA 필드의 정보를 파싱하여 반환정보에 저장한다.
   */
  ret = dot3_ffasn1c_ParseWRA(wsa_msg, params);
  if (ret < 0) {
    asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);
    return ret;
  }

  /*
   * asn.1 정보구조체를 해제한다.
   */
  asn1_free_value(asn1_type_dot3SrvAdvMsg, wsa_msg);

  Log(kDot3LogLevel_Event, "Success to decode WSA\n");
  return kDot3Result_Success;
}
