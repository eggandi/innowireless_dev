/** 
  * @file 
  * @brief asn.1 디코딩된 SPDU 관련 정보를 파싱하여 일반 형식의 정보로 변환하는 함수들을 구현한 파일
  * @date 2021-06-04 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-ffasn1c.h"
#include "dot2-ffasn1c-inline.h"


/**
 * @brief ffasn1c 라이브러리를 이용하여 메시지 내 디코딩된 SignedDataPayload 필드 정보를 파싱하여 패킷파싱데이터에 저장한다.
 * @param[in] asn1_data SignedDataPayload 필드 asn.1 디코딩 정보
 * @param[out] parsed 파싱정보가 저장될 패킷파싱데이터 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int
dot2_ffasn1c_ParseSignedDataPayload(const dot2SignedDataPayload *asn1_data, struct V2XPacketParseData *parsed)
{
  int ret;
  Log(kDot2LogLevel_Event, "Parse SignedDataPayload\n");

  /*
   * 페이로드 내에 data 필드가 포함되어 있으면 파싱하여 패킷파싱데이터에 저장한다.
   *  - 현 버전의 표준에서, 페이로드 내의 data 필드는 UnsecuredData 형식을 가져야 한다.
   */
  if (asn1_data->data_option == true) {
    const dot2Ieee1609Dot2Data *data = asn1_data->data;
    if (!data) {
      return -kDot2Result_FailToAsn1;
    }
    if (data->protocolVersion != DOT2_PROTOCOL_VERSION) {
      Err("Fail to parse SignedDataPayload - invalid inner content protocol version %d\n", data->protocolVersion);
      return -kDot2Result_InvalidInnerContentProtocolVersion;
    }
    if (data->content.choice != dot2Ieee1609Dot2Content_unsecuredData) {
      Err("Fail to parse SignedDataPayload - inner content is not unsecuredData. it's %d\n", data->content.choice);
      return -kDot2Result_InvalidInnerContentType;
    }
    ret = dot2_ffasn1c_ParseUnsecuredData(&(data->content.u.unsecuredData), parsed);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 페이로드 내에 extDataHash 필드가 포함되어 있으면 파싱하여 패킷파싱데이터에 저장한다.
   */
  if (asn1_data->extDataHash_option == true) {
    const dot2HashedData *h = &(asn1_data->extDataHash);
    if (h->choice != dot2HashedData_sha256HashedData) {
      Err("Fail to parse SignedDataPayload - invalid external hash type %d\n", h->choice);
      return -kDot2Result_InvalidExtHashType;
    }
    ret = dot2_ffasn1c_ParseOctetString(&(h->u.sha256HashedData),
                                        0,
                                        sizeof(parsed->spdu.signed_data.ext_h),
                                        parsed->spdu.signed_data.ext_h);
    if (ret < 0) {
      return -kDot2Result_InvalidExtHashData;
    }
    parsed->spdu.signed_data.ext_h_present = true;
  }

  Log(kDot2LogLevel_Event, "Success to parse SignedDataPayload\n");
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 HeaderInfo 필드 정보를 파싱하여 패킷파싱데이터에 저장한다.
 * @param[in] asn1_data HeaderInfo 필드 asn.1 디코딩 정보
 * @param[out] parsed 파싱정보가 저장될 패킷파싱데이터 포인터
 */
static void dot2_ffasn1c_ParseHeaderInfo(const dot2HeaderInfo *asn1_data, struct V2XPacketParseData *parsed)
{
  Log(kDot2LogLevel_Event, "Parse HeaderInfo\n");
  struct Dot2SPDUParseData *parse_data = &(parsed->spdu);
  parse_data->signed_data.psid = dot2_ffasn1c_ParsePSID(&(asn1_data->psid));
  if (asn1_data->generationTime_option == true) {
    parse_data->signed_data.gen_time_present = true;
    parse_data->signed_data.gen_time = dot2_ffasn1c_ParseU64ASN1Integer(&(asn1_data->generationTime));
  }
  if (asn1_data->expiryTime_option == true) {
    parse_data->signed_data.expiry_time_present = true;
    parse_data->signed_data.expiry_time = dot2_ffasn1c_ParseU64ASN1Integer(&(asn1_data->expiryTime));
  }
  if (asn1_data->generationLocation_option == true) {
    parse_data->signed_data.gen_location_present = true;
    parse_data->signed_data.gen_location.lat = asn1_data->generationLocation.latitude;
    parse_data->signed_data.gen_location.lon = asn1_data->generationLocation.longitude;
    parse_data->signed_data.gen_location.elev = asn1_data->generationLocation.elevation;
  }
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 ToBeSignedData 필드 정보를 파싱하여 패킷파싱데이터에 저장한다.
 * @param[in] asn1_data ToBeSignedData 필드 asn.1 디코딩 정보
 * @param[out] parsed 파싱정보가 저장될 패킷파싱데이터 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseToBeSignedData(const dot2ToBeSignedData *asn1_data, struct V2XPacketParseData *parsed)
{
  Log(kDot2LogLevel_Event, "Parse ToBeSignedData\n");
  int ret = dot2_ffasn1c_ParseSignedDataPayload(&(asn1_data->payload), parsed);
  if (ret == kDot2Result_Success) {
    dot2_ffasn1c_ParseHeaderInfo(&(asn1_data->headerInfo), parsed);
  }
  return ret;
}
