/** 
 * @file
 * @brief ffasn1c 라이브러리를 이용하여 인증서를 디코딩/파싱하는 기능을 구현한 파일
 * @date 2020-04-02
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "dot2-ffasn1c.h"


/*
 * 각 CA 별 SCMS 어플리케이션 권한(PSID=35)에 대한 인코딩된 SSP 값
 *  - V2X 보안인증체계 세부 기술규격(KISA) v1.1 "PSID와 SSP 가이드 라인" 참조
 */
#define DOT2_CA_SCMS_APP_PERMS_SSP_LEN (3) ///< CA의 SCMS appPermissions(psid=35)의 인코딩된 SSP 길이
static const uint8_t rca_scms_app_perms_ssp[DOT2_CA_SCMS_APP_PERMS_SSP_LEN] = { 0x81, 0x00, 0x01 };
static const uint8_t ica_scms_app_perms_ssp[DOT2_CA_SCMS_APP_PERMS_SSP_LEN] = { 0x83, 0x00, 0x01 };
static const uint8_t eca_scms_app_perms_ssp[DOT2_CA_SCMS_APP_PERMS_SSP_LEN] = { 0x84, 0x00, 0x01 };
static const uint8_t pca_scms_app_perms_ssp[DOT2_CA_SCMS_APP_PERMS_SSP_LEN] = { 0x85, 0x00, 0x01 };
static const uint8_t crlg_scms_app_perms_ssp[DOT2_CA_SCMS_APP_PERMS_SSP_LEN] = { 0x86, 0x00, 0x01 };
static const uint8_t ra_scms_app_perms_ssp[DOT2_CA_SCMS_APP_PERMS_SSP_LEN] = { 0x8B, 0x00, 0x01 };


/**
 * @brief SCC 인증서에 수납된 SSP를 이용해서 인증서의 유형을 확인한다.
 * @param[in] asn1_ssp SCC 인증서에 수납된 SSP
 * @return SCC 인증서 유형
 */
Dot2SCCCertType INTERNAL dot2_ffasn1c_CheckSCCCertTypeWithSSP(dot2ServiceSpecificPermissions *asn1_ssp)
{
  Dot2SCCCertType type = kDot2SCCCertType_Unknown;
  if ((asn1_ssp->choice == dot2ServiceSpecificPermissions_opaque) &&
      (asn1_ssp->u.opaque.buf) &&
      (asn1_ssp->u.opaque.len == DOT2_CA_SCMS_APP_PERMS_SSP_LEN)) {
    if (memcmp(asn1_ssp->u.opaque.buf, rca_scms_app_perms_ssp, DOT2_CA_SCMS_APP_PERMS_SSP_LEN) == 0) {
      type = kDot2SCCCertType_RCA;
    } else if (memcmp(asn1_ssp->u.opaque.buf, ica_scms_app_perms_ssp, DOT2_CA_SCMS_APP_PERMS_SSP_LEN) == 0) {
      type = kDot2SCCCertType_ICA;
    } else if (memcmp(asn1_ssp->u.opaque.buf, eca_scms_app_perms_ssp, DOT2_CA_SCMS_APP_PERMS_SSP_LEN) == 0) {
      type = kDot2SCCCertType_ECA;
    } else if (memcmp(asn1_ssp->u.opaque.buf, pca_scms_app_perms_ssp, DOT2_CA_SCMS_APP_PERMS_SSP_LEN) == 0) {
      type = kDot2SCCCertType_PCA;
    } else if (memcmp(asn1_ssp->u.opaque.buf, crlg_scms_app_perms_ssp, DOT2_CA_SCMS_APP_PERMS_SSP_LEN) == 0) {
      type = kDot2SCCCertType_CRLG;
    } else if (memcmp(asn1_ssp->u.opaque.buf, ra_scms_app_perms_ssp, DOT2_CA_SCMS_APP_PERMS_SSP_LEN) == 0) {
      type = kDot2SCCCertType_RA;
    }
  }
  return type;
}


/**
 * @brief SCC 인증서의 유형을 확인한다.
 * @param[in] asn1_cert SCC 인증서
 * @return SCC 인증서 유형
 */
Dot2SCCCertType INTERNAL dot2_ffasn1c_ParseSCCCertType(dot2Certificate *asn1_cert)
{
  Dot2SCCCertType type = kDot2SCCCertType_Unknown;
  int32_t psid;
  if (asn1_cert->toBeSigned.appPermissions_option) {
    for (size_t j = 0; j < asn1_cert->toBeSigned.appPermissions.count; j++) {
      dot2PsidSsp *psid_ssp = asn1_cert->toBeSigned.appPermissions.tab + j;
      if ((psid_ssp->ssp_option) &&
          (asn1_integer_get_si_ov(&(psid_ssp->psid), &psid) == 0) &&
          (psid == kDot2PSID_SCMS)) {
        type = dot2_ffasn1c_CheckSCCCertTypeWithSSP(&(psid_ssp->ssp));
      }
    }
  }
  return type;
}


/**
 * @brief ffasn1c CertificateType 정보를 파싱하여 Dot2CertType 정보 형식으로 반환한다.
 * @param[in] type ffasn1c CertificateType 정보
 * @return 인증서 유형(Dot2CertType)
 */
static inline Dot2CertType dot2_ffasn1c_ParseCertType(dot2CertificateType type)
{
  return (type == dot2CertificateType_Explicit) ? kDot2CertType_Explicit : kDot2CertType_Implicit;
}


/**
 * @brief ffasn1c IssuerIdentifier 정보구조체 내의 정보를 파싱하여 라이브러리 IssuerIdentifier 정보구조체에 저장한다.
 * @param[in] from ffasn1c IssuerIdentifier 정보구조체
 * @param[out] to 라이브러리 IssuerIdentifier 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseCertIssuerIdentifier(const dot2IssuerIdentifier *from, struct Dot2CertIssuerIdentifier *to)
{
  Log(kDot2LogLevel_Event, "Parse certificate issuer identifier\n");
  switch (from->choice) {
    case dot2IssuerIdentifier_self:
      to->type = kDot2CertIssuerIdentifierType_Self;
      break;
    case dot2IssuerIdentifier_sha256AndDigest:
      to->type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
      memcpy(to->h8, from->u.sha256AndDigest.buf, sizeof(to->h8));
      break;
    default:
      Err("Fail to parse certificate issuer identifier - invalid type %d\n", from->choice);
      return -kDot2Result_InvalidCertIssuerIdentifierType;
  }
  Log(kDot2LogLevel_Event, "Success to parse certificate issuer identifier\n");
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c dot2LinkageData 정보를 파싱하여 Dot2CertLinakgeData 정보에 저장한다.
 * @param[in] from ffasn1c dot2LinkageData 정보구조체
 * @param[out] to 라이브러리 Dot2CertLinakgeData 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseCertId_LinkageData(const dot2LinkageData *from, struct Dot2CertLinakgeData *to)
{
  // iCert
  to->i = from->iCert;
  // linkage-value
  if (from->linkage_value.len != DOT2_LINKAGE_VALUE_LEN) {
    Err("Fail to parse cert id - invalid linkageData.linkage_value len %zu\n", from->linkage_value.len);
    return -kDot2Result_InvalidCertId;
  }
  memcpy(to->val, from->linkage_value.buf, DOT2_LINKAGE_VALUE_LEN);
  // group-link-value
  if (from->group_linkage_value_option) {
    to->grp_present = true;
    // jValue
    if (from->group_linkage_value.jValue.len != DOT2_GROUP_LINKAGE_J_VALUE_LEN) {
      Err("Fail to parse cert id - invalid linkageData.group_linkage_value.jValue len : %zu\n",
          from->group_linkage_value.jValue.len);
      return -kDot2Result_InvalidCertId;
    }
    memcpy(to->grp.j, from->group_linkage_value.jValue.buf, DOT2_GROUP_LINKAGE_J_VALUE_LEN);
    // Value
    if (from->group_linkage_value.value.len != DOT2_LINKAGE_VALUE_LEN) {
      Err("Fail to parse cert id - invalid linkageData.group_linkage_value.value len: %zu\n",
          from->group_linkage_value.value.len);
      return -kDot2Result_InvalidCertId;
    }
    memcpy(to->grp.val, from->group_linkage_value.value.buf, DOT2_LINKAGE_VALUE_LEN);
  }
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c dot2Hostname 정보를 파싱하여 Dot2CertHostName 정보에 저장한다.
 * @param[in] from ffasn1c dot2Hostname 정보구조체
 * @param[out] to 라이브러리 Dot2CertHostName 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseCertId_HostName(const dot2Hostname *from, struct Dot2CertHostName *to)
{
  if (from->len > kDot2CertIdHostNameLen_Max) {
    Err("Fail to parse cert id - too long name : %zu\n", from->len);
    return -kDot2Result_InvalidCertId;
  }
  to->len = from->len;
  if (to->len) {
    to->name = malloc(to->len + 1);
    if (to->name == NULL) {
      Err("Fail to parse cert id - no memory\n");
      return -kDot2Result_NoMemory;
    }
    memcpy(to->name, from->buf, to->len);
    to->name[to->len] = 0;
  }
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c ASN1String 정보를 파싱하여 Dot2CertBinaryId 정보에 저장한다.
 * @param[in] from ffasn1c ASN1String 정보구조체
 * @param[out] to 라이브러리 Dot2CertBinaryId 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseCertId_BinaryId(const ASN1String *from, struct Dot2CertBinaryId *to)
{
  if (from->len != kDot2CertBinaryIdLen_Default) {
    Err("Fail to parse cert id - invalid binaryId len: %zu\n", from->len);
    return -kDot2Result_InvalidCertId;
  }
  to->len = from->len;
  memcpy(to->id, from->buf, to->len);
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c dot2CertificateId 정보를 파싱하여 Dot2CertId 정보에 저장한다.
 * @param[in] from ffasn1c dot2CertificateId 정보구조체
 * @param[out] to 라이브러리 Dot2CertId 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseCertId(const dot2CertificateId *from, struct Dot2CertId *to)
{
  int ret;
  switch (from->choice)
  {
    case dot2CertificateId_linkageData:
      to->type = kDot2CertIdType_LinkageData;
      ret = dot2_ffasn1c_ParseCertId_LinkageData(&(from->u.linkageData), &(to->u.linkage_data));
      break;

    case dot2CertificateId_name:
      to->type = kDot2CertIdType_Name;
      ret = dot2_ffasn1c_ParseCertId_HostName(&(from->u.name), &(to->u.name));
      break;

    case dot2CertificateId_binaryId:
      to->type = kDot2CertIdType_BinaryId;
      ret = dot2_ffasn1c_ParseCertId_BinaryId(&(from->u.binaryId), &(to->u.binary_id));
      break;

    case dot2CertificateId_none:
      to->type = kDot2CertIdType_None;
      ret = kDot2Result_Success;
      break;

    default:
      Err("Fail to parse cert id - invalid type: %d\n", from->choice);
      ret = -kDot2Result_InvalidCertId;
      break;
  }

  return ret;
}


/**
 * @brief ffasn1c cracaId 정보를 파싱하여 라이브러리 craca_id 버퍼에 저장한다.
 * @param[in] from ffasn1c cracaId 정보구조체
 * @param[out] to 라이브러리 craca_id 버퍼
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseCertCracaId(const ASN1String *from, uint8_t *to)
{
  if (from->len != DOT2_CRACA_ID_LEN) {
    Err("Fail to parse craca id - invalid len: %zu\n", from->len);
    return -kDot2Result_InvalidCertCracaId;
  }
  memcpy(to, from->buf, DOT2_CRACA_ID_LEN);
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c 정보형식의 Duration 값을 Time64 값으로 변환한다.
 * @param[in] duration 변환할 Duration 값
 * @return 변환된 Time64 값
 */
static inline Dot2Time64 dot2_ffasn1c_ConvertDurationToTime64(const dot2Duration *duration)
{
  Dot2Time64 ret;
  switch (duration->choice) {
    case dot2Duration_microseconds:
      ret = duration->u.microseconds;
      break;
    case dot2Duration_milliseconds:
      ret = (Dot2Time64)(duration->u.milliseconds) * 1000ULL;
      break;
    case dot2Duration_seconds:
      ret = (Dot2Time64)(duration->u.seconds) * 1000000ULL;
      break;
    case dot2Duration_minutes:
      ret = (Dot2Time64)(duration->u.minutes) * 60 * 1000000ULL;
      break;
    case dot2Duration_hours:
      ret = (Dot2Time64)(duration->u.hours) * 60 * 60 * 1000000ULL;
      break;
    case dot2Duration_sixtyHours:
      ret = (Dot2Time64)(duration->u.sixtyHours) * 60 * 60 * 60 * 1000000ULL;
      break;
    case dot2Duration_years:
      ret = (Dot2Time64)(duration->u.years) * 60 * 60 * 24 * 365 * 1000000ULL; // Time64 변수 크기 상, 약 60만년까지 사용 가능
      break;
    default:
      ret = 0;
  }
  return ret;
}


/**
 * @brief ffasn1c 원형지역 정보구조체 내의 정보를 파싱하여 라이브러리 원형지역 정보구조체에 저장한다.
 * @param[in] from ffasn1c 원형지역 정보구조체
 * @param[out] to 라이브러리 원형지역 정보구조체
 */
static inline void dot2_ffasn1c_ParseCertCircularRegion(const dot2CircularRegion *from, struct Dot2CircularRegion *to)
{
  to->center.lat = from->center.latitude;
  to->center.lon = from->center.longitude;
  to->radius = from->radius;
}


/**
 * @brief ffasn1c dot2SequenceOfIdentifiedRegion 정보를 파싱하여 라이브러리 Dot2CertIdentifiedRegion 정보구조체에 저장한다.
 * @param[in] from ffasn1c dot2SequenceOfIdentifiedRegion 정보구조체
 * @param[out] to 라이브러리 Dot2CertIdentifiedRegion 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 현 시점의 V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라, countryOnly 형식의 Identified region 정보만을 지원한다.
 */
static inline int dot2_ffasn1c_ParseCertIdentifiedRegions(
const dot2SequenceOfIdentifiedRegion *from,
struct Dot2CertIdentifiedRegions *to)
{
  if (from->count > kDot2IdentifiedRegionNum_Max) {
    Err("Fail to parse cert identified region - too many region: %u > %u\n", from->count, kDot2IdentifiedRegionNum_Max);
    return -kDot2Result_TooManyCertValidRegion;
  }
  to->num = from->count;
  dot2IdentifiedRegion *region;
  for (unsigned int i = 0; i < to->num; i++) {
    region = (dot2IdentifiedRegion *)(from->tab + i);
    if (region->choice != dot2IdentifiedRegion_countryOnly) {
      Err("Fail to parse cert identified region - invalid type: %d\n", region->choice);
      return -kDot2Result_InvalidCertValidRegion;
    }
    to->country[i] = region->u.countryOnly;
  }
  return kDot2Result_Success;
}


/**
 * @brief ffasn1c 유효지역 정보구조체 내의 정보를 파싱하여 라이브러리 유효지역 정보구조체에 저장한다.
 * @param[in] from ffasn1c 유효지역 정보구조체
 * @param[out] to 라이브러리 유효지역 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 현 시점의 V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라, Circular region 및 Identified region 정보만을 지원한다.
 */
static int dot2_ffasn1c_ParseCertValidRegion2(const dot2GeographicRegion *from, struct Dot2CertValidRegion2 *to)
{
  int ret;
  switch (from->choice) {
    case dot2GeographicRegion_circularRegion:
      to->type = kDot2CertValidRegionType_Circular;
      dot2_ffasn1c_ParseCertCircularRegion(&(from->u.circularRegion), &(to->u.circular));
      ret = kDot2Result_Success;
      break;
    case dot2GeographicRegion_identifiedRegion:
      to->type = kDot2CertValidRegionType_Identified;
      ret = dot2_ffasn1c_ParseCertIdentifiedRegions(&(from->u.identifiedRegion), &(to->u.id));
      break;
    default:
      Err("Fail to parse cert valid region - invalid valid region type %d\n", from->choice);
      ret = -kDot2Result_InvalidCertValidRegion;
  }
  return ret;
}


/**
 * @brief ffasn1c PublicVerificationKey 정보구조체 내의 정보를 파싱하여 라이브러리 PublicVerificationKey 정보구조체에 저장한다.
 * @param[in] from ffasn1c PublicVerificationKey 정보구조체
 * @param[out] to 라이브러리 PublicVerificationKey 정보구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int
dot2_ffasn1c_ParseCertPublicVerificationKey2(const dot2PublicVerificationKey *from, struct Dot2ECPublicKey *to)
{
  if (from->choice != dot2PublicVerificationKey_ecdsaNistP256) {
    Err("Fail to parse cert verification key - invalid type: %d\n", from->choice);
    return -kDot2Result_InvalidVerificationKeyType;
  }
  return dot2_ffasn1c_ParseEccP256CurvePoint(&(from->u.ecdsaNistP256), to);
}


/**
 * @brief VerificationKeyIndicator 정보에 대한 asn.1 디코딩정보를 파싱하여 공용 정보구조체에 저장한다.
 * @param[in] from 파싱할 디코딩정보
 * @param[out] to 파싱된 정보가 저장될 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_ParseCertVerificationKeyIndicator2(
const dot2VerificationKeyIndicator *from,
struct Dot2CertVerificationKeyIndicator *to)
{
  Log(kDot2LogLevel_Event, "Parse cert verification key indicator\n");
  int ret;
  if (from->choice == dot2VerificationKeyIndicator_verificationKey) {
    to->type = kDot2CertVerificationKeyIndicatorType_Key;
    ret = dot2_ffasn1c_ParseCertPublicVerificationKey2(&(from->u.verificationKey), &(to->key));
  } else if (from->choice == dot2VerificationKeyIndicator_reconstructionValue) {
    to->type = kDot2CertVerificationKeyIndicatorType_ReconstructValue;
    ret = dot2_ffasn1c_ParseEccP256CurvePoint(&(from->u.reconstructionValue), &(to->key));
  } else {
    Err("Fail to parse certificate verification key indicator - invalid type %d\n", from->choice);
    ret = -kDot2Result_InvalidVerificationKeyIndicatorType;
  }
  return ret;
}


/**
 * @brief 인증서내 암호화용공개키에 대한 asn.1 디코딩정보를 파싱하여 공용 정보구조체에 저장한다.
 * @param[in] from 파싱할 디코딩정보
 * @param[out] to 파싱된 정보가 저장될 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_ParseCertEncryptionKey(const dot2PublicEncryptionKey *from, struct Dot2ECPublicKey *to)
{
  if (from->publicKey.choice != dot2BasePublicEncryptionKey_eciesNistP256) {
    Err("Fail to parse cert encryption key - invalid type: %d\n", from->publicKey.choice);
    return -kDot2Result_InvalidEncryptionPubKey;
  }
  return dot2_ffasn1c_ParseEccP256CurvePoint(&(from->publicKey.u.eciesNistP256), to);
}


/**
 * @brief 인증서 디코딩정보를 파싱하여 인증서공통컨텐츠정보에 저장한다.
 * @param[in] asn1_cert 인증서 디코딩정보
 * @param[out] to 파싱된 정보가 저장될 인증서공통컨텐츠정보 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL
dot2_ffasn1c_ParseCertCommonContents(const dot2Certificate *asn1_cert, struct Dot2CertCommonContents *contents)
{
  Log(kDot2LogLevel_Event, "Parse cert common contents\n");

  int ret;

  /*
   * 인증서 유형 정보를 파싱한다.
   */
  contents->type = dot2_ffasn1c_ParseCertType(asn1_cert->type);

  /*
   * 상위인증서 식별자(issuer) 정보를 파싱한다.
   */
  ret = dot2_ffasn1c_ParseCertIssuerIdentifier(&(asn1_cert->issuer), &(contents->issuer));
  if (ret < 0) {
    return ret;
  }

  const dot2ToBeSignedCertificate *tbs = &(asn1_cert->toBeSigned);

  /*
   * 인증서 ID 정보를 파싱한다.
   */
  ret = dot2_ffasn1c_ParseCertId(&(tbs->id), &(contents->id));
  if (ret < 0) {
    return ret;
  }

  /*
   * CracaId 정보를 파싱한다.
   */
  ret = dot2_ffasn1c_ParseCertCracaId(&(tbs->cracaId), contents->craca_id);
  if (ret < 0) {
    return ret;
  }

  /*
   * CrlSeries 정보를 파싱한다.
   */
  contents->crl_series = tbs->crlSeries;

  /*
   * 유효기간(toBeSigned.validityPeriod) 정보를 파싱한다.
   */
  contents->valid_start = dot2_ConvertTime32ToTime64(tbs->validityPeriod.start);
  contents->valid_end = contents->valid_start + dot2_ffasn1c_ConvertDurationToTime64(&(tbs->validityPeriod.duration));

  /*
   * 유효지역(toBeSigned.region) 정보를 파싱한다.
   */
  if (tbs->region_option == true) {
    ret = dot2_ffasn1c_ParseCertValidRegion2(&(tbs->region), &(contents->valid_region));
    if (ret < 0) {
      return ret;
    }
  } else {
    contents->valid_region.type = kDot2CertValidRegionType_None;
  }

  /*
   * 검증키 지시자(toBeSigned.verifyKeyIndicator) 정보를 파싱한다.
   */
  ret = dot2_ffasn1c_ParseCertVerificationKeyIndicator2(&(tbs->verifyKeyIndicator), &(contents->verify_key_indicator));
  if (ret < 0) {
    return ret;
  }

  /*
   * 암호화용 공개키 정보를 파싱한다.
   */
  if (tbs->encryptionKey_option == true) {
    contents->enc_pub_key_present = true;
    ret = dot2_ffasn1c_ParseCertEncryptionKey(&(tbs->encryptionKey), &(contents->enc_pub_key));
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot2LogLevel_Event, "Success to parse cert common contents\n");
  return kDot2Result_Success;
}
