/** 
  * @file 
  * @brief Rotate CMHF 로딩 관련 구현
  * @date 2022-08-05 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <arpa/inet.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "certificate/cmh/dot2-cmh-inline.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c-inline.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c-inline.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief CMHF 내 공통정보 내 필수정보로부터 Rotate CMH 세트 공통정보를 채운다.
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @param[out] cmh_common_info 정보가 저장될 CMH 세트 공통정보 구조체 포인터
 * @return 성공시: CMHF의 처리된 바이트수, 실패 시: 에러코드(-Dot2ResultCode)
 */
static int dot2_FillRotateCMHSetCommonInfoUsingCMHFMandatoryCommonInfo(
  const uint8_t *cmhf,
  int cmhf_size,
  struct Dot2RotateCMHSetCommonInfo *cmh_common_info)
{
  Log(kDot2LogLevel_Event, "Fill rotate CMH set common info using CMHF mandatory common info\n");
  struct Dot2CMHFCommonInfo *cmhf_common_info = (struct Dot2CMHFCommonInfo *)cmhf;
  if (cmhf_size < (int)sizeof(struct Dot2CMHFCommonInfo)) {
    return -kDot2Result_CMHF_TooShort;
  }

  cmh_common_info->type = kDot2CertType_Implicit;
  cmh_common_info->issuer.type = kDot2CertIssuerIdentifierType_Sha256AndDigest;
  memcpy(cmh_common_info->issuer.h8, cmhf_common_info->issuer_h8, 8);
  memcpy(cmh_common_info->craca_id, cmhf_common_info->craca_id, DOT2_CRACA_ID_LEN);
  cmh_common_info->crl_series = (Dot2CertCRLSeries)ntohs(cmhf_common_info->crl_series);
  cmh_common_info->valid_start = dot2_ConvertTime32ToTime64(ntohl(cmhf_common_info->valid_start));
  cmh_common_info->valid_end = dot2_ConvertTime32ToTime64(ntohl(cmhf_common_info->valid_end));
  cmh_common_info->valid_region.type = (Dot2CertValidRegionType)(cmhf_common_info->valid_region_type);
  cmh_common_info->psid_num = (Dot2CertPermissionNum)(cmhf_common_info->psid_num);
  return (int)sizeof(struct Dot2CMHFCommonInfo);
}


/**
 * @brief CMHF 내 공통정보 내 옵션정보로부터 Rotate CMH 세트 공통정보를 채운다.
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @param[out] cmh_info 정보가 저장될 CMH 세트 공통정보 구조체 포인터
 * @return 성공시: CMHF의 처리된 바이트수, 실패 시: 에러코드(-Dot2ResultCode)
 */
static int dot2_FillRotateCMHSetCommonInfoInfoUsingCMHFOptionalCommonInfo(
  const uint8_t *cmhf,
  int cmhf_size,
  struct Dot2RotateCMHSetCommonInfo *cmh_common_info)
{
  Log(kDot2LogLevel_Event, "Fill rotate CMH set common info using CMHF optional common info\n");
  const uint8_t *ptr = cmhf;
  int remained = cmhf_size;

  /*
   * PSID 정보를 채운다.
   */
  if (remained < (int)(sizeof(uint32_t) * cmh_common_info->psid_num)) {
    return -kDot2Result_CMHF_TooShort;
  }
  for (unsigned int i = 0; i < cmh_common_info->psid_num; i++) {
    cmh_common_info->psid[i] = (Dot2PSID)ntohl(*(uint32_t *)ptr);
    ptr += sizeof(uint32_t);
    remained -= sizeof(uint32_t);
  }

  /*
   * 유효지역 정보를 채운다.
   */
  struct Dot2CertValidRegion2 *cmh_region = &(cmh_common_info->valid_region);
  if (cmh_region->type == kDot2CertValidRegionType_Circular) {
    if (remained < (int)sizeof(struct Dot2CMHFInfoCircularRegion)) {
      return -kDot2Result_CMHF_TooShort;
    }
    struct Dot2CMHFInfoCircularRegion *cmhf_region = (struct Dot2CMHFInfoCircularRegion *)ptr;
    cmh_region->u.circular.center.lat = ntohl(cmhf_region->center.lat);
    cmh_region->u.circular.center.lon = ntohl(cmhf_region->center.lon);
    cmh_region->u.circular.radius = ntohs(cmhf_region->radius);
    ptr += sizeof(struct Dot2CMHFInfoCircularRegion);
    remained -= sizeof(struct Dot2CMHFInfoCircularRegion);
  } else if (cmh_region->type == kDot2CertValidRegionType_Identified) {
    if (remained < (int)sizeof(uint8_t)) {
      return -kDot2Result_CMHF_TooShort;
    }
    struct Dot2CMHFInfoIdentifiedRegions *cmhf_region = (struct Dot2CMHFInfoIdentifiedRegions *)ptr;
    cmh_region->u.id.num = (Dot2IdentifiedRegionNum)(cmhf_region->num);
    ptr += sizeof(uint8_t);
    remained -= sizeof(uint8_t);
    if (dot2_CheckCertIdentifiedRegionNum(cmh_region->u.id.num) == false) {
      return -kDot2Result_CMHF_InvalidIdentifiedRegionNum;
    }
    if (remained < (int)(sizeof(uint16_t) * cmh_region->u.id.num)) {
      return -kDot2Result_CMHF_TooShort;
    }
    for (unsigned int i = 0; i < cmh_region->u.id.num; i++) {
      cmh_region->u.id.country[i] = (Dot2CountryCode)ntohs(*(uint16_t *)ptr);
      ptr += sizeof(uint16_t);
      remained -= sizeof(uint16_t);
    }
  }
  return (cmhf_size - remained);
}


/**
 * @brief CMHF 내 공통정보로부터 Rotate CMH 세트 공통정보를 채운다.
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @param[out] cmh_common_info 정보가 저장될 CMH 세트 공통정보 구조체 포인터
 * @return 성공시: CMHF의 처리된 바이트수, 실패 시: 에러코드(-Dot2ResultCode)
 */
static int dot2_FillRotateCMHSetCommonInfoUsingCMHFCommonInfo(
  const uint8_t *cmhf,
  int cmhf_size,
  struct Dot2RotateCMHSetCommonInfo *cmh_common_info)
{
  Log(kDot2LogLevel_Event, "Fill rotate CMH set common info using CMHF common info\n");

  const uint8_t *ptr = cmhf;
  int remained = cmhf_size;
  struct Dot2CMHFCommonInfo *cmhf_common_info = (struct Dot2CMHFCommonInfo *)cmhf;

  /*
   * CMHF 공통정보 내 필수정보의 유효성을 확인한다.
   */
  int ret = dot2_CheckCMHFCommonInfo(cmhf_common_info);
  if (ret < 0) {
    return ret;
  }

  /*
   * CMHF 공통정보 내 필수정보를 CMH에 저장한다.
   */
  ret = dot2_FillRotateCMHSetCommonInfoUsingCMHFMandatoryCommonInfo(ptr, remained, cmh_common_info);
  if (ret < 0) {
    return ret;
  }
  ptr += ret;
  remained -= ret;

  /*
   * CMHF 공통정보 내 옵션정보를 CMH에 저장한다.
   */
  ret = dot2_FillRotateCMHSetCommonInfoInfoUsingCMHFOptionalCommonInfo(ptr, remained, cmh_common_info);
  if (ret < 0) {
    return ret;
  }
  ptr += ret;
  remained -= ret;

  return ((int)cmhf_size - remained);
}


/**
 * @brief CMHF 내 개별정보 내 필수정보로부터 rotate CMH 정보를 채운다.
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @param[out] cmh_info 정보가 저장될 CMH 정보 구조체 포인터
 * @return 성공시: CMHF의 처리된 바이트수, 실패 시: 에러코드(-Dot2ResultCode)
 */
static int dot2_FillRotateCMHInfoUsingCMHFMandatoryIndividualInfo(
  const uint8_t *cmhf,
  int cmhf_size,
  struct Dot2RotateCMHInfo *cmh_info)
{
  Log(kDot2LogLevel_Event, "Fill rotate CMH info using CMHF mandatory individual info\n");
  struct Dot2CMHFIndividualInfo *cmhf_info = (struct Dot2CMHFIndividualInfo *)cmhf;
  if (cmhf_size < (int)sizeof(struct Dot2CMHFIndividualInfo)) {
    return -kDot2Result_CMHF_TooShort;
  }
  cmh_info->cert_size = (Dot2CertSize)ntohs(cmhf_info->cert_size);
  memcpy(cmh_info->cert_h.octs, cmhf_info->cert_h, DOT2_SHA_256_LEN);
  cmh_info->info.id.type = (Dot2CertIdType)(cmhf_info->cert_id_type);
  return (int)sizeof(struct Dot2CMHFIndividualInfo);
}


/**
 * @brief CMHF 내 개별정보 내 옵션정보로부터 rotate CMH 정보를 채운다.
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @param[out] cmh_info 정보가 저장될 CMH 정보 구조체 포인터
 * @return 성공시: CMHF의 처리된 바이트수, 실패 시: 에러코드(-Dot2ResultCode)
 */
static int dot2_FillRotateCMHInfoUsingCMHFOptionalIndividualInfo(
  const uint8_t *cmhf,
  int cmhf_size,
  struct Dot2RotateCMHInfo *cmh_info)
{
  Log(kDot2LogLevel_Event, "Fill rotate CMH info using CMHF optional individual info\n");
  const uint8_t *ptr = cmhf;
  int remained = cmhf_size;

  /*
   * 개인키 정보를 채운다.
   */
  if (remained < DOT2_EC_256_KEY_LEN) {
    Err("Fail to fill rotate CMH info using CMHF optional individual info - too short private key\n");
    return -kDot2Result_CMHF_TooShort;
  }
  memcpy(cmh_info->info.priv_key.octs, ptr, DOT2_EC_256_KEY_LEN);
  ptr += DOT2_EC_256_KEY_LEN;
  remained -= DOT2_EC_256_KEY_LEN;

  /*
   * 인증서 ID 정보를 채운다.
   */
  struct Dot2CertId *cmh_cert_id = &(cmh_info->info.id);
  if (cmh_cert_id->type == kDot2CertIdType_LinkageData) {
    if (remained < (int)sizeof(struct Dot2CMHFInfoLinakgeData)) {
      Err("Fail to fill rotate CMH info using CMHF optional individual info - too short LinkageData\n");
      return -kDot2Result_CMHF_TooShort;
    }
    struct Dot2CMHFInfoLinakgeData *cmhf_cert_id = (struct Dot2CMHFInfoLinakgeData *)ptr;
    cmh_cert_id->u.linkage_data.i = ntohs(cmhf_cert_id->i);
    memcpy(cmh_cert_id->u.linkage_data.val, cmhf_cert_id->val, DOT2_LINKAGE_VALUE_LEN);
    cmh_cert_id->u.linkage_data.grp_present = (bool)(cmhf_cert_id->grp_present);
    if (cmh_cert_id->u.linkage_data.grp_present) {
      memcpy(cmh_cert_id->u.linkage_data.grp.j, cmhf_cert_id->grp.j, DOT2_GROUP_LINKAGE_J_VALUE_LEN);
      memcpy(cmh_cert_id->u.linkage_data.grp.val, cmhf_cert_id->grp.val, DOT2_LINKAGE_VALUE_LEN);
    }
    ptr += sizeof(struct Dot2CMHFInfoLinakgeData);
    remained -= (int)sizeof(struct Dot2CMHFInfoLinakgeData);
  } else if (cmh_cert_id->type == kDot2CertIdType_Name) {
    if (remained < (int)sizeof(uint8_t)) {
      Err("Fail to fill rotate CMH info using CMHF optional individual info - too short Name\n");
      return -kDot2Result_CMHF_TooShort;
    }
    struct Dot2CMHFInfoHostName *cmhf_cert_id = (struct Dot2CMHFInfoHostName *)ptr;
    cmh_cert_id->u.name.len = (Dot2CertIdHostNameLen)(cmhf_cert_id->len);
    ptr += sizeof(uint8_t);
    remained -= (int)sizeof(uint8_t);
    if (dot2_CheckCertIdHostNameLen(cmh_cert_id->u.name.len) == false) {
      return -kDot2Result_CMHF_InvalidCertIdHostNameLen;
    }
    if (cmh_cert_id->u.name.len) {
      if (remained < (int)(cmh_cert_id->u.name.len)) {
        return -kDot2Result_CMHF_TooShort;
      }
      cmh_cert_id->u.name.name = (char *)calloc(1, cmh_cert_id->u.name.len);
      if (cmh_cert_id->u.name.name == NULL) {
        return -kDot2Result_NoMemory;
      }
      memcpy(cmh_cert_id->u.name.name, ptr, cmh_cert_id->u.name.len);
      ptr += cmh_cert_id->u.name.len;
      remained -= (int)(cmh_cert_id->u.name.len);
    }
  } else if (cmh_cert_id->type == kDot2CertIdType_BinaryId) {
    if (remained < (int)sizeof(uint8_t)) {
      Err("Fail to fill rotate CMH info using CMHF optional individual info - too short BinaryId\n");
      return -kDot2Result_CMHF_TooShort;
    }
    struct Dot2CMHFInfoBinaryID *cmhf_cert_id = (struct Dot2CMHFInfoBinaryID *)ptr;
    cmh_cert_id->u.binary_id.len = (Dot2CertBinaryIdLen)(cmhf_cert_id->len);
    ptr += sizeof(uint8_t);
    remained -= (int)sizeof(uint8_t);
    if (dot2_CheckCertBinaryIdLen(cmh_cert_id->u.binary_id.len) == false) {
      return -kDot2Result_CMHF_InvalidCertBinaryIdLen;
    }
    if (cmh_cert_id->u.binary_id.len) {
      memcpy(cmh_cert_id->u.binary_id.id, ptr, cmh_cert_id->u.binary_id.len);
      ptr += cmh_cert_id->u.binary_id.len;
      remained -= (int)(cmh_cert_id->u.binary_id.len);
    }
  } else if (cmh_cert_id->type == kDot2CertIdType_None) { // None은 정보가 없다.
  } else {
    Err("Fail to fill rotate CMH info using CMHF optional individual info - invalid cert id type: %u\n", cmh_cert_id->type);
    return -kDot2Result_CMHF_InvalidCertIdType;
  }

  /*
   * 인증서 바이트열 정보를 채운다.
   */
  if (remained < (int)(cmh_info->cert_size)) {
    Err("Fail to fill rotate CMH info using CMHF optional individual info - too short cert\n");
    return -kDot2Result_CMHF_TooShort;
  }
  cmh_info->cert = (uint8_t *)malloc(cmh_info->cert_size);
  if (cmh_info->cert == NULL) {
    return -kDot2Result_NoMemory;
  }
  memcpy(cmh_info->cert, ptr, cmh_info->cert_size);
  remained -= (int)(cmh_info->cert_size);

  Log(kDot2LogLevel_Event, "Success to fill sequential CMH entry using CMHF optional individual info - remained: %d\n", remained);
  return (cmhf_size - remained);
}


/**
 * @brief CMHF 개별정보로부터 rotate CMH 정보를 채운다.
 * @param[in] cmhf CMHF 데이터
 * @param[in] cmhf_size CMHF 데이터의 길이
 * @param[out] cmh_info 정보가 저장될 CMH 정보 구조체 포인터
 * @return 성공시: CMHF의 처리된 바이트수, 실패 시: 결과코드(-Dot2ResultCode)
 */
static int dot2_FillRotateCMHInfoUsingCMHFIndividualInfo(
  const uint8_t *cmhf,
  int cmhf_size,
  struct Dot2RotateCMHInfo *cmh_info)
{
  Log(kDot2LogLevel_Event, "Fill rotate CMH info using CMHF individual info\n");

  struct Dot2CMHFIndividualInfo *cmhf_info = (struct Dot2CMHFIndividualInfo *)cmhf;
  const uint8_t *ptr = cmhf;
  int remained = cmhf_size;

  /*
   * CMHF 개별정보 내 필수정보의 유효성을 확인한다.
   */
  int ret = dot2_CheckCMHFIndividualInfo(cmhf_info);
  if (ret < 0) {
    Err("Fail to fill rotate CMH info using CMHF individual info - dot2_CheckCMHFIndividualInfo() failed\n");
    return ret;
  }

  /*
   * CMHF 개별정보 내 필수정보를 CMH에 저장한다.
   */
  ret = dot2_FillRotateCMHInfoUsingCMHFMandatoryIndividualInfo(ptr, remained, cmh_info);
  if (ret < 0) {
    Err("Fail to fill rotate CMH info using CMHF individual info - dot2_FillRotateCMHInfoUsingCMHFMandatoryIndividualInfo() failed\n");
    return ret;
  }
  ptr += ret;
  remained -= ret;

  /*
   * CMHF 개별정보 내 옵션정보를 CMH에 저장한다.
   */
  ret = dot2_FillRotateCMHInfoUsingCMHFOptionalIndividualInfo(ptr, remained, cmh_info);
  if (ret < 0) {
    Err("Fail to fill rotate CMH info using CMHF individual info - dot2_FillRotateCMHInfoUsingCMHFOptionalIndividualInfo() failed\n");
    return ret;
  }
  remained -= ret;

  Log(kDot2LogLevel_Event, "Success to fill rotate CMH info using CMHF individual info - remained: %d\n", remained);
  return ((int)cmhf_size - remained);
}



/**
 * @brief CMHF 바이트열에서 정보를 추출하여 rotate CMH 세트 엔트리를 생성한다.
 * @param[in] cmh_type CMH 유형
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @param[out] err 실패 시 에러코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 생성된 엔트리 포인터 (사용 후 free()해 주어야 한다.
 */
static struct Dot2RotateCMHSetEntry *
dot2_MakeRotateCMHSetEntryFromCMHF(Dot2CMHType cmh_type, const uint8_t *cmhf, int cmhf_size, int *err)
{
  EC_KEY *eck_priv_key = NULL;
  struct Dot2RotateCMHSetEntry *cmh_set_entry;
  const uint8_t *ptr = cmhf;
  int remained = cmhf_size;

  Log(kDot2LogLevel_Event, "Make rotate CMH set entry from %d-bytes CMHF\n", cmhf_size);

  /*
   * CMH set 엔트리를 할당한다.
   */
  cmh_set_entry = dot2_AllocateRotateCMHSetEntry(cmh_type);
  if (!cmh_set_entry) {
    *err = -kDot2Result_NoMemory;
    return NULL;
  }

  /*
   * CMHF 공통정보로부터 CMH 정보를 채운다.
   */
  int ret = dot2_FillRotateCMHSetCommonInfoUsingCMHFCommonInfo(ptr, remained, &(cmh_set_entry->common));
  if (ret < 0) {
    goto err;
  }
  ptr += ret;
  remained -= ret;

  /*
   * 인증서 i 값을 채운다.
   */
  if (remained < (int)sizeof(uint32_t)) {
    ret = -kDot2Result_CMHF_TooShort;
    goto err;
  }
  cmh_set_entry->common.i = ntohl(*(uint32_t *)ptr);
  ptr += sizeof(uint32_t);
  remained -= sizeof(uint32_t);

  /*
   * 인증서 개수를 채운다.
   */
  if (remained < (int)sizeof(uint8_t)) {
    ret = -kDot2Result_CMHF_TooShort;
    goto err;
  }
  uint8_t cert_num = *ptr;
  if (cert_num > cmh_set_entry->max_info_num) {
    Err("Fail to make rotate CMH set entry - too many cert %u\n", cert_num);
    ret = -kDot2Result_CMHF_TooManyCert;
    goto err;
  }
  cmh_set_entry->info_num = (Dot2RotateCMHInfoNum)cert_num;
  ptr += sizeof(uint8_t);
  remained -= sizeof(uint8_t);

  /*
   * CMHF 개별정보로부터 CMH 엔트리 정보를 채운다.
   */
  for (unsigned int i = 0; i < cmh_set_entry->info_num; i++) {
    ret = dot2_FillRotateCMHInfoUsingCMHFIndividualInfo(ptr, remained, &(cmh_set_entry->cmh[i]));
    if (ret < 0) {
      goto err;
    }
    ptr += ret;
    remained -= ret;
  }

  /*
   * 각 인증서에 대해 EC_KEY 형식의 개인키를 생성하고, 인증서바이트열을 디코딩하여 저장한다.
   */
  for (unsigned int i = 0; i < cmh_set_entry->info_num; i++) {

    struct Dot2RotateCMHInfo *cmh_info = &(cmh_set_entry->cmh[i]);

    // EC_KEY 형식의 개인키를 생성한다.
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&(cmh_info->info.priv_key), &ret);
    if (!eck_priv_key) {
      goto err;
    }

    // 인증서바이트열을 디코딩하여 저장한다.
#if defined(_FFASN1C_)
    dot2Certificate *asn1_cert = dot2_ffasn1c_DecodeCertificate(cmh_info->cert, cmh_info->cert_size, &ret);
    if (!asn1_cert) {
      ret = -kDot2Result_CMHF_DecodeCertificate;
      goto err;
    }
#elif defined(_OBJASN1C_)
    dot2Certificate *asn1_cert = NULL;
    OSCTXT *ctxt = NULL;
    ret = dot2_objasn1c_DecodeCertificate(cmh_info->cert, cmh_info->cert_size, &asn1_cert, &ctxt);
    if (ret < 0) {
      ret = -kDot2Result_CMHF_DecodeCertificate;
      goto err;
    }
#else
#error "3rd party asn.1 library is not defined"
#endif

    cmh_info->info.eck_priv_key = eck_priv_key;
    cmh_info->asn1_cert = asn1_cert;
#if defined(_OBJASN1C_)
    cmh_info->ctxt = ctxt;
#endif
  }

  Log(kDot2LogLevel_Event, "Success to make rotate CMH entry from CMHF\n");
  return cmh_set_entry;

err:
  dot2_ReleaseRotateCMHSetEntry(cmh_set_entry);
  *err = ret;
  return NULL;
}


/**
 * @brief CMHF 바이트열로부터 Sequential CMH 정보를 생성하여 테이블에 추가한다.
 * @param[in] cmh_type CMH 유형
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_AddRotateCMHfromCMHF(Dot2CMHType cmh_type, const uint8_t *cmhf, int cmhf_size)
{
  Log(kDot2LogLevel_Event, "Add rotate CMH from CMHF\n");

  /*
   * CMHF 바이트열로부터 CMH 엔트리 정보를 생성한다.
   */
  int ret;
  struct Dot2RotateCMHSetEntry *cmh_set_entry = dot2_MakeRotateCMHSetEntryFromCMHF(cmh_type, cmhf, cmhf_size, &ret);
  if (!cmh_set_entry) {
    return ret;
  }

  /*
   * CMH 엔트리의 인증서체인을 구성한다. (SCC 인증서리스트에서 상위인증서를 찾아 참조포인터에 연결한다)
   * CMH 엔트리를 테이블에 저장한다.
   */
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  uint8_t *issuer_id = cmh_set_entry->common.issuer.h8;
  struct Dot2SCCCertInfoEntry *issuer_entry = dot2_FindSCCCertWithHashedID8(issuer_id);
  if (issuer_entry) {
    Dot2Time64 valid_start = cmh_set_entry->common.valid_start;
    Dot2Time64 valid_end = cmh_set_entry->common.valid_end;
    Dot2Time64 i_valid_start = issuer_entry->contents.common.valid_start;
    Dot2Time64 i_valid_end = issuer_entry->contents.common.valid_end;
    if (dot2_CheckIssuerSignedCertValidTime(valid_start, valid_end, i_valid_start, i_valid_end)) {
      ret = dot2_PushRotateCMHSetEntry(cmh_type, cmh_set_entry);
      if (ret == kDot2Result_Success) {
        cmh_set_entry->issuer = issuer_entry;
      }
    } else {
      Err("Fail to add rotate CMH from CMHF - invalid cert valid time\n");
      ret = -kDot2Result_CMHF_InvalidCertValidTime;
    }
  } else {
    Err("Fail to add rotate CMH from CMHF - no issuer\n");
    ret = -kDot2Result_CMHF_NoIssuer;
  }
  pthread_mutex_unlock(&(g_dot2_mib.mtx));

  if (ret == kDot2Result_Success) {
    Log(kDot2LogLevel_Event, "Success to add rotate CMH from CMHF\n");
  } else {
    dot2_ReleaseRotateCMHSetEntry(cmh_set_entry);
  }
  return ret;
}
