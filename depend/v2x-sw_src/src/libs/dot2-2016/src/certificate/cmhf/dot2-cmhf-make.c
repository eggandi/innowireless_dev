/** 
 * @file
 * @brief cmhf 생성 관련 구현
 * @date 2020-05-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "certificate/cmhf/dot2-cmhf.h"


/**
 * @brief CMHF 버퍼에 공통정보를 채운다.
 * @param[in] cmh_type CMH 유형
 * @param[in] issuer_h 상위인증서 해시값
 * @param[in] contents 인증서컨텐츠
 * @param[in] buf_size CMHF 버퍼의 남은 길이
 * @param[out] ptr CMHF 버퍼 내에서 공통정보를 채우기 시작할 위치
 * @return 성공 시 채워진 정보의 길이, 실패 시 결과코드(-Dot2ResultCode)
 */
int INTERNAL dot2_FillCMHFCommonInfo(
  Dot2CMHType cmh_type,
  const struct Dot2SHA256 *issuer_h,
  const struct Dot2EECertContents *contents,
  int buf_size,
  uint8_t *ptr)
{
  Log(kDot2LogLevel_Event, "Fill CMHF common info\n");

  int remained = buf_size;
  struct Dot2CMHFCommonInfo *info = (struct Dot2CMHFCommonInfo *)ptr;

  /*
   * 필수정보를 채운다.
   */
  if (remained < (int)sizeof(struct Dot2CMHFCommonInfo)) {
    return -kDot2Result_CMHF_TooLong;
  }
  info->cmh_type = (uint8_t)cmh_type;
  memcpy(info->issuer_h8, DOT2_GET_SHA256_H8(issuer_h->octs), 8);
  memcpy(info->craca_id, contents->common.craca_id, DOT2_CRACA_ID_LEN);
  info->crl_series = htons((uint16_t)(contents->common.crl_series));
  info->valid_start = htonl(dot2_ConvertTime64ToTime32(contents->common.valid_start));
  info->valid_end = htonl(dot2_ConvertTime64ToTime32(contents->common.valid_end));
  info->valid_region_type = (uint8_t)(contents->common.valid_region.type);
  info->psid_num = (uint8_t)(contents->app_perms.psid_num);
  ptr += sizeof(struct Dot2CMHFCommonInfo);
  remained -= sizeof(struct Dot2CMHFCommonInfo);

  /*
   * 옵션정보를 채운다.
   */
  if (remained < (int)(sizeof(uint32_t) * info->psid_num)) {
    return -kDot2Result_CMHF_TooLong;
  }
  for (uint8_t i = 0; i < info->psid_num; i++) {
    *(uint32_t *)ptr = htonl((uint32_t)(contents->app_perms.psid[i]));
    ptr += sizeof(uint32_t);
    remained -= sizeof(uint32_t);
  }

  if (contents->common.valid_region.type == kDot2CertValidRegionType_Circular) {
    if (remained < (int)sizeof(struct Dot2CMHFInfoCircularRegion)) {
      return -kDot2Result_CMHF_TooLong;
    }
    struct Dot2CMHFInfoCircularRegion *cmhf_region = (struct Dot2CMHFInfoCircularRegion *)ptr;
    cmhf_region->center.lat = htonl(contents->common.valid_region.u.circular.center.lat);
    cmhf_region->center.lon = htonl(contents->common.valid_region.u.circular.center.lon);
    cmhf_region->radius = htons(contents->common.valid_region.u.circular.radius);
    ptr += sizeof(struct Dot2CMHFInfoCircularRegion);
    remained -= sizeof(struct Dot2CMHFInfoCircularRegion);
  } else if (contents->common.valid_region.type == kDot2CertValidRegionType_Identified) {
    if (remained < (int)(sizeof(uint8_t) + sizeof(uint16_t) * contents->common.valid_region.u.id.num)) {
      return -kDot2Result_CMHF_TooLong;
    }
    struct Dot2CMHFInfoIdentifiedRegions *cmhf_region = (struct Dot2CMHFInfoIdentifiedRegions *)ptr;
    cmhf_region->num = (uint8_t)(contents->common.valid_region.u.id.num);
    ptr += sizeof(uint8_t);
    remained -= sizeof(uint8_t);
    for (uint8_t i = 0; i < cmhf_region->num; i++) {
      *(uint16_t *)ptr = htons((uint16_t)(contents->common.valid_region.u.id.country[i]));
      ptr += sizeof(uint16_t);
      remained -= sizeof(uint16_t);
    }
  }
  return buf_size - remained;
}


/**
 * @brief CMHF 버퍼에 개별정보를 채운다.
 * @param[in] cert 인증서바이트열
 * @param[in] cert_h 인증서 해시값
 * @param[in] priv_key 개인키
 * @param[in] contents EE 인증서컨텐츠정보
 * @param[in] buf_size CMHF 버퍼의 남은 길이
 * @param[out] ptr CMHF 버퍼 내에서 개별정보를 채우기 시작할 위치
 * @return 성공 시 채워진 정보의 길이, 실패 시 결과코드(-Dot2ResultCode)
 */
int INTERNAL dot2_FillCMHFIndividualInfo(
  const struct Dot2Cert *cert,
  const struct Dot2SHA256 *cert_h,
  const struct Dot2ECPrivateKey *priv_key,
  const struct Dot2EECertContents *contents,
  int buf_size,
  uint8_t *ptr)
{
  Log(kDot2LogLevel_Event, "Fill CMHF individual info\n");

  int remained = buf_size;
  struct Dot2CMHFIndividualInfo *info = (struct Dot2CMHFIndividualInfo *)ptr;

  /*
   * 필수 정보를 채운다.
   */
  if (remained < (int)sizeof(struct Dot2CMHFIndividualInfo)) {
    return -kDot2Result_CMHF_TooLong;
  }
  info->cert_size = htons((uint16_t)(cert->size));
  memcpy(info->cert_h, cert_h->octs, DOT2_SHA_256_LEN);
  info->cert_id_type = (uint8_t)(contents->common.id.type);
  info->priv_key_type = (uint8_t)kDot2PrivKeyType_Key;
  ptr += sizeof(struct Dot2CMHFIndividualInfo);
  remained -= (int)sizeof(struct Dot2CMHFIndividualInfo);

  /*
   * 옵션정보를 채운다.
   */
  if (remained < DOT2_EC_256_KEY_LEN) {
    return -kDot2Result_CMHF_TooLong;
  }
  memcpy(ptr, priv_key->octs, DOT2_EC_256_KEY_LEN);
  ptr += DOT2_EC_256_KEY_LEN;
  remained -= DOT2_EC_256_KEY_LEN;
  if (contents->common.id.type == kDot2CertIdType_LinkageData) {
    if (remained < (int)sizeof(struct Dot2CMHFInfoLinakgeData)) {
      return -kDot2Result_CMHF_TooLong;
    }
    struct Dot2CMHFInfoLinakgeData *id = (struct Dot2CMHFInfoLinakgeData *)ptr;
    id->i = htons(contents->common.id.u.linkage_data.i);
    memcpy(id->val, contents->common.id.u.linkage_data.val, DOT2_LINKAGE_VALUE_LEN);
    id->grp_present = (uint8_t)(contents->common.id.u.linkage_data.grp_present);
    memcpy(id->grp.j, contents->common.id.u.linkage_data.grp.j, DOT2_GROUP_LINKAGE_J_VALUE_LEN);
    memcpy(id->grp.val, contents->common.id.u.linkage_data.grp.val, DOT2_LINKAGE_VALUE_LEN);
    ptr += sizeof(struct Dot2CMHFInfoLinakgeData);
    remained -= (int)sizeof(struct Dot2CMHFInfoLinakgeData);;
  } else if (contents->common.id.type == kDot2CertIdType_Name) {
    if (remained < (int)(sizeof(uint8_t) + contents->common.id.u.name.len)) {
      return -kDot2Result_CMHF_TooLong;
    }
    struct Dot2CMHFInfoHostName *id = (struct Dot2CMHFInfoHostName *)ptr;
    id->len = (uint8_t)(contents->common.id.u.name.len);
    ptr += sizeof(uint8_t);
    remained -= sizeof(uint8_t);
    memcpy(ptr, contents->common.id.u.name.name, id->len);
    ptr += id->len;
    remained -= id->len;
  } else if (contents->common.id.type == kDot2CertIdType_BinaryId) {
    if (remained < (int)(sizeof(uint8_t) + contents->common.id.u.binary_id.len)) {
      return -kDot2Result_CMHF_TooLong;
    }
    struct Dot2CMHFInfoBinaryID *id = (struct Dot2CMHFInfoBinaryID *)ptr;
    id->len = (uint8_t)(contents->common.id.u.binary_id.len);
    ptr += sizeof(uint8_t);
    remained -= sizeof(uint8_t);
    memcpy(ptr, contents->common.id.u.binary_id.id, id->len);
    ptr += id->len;
    remained -= id->len;
  }
  if (remained < (int)(cert->size)) {
    return -kDot2Result_CMHF_TooLong;
  }
  memcpy(ptr, cert->octs, cert->size);
  remained -= (int)(cert->size);

  return (buf_size - remained);
}


/**
 * @brief CMHF의 이름을 생성한다.
 * @param[in] cmh_type 생성하고자 하는 CMHF의 CMH 유형 (app, id, enrol 만 가능하다)
 * @param[in] priv_key_type 개인키 유형
 * @param[in] contents 인증서컨텐츠정보
 * @param[out] err 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 생성된 CMHF 이름 문자열
 * @retval NULL: 실패
 *
 * CMHF 이름 규칙은 다음과 같다.
 *  - <CMH유형>_<psid#1>_..._<psid#N>_<valid start>_<valid end>_<key/idx>.cmhf2
 */
char INTERNAL * dot2_MakeCMHFName(
  Dot2CMHType cmh_type,
  Dot2PrivKeyType priv_key_type,
  const struct Dot2EECertContents *contents,
  int *err)
{
  int ret;
  Log(kDot2LogLevel_Event, "Make CMHF name\n");

  // 임시 버퍼
  char t[40];
  memset(t, 0, sizeof(t));

  /*
   * 버퍼를 최대길이로 할당한다.
   */
  ret = -kDot2Result_NoMemory;
  char *cmhf_name = (char *)calloc(1, kDot2CMHFNameLen_Max);
  if (!cmhf_name) {
    goto err;
  }
  int buf_size = kDot2CMHFNameLen_Max, remained = kDot2CMHFNameLen_Max;

  /*
   * CMH 유형을 삽입한다.
   */
  if (cmh_type == kDot2CMHType_Application) {
    snprintf(cmhf_name, remained, "a_");
  } else if (cmh_type == kDot2CMHType_Identification) {
    snprintf(cmhf_name, remained, "i_");
  } else if (cmh_type == kDot2CMHType_Enrollment) {
    snprintf(cmhf_name, remained, "e_");
  } else if (cmh_type == kDot2CMHType_Pseudonym) {
    snprintf(cmhf_name, remained, "p_");
  }
  remained = buf_size - (int)strlen(cmhf_name);

  ret = -kDot2Result_CMHF_TooLongName;

  /*
   * psid(들)을 삽입한다.
   */
  for (unsigned int cnt = 0; cnt < contents->app_perms.psid_num; cnt++) {
    memset(t, 0, sizeof(t));
    snprintf(t, sizeof(t), "%u_", contents->app_perms.psid[cnt]);
    if (remained < (int)strlen(t)) {
      goto err;
    }
    strcat(cmhf_name, t);
    remained = buf_size - (int)strlen(cmhf_name);
  }

  /*
   * 유효기간을 삽입한다.
   */
  time_t valid_start = dot2_ConvertTime32ToSystemTimeSeconds(dot2_ConvertTime64ToTime32(contents->common.valid_start));
  time_t valid_end = dot2_ConvertTime32ToSystemTimeSeconds(dot2_ConvertTime64ToTime32(contents->common.valid_end));
  struct tm tm_valid_start, tm_valid_end;
  memset(&tm_valid_start, 0, sizeof(struct tm));
  memset(&tm_valid_end, 0, sizeof(struct tm));
  localtime_r(&valid_start, &tm_valid_start);
  localtime_r(&valid_end, &tm_valid_end);
  memset(t, 0, sizeof(t));
  snprintf(t, sizeof(t), "%02u%02u%02u.%02u%02u%02u-%02u%02u%02u.%02u%02u%02u",
           tm_valid_start.tm_year + 1900 - 2000, tm_valid_start.tm_mon + 1, tm_valid_start.tm_mday,
           tm_valid_start.tm_hour, tm_valid_start.tm_min, tm_valid_start.tm_sec,
           tm_valid_end.tm_year + 1900 - 2000, tm_valid_end.tm_mon + 1, tm_valid_end.tm_mday,
           tm_valid_end.tm_hour, tm_valid_end.tm_min, tm_valid_end.tm_sec);
  if (remained < (int)strlen(t)) {
    goto err;
  }
  strcat(cmhf_name, t);
  remained = buf_size - (int)strlen(cmhf_name);

  /*
   * 키값이 저장되었는지 or 키 인덱스가 저장되었는지 여부와 확장자를 삽입한다.
   */
  memset(t, 0, sizeof(t));
  if (priv_key_type == kDot2PrivKeyType_Key) {
    sprintf(t, "_key.cmhf2");
  } else {
    sprintf(t, "_idx.cmhf2");
  }
  if (remained < (int)strlen(t)) {
    goto err;
  }
  strcat(cmhf_name, t);

  Log(kDot2LogLevel_Event, "Success to make CMHF name - %s\n", cmhf_name);
  return cmhf_name;

err:
  *err = ret;
  if (cmhf_name) { free(cmhf_name); }
  return NULL;
}
