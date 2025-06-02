/** 
 * @file
 * @brief CMHF 로딩 기능 구현
 * @date 2020-05-29
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "certificate/cmh/dot2-cmh-sequential.h"


/**
 * @brief CMHF 내 H8값이 유효한지 확인한다.
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @return 유효한지 여부
 *
 * CMHF의 마지막 8바이트는 CMHF에 대한 H8 값이다. H8 값을 제외한 CMHF에 대한 H8값을 계산하여 해당 값과 비교한다.
 */
static inline bool dot2_CheckCMHFH8(const uint8_t *cmhf, Dot2CMHFSize cmhf_size)
{
  uint8_t h[DOT2_SHA_256_LEN];
  SHA256(cmhf, cmhf_size - 8, h);
  return (memcmp(cmhf + cmhf_size - 8, DOT2_GET_SHA256_H8(h), 8) == 0) ? true : false;
}


/**
 * @brief CMHF 바이트열로부터 정보를 추출하여 CMH 저장소에 추가한다.
 * @param[in] cmhf CMHF 바이트열
 * @param[in] cmhf_size CMHF 바이트열의 길이
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_LoadCMHF(const uint8_t *cmhf, Dot2CMHFSize cmhf_size)
{
  Log(kDot2LogLevel_Event, "Load CMHF\n");
  struct Dot2SequentialCMHFInfo *cmhf_info = (struct Dot2SequentialCMHFInfo *)cmhf;

  /*
   * CMHF 유효성을 체크한다 - 매직넘버 및 H8 값의 유효성을 확인한다.
   */
  if (dot2_CheckCMHFMagicNumber(ntohl(cmhf_info->magic_number)) == false) {
    Err("Fail to load CMHF - invalid magic number: %u\n", ntohl(cmhf_info->magic_number));
    return -kDot2Result_CMHF_InvalidMagicNumber;
  }
  if (dot2_CheckCMHFH8(cmhf, cmhf_size) == false) {
    Err("Fail to load CMHF - invalid H8\n");
    return -kDot2Result_CMHF_InvalidH8;
  }

  const uint8_t *ptr = cmhf + sizeof(uint32_t);
  int remained = (int)(cmhf_size - sizeof(uint32_t));

  /*
   * CMHF 내 CMH 유형정보에 따라 해당되는 CMH를 생성한다.
   */
  int ret;
  Dot2CMHType cmh_type = (Dot2CMHType)(cmhf_info->common.cmh_type);
  if ((cmh_type == kDot2CMHType_Application) ||
      (cmh_type == kDot2CMHType_Enrollment)) {
    ret = dot2_AddSequentialCMHfromCMHF(cmh_type, ptr, remained);
  } else if ((cmh_type == kDot2CMHType_Pseudonym) ||
             (cmh_type == kDot2CMHType_Identification)) {
    ret = dot2_AddRotateCMHfromCMHF(cmh_type, ptr, remained);
  } else {
    ret = -kDot2Result_CMHF_InvalidCMHType;
  }
  return ret;
}


/**
 * @brief CMHF 공통정보의 유효성을 체크한다.
 * @param[in] info CMHF 공통정보
 * @retval 0: 유효함
 * @retval 음수(-Dot2ResultCode): 유효하지 않음
 */
int INTERNAL dot2_CheckCMHFCommonInfo(struct Dot2CMHFCommonInfo *info)
{
  Log(kDot2LogLevel_Event, "Check CMHF common info\n");

  /*
   * CMH 유형 및 CRL sereis 값의 유효성을 체크한다.
   */
  Dot2CMHType cmh_type = (Dot2CMHType)(info->cmh_type);
  Dot2CertCRLSeries crl_series = (Dot2CertCRLSeries)ntohs(info->crl_series);
  if ((cmh_type == kDot2CMHType_Application) ||
      (cmh_type == kDot2CMHType_Identification)) {
#if 0 // NOTE:: 일부 인증서의 경우, CRLseries가 잘못된 경우가 있어, 체크를 생략한다.
    if (crl_series != kDot2CertCRLSeries_EeNonPseudonym) {
      Err("Fail to check CMHF common info - invalid App/Id cert CRL series: %u\n", crl_series);
      return -kDot2Result_CMHF_InvalidCRLSeries;
    }
#endif
  } else if (cmh_type == kDot2CMHType_Pseudonym) {
#if 0 // NOTE:: 일부 인증서의 경우, CRLseries가 잘못된 경우가 있어, 체크를 생략한다.
    if (crl_series != kDot2CertCRLSeries_ObuPseudonym) {
      Err("Fail to check CMHF common info - invalid Pseudonym cert CRL series: %u\n", crl_series);
      return -kDot2Result_CMHF_InvalidCRLSeries;
    }
#endif
  } else if (cmh_type == kDot2CMHType_Enrollment) {
#if 0 // NOTE:: 일부 인증서의 경우, CRLseries가 잘못된 경우가 있어, 체크를 생략한다.
    if (crl_series != kDot2CertCRLSeries_EeEnrollment) {
      Err("Fail to check CMHF common info - invalid Enrollment cert CRL series: %u\n", crl_series);
      return -kDot2Result_CMHF_InvalidCRLSeries;
    }
#endif
  } else {
    Err("Fail to check CMHF common info - invalid CMH type: %u\n", cmh_type);
    return -kDot2Result_CMHF_InvalidCMHType;
  }

  /*
   * 유효기간의 유효성을 체크한다.
   */
  Dot2Time32 valid_start = (Dot2Time32)ntohl(info->valid_start);
  Dot2Time32 valid_end = (Dot2Time32)ntohl(info->valid_end);
  if ((valid_start == 0) ||
      (valid_end == 0) ||
      (valid_start > valid_end)) {
    Err("Fail to check CMHF common info - invalid valid time (start: %u, end: %u)\n", valid_start, valid_end);
    return -kDot2Result_CMHF_InvalidCertValidTime;
  }

  /*
   * 유효지역 유형의 유효성을 체크한다.
   */
  Dot2CertValidRegionType valid_region_type = (Dot2CertValidRegionType)(info->valid_region_type);
  if ((valid_region_type != kDot2CertValidRegionType_Circular) &&
      (valid_region_type != kDot2CertValidRegionType_Identified)) {
    Err("Fail to check CMHF common info - invalid region type: %u\n", valid_region_type);
    return -kDot2Result_CMHF_InvalidValidRegionType;
  }

  /*
   * PSID(권한) 개수의 유효성을 체크한다.
   */
  Dot2CertPermissionNum psid_num = (Dot2CertPermissionNum)(info->psid_num);
  if ((psid_num == 0) ||
      (psid_num > kDot2CertPermissionNum_Max)) {
    Err("Fail to check CMHF common info - invalid PSID num: %u\n", psid_num);
    return -kDot2Result_CMHF_InvalidPermissionNum;
  }

  return kDot2Result_Success;
}


/**
 * @brief CMHF 개별정보의 유효성을 체크한다.
 * @param[in] info CMHF 개별정보
 * @retval 0: 유효함
 * @retval 음수(-Dot2ResultCode): 유효하지 않음
 */
int INTERNAL dot2_CheckCMHFIndividualInfo(struct Dot2CMHFIndividualInfo *info)
{
  /*
   * 인증서 크기의 유효성을 체크한다.
   */
  if (dot2_CheckCertSize((Dot2CertSize)ntohs(info->cert_size)) == false) {
    return -kDot2Result_CMHF_InvalidCertSize;
  }

  /*
   * 인증서 ID 유형의 유효성을 체크한다.
   */
  if (dot2_CheckCertIdType((Dot2CertIdType)(info->cert_id_type)) == false) {
    return -kDot2Result_CMHF_InvalidCertIdType;
  }

  /*
   * 개인키 유형의 유효성을 체크한다.
   */
  if (dot2_CheckPrivKeyType((Dot2PrivKeyType)(info->priv_key_type)) == false) {
    return -kDot2Result_CMHF_InvalidPrivKeyType;
  }
  return kDot2Result_Success;
}


/**
 * @brief CMHF 파일로부터 정보를 추출하여 CMH 저장소에 추가한다.
 * @param[in] file_path CMHF 파일 경로(상대경로 및 절대경로 모두 가능)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_LoadCMHFFile(const char *file_path)
{
  Log(kDot2LogLevel_Event, "Load CMHF file - %s\n", file_path);

  /*
   * CMHF 파일 내용을 저장할 버퍼를 할당한다.
   */
  uint8_t *cmhf = (uint8_t *)calloc(1, kDot2CMHFSize_Max);
  if (cmhf == NULL) {
    Err("Fail to load CMHF file - calloc(cmhf) failed: %m\n");
    return -kDot2Result_NoMemory;
  }

  /*
   * CMHF 파일의 내용을 import한다.
   */
  int cmhf_size = dot2_ImportFile(file_path, cmhf, kDot2CMHFSize_Min, kDot2CMHFSize_Max);
  if (cmhf_size < 0) {
    free(cmhf);
    return cmhf_size;
  }

  /*
   * CMHF의 길이를 확인한다.
   */
  if (dot2_CheckCMHFSize(cmhf_size) == false) {
    free(cmhf);
    return -kDot2Result_CMHF_InvalidSize;
  }

  /*
   * CMH를 등록한다.
   */
  int ret = dot2_LoadCMHF(cmhf, cmhf_size);
  free(cmhf);
  if (ret < 0) {
    return ret;
  }

  Log(kDot2LogLevel_Event, "Sucess to load CMHF file\n");
  return kDot2Result_Success;
}
