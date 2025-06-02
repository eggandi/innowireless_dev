/** 
 * @file
 * @brief CMHF(Crypto Material Handle File) 정보 형식을 정의한 헤더 파일
 * @date 2020-05-28
 * @author gyun
 *
 * CMHF는 CMH를 파일로 저장한 정보를 의미한다. \n
 * 어플리케이션은 CMHF 파일을 읽어들여 CMH를 확보한다.
 */


#ifndef V2X_SW_DOT2_CMHF_C_H
#define V2X_SW_DOT2_CMHF_C_H


// 시스템 헤더 파일
#include <stdint.h>


#define CMHF_MAGIC_NUMBER (0x4954454B) ///< CMHF 유효성을 확인하기 위한 매직넘버


/**
 * @brief CMHF에 저장되는 2D 좌표 정보 형식 (struct Dot2TwoDLocation 참조)
 */
struct Dot2CMHFInfoTwoDLocation
{
  int32_t lat; ///< 위도
  int32_t lon; ///< 경도
} __attribute__((packed));


/**
 * @brief CMHF에 저장되는 CircularRegion 정보 형식 (struct Dot2CircularRegion 참조)
 */
struct Dot2CMHFInfoCircularRegion
{
  struct Dot2CMHFInfoTwoDLocation center; ///< 중심점
  uint16_t radius; ///< 반지름(미터단위)
} __attribute__((packed));


/**
 * @brief CMHF에 저장되는 IdentifiedRegion 정보 형식 (struct Dot2CertIdentifiedRegions 참조)
 */
struct Dot2CMHFInfoIdentifiedRegions
{
  uint8_t num; ///> region 정보의 개수
  // num 개의 uint16_t region 정보 존재 (countryOnly)
} __attribute__((packed));


/**
 * @brief CMHF에 저장되는 BinaryID 유형 Id 정보 (struct Dot2CertBinaryId 참조)
 */
struct Dot2CMHFInfoBinaryID
{
  uint8_t len; // id의 길이
  // len 바이트 길이의 uint8_t id[] 바이트열 존재
} __attribute__((packed));


/**
 * @brief CMHF에 저장되는 Name 유형 Id 정보 (struct Dot2CertHostName 참조)
 */
struct Dot2CMHFInfoHostName
{
  uint8_t len; ///< name의 길이
  // len 바이트 길이의 uint8_t name[] 바이트열 존재
} __attribute__((packed));


/**
 * @brief CMHF에 저장되눈 LinkageData 유형 Id 정보 (struct Dot2CertLinakgeData 참조)
 */
struct Dot2CMHFInfoLinakgeData
{
  uint16_t i; ///< iCert
  uint8_t val[DOT2_LINKAGE_VALUE_LEN]; ///< linkage-value
  uint8_t grp_present; ///< grp 정보 존재 여부 (bool)
  struct {
    uint8_t j[DOT2_GROUP_LINKAGE_J_VALUE_LEN]; ///< jValue
    uint8_t val[DOT2_LINKAGE_VALUE_LEN]; ///< value
  } grp; ///< group-linkage-value
} __attribute__((packed));


/**
 * @brief CMHF에 저장되는 개인키 인덱스 관련 정보
 */
struct Dot2CMHFInfoPrivKeyIdx
{
  uint8_t len; ///< 개인키 인덱스의 길이
  // len 바이트 길이의 개인키 인덱스 관련 정보 바이트열
} __attribute__((packed));


/**
 * @brief CMHF 공통정보 형식
 *
 * Rotate CMHF일 경우, Rotate CMHF 묶음에 포함된 각 Pseudonym 인증서 간에 동일한 값을 갖는 정보들의 모음
 */
struct Dot2CMHFCommonInfo
{
  /*
   * 필수 정보
   */
  uint8_t cmh_type; ///< CMH 유형 (Dot2CMHType)
  uint8_t issuer_h8[8]; ///< 상위인증서 HashedId8
  uint8_t craca_id[DOT2_CRACA_ID_LEN]; ///< cracaId
  uint16_t crl_series; ///< CRL series (Dot2CertCRLSeries)
  uint32_t valid_start; ///< 인증서 유효기간 시작 시점 (Dot2Time32)
  uint32_t valid_end; ///< 인증서 유효기간 종료 시점 (Dot2Time32)
  uint8_t valid_region_type; ///< 유효지역정보 유형(Dot2CertValidRegionType)
  uint8_t psid_num; ///< psid 개수 (Dot2CertPermissionNum)

  /*
   * 옵션 정보. 상황에 따라 존재하거나 존재하지 않는 정보들이다.
   */
  // 1. psid_num 개의 uint32_t psid 정보 존재
  //    V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라, EE 인증서의 권한에는 PSID만 포함된다)
  // 2-1. (valid_region_type == circular)인 경우
  //      "Circular" 유형의 유효지역 정보 존재 (struct Dot2CMHFInfoCircularRegion)
  // 2-2. (valid_region_type == identified)인 경우
  //      "Identified" 유형의 유효지역 정보 존재 (struct Dot2CMHFInfoIdentifiedRegions)
} __attribute__((packed));


/**
 * @brief CMHF 개별정보 형식
 *
 * Rotate CMHF일 경우, Rotate CMHF 묶음에 포함된 각 Pseudonym 인증서 간에 상이한 값을 갖는 정보들의 모음
 */
struct Dot2CMHFIndividualInfo
{
  /*
   * 필수 정보
   */
  uint16_t cert_size; ///< 인증서데이터 크기 (Dot2CertSize)
  uint8_t cert_h[DOT2_SHA_256_LEN]; ///< 인증서 해시
  uint8_t cert_id_type; ///< 인증서 ID 정보 유형 (Dot2CertIdType)
  //uint8_t pub_key[DOT2_EC_256_PUB_KEY_LEN]; ///< 공개키
  uint8_t priv_key_type; ///< 개인키유형(Dot2PrivKeyType) NOTE:: 현재 kDot2PrivKeyType_Key 만 사용된다.

  /*
   * 옵션 정보. 상황에 따라 존재하거나 존재하지 않는 정보들이다.
   */
  // 1-1. (priv_key_type == kDot2PrivKeyType_Idx)인 경우
  //      priv_key_idx 정보 존재 (struct Dot2CMHFInfoPrivKeyIdx)
  // 1-2. (priv_key_type == kDot2PrivKeyType_Key)인 경우
  //      uint8_t priv_key[DOT2_EC_256_KEY_LEN] 정보 존재
  // 2-1. (cert_id_type == BinaryId)인 경우
  //      "BinaryId" 유형의 인증서 ID 존재 (struct Dot2CMHFInfoBinaryID)
  // 2-2. (cert_id_type == LinkageData)인 경우
  //      "LinkageData" 유형의 인증서 ID 존재 (struct Dot2CMHFInfoLinakgeData)
  // 2-3. (cert_id_type == Name)인 경우
  //      "Name" 유형의 인증서 ID 존재 (struct Dot2CMHFInfoHostName)
  // 3. 인증서 존재 (길이 = cert_size)
} __attribute__((packed));


/**
 * @brief Sequential 인증서에 대한 CMHF 정보 형식 (Application, Identification, Enrollment 인증서에 대한 CMHF 정보 형식)
 *        (struct Dot2SequentialCMHEntry 참조)
 *
 * 사이즈 고정 변수형과 바이트 정렬 해제를 적용하여 실행 플랫폼에 무관하게 동일한 파일의 사용이 가능함
 * NOTE:: common 정보와 individual 정보는 가변길이 정보이므로 본 구조체 형식을 그대로 사용해서는 안됨.
 */
struct Dot2SequentialCMHFInfo
{
  uint32_t magic_number; ///< 유효한 CMHF인지를 판별하기 위한 매직넘버
  struct Dot2CMHFCommonInfo common; ///< CMHF 공통정보
  struct Dot2CMHFIndividualInfo individual; ///< CMHF 개별정보
  uint8_t h8[8]; ///< magic number, common, individual 정보를 포함한 바이트열에 대한 H8 값
} __attribute__((packed));


/**
 * @brief Rotate 인증서 세트에 대한 CMHF 정보 형식 (Pseudonym 인증서 묶음에 대한 CMHF 정보 형식)
 *        (struct Dot2RotateCMHSetEntry 참조)
 *
 * 사이즈 고정 변수형과 바이트 정렬 해제를 적용하여 실행 플랫폼에 무관하게 동일한 파일의 사용이 가능함
 * NOTE:: common 정보와 individual 정보는 가변길이 정보이므로 본 구조체 형식을 그대로 사용해서는 안됨.
 */
struct Dot2RotateCMHFSetInfo
{
  uint32_t magic_number; ///< 유효한 CMHF인지를 판별하기 위한 매직넘버
  struct Dot2CMHFCommonInfo common; ///< CMHF 공통정보
  uint32_t i; ///< 인증서 i-period 값
  uint8_t cert_num; ///< 동일한 Rotate 세트 내 인증서 개수 (V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라 현재 20의 값을 가진다)
  // cert_num 개의 인증서 개별 정보 존재 (struct Dot2CMHFIndividualInfo)
  uint8_t h8[8]; ///< magic number, common, individual 정보를 포함한 바이트열에 대한 H8 값
} __attribute__((packed));


#endif //V2X_SW_DOT2_CMHF_C_H
