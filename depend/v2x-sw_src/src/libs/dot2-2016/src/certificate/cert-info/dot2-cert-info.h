/** 
 * @file
 * @brief 인증서 정보 헤더 파일
 * @date 2020-03-20
 * @author gyun
 */


#ifndef V2X_SW_2019_DOT2_CERT_INFO_H
#define V2X_SW_2019_DOT2_CERT_INFO_H


// 시스템 헤더 파일
#include <stdint.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-defines.h"
#include "dot2-internal-types.h"


/**
 * @brief 인증서정보 엔트리 개수
 */
enum eDot2CertInfoEntryNum
{
  kDot2CertInfoEntryNum_Max = 10000, ///< 엔트리 최대개수(임의로 정함)
};
typedef unsigned int Dot2CertInfoEntryNum; ///< @ref eDot2CertInfoEntryNum


/**
 * @brief 인증서 유형
 */
enum eDot2CertType
{
  kDot2CertType_Explicit, ///< Explicit 인증서 (서명검증용 공개키와 서명이 포함된 인증서)
  kDot2CertType_Implicit ///< Implicit 인증서 (서명검증용 공개키 재구성값이 포함된 인증서)
};
typedef unsigned int Dot2CertType; ///< @ref eDot2CertType


/**
 * @brief 인증서 내 CRL Series
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1 참조
 *  - 인증서 폐지 목록 프로파일 규격 부록.1
 *  - 인증서 프로파일 규격 부록.1
 */
enum eDot2CertCRLSeries
{
  kDot2CertCRLSeries_RootCA = 0, ///< RootCA 인증서
  kDot2CertCRLSeries_Elector = 0, ///< Elector 인증서
  kDot2CertCRLSeries_ObuPseudonym = 1, ///< 익명(Pseudonym) 인증서
  kDot2CertCRLSeries_ScmsComponent = 2, ///< ICA,ECA,ACA/PCA,RA,LA,DCM 인증서
  kDot2CertCRLSeries_EeNonPseudonym = 3, ///< 응용(Application) 인증서, 식별(Identification) 인증서
  kDot2CertCRLSeries_EeEnrollment = 4, ///< 등록(Enrollment) 인증서
  kDot2CertCRLSeries_ScmsSpclComponent = 256, ///< PG, MA, CRLG 인증서
};
typedef unsigned int Dot2CertCRLSeries; ///< @ref Dot2CertCRLSeries


/**
 * @brief 인증서 내 유효지역 정보 유형
 *
 * IEEE 1609.2-2016 표준에는 circular, rectangular, polygonal, identified 유형이 정의되어 있으나,
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라 실제로는 circular, identified 유형만 사용되고 있다.
 */
enum eDot2CertValidRegionType
{
  kDot2CertValidRegionType_None, ///< 유효지역 정보가 없음
  kDot2CertValidRegionType_Circular, ///< 원형 영역정보
  kDot2CertValidRegionType_Identified, ///< 식별자 기반 영역정보 (예: 한국은 X 번)
};
typedef unsigned int Dot2CertValidRegionType; ///< @ref eDot2CertValidRegionType


/**
 * @brief 인증서 내 id 정보의 유형
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라,
 *  - SCC인증서: name 유형
 *  - Application 인증서: binaryId 유형
 *  - Identification 인증서: binaryId 유형
 *  - Pseudonym 인증서: linkageData 유형
 *  - Enrollment 인증서: 빈 문자열("")을 갖는 name 유형
 * 을 가진다.
 */
enum eDot2CertIdType
{
  kDot2CertIdType_LinkageData = 0,
  kDot2CertIdType_Name = 1,
  kDot2CertIdType_BinaryId = 2,
  kDot2CertIdType_None = 3,
  kDot2CertIdType_Max = kDot2CertIdType_None,
};
typedef unsigned int Dot2CertIdType; ///< @ref eDot2CertIdType


/**
 * @brief 인증서 내 binaryId 길이
 */
enum eDot2CertBinaryIdLen
{
  kDot2CertBinaryIdLen_Min = 1, ///< per IEEE 1609.2-2016 asn.1
  kDot2CertBinaryIdLen_Default = 8, ///< per V2X 보안인증체계 세부 기술규격(KISA) v1.1
  kDot2CertBinaryIdLen_Max = 64 ///< per IEEE 1609.2-2016 asn.1
};
typedef unsigned int Dot2CertBinaryIdLen; ///< @ref eDot2CertBinaryIdLen


/**
 * @brief VerificationKeyIndicator 유형
 */
enum eDot2CertVerificationKeyIndicatorType
{
  kDot2CertVerificationKeyIndicatorType_Key, ///< 키
  kDot2CertVerificationKeyIndicatorType_ReconstructValue, ///< 재구성값
  kDot2CertVerificationKeyIndicatorType_Max = kDot2CertVerificationKeyIndicatorType_ReconstructValue
};
typedef unsigned int Dot2CertVerificationKeyIndicatorType; ///< @ref eDot2CertVerificationKeyIndicatorType



/**
 * @brief IssuerIdentifier 유형
 */
enum eDot2CertIssuerIdentifierType
{
  kDot2CertIssuerIdentifierType_Sha256AndDigest, ///< SHA256 해시값의 HashedId8
  kDot2CertIssuerIdentifierType_Self, ///< Self 서명
};
typedef unsigned int Dot2CertIssuerIdentifierType; ///< @ref eDot2CertIssuerIdentifierType


/**
 * @brief 인증서정보의 폐기 상태
 */
enum eDot2CertRevocationStatus
{
  kDot2CertRevocationStatus_NotChecked, ///< 아직 확인되지 않음
  kDot2CertRevocationStatus_Revoked, ///< 폐기됨
  kDot2CertRevocationStatus_NotRevoked, ///< 폐기되지 않음
};
typedef unsigned int Dot2CertRevocationStatus; ///< @ref eDot2CertRevocationStatus


/**
 * @brief 인증서 내 LinkageData 유형 Id 정보
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라, Pseudonym 인증서 내에만 존재한다.
 */
struct Dot2CertLinakgeData
{
  uint16_t i; ///< iCert
  uint8_t val[DOT2_LINKAGE_VALUE_LEN]; ///< linkage-value
  bool grp_present;
  struct {
    uint8_t j[DOT2_GROUP_LINKAGE_J_VALUE_LEN]; ///< jValue
    uint8_t val[DOT2_LINKAGE_VALUE_LEN]; ///< value
  } grp; ///< group-linkage-value
};


/**
 * @brief 인증서 내 binaryId 유형 Id 정보
 */
struct Dot2CertBinaryId
{
  Dot2CertBinaryIdLen len; ///< binaryId의 길이
  uint8_t id[kDot2CertBinaryIdLen_Default]; ///< binaryId 값
};


/**
 * @brief 인증서 내 name 유형 Id 정보
 */
struct Dot2CertHostName
{
  Dot2CertIdHostNameLen len; ///< name의 길이
  char *name; ///< name 값
};


/**
 * @brief 인증서 내 id 정보
 */
struct Dot2CertId
{
  Dot2CertIdType type; ///< id 유형
  union {
    struct Dot2CertLinakgeData linkage_data; ///< type=linkageData인 경우
    struct Dot2CertHostName name; ///< type=name인 경우 동적할당된 문자열
    struct Dot2CertBinaryId binary_id; ///< type=binaryId인 경우
  } u;
};


/**
 * @brief 식별자 유형의 유효지역 정보
 *
 * IEEE 1609.2-2016 표준에는 countryOnly, countryAndRegion, countryAndSubregion 유형의 정보가 정의되어 있으나,
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라 실제로는 countryOnly 유형의 정보만 사용되고 있다.
 */
struct Dot2CertIdentifiedRegions
{
  Dot2IdentifiedRegionNum num; ///> region 정보의 개수
  Dot2CountryCode country[kDot2IdentifiedRegionNum_Max]; ///< countryOnly 유형의 region 정보(들)
};


/**
 * @brief 인증서 유효지역 정보
 */
struct Dot2CertValidRegion2
{
  Dot2CertValidRegionType type; ///< 인증서 유효지역 유형
  union {
    struct Dot2CircularRegion circular; ///< 원형 유효지역
    struct Dot2CertIdentifiedRegions id; ///< 식별자 유형 유효지역
  } u;
};


/**
 * @brief 인증서 내 VerificationKeyIndicator 정보 형식
 */
struct Dot2CertVerificationKeyIndicator
{
  Dot2CertVerificationKeyIndicatorType type; ///< 검증키 지시자 유형
  struct Dot2ECPublicKey key; ///< 검증키 (공개키 또는 공개키재구성값)
};


/**
 * @brief IssuerIdentifier 정보 형식
 */
struct Dot2CertIssuerIdentifier
{
  Dot2CertIssuerIdentifierType type; ///< 상위인증서 식별자 유형
  uint8_t h8[8]; ///< 상위인증서 HashedId8 (type 이 self 가 아닌 경우에 사용됨)
};


/**
 * @brief 인증서 공통컨텐츠 정보 형식
 *
 * 모든 인증서 내에 공통으로 포함된 정보들이 저장된다.
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1을 준수하는 CA 인증서, End-entity 인증서 등 각 인증서들이 공통으로 갖는 정보를 저장한다.
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1을 준수하는 인증서 내 정보 중,
 *  - version, type은 저장되지 않는다. (version=3, type=explicit로 정해져 있다)
 *  - 서명은 저장되지 않는다.
 */
struct Dot2CertCommonContents
{
  /*
   * 인증서에 포함된 정보
   */
  Dot2CertType type; ///< 인증서 유형
  struct Dot2CertIssuerIdentifier issuer; ///< 상위인증서 식별자 정보
  struct Dot2CertId id; ///< 인증서 ID
  uint8_t craca_id[DOT2_CRACA_ID_LEN]; ///< cracaId
  Dot2CertCRLSeries crl_series; ///< CRL series
  Dot2Time64 valid_start; ///< 인증서 유효기간 시작 시점
  Dot2Time64 valid_end; ///< 인증서 유효기간 종료 시점
  struct Dot2CertValidRegion2 valid_region; ///< 인증서 유효지역
  struct Dot2CertVerificationKeyIndicator verify_key_indicator; ///< 검증키 지시자
  bool enc_pub_key_present; ///< 암호화용 공개키 존재 여부
  struct Dot2ECPublicKey enc_pub_key; ///< 암호화용 공개키
};

#endif //V2X_SW_2019_DOT2_CERT_INFO_H
