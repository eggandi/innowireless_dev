/** 
  * @file 
  * @brief dot2 라이브러리 내부에서 사용되는 인라인 함수들을 정의한 파일
  * @date 2021-09-05 
  * @author gyun 
  */

#ifndef V2X_SW_2019_DOT2_INTERNAL_INLINE_H
#define V2X_SW_2019_DOT2_INTERNAL_INLINE_H


// 시스템 헤더 파일
#include <math.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"


/**
 * @brief Time32 유형의 시간값을 Time64 유형으로 변환한다.
 * @param[in] from 변환할 Time32 유형 시간값
 * @return 변환된 Time64 유형 시간값
 */
static inline Dot2Time64 dot2_ConvertTime32ToTime64(Dot2Time32 from)
{
  return (Dot2Time64)((Dot2Time64)from * 1000000ULL);
}


/**
 * @brief Time64 유형의 시간값을 Time32 유형으로 변환한다.
 * @param[in] from 변환할 Time64 유형 시간값
 * @return 변환된 Time32 유형 시간값
 */
static inline Dot2Time32 dot2_ConvertTime64ToTime32(Dot2Time64 from)
{
  return (Dot2Time32)(from / 1000000ULL);
}


/**
 * @brief 인증서의 길이가 유효한지 체크한다.
 * @param[in] cert_size 인증서 길이
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCertSize(Dot2CertSize cert_size)
{
  return ((cert_size >= kDot2CertSize_Min) && (cert_size <= kDot2CertSize_Max)) ? true : false;
}


/**
 * @brief LCM 설정 유형이 유효한지 체크한다.
 * @param[in] type LCM 설정 유형
 * @return 유효한지 여부
 */
static inline bool dot2_CheckLCMConfigType(Dot2LCMConfigType type)
{
  return (type <= kDot2LCMConfigType_Max) ? true : false;
}


/**
 * @brief 인증서내 권한개수가 유효한지 체크한다.
 * @param[in] num 인증서내 권한개수
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCertPermssionsNum(Dot2CertPermissionNum num)
{
  return (num <= kDot2CertPermissionNum_Max) ? true : false;
}


/**
 * @brief CMHF의 길이가 유효한지 체크한다.
 * @param[in] cmhf_size CMHF 길이
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCMHFSize(Dot2CMHFSize cmhf_size)
{
  return ((cmhf_size >= kDot2CMHFSize_Min) && (cmhf_size <= kDot2CMHFSize_Max)) ? true : false;
}


/**
 * @brief 인증서 ID 유형이 유효한지 체크한다.
 * @param[in] type 인증서 ID 유형
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCertIdType(Dot2CertIdType type)
{
  return (type <= kDot2CertIdType_Max) ? true : false;
}


/**
 * @brief BinaryID 유형의 인증서 ID 길이가 유효한지 체크한다.
 * @param[in] len 인증서 ID 길이
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCertBinaryIdLen(Dot2CertBinaryIdLen len)
{
  return ((len >= kDot2CertBinaryIdLen_Min) && (len <= kDot2CertBinaryIdLen_Default)) ? true : false;
}


/**
 * @brief HostName 유형의 인증서 ID 길이가 유효한지 체크한다.
 * @param[in] len 인증서 ID 길이
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCertIdHostNameLen(Dot2CertIdHostNameLen len)
{
  return (len <= kDot2CertIdHostNameLen_Max) ? true : false;
}


/**
 * @brief 개인키 유형이 유효한지 체크한다.
 * @param[in] type 개인키 유형
 * @return 유효한지 여부
 */
static inline bool dot2_CheckPrivKeyType(Dot2PrivKeyType type)
{
  // 현재는 kDot2PrivKeyType_Key만 사용된다.
  return (type == kDot2PrivKeyType_Key) ? true : false;
}


/**
 * @brief CMHF 내 매직넘버가 유효한지 확인한다.
 * @param[in] magic 매직넘버
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCMHFMagicNumber(uint32_t magic)
{
  return (magic == CMHF_MAGIC_NUMBER) ? true : false;
}


/**
 * @brief Issuer-signed 인증서의 유효기간이 유효한지 확인한다.
 * @param[in] valid_start 인증서 유효기간 시작시점
 * @param[in] valid_end 인증서 유효기간 종료시점
 * @param[in] i_valid_start 상위인증서 유효기간 시작시점
 * @param[in] i_valid_end 상위인증서 유효기간 종료시점
 * @return 유효한지 여부
 */
static inline bool dot2_CheckIssuerSignedCertValidTime(
  Dot2Time64 valid_start,
  Dot2Time64 valid_end,
  Dot2Time64 i_valid_start,
  Dot2Time64 i_valid_end)
{
  return ((valid_start <= valid_end) && (valid_start >= i_valid_start) && (valid_end <= i_valid_end)) ? true : false;
}


/**
 * @brief 인증서 내 Identified 영역의 개수가 유효한지 확인한다.
 * @param[in] num Identified 영역 개수
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCertIdentifiedRegionNum(Dot2IdentifiedRegionNum num)
{
  return ((num != 0) && (num <= kDot2IdentifiedRegionNum_Max)) ? true : false;
}


/**
 * @brief SPDU 길이의 유효성을 체크한다.
 * @param[in] spdu_size 유효성을 체크할 SPDU 길이
 * @return 유효한지 여부
 */
static inline bool dot2_CheckSPDUSize(Dot2SPDUSize spdu_size)
{
  return ((spdu_size >= kDot2SPDUSize_Min) && (spdu_size <= kDot2SPDUSize_Max)) ? true : false;
}


/**
 * @brief psid 값의 유효성을 체크한다.
 * @param[in] psid 유효성을 체크할 psid
 * @return 유효한지 여부
 */
static inline bool dot2_CheckPSID(Dot2PSID psid)
{
  return (psid <= kDot2PSID_Max) ? true : false;
}


/**
 * @brief 서명파라미터 사전계산 주기의 유효성을 체크한다.
 * @param[in] interval 서명파라미터 사전계산 주기
 * @return 유효한지 여부
 */
static inline bool dot2_CheckSigningParamsPrecomputeInterval(Dot2SigningParamsPrecomputeInterval interval)
{
  if ((interval == kDot2SigningParamsPrecomputeInterval_NotUse) ||
      ((interval >= kDot2SigningParamsPrecomputeInterval_Min) &&
       (interval <= kDot2SigningParamsPrecomputeInterval_Max))) {
    return true;
  }
  return false;
}


/**
 * @brief CRL 길이값의 유효성을 체크한다.
 * @param[in] crl_size CRL 길이
 * @return 유효한지 여부
 */
static inline bool dot2_CheckCRLSize(Dot2CRLSize crl_size)
{
  return (((crl_size >= kDot2CRLSize_Min) && (crl_size <= kDot2CRLSize_Max)) ? true : false);
}


/**
 * @brief 초 단위의 현재 리눅스시스템시각을 구한다.
 * @return 초 단위 리눅스시스템시각
 */
static inline time_t dot2_GetCurrentSystemTimeInSeconds(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec;
}


/**
 * @brief 초단위 리눅스시스템시간 값을 Time32 값으로 변환한다.
 * @param[in] sec 변환할 UTC 시스템시간(초 단위)
 * @return 변환된 Time32(초단위 TAI) 값 (2004년 1월 1일보다 과거일 경우 0)
 *
 * 리눅스 시스템시간 : 1970-01-01 0시 이후부터의 UTC 초 값 \n
 * Time32 : 2004-01-01 0시 이후부터의 TAI 초 값 (TAI)
 */
static inline Dot2Time32 dot2_ConvertSystemTimeToTime32(time_t sec)
{
  // 2004년 1월 1일보다 과거이면 0을 반환한다.
  return (sec <= (time_t)SYSTIME_TAI_SEC_DIFF) ?
         0 : (sec - (time_t)SYSTIME_TAI_SEC_DIFF + (time_t)(g_dot2_mib.leap_secs));
}


/**
 * @brief 현 시점의 Time32(초 단위 TAI) 값을 구한다.
 * @return 현 시점의 Time32 값
 */
static inline Dot2Time32 dot2_GetCurrentTime32(void)
{
  time_t current = dot2_GetCurrentSystemTimeInSeconds();
  return dot2_ConvertSystemTimeToTime32(current);
}


/**
 * @brief 마이크로초 단위의 현재 리눅스시스템시각을 구한다.
 * @return 마이크로초 단위 리눅스시스템시각
 */
static inline Dot2SystemTime dot2_GetCurrentSystemTimeInMicroseconds(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ((uint64_t)(ts.tv_sec) * 1000000) + ((uint64_t)(ts.tv_nsec) / 1000);
}


/**
 * @brief 마이크로초단위 리눅스시스템시간 값을 Time64 값으로 변환한다.
 * @param[in] usec 변환할 시스템시간(마이크로초 단위) (UTC)
 * @return 변환된 Time64(마이크로초단위 TAI) 값 (2004년 1월 1일보다 과거일 경우 0)
 *
 * 리눅스 시스템시간 : 1970-01-01 0시 이후부터의 UTC 마이크로초 값  \n
 * Time64 : 2004-01-01 0시 이후부터의 TAI 마이크로초 값
 */
static inline Dot2Time64 dot2_ConvertSystemTimeToTime64(Dot2SystemTime usec)
{
  // 2004년 1월 1일보다 과거이면 0을 반환한다.
  return (usec <= SYSTIME_TAI_USEC_DIFF) ?
         0 : (usec - SYSTIME_TAI_USEC_DIFF + ((uint64_t)(g_dot2_mib.leap_secs) * 1000000ULL));
}


/**
 * @brief 현 시점의 Time64(마이크로초 단위 TAI) 값을 구한다.
 * @return 현 시점의 Time64 값
 */
static inline Dot2Time64 dot2_GetCurrentTime64(void)
{
  Dot2SystemTime current = dot2_GetCurrentSystemTimeInMicroseconds();
  return dot2_ConvertSystemTimeToTime64(current);
}


/**
 * @brief Time32 값을 초단위 리눅스시스템시간 값으로 변환한다.
 * @param[in] tai_sec 변환할 Time32(초단위 TAI) 값
 * @return 변환된 초단위 리눅스시스템시간 (UTC)
 *
 * 리눅스 시스템시간 : 1970-01-01 0시 이후부터의 UTC 초 값 \n
 * Time32 : 2004-01-01 0시 이후부터의 TAI 초 값
 */
static inline time_t dot2_ConvertTime32ToSystemTimeSeconds(Dot2Time32 tai_sec)
{
  return (tai_sec + (time_t)SYSTIME_TAI_SEC_DIFF - (time_t)(g_dot2_mib.leap_secs));
}


/**
 * @brief Time32 값을 마이크로초단위 리눅스시스템시간 값으로 변환한다.
 * @param[in] tai_sec 변환할 Time32(초단위 TAI) 값
 * @return 변환된 마이크로초단위 리눅스시스템시간 (UTC)
 *
 * 리눅스 시스템시간 : 1970-01-01 0시 이후부터의 UTC 마이크로초 값 \n
 * Time32 : 2004-01-01 0시 이후부터의 TAI 초 값
 */
static inline Dot2SystemTime dot2_ConvertTime32ToSystemTimeMicroseconds(Dot2Time32 tai_sec)
{
  return ((Dot2SystemTime)dot2_ConvertTime32ToSystemTimeSeconds(tai_sec) * 1000000ULL);
}


/**
 * @brief 16진수 바이트열을 문자열로 변환한다.
 * @param[in] octs 16진수 바이트열
 * @param[in] len 16진수 바이트열 길이
 * @param[out] str 변환된 문자열이 저장될 버퍼
 */
static inline void dot2_ConvertOctsToHexStr(const uint8_t *octs, size_t len, char *str)
{
  for (size_t i = 0; i < len; i++) {
    sprintf(str + (i * 2), "%02x", octs[i]);
  }
}


/**
 * @brief 현시점의 I-period를 반환한다.
 * @return 현시점의 I-period값
 */
static inline Dot2IPeriod dot2_GetCurrentIPeriod(void)
{
  Dot2Time32 current = dot2_GetCurrentTime32();
  return (current - DOT2_ZERO_I_PERIOD_TIME32) / (7 * 24 * 3600);
}


/**
 * @brief 식별인증서에 대한 현시점의 i value를 반환한다.
 * @param[in] ec_valid_start 등록인증서 유효기간 시작시점
 * @return 현시점에 해당되는 i value 값
 *
 * KISA v1.1 규격에 따라,
 * 등록인증서의 toBeSigned.validityPeriod.start 값(=등록인증서 유효기간 시작시점)이 i=0에 대응된다.
 * i 값의 증가 주기는 식별인증서의 toBeSigned.validityPeriod.duration 필드값(=식별인증서 유효기간)이다.
 */
static inline unsigned int dot2_GetCurrentIdCertIValue(Dot2Time32 ec_valid_start)
{
  Dot2Time32 current = dot2_GetCurrentTime32();
  return (current - ec_valid_start) / DOT2_ID_CERT_VALID_DURATION;
}


/**
 * @brief 0.1 마이크로도 단위의 위도값을 도단위 형식으로 변환한다 (0.1 마이크로도 단위 -> 1도 단위)
 * @param[in] lat 0.1 마이크로도 단위 위도값
 * @return 1도 단위 위도값
 */
static inline double dot2_ConvertToDegreeUnitLatitude(Dot2Latitude lat)
{
  double lat_raw = NAN;
  if ((lat >= kDot2Latitude_Min) && (lat <= kDot2Latitude_Max)) {
    lat_raw = (double)lat / 1e7;
  }
  return lat_raw;
}


/**
 * @brief 0.1 마이크로도 단위의 경도값을 도단위 형식으로 변환한다 (0.1 마이크로도 단위 -> 1도 단위)
 * @param[in] lon 0.1 마이크로도 단위 경도값
 * @return 1도 단위 경도값
 */
static inline double dot2_ConvertToDegreeUnitLongitude(Dot2Longitude lon)
{
  double lon_raw = NAN;
  if ((lon >= kDot2Longitude_Min) && (lon <= kDot2Longitude_Max)) {
    lon_raw = (double)lon / 1e7;
  }
  return lon_raw;
}


/**
 * @brief 소수점 도(decimal degree)를 라디언(radian)으로 변환한다.
 * @param[in] deg 변환할 도 값
 * @return 변환된 라디언 값
 *
 * 코드 참조: GeoDataSource (https://www.geodatasource.com/developers/c)
 */
static inline double dot2_ConvertDecimalDegreesToRadians(double deg)
{
  return (deg * PI / 180);
}


/**
 * @brief 라디언(radian)을 소수점 도(decimal degree)로 변환한다.
 * @param[in] rad 변환할 라디언 값
 * @return 변환된 도 값
 *
 * 코드 참조 : GeoDataSource (https://www.geodatasource.com/developers/c)
 */
static inline double dot2_ConvertRadiansToDecimalDegrees(double rad)
{
  return (rad * 180 / PI);
}


/**
 * @brief 두 좌표간의 거리(미터단위)를 계산하여 반환한다.
 * @param[in] lat1 좌표1의 위도(도단위)
 * @param[in] lon1 좌표1의 경도(도단위)
 * @param[in] lat2 좌표2의 위도(도단위)
 * @param[in] lon2 좌표2의 경도(도단위)
 * @return 두 좌표간 거리(미터 단위)
 * @retval -1: 계산 실패
 *
 * 코드 참조 : GeoDataSource (https://www.geodatasource.com/developers/c)
 */
static inline double dot2_GetDistanceBetweenPoints(double lat1, double lon1, double lat2, double lon2)
{
  double theta, dist;
  if (isnan(lat1) || isnan(lon1) || isnan(lat2) || isnan(lon2)) {
    return -1;
  }
  else if ((lat1 == lat2) && (lon1 == lon2)) {
    return 0;
  }
  else {
    theta = lon1 - lon2;
    dist = sin(dot2_ConvertDecimalDegreesToRadians(lat1)) * sin(dot2_ConvertDecimalDegreesToRadians(lat2)) +
           cos(dot2_ConvertDecimalDegreesToRadians(lat1)) * cos(dot2_ConvertDecimalDegreesToRadians(lat2)) *
           cos(dot2_ConvertDecimalDegreesToRadians(theta));
    dist = acos(dist);
    dist = dot2_ConvertRadiansToDecimalDegrees(dist);
    dist = dist * 60 * 1.1515;
    dist = dist * 1.609344 * 1000;  // 미터 단위로 변환
    return dist;
  }
}

#endif //V2X_SW_2019_DOT2_INTERNAL_INLINE_H
