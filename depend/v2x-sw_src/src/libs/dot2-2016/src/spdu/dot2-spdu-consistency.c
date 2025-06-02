/**
  * @file
  * @brief
  * @date 2021-07-14
  * @author gyun
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"


/**
 * @brief SPDU의 생성좌표가 서명자 인증서 "원형" 유효영역 내에 포함되는지에 대한 consistency 체크를 수행한다.
 * @param[in] gen_lat SPDU 생성 위도 (1도 단위)
 * @param[in] gen_lon SPDU 생성 경도 (1도 단위)
 * @param[in] valid_region 서명자 인증서 "원형" 유효영역
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckSPDUGenerationLocationConsistencyWithSigner_Circular(
  double gen_lat,
  double gen_lon,
  struct Dot2CircularRegion *valid_region)
{
  /*
   * 인증서 유효영역 중심점 좌표와 SPDU 생성좌표간의 거리가 인증서 유효영역 반지름보다 크면 인증서 유효영역을 벗어난다.
   */
  double signer_lat = dot2_ConvertToDegreeUnitLatitude(valid_region->center.lat);
  double signer_lon = dot2_ConvertToDegreeUnitLongitude(valid_region->center.lon);
  double distance = dot2_GetDistanceBetweenPoints(gen_lat, gen_lon, signer_lat, signer_lon);
  if ((distance == -1) || (distance > valid_region->radius)) {
    Err("Fail to check SPDU generation location consistency with signer (Circular)\n");
    return -kDot2Result_SPDUConsistency_GenLocationIsNotInSignerValidRegion;
  }
  Log(kDot2LogLevel_Event, "Success to check SPDU generation location consistency with signer (Circular)\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU의 생성좌표가 서명자 인증서 유효영역 내에 포함되는지에 대한 consistency 체크를 수행한다.
 * @param[in] gen_lat SPDU 생성 위도
 * @param[in] gen_lon SPDU 생성 경도
 * @param[in] valid_region 서명자 인증서 내 유효영역 정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckSPDUGenerationLocationConsistencyWithSigner(
  Dot2Latitude gen_lat,
  Dot2Longitude gen_lon,
  struct Dot2CertValidRegion2 *valid_region)
{
  Log(kDot2LogLevel_Event, "Check SPDU generation location consistency with signer\n");
  int ret;
  double lat, lon;
  switch (valid_region->type) {
    case kDot2CertValidRegionType_Circular:
      lat = dot2_ConvertToDegreeUnitLatitude(gen_lat);
      lon = dot2_ConvertToDegreeUnitLongitude(gen_lon);
      ret = dot2_CheckSPDUGenerationLocationConsistencyWithSigner_Circular(lat, lon, &(valid_region->u.circular));
      break;
    case kDot2CertValidRegionType_Identified:
      ret = kDot2Result_Success; // Identifier region인 경우 체크하지 않는다.
      break;
    default:
      Err("Fail to check SPDU generation location consistency with signer - invalid signer's valid region type : %u\n",
          valid_region->type);
      ret = -kDot2Result_SPDUConsistency_InvalidSignerRegionType;
      break;
  }
  return ret;
}


/**
 * @brief SPDU의 생성시각이 서명자 인증서 유효기간 내에 포함되는지에 대한 consistency 체크를 수행한다.
 * @param[in] gen_time SPDU 생성시각
 * @param[in] valid_start 서명자 인증서 유효기간 시작시점
 * @param[in] valid_end 서명자 인증서 유효기간 종료시점
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int
dot2_CheckSPDUGenerationTimeConsistencyWithSigner(Dot2Time64 gen_time, Dot2Time64 valid_start, Dot2Time64 valid_end)
{
  if ((gen_time < valid_start) ||
      (gen_time > valid_end)) {
    Err("Fail to check SPDU generation time consistency with signer - "
        "invalid generation time(gen: %"PRIu64", signer_valid: %"PRIu64" ~ %"PRIu64")\n",
        gen_time, valid_start, valid_end);
    return -kDot2Result_SPDUConsistency_GenTimeIsNotInSignerValidPeriod;
  }
  Log(kDot2LogLevel_Event, "Success to check SPDU generation time consistency with signer\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU의 만기시각이 서명자 인증서 유효기간 내에 포함되는지에 대한 consistency 체크를 수행한다.
 * @param[in] exp_time SPDU 만기시각
 * @param[in] valid_start 서명자 인증서 유효기간 시작시점
 * @param[in] valid_end 서명자 인증서 유효기간 종료시점
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int
dot2_CheckSPDUExpiryTimeConsistencyWithSigner(Dot2Time64 exp_time, Dot2Time64 valid_start, Dot2Time64 valid_end)
{
  if ((exp_time < valid_start) ||
      (exp_time > valid_end)) {
    Err("Fail to check SPDU expiry time consistency with signer - "
        "invalid expiry time(exp: %"PRIu64", signer_valid: %"PRIu64" ~ %"PRIu64")\n",
        exp_time, valid_start, valid_end);
    return -kDot2Result_SPDUConsistency_ExpTimeIsNotInSignerValidPeriod;
  }
  Log(kDot2LogLevel_Event, "Success to check SPDU expiry time consistency with signer\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU와 서명자 인증서간 consistency 체크를 수행한다.
 * @param[in] parsed 패킷파싱데이터
 * @param[in] sec_profile 관련 Security profile
 * @param[in] signer_entry 서명자 인증서정보 엔트리
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckSPDUConsistencyWithSigner(
  struct V2XPacketParseData *parsed,
  struct Dot2SecProfile *sec_profile,
  struct Dot2EECertCacheEntry *signer_entry)
{
  int ret;
  Log(kDot2LogLevel_Event, "Check SPDU consistency with signer\n");

  /*
   * SPDU 생성좌표가 인증서 유효지역 내에 포함되는지 확인한다.
   */
  if ((sec_profile->rx.consistency_check.gen_location) &&
      (parsed->spdu.signed_data.gen_location_present)) {
    ret = dot2_CheckSPDUGenerationLocationConsistencyWithSigner(parsed->spdu.signed_data.gen_location.lat,
                                                                parsed->spdu.signed_data.gen_location.lon,
                                                                &(signer_entry->contents.common.valid_region));
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 메시지 생성시각이 인증서 유효기간 내에 있는지 확인한다.
   */
  if (parsed->spdu.signed_data.gen_time_present) {
    ret = dot2_CheckSPDUGenerationTimeConsistencyWithSigner(parsed->spdu.signed_data.gen_time,
                                                            signer_entry->contents.common.valid_start,
                                                            signer_entry->contents.common.valid_end);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 메시지 만기시각이 인증서 유효기간 내에 있는지 확인한다.
   */
  if (parsed->spdu.signed_data.expiry_time_present) {
    ret = dot2_CheckSPDUExpiryTimeConsistencyWithSigner(parsed->spdu.signed_data.expiry_time,
                                                        signer_entry->contents.common.valid_start,
                                                        signer_entry->contents.common.valid_end);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot2LogLevel_Event, "Success to check SPDU consistency with signer\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU 내부 consistency 체크를 수행한다.
 * @param[in] parsed 패킷파싱데이터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * (존재하는 경우) SPDU의 생성시각이 만기시각과 같거나 더 과거인지 확인한다.
 */
static inline int dot2_CheckSPDUInternalConsistency(struct V2XPacketParseData *parsed)
{
  Log(kDot2LogLevel_Event, "Check SPDU internal consistency\n");
  int ret = kDot2Result_Success;
  if (parsed->spdu.signed_data.gen_time_present &&
      parsed->spdu.signed_data.expiry_time_present) {
    if (parsed->spdu.signed_data.expiry_time < parsed->spdu.signed_data.gen_time) {
      Err("Fail to check SPDU internal consistency - expiry time before generation time - %"PRIu64" < %"PRIu64"\n",
          parsed->spdu.signed_data.expiry_time, parsed->spdu.signed_data.gen_time);
      ret = -kDot2Result_SPDUConsistency_ExpTimeBeforeGenTimeInSPDU;
    }
  }
  return ret;
}


/**
 * @brief 수신된 SPDU의 consistency 체크를 수행한다.
 * @param[in] parsed 패킷파싱데이터
 * @param[in] sec_profile 관련 Security profile
 * @param[in] signer_entry 서명자 인증서정보 엔트리
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_CheckSPDUConsistency(
  struct V2XPacketParseData *parsed,
  struct Dot2SecProfile *sec_profile,
  struct Dot2EECertCacheEntry *signer_entry)
{
  Log(kDot2LogLevel_Event, "Check SPDU consistency\n");

  /*
   * SPDU 내부 consistency 체크를 수행한다.
   */
  int ret = dot2_CheckSPDUInternalConsistency(parsed);
  if (ret < 0) {
    return ret;
  }

  /*
   * SPDU와 서명자 인증서간 consistency 체크를 수행한다.
   */
  ret = dot2_CheckSPDUConsistencyWithSigner(parsed, sec_profile, signer_entry);
  if (ret < 0) {
    return ret;
  }

  Log(kDot2LogLevel_Event, "Success to check SPDU consistency\n");
  return kDot2Result_Success;
}
