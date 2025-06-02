/** 
  * @file 
  * @brief 
  * @date 2021-07-29 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"


/**
 * @brief SPDU 생성시각(과거) 관련 SDS-verified SPDU relevance 체크를 수행하여 SPDU의 유효 여부를 결정한다.
 * @param[in] rx_time 수신시각
 * @param[in] gen_time SPDU 생성시각
 * @param[in] validity_period 유효기간
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
static inline int
dot2_CheckSDSverifiedSPDURelevance_Freshness(Dot2Time64 rx_time, Dot2Time64 gen_time, Dot2Time64 validity_period)
{
  /*
   * SPDU의 생성시각이 수신시각보다 너무 과거이면 유효하지 않다.
   */
  Dot2Time64 valid_threshold = rx_time - validity_period;
  if (gen_time < valid_threshold) {
    Err("Fail to check SDS-verified SPDU relevance(freshness) - gen(%"PRIu64") < valid(%"PRIu64")\n",
        gen_time, valid_threshold);
    return -kDot2Result_SPDURelevance_TooOld;
  }
  Log(kDot2LogLevel_Event, "Check SDS-verified SPDU relevance(freshness)\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU 생성시각(미래) 관련 SDS-verified SPDU relevance 체크를 수행하여 SPDU의 유효 여부를 결정한다.
 * @param[in] rx_time 수신 시각
 * @param[in] gen_time SPDU 생성시각
 * @param[in] validity_period 유효기간
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
static inline int
dot2_CheckSDSverifiedSPDURelevance_FutureGeneration(Dot2Time64 rx_time, Dot2Time64 gen_time, Dot2Time64 validity_period)
{
  /*
   * SPDU의 생성시각이 수신시각보다 너무 미래이면 유효하지 않다.
   * "너무"의 의미: 장치간 시간 동기 오류에 대한 마진을 두기 위해 일정시간까지는 허용한다.
   */
  Dot2Time64 valid_threshold = rx_time + validity_period;
  if (gen_time > valid_threshold) {
    Err("Fail to check SDS-verified SPDU relevance(future generation) - gen(%"PRIu64") > valid(%"PRIu64")\n",
        gen_time, valid_threshold);
    return -kDot2Result_SPDURelevance_Future;
  }
  Log(kDot2LogLevel_Event, "Check SDS-verified SPDU relevance(future generation)\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU 만기시각 관련 SDS-verified SPDU relevance 체크를 수행하여 SPDU의 유효 여부를 결정한다.
 * @param[in] rx_time 수신 시각
 * @param[in] exp_time SPDU 만기시각
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
static inline int dot2_CheckSDSverifiedSPDURelevance_Expiry(Dot2Time64 rx_time, Dot2Time64 exp_time)
{
  /*
   * SPDU의 만기시각이 수신시각보다 과거이면(SPDU가 만기됨) 유효하지 않다.
   */
  if (rx_time > exp_time) {
    Err("Fail to check SDS-verified SPDU relevance(expiry) - rx(%"PRIu64") > exp(%"PRIu64")\n", rx_time, exp_time);
    return -kDot2Result_SPDURelevance_Expiry;
  }
  Log(kDot2LogLevel_Event, "Check SDS-verified SPDU relevance(expiry)\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU 생성 위치 관련 SDS-verified SPDU relevance 체크를 수행하여 SPDU의 유효 여부를 결정한다.
 * @param[in] rx_lat SPDU 수신 위도
 * @param[in] rx_lon SPDU 수신 경도
 * @param[in] gen_lat SPDU 생성 위도
 * @param[in] gen_lon SPDU 생성 경도
 * @param[in] validity_distance 유효 거리(미터단위)
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
static inline int dot2_CheckSDSverifiedSPDURelevance_Location(
  Dot2Latitude rx_lat,
  Dot2Longitude rx_lon,
  Dot2Latitude gen_lat,
  Dot2Longitude gen_lon,
  unsigned int valid_distance)
{
  /*
   * 내 위치와 SPDU 생성위치 간의 거리가 유효거리보다 너무 멀 경우 유효하지 않다.
   */
  double distance = dot2_GetDistanceBetweenPoints((double)(rx_lat) / 1e7,
                                                  (double)(rx_lon) / 1e7,
                                                  (double)(gen_lat) / 1e7,
                                                  (double)(gen_lon) / 1e7);
  if (distance > (double)valid_distance) {
    Err("Fail to check SDS-verified SPDU relevance(location) - dist(%.2fm) > valid(%um)\n", distance, valid_distance);
    return -kDot2Result_SPDURelevance_Location;
  }
  Log(kDot2LogLevel_Event, "Success to check SDS-verified SPDU relevance(location)\n");
  return kDot2Result_Success;
}


/**
 * @brief 중복된 SPDU인지 여부를 체크한다.
 * @param[in] replay_check_list Replay 체크 리스트
 * @param[in] spdu_rx_time SPDU 수신 시각
 * @param[in] spdu_gen_time SPDU 생성 시각. (SPDU 헤더에 해당 필드가 존재하지 않을 경우 0)
 * @param[in] sign SPDU 서명
 * @param[in] validity_period 중복여부를 체크할 시간 간격
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
static inline int dot2_CheckSDSverifiedSPDURelevance_Replay(
  struct Dot2SecProfileReplayCheckList *replay_check_list,
  Dot2Time64 spdu_rx_time,
  Dot2Time64 spdu_gen_time,
  struct Dot2Signature *sign,
  Dot2Time64 validity_period)
{
  Log(kDot2LogLevel_Event, "Check SDS-verified SPDU relevance(replay)\n");

  /*
   * replay 체크 리스트 내에 동일한 정보를 갖는 엔트리를 찾는다.
   */
  struct Dot2SecProfileReplayCheckEntry *entry = dot2_FindIdenticalSPDUInSecProfileReplayCheckList(replay_check_list,
                                                                                                   spdu_rx_time,
                                                                                                   spdu_gen_time,
                                                                                                   sign,
                                                                                                   validity_period);

  /*
   * 엔트리가 존재하는 경우 중복 SPDU이므로(즉, Replay) 유효하지 않음을 반환한다.
   */
  if (entry) {
    Err("Fail to check SDS-verified SPDU relevance(replay)\n");
    return -kDot2Result_SPDURelevance_Replay;
  }

  /*
   * 중복이 아니면 replay 체크 리스트에 추가한다.
   */
  int ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, spdu_rx_time, spdu_gen_time, sign);
  if (ret < 0) {
    return ret;
  }

  Log(kDot2LogLevel_Event, "Success to check SDS-verified SPDU relevance(replay)\n");
  return kDot2Result_Success;
}


/**
 * @brief SPDU 인증서만기 관련 SDS-verified SPDU relevance 체크를 수행하여 SPDU의 유효 여부를 결정한다.
 * @param[in] rx_time 수신 시각
 * @param[in] signer_entry SPDU 서명자 인증서정보 엔트리
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
static inline int
dot2_CheckSDSverifiedSPDURelevance_CertExpiry(Dot2Time64 rx_time, struct Dot2EECertCacheEntry *signer_entry)
{
  /*
   * 서명자 인증서가 만기되었으면 유효하지 않다.
   */
  if (rx_time > signer_entry->contents.common.valid_end) {
    Err("Fail to check SDS-verified SPDU relevance(cert expiry) - rx(%"PRIu64") > exp(%"PRIu64")\n",
        rx_time, signer_entry->contents.common.valid_end);
    return -kDot2Result_SPDURelevance_CertExpiry;
  }

  /*
   * SPDU 인증서 체인 내 인증서 중 하나라도 만기되었으면 유효하지 않다.
   */
  struct Dot2SCCCertInfoEntry *issuer = signer_entry->issuer;
  do {
    if (rx_time > issuer->contents.common.valid_end) {
      Err("Fail to check SDS-verified SPDU relevance(cert expiry) - rx(%"PRIu64") > exp(%"PRIu64")\n",
          rx_time, issuer->contents.common.valid_end);
      return -kDot2Result_SPDURelevance_CertExpiry;
    }
    issuer = issuer->issuer; // 상위인증서 선택
  } while(issuer != NULL);
  Log(kDot2LogLevel_Event, "Success to check SDS-verified SPDU relevance(cert expiry)\n");
  return kDot2Result_Success;
}


/**
 * @brief SDS-verified SPDU relevance 체크를 수행하여 SPDU의 유효 여부를 결정한다.
 * @param[in] work_data SPDU 처리 작업 데이터
 * @param[in] sec_profile_entry Security profile 정보엔트리
 * @param[in] signer_entry 서명자 인증서 정보엔트리
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
static int dot2_CheckSDSverifiedSPDURelevance(
  struct Dot2SPDUProcessWorkData *work_data,
  struct Dot2SecProfileEntry *sec_profile_entry,
  struct Dot2EECertCacheEntry *signer_entry)
{
  int ret;
  Log(kDot2LogLevel_Event, "Check SDS-verified SPDU relevance\n");

  struct Dot2RxRelevanceCheckSecProfile *relevance_chek = &(sec_profile_entry->profile.rx.relevance_check);
  Dot2Time64 spdu_gen_time = 0;

  /*
   * Freshness 체크(생성시각이 너무 과거인지)를 수행한다.
   */
  if ((relevance_chek->gen_time_in_past) &&
      (work_data->parsed->spdu.signed_data.gen_time_present)) {
    spdu_gen_time = work_data->parsed->spdu.signed_data.gen_time;
    ret = dot2_CheckSDSverifiedSPDURelevance_Freshness(work_data->params.rx_time,
                                                       spdu_gen_time,
                                                       relevance_chek->validity_period);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * Future generation 체크(생성시각이 미래인지)를 수행한다.
   */
  if ((relevance_chek->gen_time_in_future) &&
      (work_data->parsed->spdu.signed_data.gen_time_present)) {
    spdu_gen_time = work_data->parsed->spdu.signed_data.gen_time;
    ret = dot2_CheckSDSverifiedSPDURelevance_FutureGeneration(work_data->params.rx_time,
                                                              spdu_gen_time,
                                                              relevance_chek->acceptable_future_data_period);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * Expiry 체크(SPDU가 만기되었는지)를 수행한다.
   */
  if ((relevance_chek->exp_time) &&
      (work_data->parsed->spdu.signed_data.expiry_time_present)) {
    ret = dot2_CheckSDSverifiedSPDURelevance_Expiry(work_data->params.rx_time, work_data->parsed->spdu.signed_data.expiry_time);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * Location 체크(생성좌표가 내 좌표로부터 너무 멀리있는지)를 수행한다.
   */
  if ((relevance_chek->gen_location_distance) &&
      (work_data->parsed->spdu.signed_data.gen_location_present)) {
    ret = dot2_CheckSDSverifiedSPDURelevance_Location(work_data->params.rx_pos.lat,
                                                      work_data->params.rx_pos.lon,
                                                      work_data->parsed->spdu.signed_data.gen_location.lat,
                                                      work_data->parsed->spdu.signed_data.gen_location.lon,
                                                      relevance_chek->valid_distance);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * Replay 체크(중복된 SPDU가 수신되었는지)를 수행한다.
   */
  if (relevance_chek->replay) {
    if (work_data->parsed->spdu.signed_data.gen_time_present) {
      spdu_gen_time = work_data->parsed->spdu.signed_data.gen_time;
    }
    ret = dot2_CheckSDSverifiedSPDURelevance_Replay(&(sec_profile_entry->replay_check_list),
                                                    work_data->params.rx_time,
                                                    spdu_gen_time,
                                                    &(work_data->sign),
                                                    relevance_chek->validity_period);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * Certificate expriy 체크(인증서가 만기되었는지)를 수행한다.
   */
  if (relevance_chek->cert_expiry) {
    ret = dot2_CheckSDSverifiedSPDURelevance_CertExpiry(work_data->params.rx_time, signer_entry);
    if (ret < 0) {
      return ret;
    }
  }

  Log(kDot2LogLevel_Event, "Success to check SDS-verified SPDU relevance\n");
  return kDot2Result_Success;
}


/**
 * @brief SDS-verified SPDU relevance 체크를 수행하여 SPDU의 유효 여부를 결정한다.
 * @param[in] work_data SPDU 처리 작업 데이터
 * @param[in] sec_profile_entry 관련 Security profile 엔트리
 * @param[in] signer_entry 서명자 인증서정보 엔트리
 * @retval 0: SPDU가 유효함
 * @retval 음수(-Dot2ResultCode): SPDU가 유효하지 않음
 */
int INTERNAL dot2_CheckSPDURelevance(
  struct Dot2SPDUProcessWorkData *work_data,
  struct Dot2SecProfileEntry *sec_profile_entry,
  struct Dot2EECertCacheEntry *signer_entry)
{
  Log(kDot2LogLevel_Event, "Check SPDU relevance\n");

  /*
   * SDS-verified relevance 체크를 수행한다.
   */
  int ret = dot2_CheckSDSverifiedSPDURelevance(work_data, sec_profile_entry, signer_entry);
  if (ret < 0) {
    return ret;
  }

  /*
   * SDEE-verified relevance 체크를 수행한다.
   * 현재 정의된 체크 항목이 없으므로, 아무 동작도 수행하지 않는다.
   */

  Log(kDot2LogLevel_Event, "Success to check SPDU relevance\n");
  return kDot2Result_Success;
}
