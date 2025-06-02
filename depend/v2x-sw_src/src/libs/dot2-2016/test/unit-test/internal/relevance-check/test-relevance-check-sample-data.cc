/** 
  * @file 
  * @brief SPDU relevance check 단위테스트에 사용되는 샘플 데이터를 정의한 파일
  * @date 2021-09-11 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"
#include "v2x-sw.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// google test 헤더 파일
#include "test-relevance-check-sample-data.h"


/**
 * @brief Relevance check 테스트를 위해 기본 Security profile을 설정한다.
 * @param[out] entry 설정할 security profile 엔트리
 */
void Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(struct Dot2SecProfileEntry *entry)
{
  memset(entry, 0, sizeof(struct Dot2SecProfileEntry));
  entry->profile.rx.verify_data = true;
  entry->profile.rx.relevance_check.replay = false;
  entry->profile.rx.relevance_check.gen_time_in_past = false;
  entry->profile.rx.relevance_check.validity_period = SPDU_RELEVANCE_CHECK_VALIDITY_PERIOD;
  entry->profile.rx.relevance_check.gen_time_in_future = false;
  entry->profile.rx.relevance_check.acceptable_future_data_period = SPDU_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD;
  entry->profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  entry->profile.rx.relevance_check.exp_time = false;
  entry->profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  entry->profile.rx.relevance_check.gen_location_distance = false;
  entry->profile.rx.relevance_check.valid_distance = SPDU_RELEVANCE_CHECK_VALID_DISTANCE;
  entry->profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_SecurityHeader;
  entry->profile.rx.relevance_check.cert_expiry = false;
  dot2_InitSecProfileReplayCheckList(&(entry->replay_check_list));
}


/**
 * @brief Relevance check 테스트를 위해 정상적인 SPDU 패킷파싱데이터를 설정한다.
 * @param[out] parsed 설정할 패킷파싱데이터
 *
 * 다음과 같이 정상 데이터가 설정된다.
 *  1. SPDU 생성시각 > SPDU 수신시각 - 유효범위(과거)
 *  2. SPDU 생성시각 < SPDU 수신시각 + 유효범위(미래)
 *  3. SPDU 만기시각 > SPDU 수신시각
 *  4. SPDU 생성좌표: {SPDU 수신시점 + 유효범위} 내 지점
 *  5. 새로운 SPDU (Replay 체크에 실패하지 않는)
 */
void Dot2Test_SetPacketParseData_ForRelevanceCheck(struct V2XPacketParseData *parsed)
{
  parsed->spdu.signed_data.gen_time_present = true;
  parsed->spdu.signed_data.expiry_time_present = true;
  parsed->spdu.signed_data.gen_location_present = true;
  parsed->spdu.signed_data.gen_time = SPDU_RELEVANCE_CHECK_RX_TIME - SPDU_RELEVANCE_CHECK_VALIDITY_PERIOD + 100UL;
  parsed->spdu.signed_data.expiry_time = SPDU_RELEVANCE_CHECK_RX_TIME + 100UL;
  parsed->spdu.signed_data.gen_location.lat = SPDU_RELEVANCE_CHECK_RX_LAT + SPDU_RELEVANCE_CHECK_9000M_OFFSET_LAT;
  parsed->spdu.signed_data.gen_location.lon = SPDU_RELEVANCE_CHECK_RX_LON + SPDU_RELEVANCE_CHECK_9000M_OFFSET_LON;
  parsed->spdu.signed_data.gen_location.elev = 0;
}


/**
 * @brief Relevance check 테스트를 위해 정상적인 SPDU 처리작업데이터를 설정한다.
 * @param[out] work_data 설정할 SPDU 처리작업데이터
 */
void Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(struct Dot2SPDUProcessWorkData *work_data)
{
  work_data->params.rx_time = SPDU_RELEVANCE_CHECK_RX_TIME;
  work_data->params.rx_psid = SPDU_RELEVANCE_CHECK_PSID;
  work_data->params.rx_pos.lat = SPDU_RELEVANCE_CHECK_RX_LAT;
  work_data->params.rx_pos.lon = SPDU_RELEVANCE_CHECK_RX_LON;
  work_data->sign.R_r.u.point.form = kDot2ECPointForm_Compressed_y_0;
  for (int i = 0; i < DOT2_EC_256_KEY_LEN; i++) {
    work_data->sign.R_r.u.point.u.xy.x[i] = (uint8_t)rand();
    work_data->sign.s[i] = (uint8_t)rand();
  }
}


/**
 * @brief Relevance check 테스트를 위해 정상적인 인증서 체인 엔트리 정보들을 설정한다.
 * @param[out] signer 설정할 서명자 인증서 정보 엔트리
 * @param[out] pca 설정할 pca 인증서 정보 엔트리
 * @param[out] ica 설정할 ica 인증서 정보 엔트리
 * @param[out] rca 설정할 rca 인증서 정보 엔트리
 *
 * 인증서체인구조: spdu -> signer(EE cert) -> pca -> ica -> rca
 */
void Dot2Test_SetCertChain_ForRelevanceCheck(
  struct Dot2EECertCacheEntry *signer,
  struct Dot2SCCCertInfoEntry *pca,
  struct Dot2SCCCertInfoEntry *ica,
  struct Dot2SCCCertInfoEntry *rca)
{
  signer->contents.common.valid_end = SPDU_RELEVANCE_CHECK_PCA_CERT_VALID_END;
  pca->contents.common.valid_end = SPDU_RELEVANCE_CHECK_PCA_CERT_VALID_END;
  ica->contents.common.valid_end = SPDU_RELEVANCE_CHECK_ICA_CERT_VALID_END;
  rca->contents.common.valid_end = SPDU_RELEVANCE_CHECK_RCA_CERT_VALID_END;
  signer->issuer = pca;
  pca->issuer = ica;
  ica->issuer = rca;
  rca->issuer = nullptr;
}

