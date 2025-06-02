/** 
  * @file 
  * @brief SPDU relevance check 단위테스트에 사용되는 샘플 데이터를 정의한 파일
  * @date 2021-09-11 
  * @author gyun 
  */


#ifndef V2X_SW_TEST_RELEVANCE_CHECK_SAMPLE_DATA_H
#define V2X_SW_TEST_RELEVANCE_CHECK_SAMPLE_DATA_H


// 라이브러리 내부 헤더 파일
#include "sec-profile/dot2-sec-profile.h"


#define SPDU_RELEVANCE_CHECK_PSID (32) ///< SPDU가 수납된 PDU(예: WSM)의 PSID
#define SPDU_RELEVANCE_CHECK_VALIDITY_PERIOD (1000000ULL) ///< SPDU가 유효하다고 판정되는 수신시각과 생성시각(과거)의 차이 (마이크로초 단위)
#define SPDU_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD (1000000ULL) ///< SPDU가 유효하다고 판정되는 수신시각과 생성시각(미래)의 차이 (마이크로초 단위)
#define SPDU_RELEVANCE_CHECK_VALID_DISTANCE (10000U) ///< SPDU가 유효하다고 판정되는 수신지점과 생성지점의 차이 (미터단위). 이 값이 변경되면 아래 OFFSET 값들도 다 변경되어야 함.
#define SPDU_RELEVANCE_CHECK_RX_TIME (10000ULL*1e6) ///< SPDU 수신시각 (마이크로초 단위)
#define SPDU_RELEVANCE_CHECK_RX_LAT (374063230L) ///< SPDU 수신 위도
#define SPDU_RELEVANCE_CHECK_RX_LON (1271023340L) ///< SPDU 수신 경도
#define SPDU_RELEVANCE_CHECK_100M_OFFSET_LAT (-9910L) ///< 특정 지점으로부터 남동쪽 100m 떨어진 지점의 위도 오프셋값 (대략적인 값)
#define SPDU_RELEVANCE_CHECK_100M_OFFSET_LON (11290L) ///< 특정 지점으로부터 남동쪽 100m 떨어진 지점의 경도 오프셋값 (대략적인 값)
#define SPDU_RELEVANCE_CHECK_9000M_OFFSET_LAT (-578470L) ///< 특정 지점으로부터 남동쪽 9000m 떨어진 지점의 위도 오프셋값 (대략적인 값)
#define SPDU_RELEVANCE_CHECK_9000M_OFFSET_LON (819630L) ///< 특정 지점으로부터 남동쪽 9000m 떨어진 지점의 경도 오프셋값 (대략적인 값)
#define SPDU_RELEVANCE_CHECK_11000M_OFFSET_LAT (-758150L) ///< 특정 지점으로부터 남동쪽 11000m 떨어진 지점의 위도 오프셋값 (대략적인 값)
#define SPDU_RELEVANCE_CHECK_11000M_OFFSET_LON (976290L) ///< 특정 지점으로부터 남동쪽 11000m 떨어진 지점의 경도 오프셋값 (대략적인 값)
#define SPDU_RELEVANCE_CHECK_PCA_CERT_VALID_END (20000ULL*1e6) ///< PCA 인증서 유효기간 종료시점 (마이크로초 단위)
#define SPDU_RELEVANCE_CHECK_ICA_CERT_VALID_END (30000ULL*1e6) ///< ICA 인증서 유효기간 종료시점 (마이크로초 단위)
#define SPDU_RELEVANCE_CHECK_RCA_CERT_VALID_END (40000ULL*1e6) ///< RCA 인증서 유효기간 종료시점 (마이크로초 단위)


void Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(struct Dot2SecProfileEntry *entry);
void Dot2Test_SetPacketParseData_ForRelevanceCheck(struct V2XPacketParseData *parsed);
void Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(struct Dot2SPDUProcessWorkData *work_data);
void Dot2Test_SetCertChain_ForRelevanceCheck(struct Dot2EECertCacheEntry *signer, struct Dot2SCCCertInfoEntry *pca, struct Dot2SCCCertInfoEntry *ica, struct Dot2SCCCertInfoEntry *rca);


#endif //V2X_SW_TEST_RELEVANCE_CHECK_SAMPLE_DATA_H
