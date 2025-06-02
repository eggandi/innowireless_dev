/** 
  * @file 
  * @brief Path info 관련 정의
  * @date 2022-08-26 
  * @author gyun 
  */

#ifndef V2X_SW_J29451_PATH_INFO_H
#define V2X_SW_J29451_PATH_INFO_H


// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal-types.h"


#define J29451_vMinPHistDistance (200.0) ///< PH 최소길이(미터단위) (SAE J2945/1-2020 p.75)
#define J29451_vPathPerpendicularDist (0.875) ///< 미터단위 (SAE J2945/1-2020 p.75) - 1.0: 실패, 0.88: 실패, 0.87 이하: 성공
#if defined(_TARGET_STD_VER_2016_)
#define J29451_vMaxChordLength (210.0) ///< 연속된 두 포인트간 최대허용거리(미터단위) (SAE J2945/1-2020 p.75)
#elif defined(_TARGET_STD_VER_2020_)
/// 연속된 두 포인트간 최대허용거리(미터단위) (SAE J2945/1-2020 p.75)
/// Wayties TS로 드라이빙 테스트 수행 시, TS의 계산값과의 오차로 인해 우리가 계산한 vMaxChordLength 계산값이
/// TS 기준에서는 210미터가 초과하는 경우가 발생한다.
/// 따라서, 1미터의 여유를 두어 TS와 우리의 계산식간의 오차에 대응한다.
#define J29451_vMaxChordLength (210.0 - 1.0)
#endif
#define J29451_vMaxPHistPoints (15) ///< PH에 수납될 수 있는 포인트 최대 개수 (SAE J2945/1-2020 p.75)
#define J29451_MIN_PH_DISTANCE (J29451_vMinPHistDistance) ///< PH 최소길이(미터단위)
#ifdef _TARGET_STD_VER_2016_
#define J29451_MAX_PH_DISTANCE (J29451_vMaxChordLength) ///< PH 최대길이(미터단위)
#else
#define J29451_MAX_PH_DISTANCE (J29451_vMinPHistDistance + J29451_vMaxChordLength) ///< PH 최대길이(미터단위)
#endif
#define J29451_MIN_PH_GNSS_POINT_NUM (3) ///< Path history를 생성하기 위해 필요한 GNSS 포인트 최소 개수
#define J29451_MAX_PH_ACTUAL_ERR (J29451_vPathPerpendicularDist)
#define J29451_MAX_PH_POINT_NUM (J29451_vMaxPHistPoints)

#define J29451_PP_CURVATURE_CUTOFF_FREQ (0.33) ///< Curvature Cutoff frequency(Hz), SAE J2945/1-202004 Table A2
#define J29451_PP_CURVATURE_DAMPING_FACTOR (1) ///< Curvature Damping factor, SAE J2945/1-202004 Table A2
#define J29451_PP_CURVATURE_SAMPLING_PERIOD (100) ///< Curvature Sampling period(msec), SAE J2945/1-202004 Table A2
#define J29451_PP_CURVATURE_MIN_VEHICLE_SPEED (1) ///< Minimum vehicle speed(m/s), SAE J2945/1-202004 Table A2
#define J29451_PP_CURVATURE_MAX_RADIUS (2500) ///< Maximum radius(m), SAE J2945/1-202004 Table A2
#define J29451_PP_CONFIDENCE_CUTOFF_FREQ (1) ///< Confidence cutoff frequency(Hz), SAE J2945/1-202004 Table A2
#define J29451_PP_CONFIDENCE_DAMPING_FACTOR (1) ///< Confidence damping factor, SAE J2945/1-202004 Table A2
#define J29451_PP_CONFIDENCE_SAMPLING_PERIOD (100) ///< Confidence sampling period, SAE J2945/1-202004 Table A2
#define J29451_PP_MIN_CURVATURE_DATA_NUM_FOR_FILTERING (2) ///< 필터링을 위해 필요한 최소 데이터 개수 (현 시점에 필터링하고자 하는 데이터 제외)


/**
 * @brief Path history point 개수
 */
enum eJ29451PathHistoryPointNum
{
  kJ29451PathHistoryPointNum_Min = 1, ///< BSM에는 최소 1개 이상의 Path History point가 수납되어야 한다.
  kJ29451PathHistoryPointNum_Max = J29451_MAX_PH_POINT_NUM, ///< BSM에 수납 가능한 Path History point 최대 개수
};
typedef unsigned int J29451PathHistoryPointNum; ///< @ref eJ29451PathHistoryPointNum


/**
 * @brief Path history를 생성하기 위해 사용되는 GNSS 포인트 리스트 엔트리 개수
 */
enum eJ29451PathHistoryGNSSPointListEntryNum
{
  kJ29451PathHistoryGNSSPointListEntryNum_Min = 0,
  kJ29451PathHistoryGNSSPointListEntryNum_Sufficient = J29451_MIN_PH_GNSS_POINT_NUM, ///< Path history를 만들기에 충분한 포인트 수
};
typedef unsigned int J29451PathHistoryGNSSPointListEntryNum; ///< @ref eJ29451PathHistoryGNSSPointListEntryNum


/**
 * @brief Path history를 생성하기 위해 사용되는 GNSS 포인트 리스트 엔트리
 */
struct J29451PathHistoryGNSSPointListEntry
{
  struct J29451GNSSData point; ///< GNSS 포인트 정보

  bool is_ph_point; ///< 본 포인트 정보가 실제 BSM에 수납되는 PH point인지 여부
  struct {
    struct J29451PathHistoryGNSSPointListEntry *next; // 직후(보다 최근) PH point
    struct J29451PathHistoryGNSSPointListEntry *prev; // 직전(보다 과거) PH point
    double dist_from_prev; ///< 직전 PH point와의 거리 (미터 단위)
  } ph_point; ///< 본 포인트정보가 실제 BSM에 수납되는 PH point일 때 사용되는 정보

  TAILQ_ENTRY(J29451PathHistoryGNSSPointListEntry) entries;
};
TAILQ_HEAD(J29451PathHistoryGNSSPointListEntryHead, J29451PathHistoryGNSSPointListEntry);


/**
 * @brief Path history를 생성하기 위해 사용되는 GNSS 포인트 리스트
 *
 * 기본적으로 100msec 마다 획득한 GNSS 포인트 정보들이 저장된다.
 * 본 리스트에 저장된 포인트정보들 중 일부가 (J2945/1 메커니즘에 따라 결정되는) PH point가 되며,
 * 이 PH point들이 실제 BSM 내 Path History에 수납된다.
 * 생성된 순서대로 저장된다. 즉 가장 오래된 정보가 가장 앞에 저장된다.
 */
struct J29451PathHistoryGNSSPointList
{
  J29451PathHistoryGNSSPointListEntryNum entry_num; ///< 저장된 엔트리 개수
  struct J29451PathHistoryGNSSPointListEntryHead head;

  /// PH point를 선별하기 위해 사용되는 정보들
  /// SAE J2945/1-2020 표준 참조
  /// 메커니즘 상 p_prev와 p_next는 항상 붙어있어야 한다.
  struct {
    struct J29451PathHistoryGNSSPointListEntry *p_start;
    struct J29451PathHistoryGNSSPointListEntry *p_prev;
    struct J29451PathHistoryGNSSPointListEntry *p_next;
    struct J29451PathHistoryGNSSPointListEntry *p_recent; // 가장 최근에 추가된(리스트의 제일 뒤에 저장된) 정보 엔트리
  } internal;
};


/**
 * @brief PathHistory 정보
 */
struct J29451PathHistory
{
  struct J29451PathHistoryGNSSPointList gnss_point_list; ///< Path history를 생성하기 위한 GNSS 포인트 리스트

  struct {
    J29451PathHistoryPointNum point_num; ///< PH point 개수
    double total_dist; ///< PH point들의 총거리합(m 단위)
    struct J29451PathHistoryGNSSPointListEntry *oldest; ///< 가장 과거의 PH point
    struct J29451PathHistoryGNSSPointListEntry *recent; ///< 가장 최근의 PH point
  } ph_points; ///< GNSS 포인트정보 중 (실제 BSM에 수납되는) Path history point들에 대한 정보
};


/**
 * @brief Path prediction Curvature 정보 필터에서 사용되는 정보
 */
struct J29451PathPredictionCurvatureFilterInfo
{
  unsigned int filtering_cnt; ///< 필터링을 수행한 횟수 (0에서 시작하여 2까지 증가한다)
  double y[J29451_PP_MIN_CURVATURE_DATA_NUM_FOR_FILTERING]; ///< y1(=y[0]) & y2(=y[1]), SAE J2945/1-202004 p.98 Figure A17
  double numerator1_coeff; ///< 방정식 내 첫번째 분자의 계수, SAE J2945/1-202004 p.98 Figure A17
  double numerator2_coeff; ///< 방정식 내 두번째 분자의 계수, SAE J2945/1-202004 p.98 Figure A17
  double numerator3_coeff; ///< 방정식 내 세번째 분자의 계수, SAE J2945/1-202004 p.98 Figure A17
  double denominator; ///< 방정식 내 분모, SAE J2945/1-202004 p.98 Figure A17
};


/**
 * @brief Path prediction Confidence 정보 필터에서 사용되는 정보
 */
struct J29451PathPredictionConfidenceFilterInfo
{
  double yawrate_prev; ///< 직전 필터링에 사용된 yawrate
  double y[J29451_PP_MIN_CURVATURE_DATA_NUM_FOR_FILTERING]; ///< y1(=y[0]) & y2(=y[1]), SAE J2945/1-202004 p.99 Figure A19
  double numerator1_coeff; ///< 방정식 내 첫번째 분자의 계수, SAE J2945/1-202004 p.99 Figure A19
  double numerator2_coeff; ///< 방정식 내 두번째 분자의 계수, SAE J2945/1-202004 p.99 Figure A19
  double numerator34_coeff; ///< 방정식 내 세번째/네번째 분자의 계수, SAE J2945/1-202004 p.99 Figure A19
  double denominator; ///< 방정식 내 분모, SAE J2945/1-202004 p.99 Figure A19
};


/*&
 * @brief Path prediction 정보
 */
struct J29451PathPrediction
{
  J29451RadiusOfCurvature radius_of_curve; ///< 커브 반지름
  J29451Confidence confidence; ///< 신뢰도

  struct {
    struct J29451PathPredictionCurvatureFilterInfo cv_filter; ///< Curvature 필터
    struct J29451PathPredictionConfidenceFilterInfo cf_filter; ///< Confidence 필터
  } internal;
};


/**
 * @brief PathHistory와 PathPrediction 정보, 가장 최근 heading 값
 */
struct J29451PathInfo
{
  struct J29451PathHistory ph; ///< Path history 정보
  struct J29451PathPrediction pp; ///< Path prediction 정보
#ifdef _TARGET_STD_VER_2016_
  bool backup_ph_present; ///< 재부팅 후 로딩한 PH 백업정보가 존재하는지 여부
#endif
};



// j29451-path-history.c
bool INTERNAL j29451_UpdatePathHistoryInfo(void);
void INTERNAL j29451_RestorePHPointList(void);

// j29451-path-info.c
void INTERNAL j29451_InitPathInfo(struct J29451PathInfo *info);
void INTERNAL j29451_ReleasePathInfo(struct J29451PathInfo *info);
void INTERNAL j29451_PushGNSSPointInfo(struct J29451GNSSData *gnss_data, bool in_ph);
bool INTERNAL j29451_UpdatePathInfo(struct J29451GNSSData *gnss_data);

// j29451-path-info-backup.c
void INTERNAL j29451_SavePathInfoBackupFile(const char *file_path);
void INTERNAL j29451_LoadPathInfoBackupFile(const char *file_path);

// j29451-path-prediction.c
void INTERNAL j29451_UpdatePathPredictionInfo(void);
void INTERNAL j29451_InitPathPredictionCurvatureFilter(void);
void INTERNAL j29451_InitPathPredictionConfidenceFilter(void);


#endif //V2X_SW_J29451_PATH_INFO_H
