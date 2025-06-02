/** 
  * @file 
  * @brief Path prediction 관련 구현
  * @date 2022-09-15 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <assert.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "gps.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"


/*
 * @brief 2735 형식의 속도 값을 m/s 단위 형식으로 변환한다. (0.02m/s 단위 -> 1m/s 단위)
 * @param[in] speed 2735 형식 속도값
 * @return 1m/s 단위 속도값
 */
static inline double j29451_ConvertToRawSpeed(J29451Speed speed)
{
  return (speed <= kJ29451Speed_Max) ? ((double)speed * 0.02) : NAN;
}


/*
 * @brief 2735 형식의 요율값을 deg/s 단위 형식으로 변환한다. (0.01 deg/s 단위 -> 1 deg/s 단위)
 * @param[in] yawrate 2735 형식 요율값
 * @return 1deg/s 단위 요율값(각속도)
 */
static inline double j29451_ConvertToRawYawRate(J29451YawRate yaw_rate)
{
  if (yaw_rate < kJ29451YawRate_Min)  {
    yaw_rate = kJ29451YawRate_Min;
  } else if (yaw_rate > kJ29451YawRate_Max) {
    yaw_rate = kJ29451YawRate_Max;
  }
  return ((double)yaw_rate * 0.01);
}


/*
 * @brief RadiusOfCurvature 값을 2735 형식으로 변환한다. (1m 단위 -> 0.1m 단위)
 * @param[in] radius_of_curvature 1m 단위 RadiusOfCurvature 값
 * @return 2735 형식의 RadiusOfCurvature 값
 */
static inline J29451RadiusOfCurvature j29451_ConvertRadiusOfCurvature(double radius_of_curvature)
{
  J29451RadiusOfCurvature ret;
  double converted = (radius_of_curvature * 10.0);
  if (converted > kJ29451RadiusOfCurvature_Max) {
    ret = kJ29451RadiusOfCurvature_Max;
  } else if (converted < kJ29451RadiusOfCurvature_Min) {
    ret = kJ29451RadiusOfCurvature_Min;
  } else {
    ret = (J29451RadiusOfCurvature)converted;
  }
  return ret;
}


/**
 * @brief 필터링되지 않은 Curvature 값을 계산한다.
 * @param[in] speed 속도 (m/s 단위)
 * @param[in] yawrate 요율 (Radian/s 단위)
 * @return 필터링되지 않은 Curvature 값
 *
 * 필터가 아직 준비되지 않았을 때 호출된다.
 */
static inline J29451Curvature j29451_GetPathPredictionNotRawCurvature(double speed, double yawrate)
{
  assert(speed); // speed는 0일 수 없다 (본 함수 호출전에 필터링된다)

  /*
   * Curvature를 계산한다.
   */
  J29451Curvature curvature = yawrate / speed;

  /*
   * (향후) 필터 동작을 위한 정보를 업데이트한다.
   */
  struct J29451PathPredictionCurvatureFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cv_filter);
  filter->y[filter->filtering_cnt] = curvature;

  return curvature;
}


/**
* @brief curvature의 주파수를 감쇠시키기 위한 second order low pass filter를 적용한 curvature값을 구한다.
* @param[in] u Curvature 값 (1/m 단위)
* @return 필터링된 curvature 값 (1/m 단위)
 *
 * SAE J2945/1-202004 p.98 Figure A17 참조
*/
static inline J29451Curvature j29451_SecondOrderLowPassFilter(double u)
{
  struct J29451PathPredictionCurvatureFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cv_filter);
  double numerator1 = filter->numerator1_coeff * filter->y[0]; ///< 방정식 내 첫번째 분자, SAE J2945/1-202004 p.98 Figure A17
  double numerator2 = filter->numerator2_coeff * filter->y[1]; ///< 방정식 내 두번째 분자, SAE J2945/1-202004 p.98 Figure A17
  double numerator3 = filter->numerator3_coeff * u; ///< 방정식 내 세번째 분자, SAE J2945/1-202004 p.98 Figure A17
  double numerator = numerator1 + numerator2 + numerator3; ///< 방정식 내 분자, SAE J2945/1-202004 p.98 Figure A17
  return (numerator / filter->denominator); ///< 방정식 결과 = y_n
}


/**
* @brief yawrate 변화에 대한 주파수를 감쇠시키기 위한 second order low pass filter differentiator를 적용한 델타 yawrate 값을 구한다.
* @param[in] u yawrate 값 (deg/s 단위)
* @return 필터링된 델타 yawrate 값 (deg/s^2 단위)
 *
 * SAE J2945/1-202004 p.98 Figure A19
*/
static inline double j29451_SecondOrderLowPassFilterDifferentiator(double u)
{
  struct J29451PathPredictionConfidenceFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cf_filter);
  double numerator1 = filter->numerator1_coeff * filter->y[0]; ///< 방정식 내 첫번째 분자, SAE J2945/1-202004 p.99 Figure A19
  double numerator2 = filter->numerator2_coeff * filter->y[1]; ///< 방정식 내 두번째 분자, SAE J2945/1-202004 p.99 Figure A19
  double numerator3 = filter->numerator34_coeff * (u - filter->yawrate_prev); ///< 방정식 내 세번째/네번째 분자, SAE J2945/1-202004 p.99 Figure A19
  double numerator = numerator1 + numerator2 + numerator3; ///< 방정식 내 분자, SAE J2945/1-202004 p.99 Figure A19
  return (numerator / filter->denominator); ///< 방정식 결과 = y_n
}


/*
 * @brief 필터링된 Curvature 값을 계산한다.
 * @param[in] speed 속도 (m/s 단위)
 * @param[in] yawrate 요율 (Radian/s 단위)
 * @return 필터링된 Curvature 값
 */
static inline J29451Curvature j29451_GetPathPredictionFilteredCurvature(double speed, double yawrate)
{
  assert(speed); // speed는 0일 수 없다 (본 함수 호출전에 필터링된다)

  /*
   * 필터링된 curvature를 계산한다.
   */
  J29451Curvature curvature_raw = yawrate / speed;
  J29451Curvature curvature_filtered = j29451_SecondOrderLowPassFilter(curvature_raw);

  /*
   * 필터 파라미터를 업데이트하다.
   */
  struct J29451PathPredictionCurvatureFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cv_filter);
  filter->y[0] = filter->y[1];
  filter->y[1] = curvature_filtered;
  return curvature_filtered;
}


/**
 * @brief RadiusOfCurvature를 계산한다.
 * @param[in] speed 속도 (m/s 단위)
 * @param[in] yawrate 요율 (Radian/s 단위)
 * @return 계산된 RadiusOfCurvature 값
 */
static J29451RadiusOfCurvature j29451_CalculatePathPredictionRadiusOfCurvature(double speed, double yawrate)
{
  Log(kJ29451LogLevel_Event, "Calculate PP RadiusOfCurvature - speed: %.2fm/s, yawrate: %.2frad/s\n", speed, yawrate);

  /*
   * 필터가 아직 준비되지 않았으면(필터링에 필요한 최소 2개의 과거 Curvature 정보가 아직 저장되어 있지 않으면),
   * 필터링되지 않은 Curvature를 계산한다.
   */
  J29451Curvature curvature;
  struct J29451PathPredictionCurvatureFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cv_filter);
  if (filter->filtering_cnt < J29451_PP_MIN_CURVATURE_DATA_NUM_FOR_FILTERING) {
    curvature = j29451_GetPathPredictionNotRawCurvature(speed, yawrate);
    filter->filtering_cnt++;
  }

  /*
   * 필터가 준비되었으면(필터링에 필요한 최소 2개의 과거 Curvature 정보가 저장되었으면)
   * 필터링된 Curvature를 계산한다.
   */
  else {
    curvature = j29451_GetPathPredictionFilteredCurvature(speed, yawrate);
  }

  /*
   * RadiusOfCurvature(=1/curvature)를 계산한다.
   * curvature가 0이면 나눌수가 없으므로 그냥 임계값보다 큰 값으로 설정한다 -> 직진으로 간주
   * (curvature가 0이면 RadiusOfCurvature가 무한대이므로, 이는 임계값보다 큰 값에 해당된다)
   */
  double radius_of_curvature; // m 단위 radius of curvature
  if (curvature) {
    radius_of_curvature = 1 / curvature;
  } else {
    radius_of_curvature = J29451_PP_CURVATURE_MAX_RADIUS + 1;
  }

  /*
   * RadiusOfCurvature 값이 너무 크면(임계치를 초과하면), 직진으로 설정한다.
   */
  if (fabs(radius_of_curvature) > J29451_PP_CURVATURE_MAX_RADIUS) {
    return kJ29451RadiusOfCurvature_Straight;
  }

  return j29451_ConvertRadiusOfCurvature(radius_of_curvature); // 단위변환하여 반환
}


/*
 * @brief 필터링된 델타 yawrate(=yawrate의 변화)로 예측한 radiusOfCurvature의 신뢰도를 찾는다. *
 * @param[in] x 필터링된 델타 yawrate의 절대값
 * @return 신뢰도
 *
 * AE J2945/1-202004 p.101 Table A3 참조
 */
static inline J29451Confidence j29451_LookupPathPredictionConfidence(double x)
{
  double y;
  if (x > 25) {
    y = 0;
  } else if (x >= 5) {
    y = -2 * x + 50;
  } else if (x >= 2.5) {
    y = -4 * x + 60;
  } else {
    y = -20 * x + 100;
  }
  return (J29451Confidence)(2 * y); // % 단위를 0.5% 단위로 변환
}


/**
 * @brief Confidence를 계산한다.
 * @param[in] yawrate 요율 (deg/s 단위)
 * @return 계산된 Confidence 값
 *
 * SAE J2945/1-202004 p.99 A.6.4 참조
 * SAE J2945/1-202004 p.100 Figure A20 참조
 */
static J29451Confidence j29451_CalculatePathPredictionConfidence(double yawrate)
{
  Log(kJ29451LogLevel_Event, "Calculate PP Confidence - yawrate: %.2fdeg/s\n", yawrate);

  /*
   * 필터링된 delta yawrate를(deg/s^2)을 계산한다.
   * delta yawrate : 직전 yawrate와 현시점 yawrate 사이의 변화율
   */
  double delta_yawrate_filtered = j29451_SecondOrderLowPassFilterDifferentiator(yawrate);

  /*
   * 필터 파라미터를 업데이트한다.
   */
  struct J29451PathPredictionConfidenceFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cf_filter);
  filter->yawrate_prev = yawrate;
  filter->y[0] = filter->y[1];
  filter->y[1] = delta_yawrate_filtered;

  /*
   * 필터링된 델타 Yawrate로부터 Confidence를 구한다.
   */
  return j29451_LookupPathPredictionConfidence(fabs(delta_yawrate_filtered));
}


/**
 * @brief Path prediction 정보를 업데이트한다.
 *
 * 업데이트된 정보는 PP에 수납된다.
 * SAE J2945/1-202004 p.96 A.6 참조
 * SAE J2945/1-202004 p.99 Figure A18 참조
 */
void INTERNAL j29451_UpdatePathPredictionInfo(void)
{
  Log(kJ29451LogLevel_Event, "Update path prediction info\n");

  /*
   * 최신 GNSS 포인트 정보를 가져온다 -> PP 계산에 사용된다.
   */
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *recent = TAILQ_LAST(&(list->head), J29451PathHistoryGNSSPointListEntryHead);
  assert(recent); ///< 본 함수는 최소 하나 이상의 GNSS 정보가 저장된 후 호출되어야 한다.

  /*
   * 연산을 위해 speed와 yawrate의 단위를 변환한다. SAE J2945/1-202004 p.98
   * RadiusOfCurvature 연산 - speed: m/s, yawrate: rad/s
   * Confidence 연산 - yawrate: deg/s
   */
  double speed = j29451_ConvertToRawSpeed(recent->point.speed);
  double yawrate_deg = j29451_ConvertToRawYawRate(recent->point.acceleration_set.yaw);
  double yawrate_rad = j29451_ConvertDecimalDegreesToRadians(yawrate_deg);

  /*
   * 속도가 너무 느리거나(임계치보다 작으면) 직진으로 간주한다.
   * 그렇지 않으면 RadiusOfCurvature를 계산한다.
   */
  J29451RadiusOfCurvature radius_of_curve;
  if (speed < J29451_PP_CURVATURE_MIN_VEHICLE_SPEED) {
    Log(kJ29451LogLevel_Event, "RadiusOfCurvature is straight - low speed(%.2fm/s)\n", speed);
    radius_of_curve = kJ29451RadiusOfCurvature_Straight;
  } else {
    radius_of_curve = j29451_CalculatePathPredictionRadiusOfCurvature(speed, yawrate_rad);
  }

  /*
   * PP에 수납될 RadiusOfCurvate와 Confidence 값을 저장한다.
   */
  struct J29451PathPrediction *pp = &(g_j29451_mib.path.pp);
  pp->radius_of_curve = radius_of_curve;
  if (radius_of_curve == kJ29451RadiusOfCurvature_Straight) {
    pp->confidence = kJ29451Confidence_Max;
  } else {
    pp->confidence = j29451_CalculatePathPredictionConfidence(yawrate_deg);
  }
}


/**
 * @brief Path prediction Curvature filter를 초기화한다.
 */
void INTERNAL j29451_InitPathPredictionCurvatureFilter(void)
{
  struct J29451PathPredictionCurvatureFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cv_filter);
  memset(filter, 0, sizeof(struct J29451PathPredictionCurvatureFilterInfo));
  double f0 = J29451_PP_CURVATURE_CUTOFF_FREQ; ///< cutoff frequency(Hz), SAE J2945/1-202004 p.98 Figure A17
  double zeta = J29451_PP_CURVATURE_DAMPING_FACTOR; ///< damping factor, SAE J2945/1-202004 p.98 Figure A17
  double Ts = J29451_PP_CURVATURE_SAMPLING_PERIOD; ///< sampling time(msec), SAE J2945/1-202004 p.98 Figure A17
  double w0 = (2 * GPS_PI * f0); ///< SAE J2945/1-202004 p.98 Figure A17
  filter->numerator1_coeff = -1;
  filter->numerator2_coeff = (2 + (2 * w0 * zeta * Ts));
  filter->numerator3_coeff = (w0 * w0 * Ts * Ts);
  filter->denominator = (1 + (2 * w0 * zeta * Ts) + (w0 * w0 * Ts * Ts));
}


/**
 * @brief Path prediction Confidence filter를 초기화한다.
 */
void INTERNAL j29451_InitPathPredictionConfidenceFilter(void)
{
  struct J29451PathPredictionConfidenceFilterInfo *filter = &(g_j29451_mib.path.pp.internal.cf_filter);
  memset(filter, 0, sizeof(struct J29451PathPredictionConfidenceFilterInfo));
  double f0 = J29451_PP_CONFIDENCE_CUTOFF_FREQ; ///< cutoff frequency(Hz), SAE J2945/1-202004 p.99 Figure A19
  double zeta = J29451_PP_CONFIDENCE_DAMPING_FACTOR; ///< damping factor, SAE J2945/1-202004 p.99 Figure A19
  double Ts = J29451_PP_CONFIDENCE_SAMPLING_PERIOD; ///< sampling time(msec), SAE J2945/1-202004 p.99 Figure A19
  double w0 = (2 * GPS_PI * f0); ///< SAE J2945/1-202004 p.99 Figure A19
  filter->numerator1_coeff = -1;
  filter->numerator2_coeff = (2 + (2 * w0 * zeta * Ts));
  filter->numerator34_coeff = (w0 * w0 * Ts);
  filter->denominator = ((w0 * w0 * Ts * Ts) + (2 * w0 * zeta * Ts) + 1);
}
