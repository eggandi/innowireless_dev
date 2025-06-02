/** 
  * @file 
  * @brief Path history 관련 구현
  * @date 2022-08-26 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <assert.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "gps.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"


/**
 * @brief GNSS 포인트정보를 최초 PH point로 만든다.
 * @param[in] entry GNSS 포인트정보 엔트리
 */
static inline void j29451_MakeFirstPHPoint(struct J29451PathHistoryGNSSPointListEntry *entry)
{
  struct J29451PathHistory *ph = &( g_j29451_mib.path.ph);

  /*
   * PH point임을 표시한다.
   */
  entry->is_ph_point = true;
  entry->ph_point.next = NULL;
  entry->ph_point.prev = NULL;
  entry->ph_point.dist_from_prev = 0.0;

  /*
   * PH point 리스트 정보를 업데이트한다.
   */
  ph->ph_points.point_num++;
  ph->ph_points.total_dist = 0.0;
  ph->ph_points.oldest = entry;
  ph->ph_points.recent = entry;
}


/**
 * @brief GNSS 포인트정보를 최신 PH point로 만든다.
 * @param[in] entry GNSS 포인트정보 엔트리
 */
static inline void j29451_MakeRecentPHPoint(struct J29451PathHistoryGNSSPointListEntry *entry)
{
  double dist_from_prev;
  struct J29451PathHistory *ph = &( g_j29451_mib.path.ph);

  /*
   * 직전 PH point(기존 PH point 중 가장 최근 point)와 연결하고 거리를 계산한다.
   */
  struct J29451PathHistoryGNSSPointListEntry *prev = ph->ph_points.recent;
  assert(prev);
  prev->ph_point.next = entry;
  entry->ph_point.next = NULL;
  entry->ph_point.prev = prev;
  dist_from_prev = earth_distance(prev->point.lat_deg,
                                  prev->point.lon_deg,
                                  entry->point.lat_deg,
                                  entry->point.lon_deg);
  entry->ph_point.dist_from_prev = dist_from_prev;

  /*
   * PH point임을 표시한다.
   */
  entry->is_ph_point = true;

  /*
   * PH point 리스트 정보를 업데이트한다.
   */
  ph->ph_points.point_num++;
  ph->ph_points.total_dist += dist_from_prev;
  ph->ph_points.recent = entry;
}


/**
 * @brief GNSS 포인트정보를 가장 오래된 PH point로 만든다.
 * @param[in] entry GNSS 포인트정보 엔트리
 */
static inline void j29451_MakeOldestPHPoint(struct J29451PathHistoryGNSSPointListEntry *entry)
{
  double dist_to_next;
  struct J29451PathHistory *ph = &( g_j29451_mib.path.ph);

  /*
   * 직후 PH point(기존 PH point 중 가장 오래된 point)와 연결하고 거리를 계산한다.
   */
  struct J29451PathHistoryGNSSPointListEntry *next = ph->ph_points.oldest;
  assert(next);
  next->ph_point.prev = entry;
  dist_to_next = earth_distance(next->point.lat_deg,
                                next->point.lon_deg,
                                entry->point.lat_deg,
                                entry->point.lon_deg);
  next->ph_point.dist_from_prev = dist_to_next;
  entry->ph_point.next = next;
  entry->ph_point.prev = NULL;
  entry->ph_point.dist_from_prev = 0.0;

  /*
   * PH point임을 표시한다.
   */
  entry->is_ph_point = true;

  /*
   * PH point 리스트 정보를 업데이트한다.
   */
  ph->ph_points.point_num++;
  ph->ph_points.total_dist += dist_to_next;
  ph->ph_points.oldest = entry;
}


/**
 * @brief PH point 리스트 내 가장 오래된 PH point 정보의 자격을 박탈한다. (더이상 PH point가 아니게 된다)
 * @return 자격이 박탈된 PH point 엔트리 포인터
 *
 * 본 함수는 next가 반드시 있는 경우에만 호출되어야 한다 -> 그래야 oldest를 삭제하고도 최소 1개의 PH point가 존재한다.
 */
static inline struct J29451PathHistoryGNSSPointListEntry * j29451_DisqualifyOldestPHPoint(void)
{
  struct J29451PathHistory *ph = &( g_j29451_mib.path.ph);
  struct J29451PathHistoryGNSSPointListEntry *oldest = ph->ph_points.oldest;
  assert(oldest); // PH point는 GNSS 포인트가 3개 생기기 전인 최초 시점을 제외하고는 항상 1개 이상 존재한다.
  struct J29451PathHistoryGNSSPointListEntry *next = oldest->ph_point.next;
  assert(next); // oldest를 삭제하고도 최소 1개의 PH point(=next)가 존재해야 한다.
  oldest->is_ph_point = false;
  oldest->ph_point.next = NULL;
  ph->ph_points.point_num--;
  ph->ph_points.total_dist -= next->ph_point.dist_from_prev;
  ph->ph_points.oldest = next;
  next->ph_point.prev = NULL;
  next->ph_point.dist_from_prev = 0.0;
  return oldest;
}


/**
 * @brief 가장 오래된 PH point를 제거한다. (GNSS 포인트정보 리스트에서 제거하고 삭제한다)
 *
 * 본 함수는 next가 반드시 있는 경우에만 호출되어야 한다 -> 그래야 oldest를 삭제하고도 최소 1개의 PH point가 존재한다.
 */
static inline void j29451_RemoveOldestPHPoint(void)
{
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *oldest = j29451_DisqualifyOldestPHPoint();
  TAILQ_REMOVE(&(list->head), oldest, entries);
  list->entry_num--;
  free(oldest);
}


/**
 * @brief 첫번째(=가장 과거의) PH point보다 더 오래된 GNSS 포인트 정보들을 제거한다.
 *        (해당 정보들은 더이상 사용되지 않으므로)
 *
 * GNSS 포인트 리스트 내에서 첫번재 PH point인 GNSS 포인트 직전 정보까지 삭제한다.
 */
static inline void j29451_RemoveGNSSPointEntriesOlderThanFirstPHPoint(void)
{
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    if (entry->is_ph_point == true) {
      break;
    }
    TAILQ_REMOVE(&(list->head), entry, entries);
    list->entry_num--;
    free(entry);
  }
}


/*
 * @brief 두 좌표간의 ActualCordLength를 계산한다.
 * @param[in] 좌표 1
 * @param[in] 좌표 2
 * @return 두 지점 사이의 거리 (미터 단위)
*/
static inline double j29451_CalculateActualChordLength(struct J29451GNSSData *p1, struct J29451GNSSData *p2)
{
  return earth_distance(p1->lat_deg, p1->lon_deg, p2->lat_deg, p2->lon_deg);
}


/**
 * @brief REarthMeridian(radius of earth in meridian)을 계산한다.
 * @param[in] lat 참조 위도
 * @return REarthMeridian (미터 단위)
 *
 * SAE J2945/1-202004 p.82 A.2 참조
 */
static inline double j29451_CalculateREarthMeridian(double lat)
{
  double a = 6378137.0; // semi-major axis of earth (=WGS84A)
  double f = 0.003353; // flattening
  double f1 = pow((f * (2 - f)), 0.5); // eccentricity, f1 = (f*(2-f))^0.5
  double f2_numerator = a * (1 - pow(f1, 2)); // f2의 분자, a*(1-f1^2)
  double f2_denominator = pow((1 - (pow(f1, 2) * pow(sin(lat), 2))), 1.5); // f2의 분모, (1-f1^2*(sin(RefLat))^2)^(3/2);
  return (f2_numerator / f2_denominator); // f2 반환
}


/**
 * @brief 위도/경도를 X,Y 값으로 변환한다. (LLA 좌표계를 NED 좌표계로 변환)
 * @param[in] lat 위도
 * @param[in] lon 경도
 * @param[in] ref_lat 참조 위도
 * @param[in] r_earth 지구 반지름
 * @param[out] x X값이 저장될 변수 포인터
 * @param[out] y y값이 저장될 변수 포인터
 *
 * https://stackoverflow.com/questions/16266809/convert-from-latitude-longitude-to-x-y 의 latlngToGlobalXY() 참조
 */
static inline void j29451_ConvertLLAToXY(double lat, double lon, double ref_lat, double r_earth, double *x, double *y)
{
  *x = r_earth * lon * cos(ref_lat);
  *y = r_earth * lat;
}


/*
 * @brief 점과 직선 사이의 수직거리를 계산한다
 * @param[in] 직선의 끝점1 좌표 (SAE J2945/1-202004 p.89 Figure A6 상의 A 지점)
 * @param[in] 직선의 끝점2 좌표 (SAE J2945/1-202004 p.89 Figure A6 상의 C 지점)
 * @param[in] 점 좌표 (SAE J2945/1-202004 p.89 Figure A6 상의 D 지점)
 * @return 점과 직선 사이의 수직 거리 (미터단위)
 *
 * SAE J2945/1-202004 p.82 A.2 참조
*/
static double
j29451_CaculatePerpendicularDistance(struct J29451GNSSData *A, struct J29451GNSSData *C, struct J29451GNSSData *D)
{
  /*
   * A,C,D: SAE J2945/1-202004 p.89 Figure A6 상의 각 지점
   */
  double A_lat = A->lat_rad;
  double A_lon = A->lon_rad;
  double C_lat = C->lat_rad;
  double C_lon = C->lon_rad;
  double D_lat = D->lat_rad;
  double D_lon = D->lon_rad;

  /*
   * A,C,D 각 지점의 위도/경도를 X/Y 값으로 변환한다.
   */
  double x1, y1; // SAE J2945/1-202004 p.89 Figure A6 상의 A 지점
  double x2, y2; // SAE J2945/1-202004 p.89 Figure A6 상의 C 지점
  double x3, y3; // SAE J2945/1-202004 p.89 Figure A6 상의 D 지점
  double ref_lat = (A_lat + C_lat) / 2;
  double r_earth = j29451_CalculateREarthMeridian(ref_lat);
  j29451_ConvertLLAToXY(A_lat, A_lon, ref_lat, r_earth, &x1, &y1);
  j29451_ConvertLLAToXY(C_lat, C_lon, ref_lat, r_earth, &x2, &y2);
  j29451_ConvertLLAToXY(D_lat, D_lon, ref_lat, r_earth, &x3, &y3);

  /*
   * u 계산 (per SAE J2945/1-202004 p.89)
   * u = ((x3-x1)(x2-x1) + (y3-y1)(y2-y1)) / ||C-A||^2 .
   */
  double u_numerator = (x3 - x1) * (x2 - x1) + (y3 - y1) * (y2 - y1); // u의 분자, ((x3-x1)(x2-x1) + (y3-y1)(y2-y1))
  double u_denominator = pow(x1 - x2, 2) + pow(y1 - y2, 2); // u의 분모, ||C - A||^2 (= (x1-x2)^2 + (y1-y2)^2 )
  double u = u_numerator / u_denominator;

  /*
   * B(x,y) 계산 (per SAE J2945/1-202004 p.89)
   */
  double x = x1 + u * (x2 - x1); // x = x1 + u(x2 - x1)
  double y = y1 + u * (y2 - y1); // y = y1 + u(y2 - y1)

  /*
   * B(x,y) - D(x3,y3) 간 거리 계산 (per SAE J2945/1-202004 p.89)
   */
  return sqrt(pow(x3 - x, 2) + pow(y3 - y, 2)); // d = sqrt((x3-x)^2 + (y3-y)^2).
}


/*
 * @brief p1과 p2 사이의 ActualError를 계산한다.
 * @param[in] p1 포인트1 (시간 상 p2보다 과거 시점의 포인트)
 * @param[in] p2 포인트2 (시간 상 p1보다 미래 시점의 포인트)
 * @return 계산된 ActualError (미터 단위).
 *
 * p1과 p2 사이에는 최소 1개 이상의 포인트가 존재해야 한다.
 * ActualError = p1과 p2를 잇는 직선과 p1~p2 사이에 있는 각 포인트 사이의 수직 거리 중 최대값.
 */
static double j29451_CaculateActualError(
  struct J29451PathHistoryGNSSPointListEntry *p1,
  struct J29451PathHistoryGNSSPointListEntry *p2)
{
  Log(kJ29451LogLevel_Event, "Calculate ActualError\n");

  /*
   * 두 포인트의 좌표가 동일하면 0을 반환한다
   */
  if ((p1->point.lat == p2->point.lat) &&
      (p1->point.lon == p2->point.lon)) {
    return 0;
  }

  /*
   * P1과 p2를 잇는 직선과 그 사이에 있는 각 포인트 사이의 수직 거리를 계산한다.
   * 계산된 각 포인트 별 수직거리들 중 최대값을 ActualError로 설정한다.
   */
  double perpendicular_dist, actual_err = 0;
  struct J29451PathHistoryGNSSPointListEntry *point = TAILQ_NEXT(p1, entries);
  assert(point);
  assert(point != p2);
  do {
    perpendicular_dist = j29451_CaculatePerpendicularDistance(&(p1->point), &(p2->point), &(point->point));
    actual_err = (perpendicular_dist > actual_err) ? perpendicular_dist : actual_err;
    point = TAILQ_NEXT(point, entries); // 다음 포인트
    assert(point);
  } while(point != p2);

  return actual_err;
}


/**
 * @brief 가장 오래된 PH point를, 그 바로 직후의 GNSS 포인트 정보로 대체한다. (PH distance를 줄이기 위해서)
 *        대체할 GNSS 포인트 정보는 PH point가 아니어야 한다.
 * @return 대체되었는지 여부
 */
static inline bool j29451_ReplaceOldestPHPointWithNextGNSSPoint(void)
{
  struct J29451PathHistory *ph = &(g_j29451_mib.path.ph);
  struct J29451PathHistoryGNSSPointListEntry *oldest = ph->ph_points.oldest;
  assert(oldest);
  assert(oldest->is_ph_point);
  struct J29451PathHistoryGNSSPointListEntry *next_gnss_point = TAILQ_NEXT(oldest, entries);
  assert(next_gnss_point);

  /*
   * 첫번째 PH point의 직후 GNSS 포인트 정보도 PH point인 경우에는 대체할 수 없다.
   */
  if (next_gnss_point->is_ph_point == true) {
    return false;
  }

  /*
   * PH point가 1개 밖에 없으면 대체할 수 없다.
   */
  if (ph->ph_points.point_num <= kJ29451PathHistoryPointNum_Min) {
    return false;
  }

  /*
   * 가장 오래된 PH point 정보를 삭제한다.
   */
  j29451_RemoveOldestPHPoint();

  /*
   * 그 다음 GNSS 포인트를 PH point로 변경한다.
   */
  j29451_MakeOldestPHPoint(next_gnss_point);
  return true;
}


/**
 * @brief PH point 리스트를 최적화한다.
 *
 * 1. PH point들간의 총 거리합이 J29451_MIN_PH_DISTANCE(=200m) 이상을 유지하는 상태에서 PH point 수를 최대한 줄인다.
 * 2. PH point 수가 J29451_MAX_PH_POINT_NUM보다 크지 않도록 조정한다 (총 거리합이 J29451_MIN_PH_DISTANCE 보다 작게 되더라도)
 * 3. (2016 버전 표준을 따르는 경우) PH point들간의 총 거리합이 J29451_MAX_PH_DISTANCE(=210m)를 초과하지 않도록
 *    가장 과거의 PH point를 보다 최근의 GNSS 포인트로 변경한다.
 */
static void j29451_OptimizePHPointList(void)
{
  struct J29451PathHistory *ph = &(g_j29451_mib.path.ph);
  Log(kJ29451LogLevel_Event, "Optimize PH point list - current(dist: %.1f, count: %u)\n",
      ph->ph_points.total_dist, ph->ph_points.point_num);

  struct J29451PathHistoryGNSSPointListEntry *oldest, *second_oldest;

  /*
   * 총 거리합이 J29451_MIN_PH_DISTANCE(=200m)보다 큰 상태를 유지하면서, 오래된 PH 포인트부터 최대한 제거한다.
   * (PH 포인트의 자격을 박탈하며, GNSS 포인트 자체를 삭제하지는 않는다)
   * 단, 최소한 1개 이상의 포인트는 있어야 한다.
   */
  while (ph->ph_points.point_num > kJ29451PathHistoryPointNum_Min) {
    oldest = ph->ph_points.oldest;
    assert(oldest);
    second_oldest = oldest->ph_point.next;
    assert(second_oldest);
    double delta = second_oldest->ph_point.dist_from_prev;
    // 가장 오래된 PH point를 제거할 경우의 총 거리합이 PH 최소길이보다 작아질 경우 PH point 제거 작업을 중지한다.
    if (ph->ph_points.total_dist - delta < J29451_MIN_PH_DISTANCE) {
      Log(kJ29451LogLevel_Event, "Stop removing oldest point - total dist will be %.1f < MIN_PH_DIST(%.1f)\n",
          (ph->ph_points.total_dist - delta), J29451_MIN_PH_DISTANCE);
      break;
    }

    // 가장 오래된 PH point를 제거해도 총 거리합이 PH 최소길이 이상일 경우에는 가장 오래된 PH point를 제거한다.
    Log(kJ29451LogLevel_Event, "Remove oldest point - total dist will be %.1f >= MIN_PH_DIST(%.1f)\n",
        (ph->ph_points.total_dist - delta), J29451_MIN_PH_DISTANCE);
    oldest = j29451_DisqualifyOldestPHPoint();
    assert(oldest);
  }

  /*
   * PH point의 개수가 J29451_MAX_PH_POINT_NUM(=15)보다 크지 않도록 오래된 PH point 부터 제거한다.
   */
  while (ph->ph_points.point_num > J29451_MAX_PH_POINT_NUM) {
    Log(kJ29451LogLevel_Event, "Total point num is %u, remove oldest point until MAX_PH_POINT_NUM(%u)\n",
        ph->ph_points.point_num, J29451_MAX_PH_POINT_NUM);
    oldest = j29451_DisqualifyOldestPHPoint();
    assert(oldest);
  }

  /*
   * 가장 과거의 PH point보다 더 과거의 GNSS 포인트 정보들을 제거한다 -> 더 이상 사용될 일이 없으므로.
   */
  j29451_RemoveGNSSPointEntriesOlderThanFirstPHPoint();

#ifdef _TARGET_STD_VER_2016_
  /*
   * PH point들의 총거리합이 J29451_MAX_PH_DISTANCE(=210m) 이하가 될 때까지, 가장 오래된 PH 포인트를 직후 GNSS 포인트정보로 대체한다.
   */
  while (ph->ph_points.total_dist > (unsigned int)J29451_MAX_PH_DISTANCE) {
    if (j29451_ReplaceOldestPHPointWithNextGNSSPoint() == false) {
      break;
    }
  }
#endif

  Log(kJ29451LogLevel_Event, "Optimize complete - total dist: %.1f, count: %u\n",
      ph->ph_points.total_dist, ph->ph_points.point_num);
}


/**
 * @brief Path history 정보를 초기화한다.
 *
 * 저장된 GNSS 포인트 정보가 3개 이상일 경우에만 호출되어야 한다.
 * 본 함수가 호출되고 나면, 다음 상태가 된다.
 *  - p_start-> p_prev -> p_next = p_recent
 *  - p_start = 함수 수행 중 PH point가 된 GNSS 포인트
 */
void INTERNAL j29451_InitPathHistoryInfo(void)
{
  Log(kJ29451LogLevel_Event, "Initialize PH info\n");
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);

  /*
   * PH point 리스트 생성을 위해 사용되는 메커니즘 파라미터를 초기화한다.
   */
  list->internal.p_start = TAILQ_FIRST(&(list->head));
  assert(list->internal.p_start);
  list->internal.p_prev = TAILQ_NEXT(list->internal.p_start, entries);
  assert(list->internal.p_prev);
  list->internal.p_next = TAILQ_NEXT(list->internal.p_prev, entries);
  assert(list->internal.p_next);

  /*
   * 첫 GNSS 포인트 정보를 첫번째 PH point로 설정한다
   */
  j29451_MakeFirstPHPoint(list->internal.p_start);
}


/*
 * @brief Path history 정보를 추가한다.
 * @return 최소개수 이상의 PH point가 생성되었는지 여부
 *
 * 본 함수가 호출되기 전, p_next는 가장 최신 포인트(p_recent)의 직전 포인트이고, p_prev는 p_next의 직전 포인트이다.
 *  - p_prev -> p_next -> p_recent
 *
 * 본 함수가 호출되고 나면, 다음 중 하나의 상태가 된다.
 *  1. 함수 수행 중 p_prev가 PH point가 된 경우
 *    - p_start -> p_prev -> p_next = p_recent
 *    - p_start = 함수 수행 중 PH point가 된 GNSS 포인트 (함수 호출 전에는 p_prev였던 포인트)
 *  2. 함수 수행 중 p_prev가 PH point가 되지 않은 경우
 *    - p_start -> ... -> p_prev -> p_next = p_recent
 *    - p_start = 예전에 마지막으로 PH point가 된 GNSS 포인트
 */
static bool j29451_AppendPathHistoryInfo(void)
{
  Log(kJ29451LogLevel_Event, "Append PH info\n");
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *p_start = list->internal.p_start;
  struct J29451PathHistoryGNSSPointListEntry *p_prev = list->internal.p_prev;
  struct J29451PathHistoryGNSSPointListEntry *p_next = list->internal.p_next;
  double actual_err;

  /*
   * Step 2
   * P_start와 P_next 간 ActualCordLength를 계산하여,
   * 최대길이보다 클 경우 ActualError 값을 큰 값으로 설정하여 Step4가 진행되도록 한다.
   * --> 직전에 PH point가 된 P_start와 P_next간의 거리가 임계값을 초과하기 때문에 P_next의 직전 포인트인 P_prev를 PH point로 만들어야 한다.
   *     (PH 포인트 간 거리는 임계값을 초과하면 안된다는 조건을 만족하기 위함)
   *     본 함수의 직전 호출 시점에 P_prev에 대한 검사가 진행되었을 것이고, P_start와 P_prev의 거리는 임계값을 초과하지 않은 상태이다.
   */
  double actual_chord_len = j29451_CalculateActualChordLength(&(p_start->point), &(p_next->point));
  Log(kJ29451LogLevel_Event, "ActualChordLen: %.2fm (p_start: %d,%d, p_next: %d,%d)\n",
      actual_chord_len, p_start->point.lat, p_start->point.lon, p_next->point.lat, p_next->point.lon);
  if (actual_chord_len > J29451_vMaxChordLength) {
    actual_err = J29451_MAX_PH_ACTUAL_ERR + 1;
  }

  /*
   * Step 3
   * P_start와 P_next간 ActualError를 계산한다.
   */
  else {
    actual_err = j29451_CaculateActualError(p_start, p_next);
  }
  Log(kJ29451LogLevel_Event, "ActualError: %.2fm\n", actual_err);

  /*
   * Step 4
   * 1. ActualError가 기준값보다 클 경우 P_prev를 최신 PH point로 만든다.
   * --> P_start와 P_next 간 경로의 굴곡이 입계값을 초과하기 때문에 P_prev를 PH point로 만들어야 한다.
   *     (PH 포인트 간 경로의 굴곡이 임계값을 초과하면 안된다는 조건을 만족하기 위함)
   *     본 함수의 직전 호출 시점에 P_prev에 대한 검사가 진행되었을 것이고, P_start와 P_prev간 경로의 굴곡은 임계값을 초과하지 않은 상태이다.
   *
   * 2. (2020 버전 표준을 따르는 경우) GNSS 포인트 정보 리스트에서 방금 PH point가 된 포인트보다 과거 포인트들의 정보를 제거한다.
   *    (방금 PH point가 된 GNSS 포인트가 P_start가 되었고, 앞으로는 해당 포인트 이후에 대해서만 계산이 수행되므로 이전 포인트들의 정보는 불필요하다)
   */
  if (actual_err > J29451_MAX_PH_ACTUAL_ERR) {
    j29451_MakeRecentPHPoint(p_prev);
    list->internal.p_start = p_prev;
    list->internal.p_prev = p_next;
    list->internal.p_next = list->internal.p_recent;

    /*
     * Step 6
     * PH point 리스트를 최적화한다.
     */
    j29451_OptimizePHPointList();
  }

  /*
   * Step 5
   * ActualError가 기준값보다 작을 경우 P_prev는 PH에 수납될 필요가 없다 -> PH point로 만들지 않는다.
   * --> P_start와 P_next 간 경로의 굴곡이 입계값 내에 있기 때문에 P_prev를 PH에 수납할 필요 없다.
   * P_prev와 P_next를 한칸씩 쉬프트한다. (최근 정보 쪽으로) -> 다음번 본 함수 호출 시, 한칸씩 최근 포인트들에 대해 검사된다.
   * 메커니즘 상, 쉬프트된 P_next는 가장 최신 포인트 정보(=본 함수 호출 직전 GNSS 포인트 정보 리스트에 추가된 정보)여야 한다.
   */
  else {
    list->internal.p_prev = p_next;
    list->internal.p_next = TAILQ_NEXT(p_next, entries);
    assert(list->internal.p_next == list->internal.p_recent);
  }

  /*
   * BSM을 생성하기에 충분한 PH 포인트가 생성되었는지 반환한다.
   * 충분하지 않을 경우 BSM을 전송하지 않는다.
   */
  bool sufficent_ph_point = false;
  if (g_j29451_mib.path.ph.ph_points.point_num >= kJ29451PathHistoryPointNum_Min) {
    sufficent_ph_point = true;
  }

  Log(kJ29451LogLevel_Event, "Append PH info complete - PH point sufficient flag: %u(T/F)\n", sufficent_ph_point);
  return sufficent_ph_point;
}


/**
 * @brief Path history 정보를 업데이트한다.
 * @return 최소개수 이상의 PH point가 생성되었는지 여부 (최소개수 이상의 PH point가 존재해야 BSM 송신이 가능하다)
 */
bool INTERNAL j29451_UpdatePathHistoryInfo(void)
{
  Log(kJ29451LogLevel_Event, "Update PH info\n");
  struct J29451PathHistoryGNSSPointList *list = &(g_j29451_mib.path.ph.gnss_point_list);
  bool sufficient_ph_point = false;

  /*
   * 충분한 개수의 GNSS 포인트 정보가 있을 경우에만 PH 정보를 업데이트할 수 있다.
   */
  if (list->entry_num >= kJ29451PathHistoryGNSSPointListEntryNum_Sufficient) {
    if (list->internal.p_start == NULL) { // 충분한 개수의 포인트 정보가 확보된 후 첫 호출 시.
      j29451_InitPathHistoryInfo();
    } else {
      sufficient_ph_point = j29451_AppendPathHistoryInfo();
    }
  } else {
    Log(kJ29451LogLevel_Event, "Not update PH info - insufficient GNSS point num: %u\n", list->entry_num);
  }
  return sufficient_ph_point;
}


/**
 * @brief PH point 리스트를 복원한다.
 */
void INTERNAL j29451_RestorePHPointList(void)
{
  Log(kJ29451LogLevel_Event, "Restore PH point list\n");
  struct J29451PathHistory *ph = &(g_j29451_mib.path.ph);
  struct J29451PathHistoryGNSSPointList *list = &(ph->gnss_point_list);

  /*
   * GNSS 포인트 정보 개수가 충분하지 않으면 복원하지 않는다.
   */
  if (list->entry_num < kJ29451PathHistoryGNSSPointListEntryNum_Sufficient) {
    Log(kJ29451LogLevel_Event, "No need to restore PH point list - point num: %u\n", list->entry_num);
    return;
  }

  /*
   * GNSS 포인트 리스트 내에서, PH point 였던 GNSS 포인트들을 다시 PH point로 만든다.
   */
  struct J29451PathHistoryGNSSPointListEntry *entry, *last_ph_point = NULL;
  TAILQ_FOREACH(entry, &(list->head), entries) {
    if (entry->is_ph_point == true) {
      if (ph->ph_points.oldest == NULL) {
        j29451_MakeFirstPHPoint(entry);
      } else {
        j29451_MakeRecentPHPoint(entry);
      }
      last_ph_point = entry;
    }
  }
  assert(last_ph_point); // GNSS 포인트 정보개수가 충분하기 때문에 PH point는 최소 1개 이상 있어야 한다.

  /*
   * 이후 PH point 선별 메커니즘의 동작을 위한 메커니즘 파라미터들을 복원한다.
   * - p_start: 가장 최근에 PH point가 된 GNSS 포인트 참조
   * - p_recent: 가장 최근 GNSS 포인트 참조
   * - p_next: p_recent와 동일 (j29451_AppendPathHistory() 함수에서 p_prev가 저장된 상황과 동일한 상황으로 간주)
   * - p_prev: p_next->prev
   *
   * 다음 중 하나의 상태가 된다.
   * (이는 j29451_InitPathHistoryInfo()나 j29451_AppendPathHistoryInfo() 함수를 호출한 후의 상태와 동일한 상태이다)
   *  1. p_start-> p_prev -> p_next = p_recent
   *  2. p_start-> ... -> p_prev -> p_next = p_recent
   */
  list->internal.p_start = last_ph_point;
  list->internal.p_recent = TAILQ_LAST(&(list->head), J29451PathHistoryGNSSPointListEntryHead);
  list->internal.p_next = list->internal.p_recent;
  assert(list->internal.p_next);
  list->internal.p_prev = TAILQ_PREV(list->internal.p_next, J29451PathHistoryGNSSPointListEntryHead, entries);
  assert(list->internal.p_prev);

#ifdef _TARGET_STD_VER_2016_
  /*
   * 백업된 PH 정보가 있음을 표시
   */
  g_j29451_mib.path.backup_ph_present = true;
#endif
}
