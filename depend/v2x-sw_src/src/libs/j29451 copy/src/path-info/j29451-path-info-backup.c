/** 
  * @file 
  * @brief Path 정보 백업 기능 구현
  * @date 2022-09-15 
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
 * @brief Path 정보를 파일에 백업한다.
 * @param[in] file_path 정보를 저장할 파일 경로
 */
void INTERNAL j29451_SavePathInfoBackupFile(const char *file_path)
{
  Log(kJ29451LogLevel_Event, "Save path info backup file (%s)\n", file_path);

  struct J29451PathInfo *path = &(g_j29451_mib.path);
  struct J29451PathHistoryGNSSPointList *list = &(path->ph.gnss_point_list);
  struct J29451PathHistoryGNSSPointListEntry *entry;

  FILE *fp = fopen(file_path, "w");
  if (fp) {
    /*
     * 리스트 내 각 GNSS 포인트 정보들을 한줄씩 기록한다.
     * 오래된(리스트의 앞쪽) 정보부터 저장된다.
     */
    TAILQ_FOREACH(entry, &list->head, entries) {
      struct J29451GNSSData *pt = &(entry->point);
      fprintf(fp, "%"PRIu64",%u,%d,%d,%d,%u,%u,%u,%u,%u,%d,%d,%d,%d,%u\n",
              pt->time, pt->msec, pt->lat, pt->lon, pt->elev, pt->speed, pt->heading,
              pt->pos_accuracy.semi_major, pt->pos_accuracy.semi_minor, pt->pos_accuracy.orientation,
              pt->acceleration_set.lon, pt->acceleration_set.lat, pt->acceleration_set.vert, pt->acceleration_set.yaw,
              entry->is_ph_point);
      Log(kJ29451LogLevel_Event, "%"PRIu64",%u,%d,%d,%d,%u,%u,%u,%u,%u,%d,%d,%d,%d,%u\n",
          pt->time, pt->msec, pt->lat, pt->lon, pt->elev, pt->speed, pt->heading,
          pt->pos_accuracy.semi_major, pt->pos_accuracy.semi_minor, pt->pos_accuracy.orientation,
          pt->acceleration_set.lon, pt->acceleration_set.lat, pt->acceleration_set.vert, pt->acceleration_set.yaw,
          entry->is_ph_point);
    }
    fclose(fp);
  }
}


/**
 * @brief Path 정보 백업파일이 기록된 라인을 파싱한다.
 * @param[in] line 파싱할 라인버퍼
 * @param[out] gnss_data 파싱된 라인정보가 저장될 GNSS 데이터 구조체 포인터
 * @param[out] is_ph_point 파싱된 라인정보가 저장될 PH point 여부 변수 포인터
 * @return 파싱 성공 여부
 */
static bool j29451_ParsePathInfoBackupLine(char *line, struct J29451GNSSData *gnss_data, bool *is_ph_point)
{
  const char *delimiter = ",\n";
  char *save_ptr = NULL;
  char *token = strtok_r(line, delimiter, &save_ptr);
  if (token) {
    gnss_data->time = (uint64_t)strtoull(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->msec = (J29451DSecond)strtoul(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->lat = (J29451Latitude)strtol(token, NULL, 10);
    gnss_data->lat_deg = j29451_ConvertToGNSSRawLatitude(gnss_data->lat);
    gnss_data->lat_rad = j29451_ConvertDecimalDegreesToRadians(gnss_data->lat_deg);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->lon = (J29451Longitude)strtol(token, NULL, 10);
    gnss_data->lon_deg = j29451_ConvertToGNSSRawLongitude(gnss_data->lon);
    gnss_data->lon_rad = j29451_ConvertDecimalDegreesToRadians(gnss_data->lon_deg);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->elev = (J29451Elevation)strtol(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->speed = (J29451Speed)strtoul(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->heading = (J29451Heading)strtoul(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->pos_accuracy.semi_major = (J29451SemiMajorAxisAccuracy)strtoul(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->pos_accuracy.semi_minor = (J29451SemiMinorAxisAccuracy)strtoul(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->pos_accuracy.orientation = (J29451SemiMajorAxisOrientation)strtoul(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->acceleration_set.lon = (J29451Acceleration)strtol(token, NULL, 10);
    gnss_data->acceleration_set.lon_raw = j29451_ConvertToGNSSRawAcceleration(gnss_data->acceleration_set.lon);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->acceleration_set.lat = (J29451Acceleration)strtol(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->acceleration_set.vert = (J29451VerticalAcceleration)strtol(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    gnss_data->acceleration_set.yaw = (J29451YawRate)strtol(token, NULL, 10);
  } else {
    return false;
  }
  token = strtok_r(NULL, delimiter, &save_ptr);
  if (token) {
    *is_ph_point = (bool)strtoul(token, NULL, 10);
  } else {
    return false;
  }
  return true;
}


/**
 * @brief 백업파일로부터 Path 정보를 로딩한다.
 * @param[in] file_path 정보가 저장된 파일 경로
 */
void INTERNAL j29451_LoadPathInfoBackupFile(const char *file_path)
{
  Log(kJ29451LogLevel_Event, "Load path info backup file (%s)\n", file_path);

  struct J29451GNSSData gnss_data;
  bool is_ph_point = false;

#define LINE_BUF_LEN (255)
  char line[LINE_BUF_LEN];
  FILE *fp = fopen(file_path, "r");
  if (fp) {
    while (!feof(fp)) {
      /*
       * 한줄씩 읽어서 파싱한다.
       */
      memset(line, 0, sizeof(line));
      if (fgets(line, sizeof(line), fp) == NULL) {
        break;
      }
      if (j29451_ParsePathInfoBackupLine(line, &gnss_data, &is_ph_point) == true) {
        Log(kJ29451LogLevel_Event, "Parse: time:%"PRIu64",msec:%u,lat:%d,lon:%d,elev:%d,speed:%u,heading:%u,smajor:%u,"
                                   "sminor:%u,ori:%u,lon:%d,lat:%d,vert:%d,yaw:%d,lon_raw:%.1f,lat_deg:%.1f,lon_deg:%.1f,"
                                   "lat_rad:%.1f,lon_rad:%.1f\n",
            gnss_data.time, gnss_data.msec, gnss_data.lat, gnss_data.lon, gnss_data.elev,
            gnss_data.speed, gnss_data.heading, gnss_data.pos_accuracy.semi_major, gnss_data.pos_accuracy.semi_minor,
            gnss_data.pos_accuracy.orientation, gnss_data.acceleration_set.lon, gnss_data.acceleration_set.lat,
            gnss_data.acceleration_set.vert, gnss_data.acceleration_set.yaw, gnss_data.acceleration_set.lon_raw,
            gnss_data.lat_deg, gnss_data.lon_deg, gnss_data.lat_rad, gnss_data.lon_rad);
        // 파싱된 정보를 GNSS 포인트 정보 리스트에 추가한다.
        j29451_PushGNSSPointInfo(&gnss_data, is_ph_point);
      }
    }
    fclose(fp);

    /*
     * 로딩된 GNSS 포인트 정보들을 기반으로 PH point 리스트를 복원한다.
     */
    j29451_RestorePHPointList();

#ifdef _TARGET_STD_VER_2020_
    /*
     * 백업된 마지막 속도, 헤딩값을 이용하여 Heading latch 상태를 복원한다.
     */
    struct J29451PathHistoryGNSSPointListEntry *recent = g_j29451_mib.path.ph.gnss_point_list.internal.p_recent;
    if (recent) {
      j29451_RestoreGNSSHeadingLatch(recent->point.speed, recent->point.heading);
    }
#endif
  }

  /*
   * 백업 파일을 삭제한다.
   */
  remove(file_path);
}
