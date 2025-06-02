/** 
 * @file
 * @brief 서명메시지 생성/처리를 위한 CMHF, 인증서정보, Security profile 등록 기능 구현 파일
 * @date 2020-05-27
 * @author gyun
 */

// 시스템 헤더 파일
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"

// 어플리케이션 헤더 파일
#include "sdee-dsrc.h"


/**
 * @brief 특정 디렉토리에 저장되어 있는 모든 CMHF 파일들을 dot2 라이브러리에 로딩한다.
 * @param[in] dir_path CMHF 파일들이 저장된 디렉토리 경로 (상대경로, 절대경로 모두 가능)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int SDEE_DSRC_LoadCMHFFiles(const char *dir_path)
{
  printf("Load CMHF files in %s\n", dir_path);

  /*
   * 디렉토리를 연다.
   */
  DIR *dir;
  struct dirent *ent;
  dir = opendir(dir_path);
  if (dir == NULL) {
    printf("Fail to load CMHF files in %s - opendir() failed : %m\n", dir_path);
    return -1;
  }

#define MAXLINE 255
  /*
   * CMHF 파일의 경로가 저장될 버퍼를 할당한다.
   */
  size_t file_path_size = strlen(dir_path) + MAXLINE;
  char *file_path = (char *)calloc(1, file_path_size);
  if (file_path == NULL) {
    printf("Fail to load CMHF files - calloc() failed : %m\n");
    closedir(dir);
    return -1;
  }

  /*
   * 디렉토리 내 모든 CMHF 파일을 import하여 등록한다.
   */
  unsigned int add_cnt = 0;
  int ret;
  while ((ent = readdir(dir)) != NULL)
  {
    // 파일의 경로를 구한다. (입력된 디렉터리명과 탐색된 파일명의 결합)
    memset(file_path, 0, file_path_size);
    strcpy(file_path, dir_path);
    *(file_path + strlen(dir_path)) = '/';
    strcat(file_path, ent->d_name);

    printf("Load CMHF file(%s)\n", file_path);

    // CMHF를 등록한다.
    ret = Dot2_LoadCMHFFile(file_path);
    if (ret < 0) {
      printf("Fail to load CMHF file(%s) - Dot2_LoadCMHFFile() failed: %d\n", file_path, ret);
      continue;
    }
    printf("Success to load CMHF file\n");
    add_cnt++;
  }
  free(file_path);
  closedir(dir);

  printf("Sucess to load %u CMHF files\n", add_cnt);
  return 0;
}


/**
 * @brief 서명메시지 생성/처리를 위한 CMHF, 인증서정보, Security profile을 등록한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int SDEE_DSRC_RegisterCryptoMaterials(void)
{
  int ret;
  printf("Register crypto materials\n");

  /*
   * 상위인증서들의 정보를 등록한다.
   */
  ret = Dot2_LoadSCCCertFile(g_mib.rca_cert_file_path);
  if (ret < 0) {
    return -1;
  }
  ret = Dot2_LoadSCCCertFile(g_mib.ica_cert_file_path);
  if (ret < 0) {
    return -1;
  }
  ret = Dot2_LoadSCCCertFile(g_mib.pca_cert_file_path);
  if (ret < 0) {
    return -1;
  }

  /*
   * 서명 생성을 위한 CMHF를 등록한다. 본 어플리케이션에서는 psid=32, 38, 135만 사용된다.
   */
  ret = SDEE_DSRC_LoadCMHFFiles(g_mib.cmhf_dir);
  if (ret < 0) {
    return -1;
  }

  /*
   * psid=135용 Security profile을 등록한다.
   */
  struct Dot2SecProfile profile;
  memset(&profile, 0, sizeof(profile));
  profile.psid = 135;
  profile.tx.gen_time_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false; // 동일한 SPDU에 대해 반복 테스트하므로 replay 체크는 비활성화한다.
  profile.rx.relevance_check.gen_time_in_past = true;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = true;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = true;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = true;
  profile.rx.relevance_check.cert_expiry = true;
  profile.rx.consistency_check.gen_location = true;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    printf("Fail to register security profile - Dot2_AddSecProfile(PSID: %u) failed: %d\n", profile.psid, ret);
    return -1;
  }

  /*
   * psid=32용 Security profile을 등록한다.
   */
  memset(&profile, 0, sizeof(profile));
  profile.psid = 32;
  profile.tx.gen_time_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 450 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false; // 동일한 SPDU에 대해 반복 테스트하므로 replay 체크는 비활성화한다.
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = true;
  profile.rx.consistency_check.gen_location = false;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    printf("Fail to register security profile - Dot2_AddSecProfile(PSID: %u) failed: %d\n", profile.psid, ret);
    return -1;
  }

  /*
   * psid=38용 Security profile을 등록한다.
   */
  memset(&profile, 0, sizeof(profile));
  profile.psid = 38;
  profile.tx.gen_time_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 290 * 1000;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false; // 동일한 SPDU에 대해 반복 테스트하므로 replay 체크는 비활성화한다.
  profile.rx.relevance_check.gen_time_in_past = true;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = true;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = true;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = true;
  profile.rx.relevance_check.cert_expiry = true;
  profile.rx.consistency_check.gen_location = true;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    printf("Fail to register security profile - Dot2_AddSecProfile(PSID: %u) failed: %d\n", profile.psid, ret);
    return -1;
  }

  printf("Success to register crypto materials\n");
  return 0;
}
