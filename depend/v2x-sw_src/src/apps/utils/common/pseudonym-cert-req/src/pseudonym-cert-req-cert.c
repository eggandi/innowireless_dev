/** 
  * @file 
  * @brief 익명인증서 발급요청/다운로드 유틸리티 인증서 관련 구현
  * @date 2022-07-30 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>
#include <dirent.h>

// 유틸리티 헤더 파일
#include "pseudonym-cert-req.h"


/**
 * @brief SCC 인증서 파일들을 로딩한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int PSEUDONYM_CERT_REQ_LoadSCCCertFiles(void)
{
  printf("Load SCC cert files(RCA,ICA,PCA,RA)\n");

  /*
   * RCA 파일을 로딩한다.
   */
  printf("Load RCA cert file(%s)\n", g_cfg.rca_file);
  int ret = Dot2_LoadSCCCertFile(g_cfg.rca_file);
  if (ret < 0) {
    printf("Fail to load RCA cert file: %d\n", ret);
    return -1;
  }

  /*
   * ICA 파일을 로딩한다.
   */
  printf("Load ICA cert file(%s)\n", g_cfg.ica_file);
  ret = Dot2_LoadSCCCertFile(g_cfg.ica_file);
  if (ret < 0) {
    printf("Fail to load ICA cert file: %d\n", ret);
    return -1;
  }

  /*
   * PCA 파일을 로딩한다.
   */
  printf("Load PCA cert file(%s)\n", g_cfg.pca_file);
  ret = Dot2_LoadSCCCertFile(g_cfg.pca_file);
  if (ret < 0) {
    printf("Fail to load PCA cert file: %d\n", ret);
    return -1;
  }

  /*
   * ECA 파일을 로딩한다.
   */
  printf("Load ECA cert file(%s)\n", g_cfg.eca_file);
  ret = Dot2_LoadSCCCertFile(g_cfg.eca_file);
  if (ret < 0) {
    printf("Fail to load ECA cert file: %d\n", ret);
    return -1;
  }

  /*
   * RA 파일을 로딩한다.
   */
  printf("Load RA cert file(%s)\n", g_cfg.ra_file);
  ret = Dot2_LoadSCCCertFile(g_cfg.ra_file);
  if (ret < 0) {
    printf("Fail to load RA cert file: %d\n", ret);
    return -1;
  }
  return 0;
}


/**
 * @brief 등록인증서 CMHF 파일을 로딩한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int PSEUDONYM_CERT_REQ_LoadEnrollmentCMHFFile(void)
{
  printf("Load enrollment CMHF file from %s\n", g_cfg.enroll_cmhf_dir);

  /*
   * 디렉토리를 연다.
   */
  DIR *dir;
  struct dirent *ent;
  dir = opendir(g_cfg.enroll_cmhf_dir);
  if (dir == NULL) {
    printf("Fail to load enrollment CMHF file in %s - opendir() failed : %m\n", g_cfg.enroll_cmhf_dir);
    return -1;
  }

  /*
   * 인증서파일의 경로가 저장될 버퍼를 할당한다.
   */
  size_t file_path_size = strlen(g_cfg.enroll_cmhf_dir) + MAXLINE;
  char *file_path = (char *)calloc(1, file_path_size);
  if (file_path == NULL) {
    printf("Fail to load enrollment CMHF file - calloc() failed : %m\n");
    closedir(dir);
    return -1;
  }

  /*
   * 디렉토리 내 모든 인증서 파일을 import하여 등록한다.
   */
  unsigned int add_cnt = 0;
  int ret;
  while ((ent = readdir(dir)) != NULL)
  {
    // 확장자가 cmhf2인 파일만 import 한다.
    if (strstr(ent->d_name, ".cmhf2") == NULL) {
      continue;
    }

    // 파일의 경로를 구한다. (입력된 디렉터리명과 탐색된 파일명의 결합)
    memset(file_path, 0, file_path_size);
    strcpy(file_path, g_cfg.enroll_cmhf_dir);
    *(file_path + strlen(g_cfg.enroll_cmhf_dir)) = '/';
    strcat(file_path, ent->d_name);

    printf("Load enrollment CMHF file(%s)\n", file_path);

    // CMHF를 로딩한다.
    ret = Dot2_LoadCMHFFile(file_path);
    if (ret < 0) {
      printf("Fail to enrollment CMHF file(%s) - Dot2_LoadCMHFFile() failed: %d\n", file_path, ret);
      ret = -1;
      break;
    }
    printf("Success to load enrollment CMHF file\n");
    ret = 0;
    add_cnt++;
  }
  free(file_path);
  closedir(dir);
  return ret;
}
