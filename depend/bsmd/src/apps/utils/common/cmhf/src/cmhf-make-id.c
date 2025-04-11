/** 
  * @file 
  * @brief 
  * @date 2022-08-14 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <dirent.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 유틸리티 헤더 파일
#include "cmhf.h"


/**
 * @brief 파일명으로부터 i, j 값을 얻는다.
 * @param[in] file_path 파일경로
 * @param[out] i 값이 저장될 변수 포인터
 * @param[out] j 값이 저장될 변수 포인터
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int CMHF_GetJValueFromFileName(char *file_path, uint32_t *i, uint32_t *j)
{
  if (g_dbg == true) {
    printf("Get i, j value from file(%s)\n", file_path);
  }

  char *tmp_file_name = basename(file_path);
  char *file_name = calloc(1, strlen(tmp_file_name) + 1);
  if (file_name == NULL) {
    printf("Fail to get i, j value from file(%s) - calloc() failed : %m\n", file_path);
    return -1;
  }
  memcpy(file_name, tmp_file_name, strlen(tmp_file_name));

  char *i_str = strtok(file_name, "_");
  char *j_str = strtok(NULL, "_");
  *i = (uint32_t)strtoul(i_str, NULL, 16);
  *j = (uint32_t)strtoul(j_str, NULL, 16);

  if (g_dbg == true) {
    printf("i = 0x%x, j = 0x%x from file(%s)\n", *i, *j, file_name);
  }

  free(file_name);
  return 0;
}


static int CMHF_MakeIdentificationCertCMHF(void)
{
  if (g_dbg == true) {
    printf("Make identification certificate CMHF from my cert directory(%s)\n", g_my_certs_dir);
  }

  /*
   * 내 인증서 및 개인키재구성값 파일들이 저장된 디렉토리를 연다.
   */
  DIR *dir;
  struct dirent *ent;
  dir = opendir(g_my_certs_dir);
  if (dir == NULL) {
    printf("Fail to make identification certificate CMHF - opendir(%s) failed : %m\n", g_my_certs_dir);
    return -1;
  }

  /*
   * 인증서 및 개인키재구성값 파일의 경로가 저장될 버퍼를 할당한다.
   */
  size_t file_path_size = strlen(g_my_certs_dir) + MAXLINE;
  char *file_path = (char *)calloc(1, file_path_size);
  if (file_path == NULL) {
    printf("Fail to make identification certificate CMHF - calloc() failed : %m");
    closedir(dir);
    return -1;
  }

  uint32_t i, j;

  /*
   * 디렉토리 내 인증서 및 개인키재구성값 파일을 import 하여 CMHF를 생성한다.
   */
  int ret;
  uint8_t cert[kDot2CertSize_Max];
  Dot2CertSize cert_size = 0;
  uint8_t recon_priv[DOT2_EC_256_KEY_LEN];
  while ((ent = readdir(dir)) != NULL)
  {
    // 파일의 경로를 구한다. (입력된 디렉터리명과 탐색된 파일명의 결합)
    memset(file_path, 0, file_path_size);
    memcpy(file_path, g_my_certs_dir, strlen(g_my_certs_dir));
    *(file_path + strlen(g_my_certs_dir)) = '/';
    strcat(file_path, ent->d_name);

    // 확장자가 cert이면 인증서 파일명으로부터 i,j 값을 구하고 내용을 import한다.
    if (strncmp(file_path + (strlen(file_path) - 5), ".cert", 5) == 0) {
      ret = CMHF_GetJValueFromFileName(file_path, &i, &j);
      if (ret < 0) {
        free(file_path);
        closedir(dir);
        return -1;
      }
      ret = CMHF_ImportCertFile(file_path, cert, sizeof(cert));
      if (ret < 0) {
        free(file_path);
        closedir(dir);
        return -1;
      }
      cert_size = (Dot2CertSize)ret;
    }
      // 확장자가 s이면 개인키재구성값 파일명으로부터 i,j 값을 구하고 내용을 import한다.
    else if (strncmp(file_path + (strlen(file_path) - 2), ".s", 2) == 0) {
      ret = CMHF_GetJValueFromFileName(file_path, &i, &j);
      if (ret < 0) {
        free(file_path);
        closedir(dir);
        return -1;
      }
      ret = CMHF_ImportPrivateKey(file_path, recon_priv);
      if (ret < 0) {
        free(file_path);
        closedir(dir);
        return -1;
      }
    }
  }
  free(file_path);
  closedir(dir);

  /*
   * import 된 각 인증서/개인키재구성값 쌍으로부터 CMHF를 생성한다.
   */
  struct Dot2IdCMHFMakeParams params;
  struct Dot2IdCMHFMakeResult res;
  params.i = i;
  memcpy(params.exp_key.octs, g_exp_key, DOT2_AES_128_LEN);
  memcpy(params.seed_priv.octs, g_seed_priv, DOT2_EC_256_KEY_LEN);
  memcpy(params.cert.octs, cert, cert_size);
  memcpy(params.recon_priv.octs, recon_priv, DOT2_EC_256_KEY_LEN);
  memcpy(params.issuer.octs, g_issuer, g_issuer_size);
  params.cert.size = g_my_cert_size;
  params.issuer.size = g_issuer_size;
  res = Dot2_MakeIdentificationCertCMHF(&params);
  if (res.ret < 0) {
    printf("Fail to make identification cmhf - Dot2_MakeIdentificationCertCMHF() failed - %d\n", res.ret);
    return -1;
  }

  /*
   * 생성된 cmhf를 파일에 저장한다.
   */
  FILE *fp = fopen(res.cmhf_name, "w");
  if (fp == NULL) {
    printf("Fail to make identification cmhf - fopen() failed : %m\n");
    ret = -1;
    goto out;
  }
  fwrite(res.cmhf, 1, res.cmhf_size, fp);
  fclose(fp);

  if (g_dbg == true) {
    printf("Success to make %zu-bytes identification CMHF(%s)\n", res.cmhf_size, res.cmhf_name);
  }

  ret = 0;

out:
  free(res.cmhf_name);
  free(res.cmhf);
  return ret;
}


/**
 * @brief 식별 인증서에 대한 cmhf 파일을 생성한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CMHF_MakeIdentificationCMHF(void)
{
  if (g_dbg == true) {
    printf("Make identifcation certificate CMHF\n");
  }

  /*
   * 상위인증서를 import 한다.
   */
  int ret = CMHF_ImportCertFile(g_issuer_file_path, g_issuer, kDot2CertSize_Max);
  if (ret < 0) {
    return ret;
  }
  g_issuer_size = (size_t)ret;

  /*
   * 시드개인키를 import 한다.
   */
  ret = CMHF_ImportPrivateKey(g_seed_priv_file_path, g_seed_priv);
  if (ret < 0) {
    return ret;
  }

  /*
   * 키 확장용 키를 import 한다.
   */
  ret = CMHF_ImportExpansionKey(g_exp_key_file_path, g_exp_key);
  if (ret < 0) {
    return ret;
  }

  /*
   * 내 인증서와 개인키재구성값을 import 하여 CMHF들을 생성한다.
   */
  ret = CMHF_MakeIdentificationCertCMHF();
  if (ret < 0) {
    return ret;
  }

  return 0;
}

