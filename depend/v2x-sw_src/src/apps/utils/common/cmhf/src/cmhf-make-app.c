/** 
 * @file
 * @brief 응용 인증서에 대한 cmhf 파일 생성 기능 구현 파일
 * @date 2020-05-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "cmhf.h"


/**
 * @brief 응용 인증서에 대한 CMHF 파일을 생성한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CMHF_MakeApplicationCMHF(void)
{
  if (g_dbg == true) {
    printf("Make application certificate CMHF\n");
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
   * 내 인증서를 import 한다.
   */
  ret = CMHF_ImportCertFile(g_my_cert_file_path, g_my_cert, kDot2CertSize_Max);
  if (ret < 0) {
    return ret;
  }
  g_my_cert_size = (size_t)ret;

  /*
   * 개인키 재구성값을 import 한다.
   */
  ret = CMHF_ImportPrivateKey(g_recon_priv_file_path, g_recon_priv);
  if (ret < 0) {
    return ret;
  }

  /*
   * 인증서 요청 개인키를 import 한다.
   */
  ret = CMHF_ImportPrivateKey(g_init_priv_file_path, g_init_priv);
  if (ret < 0) {
    return ret;
  }

  /*
   * CMHF를 생성한다.
   */
  struct Dot2AppCMHFMakeParams params;
  struct Dot2CMHFMakeResult res;
  memcpy(params.init_priv_key.octs, g_init_priv, DOT2_EC_256_KEY_LEN);
  memcpy(params.recon_priv.octs, g_recon_priv, DOT2_EC_256_KEY_LEN);
  memcpy(params.cert.octs, g_my_cert, g_my_cert_size);
  memcpy(params.issuer.octs, g_issuer, g_issuer_size);
  params.cert.size = g_my_cert_size;
  params.issuer.size = g_issuer_size;
  res = Dot2_MakeApplicationCertCMHF(&params);
  if (res.ret < 0) {
    printf("Fail to make application certificate CMHF - Dot2_MakeApplicationCertCMHF() failed - %d\n", res.ret);
    return -1;
  }

  /*
   * 생성된 CMHF를 파일에 저장한다.
   */
  FILE *fp = fopen(res.cmhf_name, "w");
  if (fp == NULL) {
    printf("Fail to make application certificate CMHF - fopen() failed : %m\n");
    ret = -1;
    goto out;
  }
  fwrite(res.cmhf, 1, res.cmhf_size, fp);
  fclose(fp);

  if (g_dbg == true) {
    printf("Success to make %zu-bytes application certificate CMHF(%s)\n", res.cmhf_size, res.cmhf_name);
  }

  ret = 0;

out:
  free(res.cmhf_name);
  free(res.cmhf);
  return ret;
}
