/** 
  * @file 
  * @brief 부트스트래핑 동작 중 ECResponse 처리 관련 구현
  * @date 2022-07-17 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "bootstrap.h"


/**
 * @brief 등록인증서 발급응답문을 처리한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int BOOTSTRAP_ProcessECResponse(void)
{
  printf("Process EC response\n");
  int ret;
  uint8_t ecresp[kDot2SPDUSize_Max], enroll_cert[kDot2CertSize_Max], eca_cert[kDot2CertSize_Max];
  uint8_t ra_cert[kDot2CertSize_Max], rca_cert[kDot2CertSize_Max], lccf[kDot2LCCFSize_Max];
  Dot2SPDUSize ecresp_size = 0;
  Dot2CertSize enroll_cert_size, eca_cert_size, ra_cert_size, rca_cert_size;
  Dot2LCCFSize lccf_size;
  struct Dot2ECPrivateKey init_priv_key, recon_priv;

  /*
   * 파일로부터 데이터를 읽는다.
   */
  // 등록인증서발급응답문
  if (g_cfg.proc.ecresp_file_present) {
    ret = BOOTSTRAP_ImportFile(g_cfg.proc.ecresp_file, ecresp, 0, sizeof(ecresp));
    if (ret < 0) {
      printf("Fail to import file(%s)\n", g_cfg.proc.ecresp_file);
      return -1;
    }
    ecresp_size = (Dot2SPDUSize)ret;
  }
  // 초기 개인키
  ret = BOOTSTRAP_ImportFile(g_cfg.init_priv_key_file, init_priv_key.octs, 0, sizeof(init_priv_key.octs));
  if (ret < 0) {
    printf("Fail to import file(%s)\n", g_cfg.init_priv_key_file);
    return -1;
  }
  // 등록인증서
  ret = BOOTSTRAP_ImportFile(g_cfg.proc.enroll_cert_file, enroll_cert, 0, sizeof(enroll_cert));
  if (ret < 0) {
    printf("Fail to import file(%s)\n", g_cfg.proc.enroll_cert_file);
    return -1;
  }
  enroll_cert_size = (Dot2CertSize)ret;
  // 개인키재구성값
  ret = BOOTSTRAP_ImportFile(g_cfg.proc.recon_priv_file, recon_priv.octs, 0, sizeof(recon_priv.octs));
  if (ret < 0) {
    printf("Fail to import file(%s)\n", g_cfg.proc.recon_priv_file);
    return -1;
  }
  // RCA 인증서
  ret = BOOTSTRAP_ImportFile(g_cfg.proc.rca_cert_file, rca_cert, 0, sizeof(rca_cert));
  if (ret < 0) {
    printf("Fail to import file(%s)\n", g_cfg.proc.rca_cert_file);
    return -1;
  }
  rca_cert_size = (Dot2CertSize)ret;
  // ECA 인증서
  ret = BOOTSTRAP_ImportFile(g_cfg.proc.eca_cert_file, eca_cert, 0, sizeof(eca_cert));
  if (ret < 0) {
    printf("Fail to import file(%s)\n", g_cfg.proc.eca_cert_file);
    return -1;
  }
  eca_cert_size = (Dot2CertSize)ret;
  // RA 인증서
  ret = BOOTSTRAP_ImportFile(g_cfg.proc.ra_cert_file, ra_cert, 0, sizeof(ra_cert));
  if (ret < 0) {
    printf("Fail to import file(%s)\n", g_cfg.proc.ra_cert_file);
    return -1;
  }
  ra_cert_size = (Dot2CertSize)ret;
  // LCCF
  ret = BOOTSTRAP_ImportFile(g_cfg.proc.lccf_file, lccf, 0, sizeof(lccf));
  if (ret < 0) {
    printf("Fail to import file(%s)\n", g_cfg.proc.lccf_file);
    return -1;
  }
  lccf_size = (Dot2LCCFSize)ret;

  /*
   * ECResponse 처리 API를 호출한다.
   */
  struct Dot2ECResponseProcessParams params;
  memset(&params, 0, sizeof(params));
  if (g_cfg.proc.ecresp_file_present) {
    params.ec_resp = ecresp;
    params.ec_resp_size = ecresp_size;
  }
  memcpy(params.ec.octs, enroll_cert, enroll_cert_size);
  params.ec.size = enroll_cert_size;
  memcpy(&(params.init_priv_key), &init_priv_key, sizeof(init_priv_key));
  memcpy(&(params.recon_priv), &recon_priv, sizeof(recon_priv));
  memcpy(params.eca_cert.octs, eca_cert, eca_cert_size);
  params.eca_cert.size = eca_cert_size;
  memcpy(params.ra_cert.octs, ra_cert, ra_cert_size);
  params.ra_cert.size = ra_cert_size;
  memcpy(params.rca_cert.octs, rca_cert, rca_cert_size);
  params.rca_cert.size = rca_cert_size;
  params.lccf = lccf;
  params.lccf_size = lccf_size;
  struct Dot2ECResponseProcessResult res = Dot2_ProcessECResponse(&params);
  if (res.ret < 0) {
    printf("Fail to Dot2_ProcessECResponse() : %d\n", res.ret);
    return -1;
  }

  /*
   * 결과를 화면에 출력한다.
   */
  BOOTSTRAP_PrintOcts(res.enrollment_cmhf_name, res.enrollment_cmhf, res.enrollment_cmf_size);
  BOOTSTRAP_PrintOcts(g_cfg.proc.enroll_priv_key_file, res.enrollment_priv_key.octs, sizeof(res.enrollment_priv_key.octs));
  if (res.rca_cert) {
    BOOTSTRAP_PrintOcts(g_cfg.proc.rca_cert_file, res.rca_cert, res.rca_cert_size);
  } else {
    printf("Error: No RCA cert in LCCF\n");
  }
  if (res.ica_cert) {
    BOOTSTRAP_PrintOcts(g_cfg.proc.ica_cert_file, res.ica_cert, res.ica_cert_size);
  } else {
    printf("Error: No ICA cert in LCCF\n");
  }
  if (res.pca_cert) {
    BOOTSTRAP_PrintOcts(g_cfg.proc.pca_cert_file, res.pca_cert, res.pca_cert_size);
  } else {
    printf("Error: No PCA cert in LCCF\n");
  }
  if (res.crlg_cert) {
    BOOTSTRAP_PrintOcts(g_cfg.proc.crlg_cert_file, res.crlg_cert, res.crlg_cert_size);
  } else {
    printf("No CRLG cert in LCCF\n");
  }

  /*
   * 결과를 파일로 저장한다.
   *  - RCA는 이미 있으므로 생략한다.
   */
  BOOTSTARP_ExportFile(res.enrollment_cmhf_name, res.enrollment_cmhf, res.enrollment_cmf_size); // 등록인증서 CMHF
  BOOTSTARP_ExportFile(g_cfg.proc.enroll_priv_key_file, res.enrollment_priv_key.octs, sizeof(res.enrollment_priv_key.octs)); // 재구성된 등록인증서 개인키
  if (res.ica_cert) {
    BOOTSTARP_ExportFile(g_cfg.proc.ica_cert_file, res.ica_cert, res.ica_cert_size); // ICA 인증서
  }
  if (res.pca_cert) {
    BOOTSTARP_ExportFile(g_cfg.proc.pca_cert_file, res.pca_cert, res.pca_cert_size); // PCA 인증서
  }
  if (res.crlg_cert) {
    BOOTSTARP_ExportFile(g_cfg.proc.crlg_cert_file, res.crlg_cert, res.crlg_cert_size); // CRLG 인증서
  }

  free(res.enrollment_cmhf);
  free(res.enrollment_cmhf_name);
  if (res.rca_cert) { free(res.rca_cert); }
  if (res.ica_cert) { free(res.ica_cert); }
  if (res.pca_cert) { free(res.pca_cert); }
  if (res.crlg_cert) { free(res.crlg_cert); }
  return ret;
}
