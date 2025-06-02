/** 
  * @file 
  * @brief 식별인증서 다운로드 관련 구현
  * @date 2022-07-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <sys/stat.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

// 유틸리티 헤더 파일
#include "id-cert-req.h"


/**
 * @brief 식별인증서를 다운로드한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int ID_CERT_REQ_DownloadIdCert(void)
{
  struct Dot2PseudonymIdCertDownloadRequestParams params;
  struct Dot2IdCertDownloadResult res;
  memset(&params, 0, sizeof(params));

  /*
   * 필요한 정보를 파일에서 로딩한다.
   */
  // 인증서발급요청문 H8
  uint8_t req_h8[8];
  int ret = ID_CERT_REQ_ImportFile(g_cfg.req_h8_file, req_h8, 8, 8);
  if (ret < 0) {
    printf("Fail to import %s\n", g_cfg.req_h8_file);
    return -1;
  }
  // 서명용 시드 개인키
  struct Dot2ECPrivateKey verify_priv_key;
  ret = ID_CERT_REQ_ImportFile(g_cfg.v_file, verify_priv_key.octs, DOT2_EC_256_KEY_LEN, DOT2_EC_256_KEY_LEN);
  if (ret < 0) {
    printf("Fail to import %s\n", g_cfg.v_file);
    return -1;
  }
  // 서명용 확장함수 키
  struct Dot2AESKey verify_exp_key;
  ret = ID_CERT_REQ_ImportFile(g_cfg.ck_file, verify_exp_key.octs, DOT2_AES_128_LEN, DOT2_AES_128_LEN);
  if (ret < 0) {
    printf("Fail to import %s\n", g_cfg.ck_file);
    return -1;
  }
  // 인증서암호화용 시드 개인키
  struct Dot2ECPrivateKey cert_enc_priv_key;
  ret = ID_CERT_REQ_ImportFile(g_cfg.e_file, cert_enc_priv_key.octs, DOT2_EC_256_KEY_LEN, DOT2_EC_256_KEY_LEN);
  if (ret < 0) {
    printf("Fail to import %s\n", g_cfg.e_file);
    return -1;
  }
  // 서명용 확장함수 키
  struct Dot2ECPrivateKey cert_enc_exp_key;
  ret = ID_CERT_REQ_ImportFile(g_cfg.ek_file, cert_enc_exp_key.octs, DOT2_AES_128_LEN, DOT2_AES_128_LEN);
  if (ret < 0) {
    printf("Fail to import %s\n", g_cfg.ek_file);
    return -1;
  }

  /*
   * API 파라미터를 설정한다.
   */
  memcpy(params.common.req_h8, req_h8, 8);
  memcpy(&(params.common.verify_priv_key), &verify_priv_key, sizeof(struct Dot2ECPrivateKey));
  memcpy(&(params.common.cert_enc_priv_key), &cert_enc_priv_key, sizeof(struct Dot2ECPrivateKey));
  params.common.cert_dl_url = g_cfg.down.download_req_url;
  memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(struct Dot2AESKey));
  memcpy(&(params.cert_enc_exp_key), &cert_enc_exp_key, sizeof(struct Dot2AESKey));
  params.target_time = g_cfg.down.target_time;
  params.return_options = true; // 옵션정보도 함께 반환하도록 설정

  /*
   * 인증서 다운로드를 수행한다.
   */
  res = Dot2_DownloadIdCert(&params);
  if (res.ret < 0) {
    printf("Fail to Dot2_DownloadIdCert() : %d\n", res.ret);
    return -1;
  }

  /*
   * 결과를 화면에 출력한다.
   */
  printf("CMHF name: %s\n", res.common.cmhf_name);
  ID_CERT_REQ_PrintOcts("CMHF", res.common.cmhf, res.common.cmhf_size);
  if (params.return_options == true) {
    printf("Directory name: %s\n", res.options.dir_name);
    printf("Cert Filename: %s\n", res.options.cert_filename);
    ID_CERT_REQ_PrintOcts("Cert", res.options.cert.octs, res.options.cert.size);
    printf("PrivKey name: %s\n", res.options.priv_key_filename);
    ID_CERT_REQ_PrintOcts("PrivKey", res.options.priv_key.octs, sizeof(res.options.priv_key.octs));
    printf("ReconPriv name: %s\n", res.options.recon_priv_filename);
    ID_CERT_REQ_PrintOcts("ReconPriv", res.options.recon_priv.octs, sizeof(res.options.recon_priv.octs));
  }

  /*
   * 결과를 파일에 저장한다.
   */
  // CMHF 파일
  ret = ID_CERT_REQ_ExportDirFile(g_cfg.down.cmhf_dir,
                                  res.common.cmhf_name,
                                  res.common.cmhf,
                                  res.common.cmhf_size);
  if (ret < 0) {
    goto out;
  }
  // 옵션 정보
  if (params.return_options == true) {

    // 저장 디렉토리 생성
    strcat(g_cfg.down.cert_dir, res.options.dir_name); // g_cfg.down.cert_dir 버퍼가 충분히 길다고 가정
    mkdir(g_cfg.down.cert_dir, 0755);

    // 인증서 파일 저장
    ret = ID_CERT_REQ_ExportDirFile(g_cfg.down.cert_dir,
                                    res.options.cert_filename,
                                    res.options.cert.octs,
                                    res.options.cert.size);
    if (ret < 0) {
      goto out;
    }
    // 개인키 파일 저장
    ret = ID_CERT_REQ_ExportDirFile(g_cfg.down.cert_dir,
                                    res.options.priv_key_filename,
                                    res.options.priv_key.octs,
                                    sizeof(res.options.priv_key.octs));
    if (ret < 0) {
      goto out;
    }
    // 개인키 재구성값 파일 저장
    ret = ID_CERT_REQ_ExportDirFile(g_cfg.down.cert_dir,
                                    res.options.recon_priv_filename,
                                    res.options.recon_priv.octs,
                                    sizeof(res.options.recon_priv.octs));
    if (ret < 0) {
      goto out;
    }
  }

  ret = 0;

out:
  free(res.common.cmhf_name);
  free(res.common.cmhf);
  return ret;
}
