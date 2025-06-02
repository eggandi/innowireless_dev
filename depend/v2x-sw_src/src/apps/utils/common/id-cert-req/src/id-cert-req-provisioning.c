/** 
  * @file 
  * @brief 식별인증서 발급요청 관련 구현
  * @date 2022-07-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

// 유틸리티 헤더 파일
#include "id-cert-req.h"


/**
 * @brief 식별인증서 발급을 요청한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int ID_CERT_REQ_RequestIdCertProvisioning(void)
{
  struct Dot2CertProvisioningRequestParams params;
  struct Dot2PseudonymIdCertProvisioningRequestResult res;
  memset(&params, 0, sizeof(params));

  /*
   * 발급요청을 수행한다.
   */
  params.current_time = 0;
  params.start_time = 0;
  params.return_options = true; // 옵션정보도 함께 반환하도록 설정
  res = Dot2_RequestIdCertProvisioning(&params);
  if (res.ret < 0) {
    printf("Fail to Dot2_RequestIdCertProvisioning() : %d\n", res.ret);
    return -1;
  }

  /*
   * 결과를 화면에 출력한다.
   */
  ID_CERT_REQ_PrintOcts("H(SecuredIdCertProvisioningRequest)", res.common.req_h8, 8);
  ID_CERT_REQ_PrintOcts("VerifyPrivKey", res.common.verify_priv_key.octs, DOT2_EC_256_KEY_LEN);
  ID_CERT_REQ_PrintOcts("CertEncryptionPrivKey", res.common.cert_enc_priv_key.octs, DOT2_EC_256_KEY_LEN);
  ID_CERT_REQ_PrintOcts("VerifyExpKey", res.verify_exp_key.octs, DOT2_AES_128_LEN);
  ID_CERT_REQ_PrintOcts("CertEncryptionExpKey", res.cert_enc_exp_key.octs, DOT2_AES_128_LEN);
  printf("CertDownloadURL: %s\n", res.common.cert_dl_url);
  printf("CertDownloadTime: %u\n", res.common.cert_dl_time);
  printf("CurremtTime32: %u\n", res.common.current_time);
  printf("Remained seconds to CertDowloadTime: %d\n", res.common.remained_cert_dl_time);
  if (params.return_options == true) {
    ID_CERT_REQ_PrintOcts("SecuredIdCertProvisioningRequest", res.options.req, res.options.req_size);
    ID_CERT_REQ_PrintOcts("SignedIdCertProvisioningAck", res.options.ack, res.options.ack_size);
  }

  /*
   * 결과를 파일에 저장한다.
   */
  int ret = ID_CERT_REQ_ExportFile(g_cfg.req_h8_file, res.common.req_h8, 8);
  if (ret < 0) {
    goto out;
  }
  ret = ID_CERT_REQ_ExportFile(g_cfg.v_file, res.common.verify_priv_key.octs, DOT2_EC_256_KEY_LEN);
  if (ret < 0) {
    goto out;
  }
  ret = ID_CERT_REQ_ExportFile(g_cfg.e_file, res.common.cert_enc_priv_key.octs, DOT2_EC_256_KEY_LEN);
  if (ret < 0) {
    goto out;
  }
  ret = ID_CERT_REQ_ExportFile(g_cfg.ck_file, res.verify_exp_key.octs, DOT2_AES_128_LEN);
  if (ret < 0) {
    goto out;
  }
  ret = ID_CERT_REQ_ExportFile(g_cfg.ek_file, res.cert_enc_exp_key.octs, DOT2_AES_128_LEN);
  if (ret < 0) {
    goto out;
  }
  if (params.return_options == true) {
    ret = ID_CERT_REQ_ExportFile(g_cfg.req.req_file, res.options.req, res.options.req_size);
    if (ret < 0) {
      goto out;
    }
    ret = ID_CERT_REQ_ExportFile(g_cfg.req.ack_file, res.options.ack, res.options.ack_size);
    if (ret < 0) {
      goto out;
    }
  }

  ret = 0;

out:
  free(res.common.cert_dl_url);
  if (params.return_options == true) {
    free(res.options.req);
    free(res.options.ack);
  }
  return ret;
}
