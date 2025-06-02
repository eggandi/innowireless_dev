/** 
  * @file 
  * @brief LCM 관련 구현
  * @date 2022-07-24 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"
#include "zip/zip.h"
#if defined(_FFASN1C_)
#include "ffasn1-dot2-2021.h"
#elif defined(_OBJASN1C_)
// nothing
#else
#error "3rd party asn.1 library is not defined"
#endif

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"


/**
 * @brief LCM 동작을 위한 설정을 수행한다.
 * @param[in] type 설정 유형
 * @param[in] cfg_str 설정 문자열
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ConfigLCM(Dot2LCMConfigType type, const char *cfg_str)
{
  Log(kDot2LogLevel_Event, "Config LCM - type: %u, cfg_str: %s\n", type, cfg_str);
  int ret = -kDot2Result_NoMemory;
  char *to = strdup(cfg_str);
  if (to) {
    switch (type) {
      case kDot2LCMConfigType_LPFReqURL:
        g_dot2_mib.lcm.ra.lpf_url = to;
        break;
      case kDot2LCMConfigType_LCCFReqURL:
        g_dot2_mib.lcm.ra.lccf_url = to;
        break;
      case kDot2LCMConfigType_CRLReqURL:
        g_dot2_mib.lcm.ra.crl_url = to;
        break;
      case kDot2LCMConfigType_AppCertProvisioningReqURL:
        g_dot2_mib.lcm.ra.acp_url = to;
        break;
      case kDot2LCMConfigType_PseudonymCertProvisioningReqURL:
        g_dot2_mib.lcm.ra.pcp_url = to;
        break;
      case kDot2LCMConfigType_IdCertProvisioningReqURL:
        g_dot2_mib.lcm.ra.icp_url = to;
        break;
      case kDot2LCMConfigType_RCATLSCertFilePath:
        g_dot2_mib.lcm.tls.rca_cert_file_path = to;
        break;
      case kDot2LCMConfigType_TmpZipFilePath:
        g_dot2_mib.lcm.tmp_zip_file_path = to;
        break;
      default:
        break;
    }
    ret = kDot2Result_Success;
  }
  return ret;
}


/**
 * @brief MIB에서 인증서 요청정보를 가져온다.
 * @param[in] current_time 현재시각
 * @param[out] info 인증서요청정보가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_GetCertRequestInfo(Dot2Time32 current_time, struct Dot2CertRequestInfo *info)
{
  memset(info, 0, sizeof(struct Dot2CertRequestInfo));

  /*
   * RA 정보를 복사해서 가져온다.
   */
  struct Dot2SCCCertInfoEntry *ra_entry = g_dot2_mib.scc_cert_info_table.ra;
  if (ra_entry) {
    memcpy(&(info->ra.cert_h), &(ra_entry->cert_h), sizeof(struct Dot2SHA256));
    if (ra_entry->contents.common.enc_pub_key_present == true) {
      memcpy(&(info->ra.enc_pub_key), &(ra_entry->contents.common.enc_pub_key), sizeof(struct Dot2ECPublicKey));
    } else {
      goto err;
    }
    info->ra.eck_verify_pub_key = EC_KEY_dup(ra_entry->contents.eck_verify_pub_key);
    if (!info->ra.eck_verify_pub_key) {
      goto err;
    }
  } else {
    goto err;
  }

  dot2_HTTPS_GetHTTPSConnInfo(&(info->https));

  /*
   * ACA/PCA 정보를 복사해서 가져온다.
   */
  struct Dot2SCCCertInfoEntry *pca_entry = g_dot2_mib.scc_cert_info_table.pca;
  if (pca_entry) {
    memcpy(&(info->pca.cert_h), &(pca_entry->cert_h), sizeof(struct Dot2SHA256));
    memcpy(&(info->pca.pub_key), &(pca_entry->contents.verify_pub_key), sizeof(struct Dot2ECPublicKey));
    info->pca.eck_pub_key = EC_KEY_dup(pca_entry->contents.eck_verify_pub_key);
    if (!info->pca.eck_pub_key) {
      goto err;
    }
  } else {
    goto err;
  }

  /*
   * 현재 가용한 등록인증서 관련 정보를 복사해서 가져온다.
   */
  struct Dot2SequentialCMHEntry *ec_entry = dot2_GetCurrentlyAvailableSequentialCMHEntry(&(g_dot2_mib.cmh_table.enrol),
                                                                                         dot2_ConvertTime32ToTime64(current_time));
  if (ec_entry &&
      ec_entry->asn1_cert &&
      ec_entry->info.eck_priv_key) {
#if defined(_FFASN1C_)
    info->ec.asn1_cert = (void *)asn1_clone_value(asn1_type_dot2Certificate, ec_entry->asn1_cert);
#elif defined(_OBJASN1C_)
    info->ec.asn1_cert = ec_entry->asn1_cert;
#else
#error "3rd party asn.1 library is not defined"
#endif
    if (!info->ec.asn1_cert) {
      goto err;
    }
    info->ec.eck_priv_key = EC_KEY_dup(ec_entry->info.eck_priv_key);
    if (!info->ec.eck_priv_key) {
      goto err;
    }
    memcpy(&(info->ec.cert_h), &(ec_entry->cert_h), sizeof(struct Dot2SHA256));
    info->ec.valid_start = dot2_ConvertTime64ToTime32(ec_entry->info.cert_contents.common.valid_start);
  } else {
    goto err;
  }

  /*
   * ZIP 파일 임시 저장 경로를 복사해서 가져온다.
   */
  if (g_dot2_mib.lcm.tmp_zip_file_path) {
    info->tmp_zip_file_path = strdup(g_dot2_mib.lcm.tmp_zip_file_path);
  }

  return kDot2Result_Success;

err:
  dot2_ClearCertRequestInfo(info);
  return -kDot2Result_LCM_NoSufficientCertRequestInfo;
}


/**
 * @brief 인증서 요청정보를 해제한다.
 * @param[in] info 인증서요청정보
 */
void INTERNAL dot2_ClearCertRequestInfo(struct Dot2CertRequestInfo *info)
{
  if (info->ra.eck_verify_pub_key) { EC_KEY_free(info->ra.eck_verify_pub_key); }
  if (info->pca.eck_pub_key) { EC_KEY_free(info->pca.eck_pub_key); }
  dot2_HTTPS_ClearHTTPSConnInfo(&(info->https));
  if (info->ec.eck_priv_key) { EC_KEY_free(info->ec.eck_priv_key); }
#if defined(_FFASN1C_)
  if (info->ec.asn1_cert) { asn1_free_value(asn1_type_dot2Certificate, info->ec.asn1_cert); }
#elif defined(_OBJASN1C_)
  if (info->ec.asn1_cert) { info->ec.asn1_cert = NULL; }
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (info->tmp_zip_file_path) { free(info->tmp_zip_file_path); }
  memset(info, 0, sizeof(struct Dot2CertRequestInfo));
}


/**
 * @brief 단일 인증서다운로드응답문 파일이 ZIP 압축된 바이트열의 압축을 해제한다. (응용/식별인증서 다운로드 시 사용된다)
 * @param[in] tmp_path 동작 디렉토리 (ZIP 파일이 저장될 디렉토리 경로)
 * @param[in] zip_octs ZIP 압축된 바이트열
 * @param[in] zip_octs_size ZIP 압축된 바이트열의 길이
 * @param[in] filename ZIP 압축 파일내에 들어 있는 인증서다운로드응답문 파일명 (=H8(인증서발급요청문))
 * @param[out] unzip_resp 압축해제된 파일내용(인증서다운로드응답문)이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_UnzipSingleCertDownloadResponseFile(
  const char *tmp_path,
  const uint8_t *zip_octs,
  size_t zip_octs_size,
  struct Dot2UnzipCertDownloadResponse *unzip_resp)
{
  Log(kDot2LogLevel_Event, "Unzip single cert download response file(%zu bytes) to %s\n", zip_octs_size, tmp_path);

  /*
   * 임시 zip 파일을 저장한다.
   */
  int ret = dot2_ExportFile(tmp_path, zip_octs, zip_octs_size);
  if (ret < 0) {
    Err("Fail to unzip single cert download response file - dot2_ExportDirFile() failed\n");
    return ret;
  }

  /*
   * zip 파일을 열고 원하는 파일을 꺼낸다.
   */
  uint8_t *buf = NULL;
  size_t buf_size;
  struct zip_t *zip = zip_open(tmp_path, 0, 'r');
  if (!zip) {
    Err("Fail to unzip single cert download response file - zip_open() failed\n");
    goto err;
  }
  if (zip_entry_openbyindex(zip, 0) < 0) {
    Err("Fail to unzip single cert download response file - zip_entry_openbyindex() failed\n");
    goto err;
  }
  ssize_t read = zip_entry_read(zip, (void **)&buf, &buf_size);
  zip_entry_close(zip);
  if (read < 0) {
    Err("Fail to unzip single cert download response file - zip_entry_read() failed\n");
    goto err;
  }
  zip_close(zip);
  remove(tmp_path); // 임시 zip 파일 삭제
  unzip_resp->octs = buf;
  unzip_resp->len = (size_t)read;

  Log(kDot2LogLevel_Event, "Success to unzip single cert download response file (len: %zu)\n", unzip_resp->len);
  return kDot2Result_Success;

err:
  if (zip) { zip_close(zip); }
  remove(tmp_path);
  return -kDot2Result_FILE_Unzip;
}


/**
 * @brief 다수의 인증서다운로드응답문 파일들이 ZIP 압축된 바이트열의 압축을 해제한다. (익명인증서 다운로드 시 사용된다)
 * @param[in] tmp_path 동작 디렉토리 (ZIP 파일이 저장될 디렉토리 경로)
 * @param[in] zip_octs ZIP 압축된 바이트열
 * @param[in] zip_octs_size ZIP 압축된 바이트열의 길이
 * @param[in] i_period 다운로드한 인증서 i-period
 * @param[in] response_file_num ZIP 압축 파일내에 들어 있는 인증서다운로드응답문 파일의 개수
 * @param[out] unzip_resps 압축해제된 response_file_num개의 파일내용(인증서다운로드응답문)이 저장될 구조체 배열 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_UnzipMultipleCertDownloadResponseFiles(
  const char *tmp_path,
  const uint8_t *zip_octs,
  size_t zip_octs_size,
  Dot2IPeriod i_period,
  unsigned int response_file_num,
  struct Dot2UnzipCertDownloadResponse *unzip_resps)
{
  Log(kDot2LogLevel_Event, "Unzip multiple cert download response files(%zu bytes) to %s, i-period: %d\n",
      zip_octs_size, tmp_path, i_period);

  /*
   * 임시 zip 파일을 저장한다.
   */
  int ret = dot2_ExportFile(tmp_path, zip_octs, zip_octs_size);
  if (ret < 0) {
    Err("Fail to unzip multiple cert download response files - dot2_ExportDirFile() failed\n");
    return ret;
  }

  /*
   * zip 파일을 열고 원하는 파일을 꺼낸다.
   */
  uint8_t *buf = NULL;
  size_t buf_size;
  struct zip_t *zip = zip_open(tmp_path, 0, 'r');
  if (!zip) {
    Err("Fail to unzip multiple cert download response files - zip_open() failed\n");
    goto err;
  }
  char filename[DOT2_I_PERIOD_HEX_STR_MAX_LEN+1+DOT2_J_VALUE_HEX_STR_MAX_LEN+1]; // i_period + '_' + j_value + '\0'
  memset(filename, 0, sizeof(filename));
  sprintf(filename, "%X", i_period);
  strcat(filename, "_");
  char *ptr = filename + strlen(filename);
  for (unsigned int j = 0; j < response_file_num; j++) {
    sprintf(ptr, "%X", j);
    if (zip_entry_open(zip, filename) < 0) {
      Err("Fail to unzip multiple cert download response files - zip_entry_open(%s) failed\n", filename);
      goto err;
    }
    ssize_t read = zip_entry_read(zip, (void **)&buf, &buf_size);
    zip_entry_close(zip);
    if (read < 0) {
      Err("Fail to unzip multiple cert download response files - zip_entry_read() failed\n");
      goto err;
    }
    (unzip_resps + j)->len = read;
    (unzip_resps + j)->octs = buf;
  }

  zip_close(zip);
  remove(tmp_path); // 임시 zip 파일 삭제

  Log(kDot2LogLevel_Event, "Success to unzip multiple cert download response files\n");
  return kDot2Result_Success;

err:
  if (zip) { zip_close(zip); }
  remove(tmp_path);
  return -kDot2Result_FILE_Unzip;
}
