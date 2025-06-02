/** 
  * @file 
  * @brief LCM 관련 인라인 함수 정의
  * @date 2022-07-09 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_LCM_INLINE_H
#define V2X_SW_DOT2_LCM_INLINE_H


// 의존 라이브러리 헤더 파일
#include "openssl/sha.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"


/**
 * @brief LCCF의 길이가 유효한지 체크한다.
 * @param[in] lccf_size LCCF 길이
 * @retval 0: LCCF 길이가 유효함
 * @retval 음수(-Dot2ResultCode): LCCF 길이가 유효하지 않음
 */
static inline int dot2_CheckLCCFSize(Dot2LCCFSize lccf_size)
{
  return (lccf_size <= kDot2LCCFSize_Max) ? kDot2Result_Success : -kDot2Result_LCM_InvalidLCCFSize;
}


/**
 * @brief 응용인증서 파일명(확장자 포함)을 설정한다.
 * @param[in] filename_no_ext 확장자를 포함하지 않은 파일명
 * @param[out] filename 파일명이 저장될 버퍼의 길이.
 *                      DOT2_A_CERT_FILE_NAME_LEN 이상의 길이를 가져야 하며, 0으로 채워져 있어야 한다.
 */
static inline void dot2_SetAppCertFileName(const char *filename_no_ext, char *filename)
{
  memcpy(filename, filename_no_ext, DOT2_H8_HEX_STR_LEN);
  strcat(filename, ".cert");
}


/**
 * @brief 응용인증서 개인키파일명(확장자 포함)을 설정한다.
 * @param[in] filename_no_ext 확장자를 포함하지 않은 파일명
 * @param[out] filename 파일명이 저장될 버퍼의 길이.
 *                      DOT2_A_PRIV_KEY_FILE_NAME_LEN 이상의 길이를 가져야 하며, 0으로 채워져 있어야 한다.
 */
static inline void dot2_SetAppCertPrivKeyFileName(const char *filename_no_ext, char *filename)
{
  memcpy(filename, filename_no_ext, DOT2_H8_HEX_STR_LEN);
  strcat(filename, ".privkey");
}


/**
 * @brief 응용인증서 개인키재구성값 파일명(확장자 포함)을 설정한다.
 * @param[in] filename_no_ext 확장자를 포함하지 않은 파일명
 * @param[out] filename 파일명이 저장될 버퍼의 길이.
 *                      DOT2_A_RECON_PRIV_FILE_NAME_LEN 이상의 길이를 가져야 하며, 0으로 채워져 있어야 한다.
 */
static inline void dot2_SetAppCertReconPrivFileName(const char *filename_no_ext, char *filename)
{
  memcpy(filename, filename_no_ext, DOT2_H8_HEX_STR_LEN);
  strcat(filename, ".s");
}


/**
 * @brief 익명/식별인증서 파일명 프리픽스(=확장자를 제외한 파일명)를 설정한다.
 * @param[in] i_period i-period 값
 * @param[in] j j 값
 * @param[out] prefix 프리픽스가 저장될 버퍼의 길이.
 *                    DOT2_P_I_CERT_FILE_NAME_PREFIX_MAX_LEN 이상의 길이를 가져야 하며, 0으로 채워져 있어야 한다.
 */
static inline void dot2_SetPseudonymIdCertFileNamePrefix(Dot2IPeriod i_period, unsigned int j, char *prefix)
{
  sprintf(prefix, "%X", i_period);
  strcat(prefix, "_");
  sprintf(prefix + strlen(prefix), "%X", j);
}


/**
 * @brief 익명/식별인증서 파일명(확장자 포함)을 설정한다.
 * @param[in] i_period i-period 값
 * @param[in] j j 값
 * @param[out] filename 파일명이 저장될 버퍼의 길이.
 *                      DOT2_P_I_CERT_FILE_NAME_MAX_LEN 이상의 길이를 가져야 하며, 0으로 채워져 있어야 한다.
 */
static inline void dot2_SetPseudonymIdCertFileName(Dot2IPeriod i_period, unsigned int j, char *filename)
{
  dot2_SetPseudonymIdCertFileNamePrefix(i_period, j, filename);
  strcat(filename, ".cert");
}


/**
 * @brief 익명/식별인증서 개인키파일명(확장자 포함)을 설정한다.
 * @param[in] i_period i-period 값
 * @param[in] j j 값
 * @param[out] filename 파일명이 저장될 버퍼의 길이.
 *                      DOT2_P_I_PRIV_KEY_FILE_NAME_MAX_LEN 이상의 길이를 가져야 하며, 0으로 채워져 있어야 한다.
 */
static inline void dot2_SetPseudonymIdPrivKeyFileName(Dot2IPeriod i_period, unsigned int j, char *filename)
{
  dot2_SetPseudonymIdCertFileNamePrefix(i_period, j, filename);
  strcat(filename, ".privkey");
}


/**
 * @brief 익명/식별인증서 개인키재구성값 파일명(확장자 포함)을 설정한다.
 * @param[in] i_period i-period 값
 * @param[in] j j 값
 * @param[out] filename 파일명이 저장될 버퍼의 길이.
 *                      DOT2_P_I_RECON_PRIV_FILE_NAME_MAX_LEN 이상의 길이를 가져야 하며, 0으로 채워져 있어야 한다.
 */
static inline void dot2_SetPseudonymIdReconPrivFileName(Dot2IPeriod i_period, unsigned int j, char *filename)
{
  dot2_SetPseudonymIdCertFileNamePrefix(i_period, j, filename);
  strcat(filename, ".s");
}


/**
 * @brief Linkage seed 값을 갱신한다.
 * @param[in] la_id Linkage seed를 생성한 LA의 식별자 (DOT2_LA_ID_LEN 길이를 가진다)
 * @param[in] ls_input 입력되는 현재 Linkage seed 값 (DOT2_LINKAGE_SEED_LEN 길이를 가진다)
 * @param[in] ls_result 갱신된 Linkage seed 값이 저장될 버퍼 (DOT2_LINKAGE_SEED_LEN 길이를 가진다)
 *
 * ls 값은 다음과 같이 계산된다.
 *  - ls = [SHA256 (laId || ls || 0^112)]_128
 */
static inline void dot2_UpdateLinkageSeed(const uint8_t *la_id, const uint8_t *ls_input, uint8_t *ls_result)
{
  uint8_t tmp[DOT2_SHA_256_LEN], tmp1[DOT2_SHA_256_LEN];
  memset(tmp, 0, sizeof(tmp));
  memcpy(tmp, la_id, DOT2_LA_ID_LEN);
  memcpy(tmp + DOT2_LA_ID_LEN, ls_input, DOT2_LINKAGE_SEED_LEN);
  SHA256(tmp, sizeof(tmp), tmp1);
  memcpy(ls_result, tmp1, DOT2_LINKAGE_SEED_LEN);
}


/**
 * @brief LinkageSeed 값을 계산한다.
 * @param[in] i_rev CRL 내 iRev 값 (폐기정보 유효기간 시작시점)
 * @param[in] i_cert 현 시점의 iCert 값
 * @param[in] la1_id CRL 내 LA1 ID (Linkage seed 1 값을 생성한 LA 식별자) (DOT2_LA_ID_LEN의 길이를 가져야 한다)
 * @param[in] la2_id CRL 내 LA2 ID (Linkage seed 2 값을 생성한 LA 식별자) (DOT2_LA_ID_LEN의 길이를 가져야 한다)
 * @param[in] ls1_in CRL 내 Linkage seed 1 값 (DOT2_LINKAGE_SEED_LEN의 길이를 가져야 한다)
 * @param[in] ls2_in CRL 내 Linkage seed 2 값 (DOT2_LINKAGE_SEED_LEN의 길이를 가져야 한다)
 * @param[out] ls1_out 계산된 Linkage seed 1 값이 반환될 버퍼 (DOT2_LINKAGE_SEED_LEN의 길이를 가져야 한다)
 * @param[out] ls2_out 계산된 Linkage seed 2 값이 반환될 버퍼 (DOT2_LINKAGE_SEED_LEN의 길이를 가져야 한다)
 *
   * iRev < iCert를 만족하는 동안, LS1 값과 LS2 값을 업데이트한다.
   *  - "KISA V2X 인증서 폐지 목록 검증 규격 v1.1" 8.2.1 절의 "나)" 절차
   *   (1) ls1 = [SHA256 (la1Id || ls1 || 0112)]128
   *   (2) ls2 = [SHA256 (la2Id || ls2 || 0112)]128
   *   (3) iRev = iRev + 1
 */
static inline void dot2_CalculateLinkageSeed(
  uint16_t i_rev,
  uint16_t i_cert,
  const uint8_t *la1_id,
  const uint8_t *la2_id,
  const uint8_t *ls1_in,
  const uint8_t *ls2_in,
  uint8_t *ls1_out,
  uint8_t *ls2_out)
{
  memcpy(ls1_out, ls1_in, DOT2_LINKAGE_SEED_LEN); // 초기값
  memcpy(ls2_out, ls2_in, DOT2_LINKAGE_SEED_LEN); // 초기값
  while (i_rev < i_cert) {
    dot2_UpdateLinkageSeed(la1_id, ls1_out, ls1_out); // (1) 절차
    dot2_UpdateLinkageSeed(la2_id, ls2_out, ls2_out); // (2) 절차
    i_rev++; // (3) 절차
  }
}


#endif //V2X_SW_DOT2_LCM_INLINE_H
