/**
 * @file
 * @brief openssl 인증서 Linkage value 관련 구현
 * @date 2023-01-07
 * @author gyun
 */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-openssl-inline.h"


/**
 * @brief 인증서 폐지 여부 확인을 위해 lv(j)값을 구한다
 * @param[in] j 인증서의 인덱스
 * @param[in] la1_id CRL 내 LA1 ID (Linkage seed 1 값을 생성한 LA 식별자)
 * @param[in] la2_id CRL 내 LA2 ID (Linkage seed 2 값을 생성한 LA 식별자)
 * @param[in] ls1 CRL 내 Linkage seed 1 값
 * @param[in] ls2 CRL 내 Linkage seed 2 값
 * @param[out] lv_j 특정 j값으로 계산된 lv(j)값이 저장될 버퍼 (DOT2_LINKAGE_VALUE_LEN 이상의 길이를 가져야 한다)
 *
 * - "KISA V2X 인증서 폐지 목록 검증 규격 v1.1" 8.2.1 절의 "다)" 절차에 따라 lv(j)값은 다음과 같이 계산된다.
 *  - (1) data1 = la1_id || Uint32(j) || 0^80
 *  - (2) plv1(j) = AES(ls1, data1) XOR (data1)
 *  - (3) data2 = la2_id || Uint32(j) || 0^80
 *  - (4) plv2(j) = AES(ls2, data2) XOR (data2)
 *  - (5) lv(j) = [plv1(j) XOR plv2(j)]_72
 */
int INTERNAL dot2_ossl_DeriveLinkageValue_j(
  uint8_t j,
  const uint8_t *la1_id,
  const uint8_t *la2_id,
  const uint8_t *ls1,
  const uint8_t *ls2,
  uint8_t *lv_j)
{
  int ret = -kDot2Result_OSSL_LinkageValue;
  uint8_t plv1[DOT2_LINKAGE_SEED_LEN], plv2[DOT2_LINKAGE_SEED_LEN], data[DOT2_LINKAGE_SEED_LEN];
  memset(plv1, 0, DOT2_LINKAGE_SEED_LEN);
  memset(plv2, 0, DOT2_LINKAGE_SEED_LEN);
  memset(data, 0, DOT2_LINKAGE_SEED_LEN);

  // (1) 계산
  memcpy(data, la1_id, DOT2_LA_ID_LEN);
  *(uint32_t *)(data + DOT2_LA_ID_LEN) = htonl((uint32_t)j);
  // (2) 계산
  if (dot2_ossl_AESECBEncrypt(ls1, data, plv1) == true) {
    dot2_XOR(data, sizeof(data), plv1); // (2) 계산 완료 -> plv1(j)
    // (3) 계산
    memset(data, 0, DOT2_LINKAGE_SEED_LEN);
    memcpy(data, la2_id, DOT2_LA_ID_LEN);
    *(uint32_t *)(data + DOT2_LA_ID_LEN) = htonl((uint32_t)j);
    // (4) 계산
    if (dot2_ossl_AESECBEncrypt(ls2, data, plv2) == true) {
      dot2_XOR(data, sizeof(data), plv2); // (4) 계산 완료 -> plv2(j)
      // (5) 계산
      dot2_XOR(plv1, sizeof(plv1), plv2);
      memcpy(lv_j, plv2, DOT2_LINKAGE_VALUE_LEN);
      ret = kDot2Result_Success;
    }
  }
  return ret;
}
