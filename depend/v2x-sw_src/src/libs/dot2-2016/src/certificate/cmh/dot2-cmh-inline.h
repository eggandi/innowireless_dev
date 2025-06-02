/**
  * @file 
  * @brief CMH 관련 인라인 함수들을 정의한 파일
  * @date 2021-09-12 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_CMH_INLINE_H
#define V2X_SW_DOT2_CMH_INLINE_H


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief CMH 유형에 따라 저장할 Sequential CMH 리스트를 선택한다.
 * @param[in] cmh_type CMH 유형
 * @return 선택된 Sequential CMH 리스트 포인터
 * @retval NULL: 실패
 *
 * 단일 EE 내에서 CMH 중 Application CMH, Identification CMH, Pseudonym CMH는 동시에 사용될 수 없다.
 * CMH 테이블에 이미 등록된 CMH이 있을 경우, 해당 CMH와 동일한 CMH유형을 갖는 CMH만이 등록 가능하다.
 * Enrollment 인증서는 별도의 리스트로 관리되므로 충돌 여부에 해당되지 않는다.
 */
static inline struct Dot2SequentialCMHList * dot2_SelectSequentialCMHList(Dot2CMHType cmh_type)
{
  struct Dot2SequentialCMHList *list = NULL;
  Dot2CMHType prev_cmh_type = g_dot2_mib.cmh_table.cmh_type;
  switch (cmh_type) {
    case kDot2CMHType_Application:
      if ((prev_cmh_type == kDot2CMHType_Undefined) || (prev_cmh_type == cmh_type)) {
        list = &(g_dot2_mib.cmh_table.app);
      }
      break;
    case kDot2CMHType_Enrollment:
      list = &(g_dot2_mib.cmh_table.enrol);
      break;
  }
  return list;
}


/**
 * @brief CMH 유형에 따라 저장할 Rotate CMH 세트 리스트를 선택한다.
 * @param[in] cmh_type CMH 유형
 * @return 선택된 Rotate CMH 세트 리스트 포인터
 * @retval NULL: 실패
 *
 * 단일 EE 내에서 CMH 중 Application CMH, Identification CMH, Pseudonym CMH는 동시에 사용될 수 없다.
 * CMH 테이블에 이미 등록된 CMH이 있을 경우, 해당 CMH와 동일한 CMH유형을 갖는 CMH만이 등록 가능하다.
 * Enrollment 인증서는 별도의 리스트로 관리되므로 충돌 여부에 해당되지 않는다.
 */
static inline struct Dot2RotateCMHSetList * dot2_SelectRotateCMHSetList(Dot2CMHType cmh_type)
{
  struct Dot2RotateCMHSetList *list = NULL;
  Dot2CMHType prev_cmh_type = g_dot2_mib.cmh_table.cmh_type;
  if ((cmh_type == kDot2CMHType_Pseudonym) ||
      (cmh_type == kDot2CMHType_Identification)) {
    if ((prev_cmh_type == kDot2CMHType_Undefined) || (prev_cmh_type == cmh_type)) {
      list = &(g_dot2_mib.cmh_table.pseudonym_id);
    }
  }
  return list;
}


/**
 * @brief 특정 Sequential CMH가 현재 가용한지 확인한다.
 * @param[in] now 현재 시각
 * @param[in] entry 확인할 Sequential CMH 엔트리
 * @return 가용 여부
 *
 * 가용조건: 현재시각이 유효기간 내에 포함되어야 함.
 */
static inline bool dot2_CheckSequentialCMHAvailableNow(Dot2Time64 now, struct Dot2SequentialCMHEntry *entry)
{
  if ((now >= entry->info.cert_contents.common.valid_start) &&
      (now <= entry->info.cert_contents.common.valid_end)) {
    return true;
  }
  return false;
}


/**
 * @brief Rotate CMH 세트 엔트리를 할당한다.
 * @param[in] cmh_type CMH 유형
 * @return 할당된 Rotate CMH 세트 엔트리 포인터
 * @retval NULL: 할당 실패
 */
static inline struct Dot2RotateCMHSetEntry * dot2_AllocateRotateCMHSetEntry(Dot2CMHType cmh_type)
{
  struct Dot2RotateCMHSetEntry *cmh_set_entry = NULL;
  cmh_set_entry = (struct Dot2RotateCMHSetEntry *)calloc(1, sizeof(struct Dot2RotateCMHSetEntry));
  if (cmh_set_entry) {
    cmh_set_entry->max_info_num = kDot2RotateCMHInfoNum_IdCertDefault;
    if (cmh_type == kDot2CMHType_Pseudonym) {
      cmh_set_entry->max_info_num = kDot2RotateCMHInfoNum_PseudonymCertDefault;
    }
  }
  return cmh_set_entry;
}


#ifdef __cplusplus
}
#endif


#endif //V2X_SW_DOT2_CMH_INLINE_H
