/**
 * @file
 * @brief PCI(Provider Channel Info) 관련 API들을 구현한 파일
 * @date 2019-09-26
 * @author gyun
 */

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief PCI 정보를 설정한다(상세 내용 API 매뉴얼 참조).
 * @param[in] pci 설정할 PCI 정보가 담긴 정보구조체 포인터
 * @retval 0 이상: 테이블에 등록되어 있는 PCI 정보의 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_SetPCI(const struct Dot3PCI *pci)
{
  Log(kDot3LogLevel_Event, "Set PCI\n");

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (pci == NULL) {
    Err("Fail to set PCI - null parameters\n");
    return -kDot3Result_NullParameters;
  }
#if 0 // NOTE:: 국내에서는 Operating class로 어떤 값을 사용할지 정의되어 있지 않으므로, 유효성 검사를 생략한다.
  if (dot3_IsValidOperatingClass(pci->operating_class) == false) {
    Err("Fail to set PCI - invalid operating class %u\n", pci->operating_class);
    return -kDot3Result_InvalidOperatingClass;
  }
#endif
  if (dot3_IsValidChannelNumber(pci->chan_num) == false) {
    Err("Fail to set PCI - invalid channel %u\n", pci->chan_num);
    return -kDot3Result_InvalidChannelNumber;
  }
  if (dot3_IsValidPower(pci->transmit_power_level) == false) {
    Err("Fail to set PCI - invalid transmit power level %d\n", pci->transmit_power_level);
    return -kDot3Result_InvalidPower;
  }
  if (dot3_IsValidDataRate(pci->datarate) == false) {
    Err("Fail to set PCI - invalid datarate %u\n", pci->datarate);
    return -kDot3Result_InvalidDataRate;
  }
  if (pci->present.edca_param_set == true) {
    int ret = dot3_CheckEDCAParameterSet(&(pci->edca_param_set));
    if (ret < 0) {
      return ret;
    }
  }
  if ((pci->present.chan_access == true) && (dot3_IsValidProviderChannelAccess(pci->chan_access) == false)) {
    Err("Fail to set PCI - invalid channel access %u\n", pci->chan_access);
    return -kDot3Result_InvalidChannelAccess;
  }

  /*
   * PCI를 추가 또는 업데이트한다.
   */
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  int ret = dot3_AddOrUpdatePCI(&(pinfo->pci_table), pci);
  pthread_mutex_unlock(&(pinfo->mtx));

  return ret;
}


/**
 * @brief 특정 채널에 관련된 PCI 정보를 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[in] chan_num 채널 번호
 * @param[out] pci PCI 정보가 반환될 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_GetPCIWithChannelNumber(Dot3ChannelNumber chan_num, struct Dot3PCI *pci)
{
  Log(kDot3LogLevel_Event, "Get PCI (channel: %u)\n", chan_num);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot3_IsValidChannelNumber(chan_num) == false) {
    Err("Fail to get PCI - invalid channel %u\n", chan_num);
    return -kDot3Result_InvalidChannelNumber;
  }
  if (pci == NULL) {
    Err("Fail to get PCI - null parameters\n");
    return -kDot3Result_NullParameters;
  }

  /*
   * PCI를 찾아서 반환한다.
   */
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  int ret = dot3_GetPCIWithChannel(&(pinfo->pci_table), chan_num, pci);
  pthread_mutex_unlock(&(pinfo->mtx));

  return ret;
}


/**
 * @brief 등록되어 있는 PCI의 개수를 확인한다(상세 내용 API 매뉴얼 참조).
 * @return 등록되어 있는 PCI의 개수
 */
Dot3PCINum OPEN_API Dot3_GetPCINum(void)
{
  return dot3_GetPCINum(&(g_dot3_mib.provider_info.pci_table));
}
