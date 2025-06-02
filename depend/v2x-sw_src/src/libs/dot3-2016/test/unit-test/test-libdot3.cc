/** 
 * @file
 * @brief dot3 라이브러리 단위테스트 메인 파일
 * @date 2020-07-14
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>
#include <unistd.h>
#include <dot3/dot3-types.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "test-libdot3.h"


/// 라이브러리 로그 레벨
Dot3LogLevel log_level = kDot3LogLevel_Err;
//Dot3LogLevel log_level = kDot3LogLevel_Event;


/**
 * @brief 정의된 모든 단위테스트를 수행한다.
 */
int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}


/**
 * @brief 테스트 환경을 초기화한다. 매 TEST() 함수의 시작 부분에서 호출된다.
 */
void InitTestEnv()
{
  /*
   * 라이브러리를 초기화한다.
   */
  ASSERT_EQ(Dot3_Init(log_level), 0);
  usleep(10000);
}


/**
 * @brief 테스트 환경을 해제한다. 매 TEST() 함수의 종료 부분에서 호출된다.
 */
void ReleaseTestEnv()
{
  /*
   * 라이브러리를 종료한다.
   */
  Dot3_Release();
  usleep(10000);
}


/**
 * @brief PSR의 필수정보를 설정한다.
 */
void SetPSRMandatoryInfo(
  Dot3WSAIdentifier wsa_id,
  Dot3PSID psid,
  Dot3ChannelNumber service_chan_num,
  struct Dot3PSR *psr)
{
  memset(psr, 0, sizeof(struct Dot3PSR));
  psr->wsa_id = wsa_id;
  psr->psid = psid;
  psr->service_chan_num = service_chan_num;
}


/**
 * @brief PSR의 PSC 옵션정보를 설정한다.
 */
void SetPSROptionalPSC(const char *psc, struct Dot3PSR *psr)
{
  memset(psr->psc.psc, 0, sizeof(psr->psc.psc));
  psr->present.psc = true;
  psr->psc.len = strlen(psc);
  strncpy(psr->psc.psc, psc, psr->psc.len);
}


/**
 * @brief PSR의 IP 서비스 옵션정보를 설정한다.
 */
void SetPSROptionalIPService(Dot3IPv6Address ip_addr, uint16_t service_port, struct Dot3PSR *psr)
{
  psr->ip_service = true;
  memcpy(psr->ipv6_address, ip_addr, IPv6_ALEN);
  psr->service_port = service_port;
}


/**
 * @brief PSR의 Provider MAC address 옵션정보를 설정한다.
 */
void SetPSROptionalProviderMACAddress(Dot3MACAddress addr, struct Dot3PSR *psr)
{
  psr->present.provider_mac_addr = true;
  memcpy(psr->provider_mac_addr, addr, MAC_ALEN);
}


/**
 * @brief PSR의 RCPI threshold 옵션정보를 설정한다.
 */
void SetPSROptionalRCPIThreshold(Dot3RCPI threshold, struct Dot3PSR *psr)
{
  psr->present.rcpi_threshold = true;
  psr->rcpi_threshold = threshold;
}


/**
 * @brief PSR의 WSA Count Threshold 옵션정보를 설정한다.
 */
void SetPSROptionalWSACountThreshold(Dot3WSACountThreshold threshold, struct Dot3PSR *psr)
{
  psr->present.wsa_cnt_threshold = true;
  psr->wsa_cnt_threshold = threshold;
}


/**
 * @brief PSR의 WSA Count threshold interval 옵션정보를 설정한다.
 */
void SetPSROptionalWSACountThresholdInterval(Dot3WSACountThresholdInterval interval, struct Dot3PSR *psr)
{
  psr->present.wsa_cnt_threshold_interval = true;
  psr->wsa_cnt_threshold_interval = interval;
}


/**
 * @brief 두 PSR의 필수정보를 비교한다.
 */
bool ComparePSRMandatoryInfo(struct Dot3PSR *psr1, struct Dot3PSR *psr2)
{
  EXPECT_EQ(psr1->wsa_id, psr2->wsa_id);
  EXPECT_EQ(psr1->psid, psr2->psid);
  EXPECT_EQ(psr1->service_chan_num, psr2->service_chan_num);
  if (psr1->wsa_id != psr2->wsa_id) { return false; }
  if (psr1->psid != psr2->psid) { return false; }
  if (psr1->service_chan_num != psr2->service_chan_num) { return false; }
  return true;
}


/**
 * @brief 두 PSR의 옵션정보를 비교한다.
 */
bool ComparePSROptionalInfo(struct Dot3PSR *psr1, struct Dot3PSR *psr2)
{
  EXPECT_EQ(psr1->ip_service, psr2->ip_service);
  EXPECT_EQ(psr1->present.psc, psr2->present.psc);
  EXPECT_EQ(psr1->present.provider_mac_addr, psr2->present.provider_mac_addr);
  EXPECT_EQ(psr1->present.rcpi_threshold, psr2->present.rcpi_threshold);
  EXPECT_EQ(psr1->present.wsa_cnt_threshold, psr2->present.wsa_cnt_threshold);
  EXPECT_EQ(psr1->present.wsa_cnt_threshold_interval, psr2->present.wsa_cnt_threshold_interval);
  if (psr1->ip_service != psr2->ip_service) { return false; }
  if (psr1->present.psc != psr2->present.psc) { return false; }
  if (psr1->present.provider_mac_addr != psr2->present.provider_mac_addr) { return false; }
  if (psr1->present.rcpi_threshold != psr2->present.rcpi_threshold) { return false; }
  if (psr1->present.wsa_cnt_threshold != psr2->present.wsa_cnt_threshold) { return false; }
  if (psr1->present.wsa_cnt_threshold_interval != psr2->present.wsa_cnt_threshold_interval) { return false; }
  if (psr1->ip_service) {
    EXPECT_TRUE(CompareBytes(psr1->ipv6_address, psr2->ipv6_address, IPv6_ALEN));
    EXPECT_EQ(psr1->service_port, psr2->service_port);
    if (!CompareBytes(psr1->ipv6_address, psr2->ipv6_address, IPv6_ALEN)) { return false; }
    if (psr1->service_port != psr2->service_port) { return false; }
  }
  if (psr1->present.psc) {
    EXPECT_EQ(psr1->psc.len, psr2->psc.len);
    EXPECT_TRUE(CompareString(psr1->psc.psc, psr2->psc.psc));
    if (psr1->psc.len != psr2->psc.len) { return false; }
    if (!CompareString(psr1->psc.psc, psr2->psc.psc)) { return false; }
  }
  if (psr1->present.provider_mac_addr) {
    EXPECT_TRUE(CompareBytes(psr1->provider_mac_addr, psr2->provider_mac_addr, MAC_ALEN));
    if (memcmp(psr1->provider_mac_addr, psr2->provider_mac_addr, IPv6_ALEN) != 0) { return false; }
  }
  if (psr1->present.rcpi_threshold) {
    EXPECT_EQ(psr1->rcpi_threshold, psr2->rcpi_threshold);
    if (psr1->rcpi_threshold != psr2->rcpi_threshold) { return false; }
  }
  if (psr1->present.wsa_cnt_threshold) {
    EXPECT_EQ(psr1->wsa_cnt_threshold, psr2->wsa_cnt_threshold);
    if (psr1->wsa_cnt_threshold != psr2->wsa_cnt_threshold) { return false; }
  }
  if (psr1->present.wsa_cnt_threshold_interval) {
    EXPECT_EQ(psr1->wsa_cnt_threshold_interval, psr2->wsa_cnt_threshold_interval);
    if (psr1->wsa_cnt_threshold_interval != psr2->wsa_cnt_threshold_interval) { return false; }
  }
  return true;
}


/**
 * @brief PCI의 필수필드를 설정한다.
 */
void SetPCIMandatoryInfo(
  Dot3OperatingClass op_class,
  Dot3ChannelNumber chan_num,
  Dot3Power transmit_power_level,
  Dot3DataRate datarate,
  bool adaptable_datarate,
  struct Dot3PCI *pci)
{
  memset(pci, 0, sizeof(struct Dot3PCI));
  pci->operating_class = op_class;
  pci->chan_num = chan_num;
  pci->transmit_power_level = transmit_power_level;
  pci->datarate = datarate;
  pci->adaptable_datarate = adaptable_datarate;
}


/**
 * @brief PCI의 EDCA Parameter Set 옵션정보 내 Record를 설정한다.
 */
void SetPCIOptionalEDCAParameterSet(
  Dot3ACI aci,
  Dot3ACM acm,
  Dot3AIFSN aifsn,
  Dot3ECW ecwmin,
  Dot3ECW ecwmax,
  Dot3TXOPLimit txoplimit,
  struct Dot3PCI *pci)
{
  pci->present.edca_param_set = true;
  struct Dot3EDCAParameterRecord *record = &(pci->edca_param_set.record[aci]);
  record->aci = aci;
  record->acm = acm;
  record->aifsn = aifsn;
  record->ecwmin = ecwmin;
  record->ecwmax = ecwmax;
  record->txoplimit = txoplimit;
}


/**
 * @brief PCI의 Channel Access 옵션정보를 설정한다.
 */
void SetPCIOptionalChannelAccess(Dot3ProviderChannelAccess chan_access, struct Dot3PCI *pci)
{
  pci->present.chan_access = true;
  pci->chan_access = chan_access;
}


/**
 * @brief 두 PCI의 필수정보가 동일한지 비교한다.
 */
bool ComparePCIMandatoryInfo(struct Dot3PCI *pci1, struct Dot3PCI *pci2)
{
  EXPECT_EQ(pci1->operating_class, pci2->operating_class);
  EXPECT_EQ(pci1->chan_num, pci2->chan_num);
  EXPECT_EQ(pci1->transmit_power_level, pci2->transmit_power_level);
  EXPECT_EQ(pci1->datarate, pci2->datarate);
  EXPECT_EQ(pci1->adaptable_datarate, pci2->adaptable_datarate);
  if (pci1->operating_class != pci2->operating_class) { return false; }
  if (pci1->chan_num != pci2->chan_num) { return false; }
  if (pci1->transmit_power_level != pci2->transmit_power_level) { return false; }
  if (pci1->datarate != pci2->datarate) { return false; }
  if (pci1->adaptable_datarate != pci2->adaptable_datarate) { return false; }
  return true;
}


/**
 * @brief 두 EDCA Parameter Set 정보가 동일한지 비교한다.
 */
bool CompareEDCAParameterSet(struct Dot3EDCAParameterSet *set1, struct Dot3EDCAParameterSet *set2)
{
  Dot3EDCAParameterRecord *record1 = &(set1->record[0]);
  Dot3EDCAParameterRecord *record2 = &(set2->record[0]);
  EXPECT_EQ(record1->aci, record2->aci);
  EXPECT_EQ(record1->acm, record2->acm);
  EXPECT_EQ(record1->aifsn, record2->aifsn);
  EXPECT_EQ(record1->ecwmin, record2->ecwmin);
  EXPECT_EQ(record1->ecwmax, record2->ecwmax);
  EXPECT_EQ(record1->txoplimit, record2->txoplimit);
  if (record1->aci != record2->aci) { return false; }
  if (record1->acm != record2->acm) { return false; }
  if (record1->aifsn != record2->aifsn) { return false; }
  if (record1->ecwmin != record2->ecwmin) { return false; }
  if (record1->ecwmax != record2->ecwmax) { return false; }
  if (record1->txoplimit != record2->txoplimit) { return false; }
  record1 = &(set1->record[1]);
  record2 = &(set2->record[1]);
  EXPECT_EQ(record1->aci, record2->aci);
  EXPECT_EQ(record1->acm, record2->acm);
  EXPECT_EQ(record1->aifsn, record2->aifsn);
  EXPECT_EQ(record1->ecwmin, record2->ecwmin);
  EXPECT_EQ(record1->ecwmax, record2->ecwmax);
  EXPECT_EQ(record1->txoplimit, record2->txoplimit);
  if (record1->aci != record2->aci) { return false; }
  if (record1->acm != record2->acm) { return false; }
  if (record1->aifsn != record2->aifsn) { return false; }
  if (record1->ecwmin != record2->ecwmin) { return false; }
  if (record1->ecwmax != record2->ecwmax) { return false; }
  if (record1->txoplimit != record2->txoplimit) { return false; }
  record1 = &(set1->record[2]);
  record2 = &(set2->record[2]);
  EXPECT_EQ(record1->aci, record2->aci);
  EXPECT_EQ(record1->acm, record2->acm);
  EXPECT_EQ(record1->aifsn, record2->aifsn);
  EXPECT_EQ(record1->ecwmin, record2->ecwmin);
  EXPECT_EQ(record1->ecwmax, record2->ecwmax);
  EXPECT_EQ(record1->txoplimit, record2->txoplimit);
  if (record1->aci != record2->aci) { return false; }
  if (record1->acm != record2->acm) { return false; }
  if (record1->aifsn != record2->aifsn) { return false; }
  if (record1->ecwmin != record2->ecwmin) { return false; }
  if (record1->ecwmax != record2->ecwmax) { return false; }
  if (record1->txoplimit != record2->txoplimit) { return false; }
  record1 = &(set1->record[3]);
  record2 = &(set2->record[3]);
  EXPECT_EQ(record1->aci, record2->aci);
  EXPECT_EQ(record1->acm, record2->acm);
  EXPECT_EQ(record1->aifsn, record2->aifsn);
  EXPECT_EQ(record1->ecwmin, record2->ecwmin);
  EXPECT_EQ(record1->ecwmax, record2->ecwmax);
  EXPECT_EQ(record1->txoplimit, record2->txoplimit);
  if (record1->aci != record2->aci) { return false; }
  if (record1->acm != record2->acm) { return false; }
  if (record1->aifsn != record2->aifsn) { return false; }
  if (record1->ecwmin != record2->ecwmin) { return false; }
  if (record1->ecwmax != record2->ecwmax) { return false; }
  if (record1->txoplimit != record2->txoplimit) { return false; }
  return true;
}


/**
 * @brief 두 PCI의 EDCA Parameter Set 옵션정보가 동일한지 비교한다.
 */
bool ComparePCIOptionalEDCAParameterSet(struct Dot3PCI *pci1, struct Dot3PCI *pci2)
{
  EXPECT_EQ(pci1->present.edca_param_set, pci2->present.edca_param_set);
  if (pci1->present.edca_param_set != pci2->present.edca_param_set) { return false; }
  if (pci1->present.edca_param_set) {
    bool ret = CompareEDCAParameterSet(&(pci1->edca_param_set), &(pci2->edca_param_set));
    EXPECT_TRUE(ret);
    if (!ret) { return false; }
  }
  return true;
}


/**
 * @brief 두 PCI의 Channel Access 옵션정보가 동일한지 비교한다.
 */
bool ComparePCIOptionalChannelAccess(struct Dot3PCI *pci1, struct Dot3PCI *pci2)
{
  EXPECT_EQ(pci1->present.chan_access, pci2->present.chan_access);
  if (pci1->present.chan_access != pci2->present.chan_access) { return false; }
  if (pci1->present.chan_access) {
    EXPECT_EQ(pci1->chan_access, pci2->chan_access);
    if (pci1->chan_access != pci2->chan_access) { return false; }
  }
  return true;
}



/**
 * @brief USR의 필수정보를 설정한다.
 */
void SetUSRMandatoryInfo(Dot3PSID psid, Dot3WSAType wsa_type, struct Dot3USR *usr)
{
  memset(usr, 0, sizeof(struct Dot3USR));
  usr->psid = psid;
  usr->wsa_type = wsa_type;
}


/**
 * @brief USR의 PSC 옵션정보를 설정한다.
 */
void SetUSROptionalPSC(const char *psc, struct Dot3USR *usr)
{
  memset(usr->psc.psc, 0, sizeof(usr->psc.psc));
  usr->present.psc = true;
  usr->psc.len = strlen(psc);
  strncpy(usr->psc.psc, psc, usr->psc.len);
}


/**
 * @brief USR의 Source MAC address 옵션정보를 설정한다.
 */
void SetUSROptionalSourceMACAddress(Dot3MACAddress addr, struct Dot3USR *usr)
{
  usr->present.src_mac_addr = true;
  memcpy(usr->src_mac_addr, addr, MAC_ALEN);
}


/**
 * @brief USR의 Source MAC address 옵션정보를 설정한다.
 */
void SetUSROptionalAdvertiserID(const char *advertiser_id, struct Dot3USR *usr)
{
  memset(usr->advertiser_id.id, 0, sizeof(usr->advertiser_id.id));
  usr->present.advertiser_id = true;
  usr->advertiser_id.len = strlen(advertiser_id);
  strncpy(usr->advertiser_id.id, advertiser_id, usr->advertiser_id.len);
}


/**
 * @brief USR의 Channel Number 옵션정보를 설정한다.
 */
void SetUSROptionalChannelNumber(Dot3ChannelNumber chan_num, struct Dot3USR *usr)
{
  usr->present.chan_num = true;
  usr->chan_num = chan_num;
}


/**
 * @brief 두 USR의 필수정보를 비교한다.
 */
bool CompareUSRMandatoryInfo(struct Dot3USR *usr1, struct Dot3USR *usr2)
{
  EXPECT_EQ(usr1->psid, usr2->psid);
  EXPECT_EQ(usr1->wsa_type, usr2->wsa_type);
  if (usr1->psid != usr2->psid) { return false; }
  if (usr1->wsa_type != usr2->wsa_type) { return false; }
  return true;
}


/**
 * @brief 두 USR의 옵션정보를 비교한다.
 */
bool CompareUSROptionalInfo(struct Dot3USR *usr1, struct Dot3USR *usr2)
{
  EXPECT_EQ(usr1->present.psc, usr2->present.psc);
  EXPECT_EQ(usr1->present.src_mac_addr, usr2->present.src_mac_addr);
  EXPECT_EQ(usr1->present.advertiser_id, usr2->present.advertiser_id);
  EXPECT_EQ(usr1->present.chan_num, usr2->present.chan_num);
  if (usr1->present.psc != usr2->present.psc) { return false; }
  if (usr1->present.src_mac_addr != usr2->present.src_mac_addr) { return false; }
  if (usr1->present.advertiser_id != usr2->present.advertiser_id) { return false; }
  if (usr1->present.chan_num != usr2->present.chan_num) { return false; }
  if (usr1->present.psc) {
    EXPECT_EQ(usr1->psc.len, usr2->psc.len);
    EXPECT_TRUE(CompareString(usr1->psc.psc, usr2->psc.psc));
    if (usr1->psc.len != usr2->psc.len) { return false; }
    if (!CompareString(usr1->psc.psc, usr2->psc.psc)) { return false; }
  }
  if (usr1->present.src_mac_addr) {
    EXPECT_TRUE(CompareBytes(usr1->src_mac_addr, usr2->src_mac_addr, MAC_ALEN));
    if (memcmp(usr1->src_mac_addr, usr2->src_mac_addr, IPv6_ALEN) != 0) { return false; }
  }
  if (usr1->present.advertiser_id) {
    EXPECT_EQ(usr1->advertiser_id.len, usr2->advertiser_id.len);
    EXPECT_TRUE(CompareString(usr1->advertiser_id.id, usr2->advertiser_id.id));
    if (usr1->advertiser_id.len != usr2->advertiser_id.len) { return false; }
    if (!CompareString(usr1->advertiser_id.id, usr2->advertiser_id.id)) { return false; }
  }
  if (usr1->present.chan_num) {
    EXPECT_EQ(usr1->chan_num, usr2->chan_num);
    if (usr1->chan_num != usr2->chan_num) { return false; }
  }
  return true;
}


/**
 * @brief 각 정보가 최대값을 갖는 WSA Service Info에 대한 파싱정보가 기대값과 동일한지 체크한다.
 */
bool CheckWSIInMaxWSA(struct Dot3WSI *wsi, Dot3PSID psid, Dot3WSAChannelIndex chan_index)
{
  EXPECT_EQ(wsi->psid, psid);
  if (wsi->psid != psid) { return false; }
  EXPECT_EQ(wsi->channel_index, chan_index);
  if (wsi->channel_index != chan_index) { return false; }
  EXPECT_TRUE(wsi->extensions.psc);
  if (!(wsi->extensions.psc)) { return false; }
  EXPECT_EQ(wsi->psc.len, strlen("0123456789012345678901234567890"));
  if (wsi->psc.len != strlen("0123456789012345678901234567890")) { return false; }
  bool ret = CompareString(wsi->psc.psc, "0123456789012345678901234567890");
  EXPECT_TRUE(ret);
  if (!ret) { return false; }
  EXPECT_TRUE(wsi->extensions.ipv6_address);
  if (!(wsi->extensions.ipv6_address)) { return false; }
  ret = CompareBytes(wsi->ipv6_address, g_my_ipv6_addr, IPv6_ALEN);
  EXPECT_TRUE(ret);
  if (!ret) { return false; }
  EXPECT_TRUE(wsi->extensions.service_port);
  if (!(wsi->extensions.service_port)) { return false; }
  EXPECT_EQ(wsi->service_port, 65535);
  if (wsi->service_port != 65535) { return false; }
  EXPECT_TRUE(wsi->extensions.provider_mac_address);
  if (!(wsi->extensions.provider_mac_address)) { return false; }
  ret = CompareBytes(wsi->provider_mac_address, g_my_addr, MAC_ALEN);
  EXPECT_TRUE(ret);
  if (!ret) { return false; }
  EXPECT_TRUE(wsi->extensions.rcpi_threshold);
  if (!(wsi->extensions.rcpi_threshold)) { return false; }
  EXPECT_EQ(wsi->rcpi_threshold, kDot3RCPI_Max);
  if (wsi->rcpi_threshold != kDot3RCPI_Max) { return false; }
  EXPECT_TRUE(wsi->extensions.wsa_cnt_threshold);
  if (!(wsi->extensions.wsa_cnt_threshold)) { return false; }
  EXPECT_EQ(wsi->wsa_cnt_threshold, kDot3WSACountThreshold_Max);
  if (wsi->wsa_cnt_threshold != kDot3WSACountThreshold_Max) { return false; }
  EXPECT_TRUE(wsi->extensions.wsa_cnt_threshold_interval);
  if (!(wsi->extensions.wsa_cnt_threshold_interval)) { return false; }
  EXPECT_EQ(wsi->wsa_cnt_threshold_interval, kDot3WSACountThresholdInterval_Max);
  if (wsi->wsa_cnt_threshold_interval != kDot3WSACountThresholdInterval_Max) { return false; }

  return true;
}


/**
 * @brief 각 정보가 최대값을 갖고 모든 확장필드를 포함한 WSA Channel Info에 대한 파싱정보가 기대값과 동일한지 체크한다.
 */
bool CheckWCIInMaxWSAWithAllExtensions(
  struct Dot3WCI *wci,
  Dot3OperatingClass op_class,
  Dot3ChannelNumber chan_num,
  Dot3Power tx_power,
  Dot3DataRate datarate,
  bool adaptable)
{
  EXPECT_EQ(wci->operating_class, op_class);
  if (wci->operating_class != op_class) { return false; }
  EXPECT_EQ(wci->chan_num, chan_num);
  if (wci->chan_num != chan_num) { return false; }
  EXPECT_EQ(wci->transmit_power_level, tx_power);
  if (wci->transmit_power_level != tx_power) { return false; }
  EXPECT_EQ(wci->datarate, datarate);
  if (wci->datarate != datarate) { return false; }
  EXPECT_EQ(wci->adaptable_datarate, adaptable);
  if (wci->adaptable_datarate != adaptable) { return false; }

  EXPECT_TRUE(wci->extension.chan_access);
  if (!(wci->extension.chan_access)) { return false; }
  EXPECT_EQ(wci->chan_access, kDot3ProviderChannelAccess_AlternatingTimeSlot0Only);
  if (wci->chan_access != kDot3ProviderChannelAccess_AlternatingTimeSlot0Only) { return false; }
  EXPECT_TRUE(wci->extension.edca_param_set);
  if (!(wci->extension.edca_param_set)) { return false; }
  for (unsigned int i = 0; i < kDot3ACI_Max + 1; i++) {
    EXPECT_EQ(wci->edca_param_set.record[i].aci, i);
    EXPECT_FALSE(wci->edca_param_set.record[i].acm);
    EXPECT_EQ(wci->edca_param_set.record[i].aifsn, kDot3AIFSN_Max);
    EXPECT_EQ(wci->edca_param_set.record[i].ecwmin, kDot3ECW_Max);
    EXPECT_EQ(wci->edca_param_set.record[i].ecwmax, kDot3ECW_Max);
    EXPECT_EQ(wci->edca_param_set.record[i].txoplimit, kDot3TXOPLimit_Max);
    if (wci->edca_param_set.record[i].aci != i) { return false; }
    if (wci->edca_param_set.record[i].acm) { return false; }
    if (wci->edca_param_set.record[i].aifsn != kDot3AIFSN_Max) { return false; }
    if (wci->edca_param_set.record[i].ecwmin != kDot3ECW_Max) { return false; }
    if (wci->edca_param_set.record[i].ecwmax != kDot3ECW_Max) { return false; }
    if (wci->edca_param_set.record[i].txoplimit != kDot3TXOPLimit_Max) { return false; }
  }
  return true;
}


/**
 * @brief WRA 정보를 체크한다.
 */
bool CheckWRA(
  struct Dot3WRA *wra,
  Dot3WRARouterLifetime router_lifetime,
  const Dot3IPv6Address ip_prefix,
  Dot3IPv6PrefixLen ip_prefix_len,
  const Dot3IPv6Address default_gw,
  const Dot3IPv6Address primary_dns,
  bool secondary_dns_present,
  const Dot3IPv6Address secondary_dns,
  bool gateway_mac_addr_present,
  const Dot3MACAddress gateway_mac_addr)
{
  EXPECT_EQ(wra->router_lifetime, router_lifetime);
  EXPECT_TRUE(CompareBytes(wra->ip_prefix, ip_prefix, IPv6_ALEN));
  EXPECT_EQ(wra->ip_prefix_len, ip_prefix_len);
  EXPECT_TRUE(CompareBytes(wra->default_gw, default_gw, IPv6_ALEN));
  EXPECT_TRUE(CompareBytes(wra->primary_dns, primary_dns, IPv6_ALEN));
  EXPECT_EQ(wra->present.secondary_dns, secondary_dns_present);
  if (wra->present.secondary_dns) {
    EXPECT_TRUE(CompareBytes(wra->secondary_dns, secondary_dns, IPv6_ALEN));
  }
  EXPECT_EQ(wra->present.gateway_mac_addr, gateway_mac_addr_present);
  if (wra->present.gateway_mac_addr) {
    EXPECT_TRUE(CompareBytes(wra->gateway_mac_addr, gateway_mac_addr, MAC_ALEN));
  }
  if (wra->router_lifetime != router_lifetime) { return false; }
  if (!CompareBytes(wra->ip_prefix, ip_prefix, IPv6_ALEN)) { return false; }
  if (wra->ip_prefix_len != ip_prefix_len) { return false; }
  if (!CompareBytes(wra->default_gw, default_gw, IPv6_ALEN)) { return false; }
  if (!CompareBytes(wra->primary_dns, primary_dns, IPv6_ALEN)) { return false; }
  if (wra->present.secondary_dns != secondary_dns_present) { return false; }
  if (wra->present.secondary_dns) {
    if (!CompareBytes(wra->secondary_dns, secondary_dns, IPv6_ALEN)) { return false; }
  }
  if (wra->present.gateway_mac_addr != gateway_mac_addr_present) { return false; }
  if (wra->present.gateway_mac_addr) {
    if (!CompareBytes(wra->gateway_mac_addr, gateway_mac_addr, MAC_ALEN)) { return false; }
  }
  return true;
}


/**
 * @brief UAS 내 필수정보를 체크한다.
 */
bool CheckUASMandatoryInfo(
  struct Dot3UAS *uas,
  const Dot3MACAddress src_mac_addr,
  Dot3WSAType wsa_type,
  Dot3RCPI rcpi,
  bool available,
  Dot3WSAIdentifier wsa_id,
  Dot3PSID psid,
  Dot3OperatingClass operating_class,
  Dot3ChannelNumber chan_num,
  Dot3Power transmit_power_level,
  Dot3DataRate datarate,
  bool adaptable_datarate)
{
  EXPECT_TRUE(CompareBytes(uas->src_mac_addr, src_mac_addr, MAC_ALEN));
  EXPECT_EQ(uas->wsa_type, wsa_type);
  EXPECT_EQ(uas->rcpi, rcpi);
  EXPECT_EQ(uas->available, available);
  EXPECT_EQ(uas->wsa_id, wsa_id);
  EXPECT_EQ(uas->psid, psid);
  EXPECT_EQ(uas->operating_class, operating_class);
  EXPECT_EQ(uas->chan_num, chan_num);
  EXPECT_EQ(uas->transmit_power_level, transmit_power_level);
  EXPECT_EQ(uas->datarate, datarate);
  EXPECT_EQ(uas->adaptable_datarate, adaptable_datarate);
  if (!CompareBytes(uas->src_mac_addr, src_mac_addr, MAC_ALEN)) { return false; }
  if (uas->wsa_type != wsa_type) { return false; }
  if (uas->rcpi != rcpi) { return false; }
  if (uas->available != available) { return false; }
  if (uas->wsa_id != wsa_id) { return false; }
  if (uas->psid != psid) { return false; }
  if (uas->operating_class != operating_class) { return false; }
  if (uas->chan_num != chan_num) { return false; }
  if (uas->transmit_power_level != transmit_power_level) { return false; }
  if (uas->adaptable_datarate != adaptable_datarate) { return false; }
  return true;
}


/**
 * @brief UAS 내 옵션정보를 체크한다.
 */
bool CheckUASOptionalInfo(
  struct Dot3UAS *uas,
  bool advertiser_id_present,
  bool psc_present,
  bool ipv6_address_present,
  bool service_port_present,
  bool provider_mac_address_present,
  bool rcpi_threshold_present,
  bool wsa_cnt_threshold_present,
  bool wsa_cnt_threshold_interval_present,
  bool edca_param_set_present,
  bool chan_access_present,
  bool wra_present,
  Dot3Latitude tx_lat,
  Dot3Longitude tx_lon,
  Dot3Elevation tx_elev,
  struct Dot3WSAAdvertiserID *advertiser_id,
  struct Dot3PSC *psc,
  Dot3IPv6Address ipv6_address,
  uint16_t service_port,
  Dot3MACAddress provider_mac_address,
  Dot3RCPI rcpi_threshold,
  Dot3WSACountThreshold wsa_cnt_threshold,
  Dot3WSACountThresholdInterval wsa_cnt_threshold_interval,
  struct Dot3EDCAParameterSet *edca_param_set,
  Dot3ProviderChannelAccess chan_access,
  struct Dot3WRA *wra)
{
  EXPECT_EQ(uas->present.advertiser_id, advertiser_id_present);
  EXPECT_EQ(uas->present.psc, psc_present);
  EXPECT_EQ(uas->present.ipv6_address, ipv6_address_present);
  EXPECT_EQ(uas->present.service_port, service_port_present);
  EXPECT_EQ(uas->present.provider_mac_address, provider_mac_address_present);
  EXPECT_EQ(uas->present.rcpi_threshold, rcpi_threshold_present);
  EXPECT_EQ(uas->present.wsa_cnt_threshold, wsa_cnt_threshold_present);
  EXPECT_EQ(uas->present.wsa_cnt_threshold_interval, wsa_cnt_threshold_interval_present);
  EXPECT_EQ(uas->present.edca_param_set, edca_param_set_present);
  EXPECT_EQ(uas->present.chan_access, chan_access_present);
  EXPECT_EQ(uas->present.wra, wra_present);
  if (uas->present.advertiser_id != advertiser_id_present) { return false; }
  if (uas->present.psc != psc_present) { return false; }
  if (uas->present.ipv6_address != ipv6_address_present) { return false; }
  if (uas->present.service_port != service_port_present) { return false; }
  if (uas->present.provider_mac_address != provider_mac_address_present) { return false; }
  if (uas->present.rcpi_threshold != rcpi_threshold_present) { return false; }
  if (uas->present.wsa_cnt_threshold != wsa_cnt_threshold_present) { return false; }
  if (uas->present.wsa_cnt_threshold_interval != wsa_cnt_threshold_interval_present) { return false; }
  if (uas->present.edca_param_set != edca_param_set_present) { return false; }
  if (uas->present.chan_access != chan_access_present) { return false; }
  if (uas->present.wra != wra_present) { return false; }
  EXPECT_EQ(uas->tx_lat, tx_lat);
  if (uas->tx_lat != tx_lat) { return false; }
  EXPECT_EQ(uas->tx_lon, tx_lon);
  if (uas->tx_lon != tx_lon) { return false; }
  EXPECT_EQ(uas->tx_elev, tx_elev);
  if (uas->tx_elev != tx_elev) { return false; }
  if (uas->present.advertiser_id) {
    EXPECT_EQ(uas->advertiser_id.len, advertiser_id->len);
    EXPECT_TRUE(CompareString(uas->advertiser_id.id, advertiser_id->id));
    if (uas->advertiser_id.len != advertiser_id->len) { return false; }
    if (!CompareString(uas->advertiser_id.id, advertiser_id->id)) { return false; }
  }
  if (uas->present.psc) {
    EXPECT_EQ(uas->psc.len, psc->len);
    EXPECT_TRUE(CompareString(uas->psc.psc, psc->psc));
    if (uas->psc.len != psc->len) { return false; }
    if (!CompareString(uas->psc.psc, psc->psc)) { return false; }
  }
  if (uas->present.ipv6_address) {
    EXPECT_TRUE(CompareBytes(uas->ipv6_address, ipv6_address, IPv6_ALEN));
    if (!CompareBytes(uas->ipv6_address, ipv6_address, IPv6_ALEN)) { return false; }
  }
  if (uas->present.service_port) {
    EXPECT_EQ(uas->service_port, service_port);
    if (uas->service_port != service_port) { return false; }
  }
  if (uas->present.provider_mac_address) {
    EXPECT_TRUE(CompareBytes(uas->provider_mac_address, provider_mac_address, MAC_ALEN));
    if (!CompareBytes(uas->provider_mac_address, provider_mac_address, MAC_ALEN)) { return false; }
  }
  if (uas->present.rcpi_threshold) {
    EXPECT_EQ(uas->rcpi_threshold, rcpi_threshold);
    if (uas->rcpi_threshold != rcpi_threshold) { return false; }
  }
  if (uas->present.wsa_cnt_threshold) {
    EXPECT_EQ(uas->wsa_cnt_threshold, wsa_cnt_threshold);
    if (uas->wsa_cnt_threshold != wsa_cnt_threshold) { return false; }
  }
  if (uas->present.wsa_cnt_threshold_interval) {
    EXPECT_EQ(uas->wsa_cnt_threshold_interval, wsa_cnt_threshold_interval);
    if (uas->wsa_cnt_threshold_interval != wsa_cnt_threshold_interval) { return false; }
  }
  if (uas->present.edca_param_set) {
    bool ret = CompareEDCAParameterSet(&(uas->edca_param_set), edca_param_set);
    EXPECT_TRUE(ret);
    if (!ret) { return false; }
  }
  if (uas->present.chan_access) {
    EXPECT_EQ(uas->chan_access, chan_access);
    if (uas->chan_access != chan_access) { return false; }
  }
  if (uas->present.wra) {
    bool ret = CheckWRA(&(uas->wra),
                        wra->router_lifetime,
                        wra->ip_prefix,
                        wra->ip_prefix_len,
                        wra->default_gw,
                        wra->primary_dns,
                        wra->present.secondary_dns,
                        wra->secondary_dns,
                        wra->present.gateway_mac_addr,
                        wra->gateway_mac_addr);
    EXPECT_TRUE(ret);
    if (!ret) { return false; }
  }
  return true;
}


/**
 * @brief 두 바이트열이 동일한지 비교한다.
 */
bool CompareBytes(const uint8_t *bytes1, const uint8_t *bytes2, size_t len)
{
#if 0
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(bytes1 + i));
  }
  printf("\n");
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(bytes2 + i));
  }
  printf("\n");
#endif
  return (memcmp(bytes1, bytes2, len) == 0);
}


/**
 * @brief 두 문자열이 동일한지 비교한다.
 */
bool CompareString(const char *str1, const char *str2)
{
  return (strcmp(str1, str2) == 0);
}
