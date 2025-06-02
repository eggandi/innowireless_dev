/** 
 * @file
 * @brief dot3 라이브러리 단위테스트 메인 헤더 파일
 * @date 2020-07-14
 * @author gyun
 */


#ifndef V2X_SW_TEST_LIBDOT3_H
#define V2X_SW_TEST_LIBDOT3_H

void InitTestEnv();
void ReleaseTestEnv();
void SetPSRMandatoryInfo(
  Dot3WSAIdentifier wsa_id,
  Dot3PSID psid,
  Dot3ChannelNumber service_chan_num,
  struct Dot3PSR *psr);
void SetPSROptionalPSC(const char *psc, struct Dot3PSR *psr);
void SetPSROptionalIPService(Dot3IPv6Address ip_addr, uint16_t service_port, struct Dot3PSR *psr);
void SetPSROptionalProviderMACAddress(Dot3MACAddress addr, struct Dot3PSR *psr);
void SetPSROptionalRCPIThreshold(Dot3RCPI threshold, struct Dot3PSR *psr);
void SetPSROptionalWSACountThreshold(Dot3WSACountThreshold threshold, struct Dot3PSR *psr);
void SetPSROptionalWSACountThresholdInterval(Dot3WSACountThresholdInterval interval, struct Dot3PSR *psr);
bool ComparePSRMandatoryInfo(struct Dot3PSR *psr1, struct Dot3PSR *psr2);
bool ComparePSROptionalInfo(struct Dot3PSR *psr1, struct Dot3PSR *psr2);
void SetPCIMandatoryInfo(
  Dot3OperatingClass op_class,
  Dot3ChannelNumber chan_num,
  Dot3Power transmit_power_level,
  Dot3DataRate datarate,
  bool adaptable_datarate,
  struct Dot3PCI *pci);
void SetPCIOptionalEDCAParameterSet(
  Dot3ACI aci,
  Dot3ACM acm,
  Dot3AIFSN aifsn,
  Dot3ECW ecwmin,
  Dot3ECW ecwmax,
  Dot3TXOPLimit txoplimit,
  struct Dot3PCI *pci);
void SetPCIOptionalChannelAccess(Dot3ProviderChannelAccess chan_access, struct Dot3PCI *pci);
bool ComparePCIMandatoryInfo(struct Dot3PCI *pci1, struct Dot3PCI *pci2);
bool CompareEDCAParameterSet(struct Dot3EDCAParameterSet *set1, struct Dot3EDCAParameterSet *set2);
bool ComparePCIOptionalEDCAParameterSet(struct Dot3PCI *pci1, struct Dot3PCI *pci2);
bool ComparePCIOptionalChannelAccess(struct Dot3PCI *pci1, struct Dot3PCI *pci2);

void SetUSRMandatoryInfo(Dot3PSID psid, Dot3WSAType wsa_type, struct Dot3USR *usr);
void SetUSROptionalPSC(const char *psc, struct Dot3USR *usr);
void SetUSROptionalSourceMACAddress(Dot3MACAddress addr, struct Dot3USR *usr);
void SetUSROptionalAdvertiserID(const char *advertiser_id, struct Dot3USR *usr);
void SetUSROptionalChannelNumber(Dot3ChannelNumber chan_num, struct Dot3USR *usr);
bool CompareUSRMandatoryInfo(struct Dot3USR *usr1, struct Dot3USR *usr2);
bool CompareUSROptionalInfo(struct Dot3USR *usr1, struct Dot3USR *usr2);
bool CheckWSIInMaxWSA(struct Dot3WSI *wsi, Dot3PSID psid, Dot3WSAChannelIndex chan_index);
bool CheckWCIInMaxWSAWithAllExtensions(
  struct Dot3WCI *wci,
  Dot3OperatingClass op_class,
  Dot3ChannelNumber chan_num,
  Dot3Power tx_power,
  Dot3DataRate datarate,
  bool adaptable);
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
  const Dot3MACAddress gateway_mac_addr);
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
  bool adaptable_datarate);
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
  struct Dot3WRA *wra);

bool CompareBytes(const uint8_t *bytes1, const uint8_t *bytes2, size_t len);
bool CompareString(const char *str1, const char *str2);

extern uint8_t g_bcast_addr[MAC_ALEN];
extern uint8_t g_ucast_addr[MAC_ALEN];
extern uint8_t g_my_addr[MAC_ALEN];
extern uint8_t g_my_ipv6_addr[IPv6_ALEN];
extern uint8_t g_min_size_wsm_with_no_ext_hdr[kDot3WSMHdrSize_Min];
extern size_t g_min_size_wsm_with_no_ext_hdr_size;
extern uint8_t g_min_size_wsm_with_chan_num_ext_hdr[kDot3WSMHdrSize_Min + 4];
extern size_t g_min_size_wsm_with_chan_num_ext_hdr_size;
extern uint8_t g_min_size_wsm_with_datarate_ext_hdr[kDot3WSMHdrSize_Min + 4];
extern size_t g_min_size_wsm_with_datarate_ext_hdr_size;
extern uint8_t g_min_size_wsm_with_tx_power_ext_hdr[kDot3WSMHdrSize_Min + 4];
extern size_t g_min_size_wsm_with_tx_power_ext_hdr_size;
extern uint8_t g_min_size_wsm_with_max_hdr[kDot3WSMHdrSize_Min + (4 * 3) + 1];
extern size_t g_min_size_wsm_with_max_hdr_size;
extern uint8_t g_1400_bytes_wsm_with_no_ext_hdr[kDot3WSMSize_DefaultMaxInMIB];
extern size_t g_1400_bytes_wsm_with_no_ext_hdr_size;
extern uint8_t g_1400_bytes_wsm_with_max_hdr[kDot3WSMSize_DefaultMaxInMIB];
extern size_t g_1400_bytes_wsm_with_max_hdr_size;
extern uint8_t g_max_size_wsm_with_max_hdr[kDot3WSMSize_Max];
extern size_t g_max_size_wsm_with_max_hdr_size;
extern uint8_t g_min_size_wsm_with_1byte_psid[];
extern size_t g_min_size_wsm_with_1byte_psid_size;
extern uint8_t g_min_size_wsm_with_2bytes_psid[];
extern size_t g_min_size_wsm_with_2bytes_psid_size;
extern uint8_t g_min_size_wsm_with_3bytes_psid[];
extern size_t g_min_size_wsm_with_3bytes_psid_size;
extern uint8_t g_min_size_wsm_with_4bytes_psid[];
extern size_t g_min_size_wsm_with_4bytes_psid_size;

extern uint8_t g_min_size_wsm_mpdu_with_no_ext_hdr[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_Min];
extern size_t g_min_size_wsm_mpdu_with_no_ext_hdr_size;
extern uint8_t g_min_size_wsm_mpdu_with_chan_num_ext_hdr[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_Min + 4];
extern size_t g_min_size_wsm_mpdu_with_chan_num_ext_hdr_size;
extern uint8_t g_min_size_wsm_mpdu_with_datarate_ext_hdr[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_Min + 4];
extern size_t g_min_size_wsm_mpdu_with_datarate_ext_hdr_size;
extern uint8_t g_min_size_wsm_mpdu_with_tx_power_ext_hdr[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_Min + 4];
extern size_t g_min_size_wsm_mpdu_with_tx_power_ext_hdr_size;
extern uint8_t g_min_size_wsm_mpdu_with_max_hdr[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMHdrSize_Max - 1];
extern size_t g_min_size_wsm_mpdu_with_max_hdr_size;
extern uint8_t g_1400_bytes_wsm_mpdu_with_no_ext_hdr[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_DefaultMaxInMIB];
extern size_t g_1400_bytes_wsm_mpdu_with_no_ext_hdr_size;
extern uint8_t g_1400_bytes_wsm_mpdu_with_max_hdr[MAC_QOS_HLEN + LLC_HLEN + kDot3WSMSize_DefaultMaxInMIB];
extern size_t g_1400_bytes_wsm_mpdu_with_max_hdr_size;
extern uint8_t g_max_size_wsm_mpdu_with_max_hdr[kDot3MPDUSize_Max];
extern size_t g_max_size_wsm_mpdu_with_max_hdr_size;

extern uint8_t g_min_wsa_with_no_ext[11];
extern size_t g_min_wsa_with_no_ext_size;
extern uint8_t g_min_wsa_with_2d_location[22];
extern size_t g_min_wsa_with_2d_location_size;
extern uint8_t g_min_wsa_with_3d_location[24];
extern size_t g_min_wsa_with_3d_location_size;
extern uint8_t g_min_wsa_with_rcpi_threshold_10[16];
extern size_t g_min_wsa_with_rcpi_threshold_10_size;
extern uint8_t g_min_wsa_with_some_ext[];
extern size_t g_min_wsa_with_some_ext_size;
extern uint8_t g_max_wsa_with_all_ext[967];
extern size_t g_max_wsa_with_all_ext_size;

#endif //V2X_SW_TEST_LIBDOT3_H
