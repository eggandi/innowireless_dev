
/**
 * @file
 * @brief 단위테스트에 사용되는 샘플 WSA
 * @date 2020-08-01
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdint.h>

// 라이브러리 헤더파일
#include "dot3-2016/dot3.h"

/*
 * Header: 최소값, 확장필드 없음
 * Service Info: 1, 최소값, 확장필드 없음
 * Channel Info: 1, 최소값, 확장필드 없음
   msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_min_wsa_with_no_ext[11] = {
  0x36, 0x00, 0x01, 0x00, 0x08, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_min_wsa_with_no_ext_size = sizeof(g_min_wsa_with_no_ext);


/*
 * Header: 최소값, 2DLocation 확장필드
 * Service Info: 1, 최소값, 확장필드 없음
 * Channel Info: 1, 최소값, 확장필드 없음
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      extensions {
        { extensionId 5 value TwoDLocation : { latitude { fill '0'B lat -900000000 } longitude -1799999999 } }
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_min_wsa_with_2d_location[22] = {
  0x3E, 0x00, 0x01, 0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
  0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_min_wsa_with_2d_location_size = sizeof(g_min_wsa_with_2d_location);

/*
 * Header: 최소값, 3DLocation 확장필드
 * Service Info: 1, 최소값, 확장필드 없음
 * Channel Info: 1, 최소값, 확장필드 없음
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      extensions {
        { extensionId 6 value ThreeDLocation: { latitude { fill '0'B lat -900000000 } longitude -1799999999 elevation -4095 } }
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_min_wsa_with_3d_location[24] = {
  0x3E, 0x00, 0x01, 0x06, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
  0x00, 0x08, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_min_wsa_with_3d_location_size = sizeof(g_min_wsa_with_3d_location);


/*
  동일한 Channel Info 정보를 사용하는 Service Info들을 포함하는 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 1
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
        { serviceID content 1 channelIndex 1 chOptions {} }
        { serviceID content 2 channelIndex 1 chOptions {} }
        { serviceID content 3 channelIndex 2 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
        { operatingClass 18 channelNumber 175 powerLevel -127 dataRate { adaptable '1'B dataRate 24 } extensions {} }
      }
    }
  }
 */
uint8_t g_wsa_with_serv_infos_sharing_chan_info[] = {
  0x36, 0x10, 0x04, 0x00, 0x08, 0x01, 0x08, 0x02, 0x08, 0x03, 0x10, 0x02, 0x11, 0xAC, 0x00, 0x06,
  0x00, 0x12, 0xAF, 0x01, 0x98, 0x00
};
size_t g_wsa_with_serv_infos_sharing_chan_info_size = sizeof(g_wsa_with_serv_infos_sharing_chan_info);

/*
  Channel Info는 없고 Service Info만 포함하는 WSA (이는 잘못된 형식의 WSA로써, 이러한 WSA에 대한 라이브러리의 대처를 확인한다)
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 1
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 0 chOptions {} }
        { serviceID content 1 channelIndex 1 chOptions {} }
        { serviceID content 2 channelIndex 3 chOptions {} }
        { serviceID content 3 channelIndex 2 chOptions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_no_chan_info[] = {
  0x34, 0x10, 0x04, 0x00, 0x00, 0x01, 0x08, 0x02, 0x18, 0x03, 0x10
};
size_t g_abnormal_wsa_with_no_chan_info_size = sizeof(g_abnormal_wsa_with_no_chan_info);


/*
  잘못된 Channel Index 값을 갖는 Service Info를 포함하는 WSA
  (이는 잘못된 형식의 WSA로써, 이러한 WSA에 대한 라이브러리의 대처를 확인한다)
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 1
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 0 chOptions {} }
        { serviceID content 1 channelIndex 1 chOptions {} }
        { serviceID content 2 channelIndex 3 chOptions {} }
        { serviceID content 3 channelIndex 2 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
        { operatingClass 18 channelNumber 175 powerLevel -127 dataRate { adaptable '1'B dataRate 24 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_serv_info_with_invalid_chan_idx[] = {
  0x36, 0x10, 0x04, 0x00, 0x00, 0x01, 0x08, 0x02, 0x18, 0x03, 0x10, 0x02, 0x11, 0xAC, 0x00, 0x06,
  0x00, 0x12, 0xAF, 0x01, 0x98, 0x00
};
size_t g_abnormal_wsa_with_serv_info_with_invalid_chan_idx_size = sizeof(g_abnormal_wsa_with_serv_info_with_invalid_chan_idx);


/*
  Service Info는 포함하지 않고 Channel Info만 포함하는 WSA
  (이는 잘못된 형식은 아니다. 다만 실제 서비스 제공 측면에서 별다른 의미를 가지지 못한다)
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 1
        contentCount 0
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
        { operatingClass 18 channelNumber 175 powerLevel -127 dataRate { adaptable '1'B dataRate 24 } extensions {} }
      }
    }
  }
 */
uint8_t g_wsa_with_no_serv_info[] = {
  0x32, 0x10, 0x02, 0x11, 0xAC, 0x00, 0x06, 0x00, 0x12, 0xAF, 0x01, 0x98, 0x00
};
size_t g_wsa_with_no_serv_info_size = sizeof(g_wsa_with_no_serv_info);


/*
  헤더 내 RCPI threshold 확장정보를 가진 1개의 Service Info, Channel Info를 포함한 WSA
  또한 모든 값을 최소값으로 설정함.
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1 -- 172
          chOptions {
            extensions {
              { extensionId 19 value RcpiThreshold : 10 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_min_wsa_with_rcpi_threshold_10[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x01, 0x13, 0x01, 0x0A, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_min_wsa_with_rcpi_threshold_10_size = sizeof(g_min_wsa_with_rcpi_threshold_10);

/*
  헤더 내 모든 확장필드와 WRA(및 모든 확장필드)를 포함한 WSA (Service Info, Channel Info의 확장필드는 불포함)
  또한 모든 값을 최소값으로 설정함.
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      extensions {
        { extensionId 17 value RepeatRate : 0 }
        { extensionId 5 value TwoDLocation : { latitude { fill '0'B lat -900000000 } longitude -1799999999 } }
        { extensionId 6 value ThreeDLocation: { latitude { fill '0'B lat -900000000 } longitude -1799999999 elevation -4095 } }
        { extensionId 7 value AdvertiserIdentifier: "0" }
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
      routingAdvertisement {
        lifetime 1
        ipPrefix '000102030405060708090a0b0c0d0e0f'H
        ipPrefixLength 1
        defaultGateway '000102030405060708090a0b0c0d0e0f'H
        primaryDns '000102030405060708090a0b0c0d0e0f'H
        extensions {
          { extensionId 13 value SecondaryDns : '000102030405060708090a0b0c0d0e0f'H }
          { extensionId 14 value GatewayMacAddress : '000102030405'H }
        }
      }
    }
  }
 */
uint8_t g_min_wsa_with_some_ext[119] = {
  0x3F, 0x00, 0x04, 0x11, 0x01, 0x00, 0x05, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x06, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x02, 0x01, 0x30,
  0x01, 0x00, 0x08, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x02, 0x0D, 0x10, 0x00,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0E,
  0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
};
size_t g_min_wsa_with_some_ext_size = sizeof(g_min_wsa_with_some_ext);

/*
   모든 확장필드를 포함한 WSA.
   또한 모든 값을 최대값으로 설정함.

   msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 15
        contentCount 15
      }
      extensions {
        { extensionId 17 value RepeatRate : 255 }
        { extensionId 5 value TwoDLocation : { latitude { fill '0'B lat 900000000 } longitude 1800000000 } }
        { extensionId 6 value ThreeDLocation: { latitude { fill '0'B lat 900000000 } longitude 1800000000 elevation 61439 } }
        { extensionId 7 value AdvertiserIdentifier: "01234567890123456789012345678901" }
      }
      serviceInfos {
        { serviceID content 15
          channelIndex 1 -- 174
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
        { serviceID content 31
          channelIndex 2 -- 177
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
        { serviceID content 47
          channelIndex 3 -- 180
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
        { serviceID content 63
          channelIndex 4 -- 183
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
        { serviceID content 79
          channelIndex 5 -- 173
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
        { serviceID content 95
          channelIndex 6 -- 176
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
        { serviceID content 111
          channelIndex 7 -- 179
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
        { serviceID content 127
          channelIndex 8 -- 182
          chOptions {
            extensions {
              { extensionId 8 value ProviderServiceContext : { fillBit '000'B psc '30313233343536373839303132333435363738393031323334353637383930'H } }
              { extensionId 9 value IPv6Address : '000102030405060708090a0b0c0d0e0f'H }
              { extensionId 10 value ServicePort : 65535 }
              { extensionId 11 value ProviderMacAddress : '000102030405'H }
              { extensionId 19 value RcpiThreshold : 220 }
              { extensionId 20 value WsaCountThreshold : 255 }
              { extensionId 22 value WsaCountThresholdInterval : 255 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
        { operatingClass 18 channelNumber 177 powerLevel 127 dataRate { adaptable '1'B dataRate 108 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
        { operatingClass 17 channelNumber 180 powerLevel 127 dataRate { adaptable '1'B dataRate 54 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
        { operatingClass 18 channelNumber 183 powerLevel 127 dataRate { adaptable '1'B dataRate 108 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
        { operatingClass 18 channelNumber 173 powerLevel 127 dataRate { adaptable '1'B dataRate 108 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
        { operatingClass 17 channelNumber 176 powerLevel 127 dataRate { adaptable '1'B dataRate 54 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
        { operatingClass 18 channelNumber 179 powerLevel 127 dataRate { adaptable '1'B dataRate 108 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
        { operatingClass 17 channelNumber 182 powerLevel 127 dataRate { adaptable '1'B dataRate 54 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:alternatingCCH }
              { extensionId 12 value EdcaParameterSet : {
                  acbeRecord { res 0 aci 0 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acbkRecord { res 0 aci 1 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acviRecord { res 0 aci 2 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                  acvoRecord { res 0 aci 3 acm 0 aifsn 15 ecwMax 15 ecwMin 15 txopLimit 65535 }
                }
              }
            }
          }
        }
      }
      routingAdvertisement {
        lifetime 65535
        ipPrefix '000102030405060708090a0b0c0d0e0f'H
        ipPrefixLength 128
        defaultGateway '000102030405060708090a0b0c0d0e0f'H
        primaryDns '000102030405060708090a0b0c0d0e0f'H
        extensions {
          { extensionId 13 value SecondaryDns : '000102030405060708090a0b0c0d0e0f'H }
          { extensionId 14 value GatewayMacAddress : '000102030405'H }
        }
      }
    }
  }
 */
uint8_t g_max_wsa_with_all_ext[967] = {
  0x3F, 0xFF, 0x04, 0x11, 0x01, 0xFF, 0x05, 0x08, 0x6B, 0x49, 0xD2, 0x00, 0xD6, 0x93, 0xA3, 0xFF,
  0x06, 0x0A, 0x6B, 0x49, 0xD2, 0x00, 0xD6, 0x93, 0xA3, 0xFF, 0xFF, 0xFF, 0x07, 0x21, 0x20, 0x30,
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x08,
  0x0F, 0x09, 0x07, 0x08, 0x20, 0x1F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39, 0x30, 0x09, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A, 0x02, 0xFF, 0xFF, 0x0B, 0x06, 0x00, 0x01, 0x02,
  0x03, 0x04, 0x05, 0x13, 0x01, 0xDC, 0x14, 0x01, 0xFF, 0x16, 0x01, 0xFF, 0x1F, 0x11, 0x07, 0x08,
  0x20, 0x1F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  0x30, 0x09, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
  0x0D, 0x0E, 0x0F, 0x0A, 0x02, 0xFF, 0xFF, 0x0B, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x13,
  0x01, 0xDC, 0x14, 0x01, 0xFF, 0x16, 0x01, 0xFF, 0x2F, 0x19, 0x07, 0x08, 0x20, 0x1F, 0x30, 0x31,
  0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x09, 0x10, 0x00,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A,
  0x02, 0xFF, 0xFF, 0x0B, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x13, 0x01, 0xDC, 0x14, 0x01,
  0xFF, 0x16, 0x01, 0xFF, 0x3F, 0x21, 0x07, 0x08, 0x20, 0x1F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
  0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x09, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A, 0x02, 0xFF, 0xFF, 0x0B,
  0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x13, 0x01, 0xDC, 0x14, 0x01, 0xFF, 0x16, 0x01, 0xFF,
  0x4F, 0x29, 0x07, 0x08, 0x20, 0x1F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39, 0x30, 0x09, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A, 0x02, 0xFF, 0xFF, 0x0B, 0x06, 0x00, 0x01, 0x02,
  0x03, 0x04, 0x05, 0x13, 0x01, 0xDC, 0x14, 0x01, 0xFF, 0x16, 0x01, 0xFF, 0x5F, 0x31, 0x07, 0x08,
  0x20, 0x1F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  0x30, 0x09, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
  0x0D, 0x0E, 0x0F, 0x0A, 0x02, 0xFF, 0xFF, 0x0B, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x13,
  0x01, 0xDC, 0x14, 0x01, 0xFF, 0x16, 0x01, 0xFF, 0x6F, 0x39, 0x07, 0x08, 0x20, 0x1F, 0x30, 0x31,
  0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x09, 0x10, 0x00,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A,
  0x02, 0xFF, 0xFF, 0x0B, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x13, 0x01, 0xDC, 0x14, 0x01,
  0xFF, 0x16, 0x01, 0xFF, 0x7F, 0x41, 0x07, 0x08, 0x20, 0x1F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
  0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x09, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A, 0x02, 0xFF, 0xFF, 0x0B,
  0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x13, 0x01, 0xDC, 0x14, 0x01, 0xFF, 0x16, 0x01, 0xFF,
  0x08, 0x11, 0xAE, 0xFF, 0xB6, 0x01, 0x02, 0x15, 0x01, 0x02, 0x0C, 0x10, 0x0F, 0xFF, 0xFF, 0xFF,
  0x2F, 0xFF, 0xFF, 0xFF, 0x4F, 0xFF, 0xFF, 0xFF, 0x6F, 0xFF, 0xFF, 0xFF, 0x12, 0xB1, 0xFF, 0xEC,
  0x01, 0x02, 0x15, 0x01, 0x02, 0x0C, 0x10, 0x0F, 0xFF, 0xFF, 0xFF, 0x2F, 0xFF, 0xFF, 0xFF, 0x4F,
  0xFF, 0xFF, 0xFF, 0x6F, 0xFF, 0xFF, 0xFF, 0x11, 0xB4, 0xFF, 0xB6, 0x01, 0x02, 0x15, 0x01, 0x02,
  0x0C, 0x10, 0x0F, 0xFF, 0xFF, 0xFF, 0x2F, 0xFF, 0xFF, 0xFF, 0x4F, 0xFF, 0xFF, 0xFF, 0x6F, 0xFF,
  0xFF, 0xFF, 0x12, 0xB7, 0xFF, 0xEC, 0x01, 0x02, 0x15, 0x01, 0x02, 0x0C, 0x10, 0x0F, 0xFF, 0xFF,
  0xFF, 0x2F, 0xFF, 0xFF, 0xFF, 0x4F, 0xFF, 0xFF, 0xFF, 0x6F, 0xFF, 0xFF, 0xFF, 0x12, 0xAD, 0xFF,
  0xEC, 0x01, 0x02, 0x15, 0x01, 0x02, 0x0C, 0x10, 0x0F, 0xFF, 0xFF, 0xFF, 0x2F, 0xFF, 0xFF, 0xFF,
  0x4F, 0xFF, 0xFF, 0xFF, 0x6F, 0xFF, 0xFF, 0xFF, 0x11, 0xB0, 0xFF, 0xB6, 0x01, 0x02, 0x15, 0x01,
  0x02, 0x0C, 0x10, 0x0F, 0xFF, 0xFF, 0xFF, 0x2F, 0xFF, 0xFF, 0xFF, 0x4F, 0xFF, 0xFF, 0xFF, 0x6F,
  0xFF, 0xFF, 0xFF, 0x12, 0xB3, 0xFF, 0xEC, 0x01, 0x02, 0x15, 0x01, 0x02, 0x0C, 0x10, 0x0F, 0xFF,
  0xFF, 0xFF, 0x2F, 0xFF, 0xFF, 0xFF, 0x4F, 0xFF, 0xFF, 0xFF, 0x6F, 0xFF, 0xFF, 0xFF, 0x11, 0xB6,
  0xFF, 0xB6, 0x01, 0x02, 0x15, 0x01, 0x02, 0x0C, 0x10, 0x0F, 0xFF, 0xFF, 0xFF, 0x2F, 0xFF, 0xFF,
  0xFF, 0x4F, 0xFF, 0xFF, 0xFF, 0x6F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x80, 0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x02, 0x0D, 0x10, 0x00,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0E,
  0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05
};
size_t g_max_wsa_with_all_ext_size = sizeof(g_max_wsa_with_all_ext);


/*
  유효하지 않은 messageID 값을 갖는 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID sarMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_msg_id[] = {
  0xB0, 0x00
};
size_t g_abnormal_wsa_with_invalid_msg_id_size = sizeof(g_abnormal_wsa_with_invalid_msg_id);


/*
  유효하지 않은 version 값을 갖는 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 2
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_version[] = {
  0x20, 0x00
};
size_t g_abnormal_wsa_with_invalid_version_size = sizeof(g_abnormal_wsa_with_invalid_version);


/*
  유효하지 않은 PISD 값을 갖는 Service Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID extension extension extension 270549120 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_psid[] = {
  0x36, 0x00, 0x01, 0xF0, 0x41, 0x02, 0x04, 0x08, 0x00, 0x80, 0x11, 0x1A, 0xC0, 0x00, 0x60, 0x00
};
size_t g_abnormal_wsa_with_invalid_psid_size = sizeof(g_abnormal_wsa_with_invalid_psid);


/*
  유효하지 않은 RCPI threshold 값을 갖는 Service Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1
          chOptions {
            extensions {
              { extensionId 19 value RcpiThreshold : 221 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_rcpi_threshold[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x01, 0x13, 0x01, 0xDD, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_invalid_rcpi_threshold_size = sizeof(g_abnormal_wsa_with_invalid_rcpi_threshold);


/*
  유효하지 않은 WSA count threshold 값을 갖는 Service Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1
          chOptions {
            extensions {
              { extensionId 20 value WsaCountThreshold : 0 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x01, 0x14, 0x01, 0x00, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold_size = sizeof(g_abnormal_wsa_with_invalid_wsa_cnt_threshold);


/*
  유효하지 않은 WSA count threshold interval 값을 갖는 Service Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1
          chOptions {
            extensions {
              { extensionId 22 value WsaCountThresholdInterval : 0 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold_interval[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x01, 0x16, 0x01, 0x00, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold_interval_size = sizeof(g_abnormal_wsa_with_invalid_wsa_cnt_threshold_interval);


/*
  유효하지 않은 Operating class 값을 갖는 Channel Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 19 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_op_class[] = {
  0x36, 0x00, 0x01, 0x00, 0x08, 0x01, 0x13, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_invalid_op_class_size = sizeof(g_abnormal_wsa_with_invalid_op_class);


/*
  유효하지 않은 Channel Number 값을 갖는 Channel Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 201 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_chan[] = {
  0x36, 0x00, 0x01, 0x00, 0x08, 0x01, 0x11, 0xC9, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_invalid_chan_size = sizeof(g_abnormal_wsa_with_invalid_chan);


/*
  유효하지 않은 datarate 값을 갖는 Channel Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 7 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_datarate[] = {
  0x36, 0x00, 0x01, 0x00, 0x08, 0x01, 0x11, 0xAC, 0x00, 0x07, 0x00
};
size_t g_abnormal_wsa_with_invalid_datarate_size = sizeof(g_abnormal_wsa_with_invalid_datarate);


/*
  유효하지 않은 Channel access 값을 갖는 Channel Info를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 }
          extensions {
            extensions {
              { extensionId 21 value ChannelAccess80211:3 }
            }
          }
        }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_chan_access[] = {
  0x36, 0x00, 0x01, 0x00, 0x08, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x01, 0x01, 0x15, 0x01, 0x03
};
size_t g_abnormal_wsa_with_invalid_chan_access_size = sizeof(g_abnormal_wsa_with_invalid_chan_access);


/*
  유효하지 않은 Router lifetime 값을 갖는 WRA를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
      routingAdvertisement {
        lifetime 0
        ipPrefix '000102030405060708090a0b0c0d0e0f'H
        ipPrefixLength 1
        defaultGateway '000102030405060708090a0b0c0d0e0f'H
        primaryDns '000102030405060708090a0b0c0d0e0f'H
        extensions {}
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_router_lifetime[] = {
  0x37, 0x00, 0x01, 0x00, 0x08, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x01, 0x00, 0x01,
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01,
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00
};
size_t g_abnormal_wsa_with_invalid_router_lifetime_size = sizeof(g_abnormal_wsa_with_invalid_router_lifetime);


/*
  유효하지 않은 IPv6 prefix len 값을 갖는 WRA를 포함한 WSA
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
      routingAdvertisement {
        lifetime 1
        ipPrefix '000102030405060708090a0b0c0d0e0f'H
        ipPrefixLength 129
        defaultGateway '000102030405060708090a0b0c0d0e0f'H
        primaryDns '000102030405060708090a0b0c0d0e0f'H
        extensions {}
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_invalid_ip_prefix_len[] = {
  0x37, 0x00, 0x01, 0x00, 0x08, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02,
  0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x81, 0x00, 0x01,
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01,
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00
};
size_t g_abnormal_wsa_with_invalid_ip_prefix_len_size = sizeof(g_abnormal_wsa_with_invalid_ip_prefix_len);


/*
  WSA count threshold 및 WSA count threshold interval 정보를 갖는 Service Info를 포함한 WSA
  WSA count threshold: 1, WSA count threshold interval: 1 -> 라이브러리의 기본 관리 타이머보다 짧은 주기
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1
          chOptions {
            extensions {
              { extensionId 20 value WsaCountThreshold : 1 }
              { extensionId 22 value WsaCountThresholdInterval : 1 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x02, 0x14, 0x01, 0x01, 0x16, 0x01, 0x01, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100_size = sizeof(g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100);


/*
  WSA count threshold 및 WSA count threshold interval 정보를 갖는 Service Info를 포함한 WSA
  WSA count threshold: 3, WSA count threshold interval: 10 -> 라이브러리의 기본 관리 타이머와 동일한 주기
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1
          chOptions {
            extensions {
              { extensionId 20 value WsaCountThreshold : 3 }
              { extensionId 22 value WsaCountThresholdInterval : 10 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x02, 0x14, 0x01, 0x03, 0x16, 0x01, 0x0A, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000_size = sizeof(g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000);


/*
  WSA count threshold 및 WSA count threshold interval 정보를 갖는 Service Info를 포함한 WSA
  WSA count threshold: 10, WSA count threshold interval: 20 -> 라이브러리의 기본 관리 타이머보다 긴 주기
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1
          chOptions {
            extensions {
              { extensionId 20 value WsaCountThreshold : 10 }
              { extensionId 22 value WsaCountThresholdInterval : 20 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x02, 0x14, 0x01, 0x0A, 0x16, 0x01, 0x14, 0x01, 0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000_size = sizeof(g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000);


/*
  RCPI threshold 및, WSA count threshold, WSA count threshold interval 정보를 갖는 Service Info를 포함한 WSA
  WSA count threshold: 3, WSA count threshold interval: 10 -> 라이브러리의 기본 관리 타이머와 동일한 주기
  msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 0
        contentCount 0
      }
      serviceInfos {
        { serviceID content 0
          channelIndex 1
          chOptions {
            extensions {
              { extensionId 19 value RcpiThreshold : 10 }
              { extensionId 20 value WsaCountThreshold : 3 }
              { extensionId 22 value WsaCountThresholdInterval : 10 }
            }
          }
        }
      }
      channelInfos {
        { operatingClass 17 channelNumber 172 powerLevel -128 dataRate { adaptable '0'B dataRate 6 } extensions {} }
      }
    }
  }
 */
uint8_t g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000[] = {
  0x36, 0x00, 0x01, 0x00, 0x09, 0x03, 0x13, 0x01, 0x0A, 0x14, 0x01, 0x03, 0x16, 0x01, 0x0A, 0x01,
  0x11, 0xAC, 0x00, 0x06, 0x00
};
size_t g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size =
  sizeof(g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000);



/*
   시스템이 지원하는 수(kDot3WSINum_Max, 현재 31)보다 많은 ServiceInfo를 포함한 WSA
   msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 15
        contentCount 15
      }
      serviceInfos {
        { serviceID content 1 channelIndex 1 chOptions {} }
        { serviceID content 2 channelIndex 1 chOptions {} }
        { serviceID content 3 channelIndex 1 chOptions {} }
        { serviceID content 4 channelIndex 1 chOptions {} }
        { serviceID content 5 channelIndex 1 chOptions {} }
        { serviceID content 6 channelIndex 1 chOptions {} }
        { serviceID content 7 channelIndex 1 chOptions {} }
        { serviceID content 8 channelIndex 1 chOptions {} }
        { serviceID content 9 channelIndex 1 chOptions {} }
        { serviceID content 10 channelIndex 1 chOptions {} }
        { serviceID content 11 channelIndex 1 chOptions {} }
        { serviceID content 12 channelIndex 1 chOptions {} }
        { serviceID content 13 channelIndex 1 chOptions {} }
        { serviceID content 14 channelIndex 1 chOptions {} }
        { serviceID content 15 channelIndex 1 chOptions {} }
        { serviceID content 16 channelIndex 1 chOptions {} }
        { serviceID content 17 channelIndex 1 chOptions {} }
        { serviceID content 18 channelIndex 1 chOptions {} }
        { serviceID content 19 channelIndex 1 chOptions {} }
        { serviceID content 20 channelIndex 1 chOptions {} }
        { serviceID content 21 channelIndex 1 chOptions {} }
        { serviceID content 22 channelIndex 1 chOptions {} }
        { serviceID content 23 channelIndex 1 chOptions {} }
        { serviceID content 24 channelIndex 1 chOptions {} }
        { serviceID content 25 channelIndex 1 chOptions {} }
        { serviceID content 26 channelIndex 1 chOptions {} }
        { serviceID content 27 channelIndex 1 chOptions {} }
        { serviceID content 28 channelIndex 1 chOptions {} }
        { serviceID content 29 channelIndex 1 chOptions {} }
        { serviceID content 30 channelIndex 1 chOptions {} }
        { serviceID content 31 channelIndex 1 chOptions {} }
        { serviceID content 32 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 }
          extensions {}
        }
      }
    }
  }
 */
uint8_t g_wsa_with_too_many_service_info[] = {
0x36, 0xFF, 0x20, 0x01, 0x08, 0x02, 0x08, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x08, 0x07,
0x08, 0x08, 0x08, 0x09, 0x08, 0x0A, 0x08, 0x0B, 0x08, 0x0C, 0x08, 0x0D, 0x08, 0x0E, 0x08, 0x0F,
0x08, 0x10, 0x08, 0x11, 0x08, 0x12, 0x08, 0x13, 0x08, 0x14, 0x08, 0x15, 0x08, 0x16, 0x08, 0x17,
0x08, 0x18, 0x08, 0x19, 0x08, 0x1A, 0x08, 0x1B, 0x08, 0x1C, 0x08, 0x1D, 0x08, 0x1E, 0x08, 0x1F,
0x08, 0x20, 0x08, 0x01, 0x11, 0xAE, 0xFF, 0xB6, 0x00
};
size_t g_wsa_with_too_many_service_info_size = sizeof(g_wsa_with_too_many_service_info);


/*
   시스템이 지원하는 수(kDot3WCINum_Max, 현재 31)보다 많은 ChannelInfo를 포함한 WSA
   msg SrvAdvMsg ::= {
    version {
      messageID saMessage
      rsvAdvPrtVersion 3
    }
    body {
      changeCount {
        saID 15
        contentCount 15
      }
      serviceInfos {
        { serviceID content 1 channelIndex 1 chOptions {} }
      }
      channelInfos {
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
        { operatingClass 17 channelNumber 174 powerLevel 127 dataRate { adaptable '1'B dataRate 54 } extensions {} }
      }
    }
  }
 */
uint8_t g_wsa_with_too_many_channel_info[] = {
  0x36, 0xFF, 0x01, 0x01, 0x08, 0x20, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00,
  0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11,
  0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE,
  0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF,
  0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6,
  0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00,
  0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11,
  0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE,
  0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF,
  0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00, 0x11, 0xAE, 0xFF, 0xB6,
  0x00, 0x11, 0xAE, 0xFF, 0xB6, 0x00
};
size_t g_wsa_with_too_many_channel_info_size = sizeof(g_wsa_with_too_many_channel_info);
