#include "relay-internal-system.h"
#include "relay-extern-defines.h"

#ifndef _D_HEADER_RELAY_INNO_CONFIG
#define _D_HEADER_RELAY_INNO_CONFIG
#include "relay_v2x.h"

#define RELAY_INNO_INITAIL_SETUP_CONFIGURAION_FILE_PATH "./"
#define RELAY_INNO_INITAIL_SETUP_CONFIGURAION_FILE_NAME "keti_relay_inno.conf"

struct relay_inno_config_realy_t
{
		bool enable;
		char dev_name[32];
		char gatewayip[INET_ADDRSTRLEN];
		uint16_t port_v2x_rx;
		uint16_t port_v2x_tx;

		bool gnss_enable; ///< GNSS 사용 여부
		uint32_t gnss_interval; ///< GNSS 수신 주기 (usec 단위)
};

struct relay_inno_config_t {
    bool config_enable;
    char config_path[512];
		
		struct relay_inno_config_realy_t relay;
    struct relay_inno_config_v2x_t v2x;
};

#endif //?_D_HEADER_RELAY_INNO_CONFIG

extern struct relay_inno_config_t G_relay_inno_config;

extern int RELAY_INNO_Config_Setup_Configuration_Read(struct relay_inno_config_t *relay_inno_config);
extern int RELAY_INNO_Config_Pasrsing_Argument(int argc, char *argv[]);
