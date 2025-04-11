#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <termios.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <getopt.h>

#ifndef _D_HEADER_RELAY_INNO_CONFIG
#define _D_HEADER_RELAY_INNO_CONFIG
#include "relay_main.h"
#include "relay_v2x.h"

#define RELAY_INNO_INITAIL_SETUP_CONFIGURAION_FILE_PATH "./"
#define RELAY_INNO_INITAIL_SETUP_CONFIGURAION_FILE_NAME "keti_relay_inno.conf"

struct relay_inno_config_t {
    bool config_enable;
    char config_path[512];
    struct relay_inno_config_v2x_t v2x;
};

#endif //?_D_HEADER_RELAY_INNO_CONFIG

extern struct relay_inno_config_t G_relay_inno_config;

extern int RELAY_INNO_Config_Setup_Configuration_Read(struct relay_inno_config_t *relay_inno_config);
extern int RELAY_INNO_Config_Pasrsing_Argument(int argc, char *argv[]);
