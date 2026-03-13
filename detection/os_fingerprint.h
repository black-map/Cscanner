#ifndef OS_FINGERPRINT_H
#define OS_FINGERPRINT_H

#include "../include/common.h"

void os_fingerprint(const char *target_ip, int port, int timeout, 
                    uint8_t *ttl, uint16_t *window, char *os_guess);
const char* guess_os_from_ttl(uint8_t ttl);
const char* guess_os_from_window(uint16_t window);

#endif
