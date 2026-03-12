#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H

#include "../include/common.h"

void parse_arguments(int argc, char *argv[], scan_config_t *config);
void usage(const char *prog);
void parse_ports(const char *port_str, int **ports, int *port_count);

#endif
