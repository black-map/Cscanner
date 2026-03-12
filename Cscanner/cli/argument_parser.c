#include "../include/argument_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

void usage(const char *prog) {
    printf("CScanner v1.4 - Advanced Network Scanner\n");
    printf("==========================================\n\n");
    printf("Usage: %s [OPTIONS] -t <target>\n\n", prog);
    printf("OPTIONS:\n");
    printf("  -t <target>      Target IP or hostname (required)\n");
    printf("  -p <ports>       Ports (e.g., 22,80,443 or 1-1000 or 1-65535 or all)\n");
    printf("  -s <type>        Scan type: connect|syn|fin|xmas|null|udp|ack|sctp\n");
    printf("  -T <timeout>     Timeout in ms (default: 2000)\n");
    printf("  -c <threads>     Concurrent threads (default: 50, max: 500)\n");
    printf("  -r <rate>        Packet rate limit\n");
    printf("  -sV              Service version detection\n");
    printf("  -O               OS fingerprinting (requires root)\n");
    printf("  -A               Enable all detections\n");
    printf("  -oN <file>       Normal output\n");
    printf("  -oX <file>       XML output\n");
    printf("  -oJ <file>       JSON output\n");
    printf("  -oG <file>       Grepable output\n");
    printf("  -oC <file>       CSV output\n");
    printf("  --color          Color output (terminal)\n");
    printf("  --adaptive       Enable adaptive scan rate\n");
    printf("  -i <interface>   Network interface\n");
    printf("  -L <script>      Lua post-scan script\n");
    printf("  -v               Verbose mode\n");
    printf("  -h               Help\n\n");
    printf("EXAMPLES:\n");
    printf("  %s -t 192.168.1.1 -p 1-1000 -sS -sV\n", prog);
    printf("  %s -t 10.0.0.0/24 -p 22,80,443 -sV --color\n", prog);
    printf("  %s -t target.com -p 1-65535 -T4 --adaptive\n", prog);
    printf("  %s -t target.com -p 1-1000 -sS -O -oJ results.json\n", prog);
}

void parse_arguments(int argc, char *argv[], scan_config_t *config) {
    memset(config, 0, sizeof(scan_config_t));
    
    config->scan_type = SCAN_CONNECT;
    config->timeout = DEFAULT_TIMEOUT;
    config->threads = 50;
    config->timing = 3;
    config->output_format = FORMAT_NORMAL;
    config->adaptive = 0;
    config->color_output = 0;
    config->version_detect = 0;
    
    static struct option long_options[] = {
        {"color", no_argument, 0, 1},
        {"adaptive", no_argument, 0, 2},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "t:p:s:T:c:r:sVo:O:Ai:L:o:vh", 
                              long_options, &option_index)) != -1) {
        switch (opt) {
            case 1:
                config->color_output = 1;
                break;
            case 2:
                config->adaptive = 1;
                break;
            case 't':
                strncpy(config->target, optarg, 255);
                break;
            case 'p':
                config->port_start = 1;
                config->port_end = 1024;
                if (strcmp(optarg, "all") == 0) {
                    config->port_start = 1;
                    config->port_end = 65535;
                } else if (strchr(optarg, '-')) {
                    sscanf(optarg, "%d-%d", &config->port_start, &config->port_end);
                } else {
                    config->port_start = atoi(optarg);
                    config->port_end = config->port_start;
                }
                break;
            case 's':
                if (strcmp(optarg, "syn") == 0 || strcmp(optarg, "S") == 0) 
                    config->scan_type = SCAN_SYN;
                else if (strcmp(optarg, "fin") == 0 || strcmp(optarg, "F") == 0) 
                    config->scan_type = SCAN_FIN;
                else if (strcmp(optarg, "xmas") == 0 || strcmp(optarg, "X") == 0) 
                    config->scan_type = SCAN_XMAS;
                else if (strcmp(optarg, "null") == 0 || strcmp(optarg, "N") == 0) 
                    config->scan_type = SCAN_NULL;
                else if (strcmp(optarg, "ack") == 0 || strcmp(optarg, "A") == 0) 
                    config->scan_type = SCAN_ACK;
                else if (strcmp(optarg, "udp") == 0 || strcmp(optarg, "U") == 0) 
                    config->scan_type = SCAN_UDP;
                else if (strcmp(optarg, "sctp") == 0) 
                    config->scan_type = SCAN_SCTP_INIT;
                else 
                    config->scan_type = SCAN_CONNECT;
                break;
            case 'T':
                config->timeout = atoi(optarg);
                if (config->timeout <= 0) config->timeout = DEFAULT_TIMEOUT;
                break;
            case 'c':
                config->threads = atoi(optarg);
                if (config->threads > MAX_THREADS) config->threads = MAX_THREADS;
                break;
            case 'r':
                config->rate_limit = atoi(optarg);
                break;
            case 'V':
                config->version_detect = 1;
                break;
            case 'O':
                config->version_detect = 1;
                break;
            case 'A':
                config->version_detect = 1;
                break;
            case 'i':
                strncpy(config->interface, optarg, 63);
                break;
            case 'L':
                strncpy(config->lua.script_path, optarg, 511);
                config->lua.enabled = 1;
                break;
            case 'o':
                if (optarg[0] == 'N' || optarg[0] == 'n') {
                    config->output_format = FORMAT_NORMAL;
                    strncpy(config->output_file, optarg + 2, 255);
                } else if (optarg[0] == 'X' || optarg[0] == 'x') {
                    config->output_format = FORMAT_XML;
                    strncpy(config->output_file, optarg + 2, 255);
                } else if (optarg[0] == 'J' || optarg[0] == 'j') {
                    config->output_format = FORMAT_JSON;
                    strncpy(config->output_file, optarg + 2, 255);
                } else if (optarg[0] == 'G' || optarg[0] == 'g') {
                    config->output_format = FORMAT_GREPEABLE;
                    strncpy(config->output_file, optarg + 2, 255);
                } else if (optarg[0] == 'C' || optarg[0] == 'c') {
                    config->output_format = FORMAT_CSV;
                    strncpy(config->output_file, optarg + 2, 255);
                }
                break;
            case 'v':
                config->verbose++;
                verbose_mode = config->verbose;
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
            default:
                usage(argv[0]);
                exit(1);
        }
    }
    
    if (config->target[0] == '\0') {
        fprintf(stderr, "Error: Target is required. Use -t <target>\n");
        usage(argv[0]);
        exit(1);
    }
    
    if (config->port_start == 0) {
        config->port_start = 1;
        config->port_end = 1024;
    }
    
    if (config->scan_type != SCAN_CONNECT && geteuid() != 0) {
        fprintf(stderr, "Warning: Raw scans require root privileges\n");
        config->scan_type = SCAN_CONNECT;
    }
}

void parse_ports(const char *port_str, int **ports, int *port_count) {
    int *ports_arr = NULL;
    int capacity = 1024;
    int count = 0;
    
    ports_arr = malloc(capacity * sizeof(int));
    if (!ports_arr) {
        perror("malloc");
        exit(1);
    }
    
    if (strcmp(port_str, "all") == 0 || strcmp(port_str, "-") == 0) {
        for (int p = 1; p <= 65535 && count < 65535; p++) {
            if (count >= capacity) {
                capacity *= 2;
                ports_arr = realloc(ports_arr, capacity * sizeof(int));
            }
            ports_arr[count++] = p;
        }
    } else {
        char *str = strdup(port_str);
        char *token = strtok(str, ",");
        
        while (token) {
            if (strchr(token, '-')) {
                int start, end;
                sscanf(token, "%d-%d", &start, &end);
                start = (start < 1) ? 1 : start;
                end = (end > 65535) ? 65535 : end;
                for (int p = start; p <= end && count < 65535; p++) {
                    if (count >= capacity) {
                        capacity *= 2;
                        ports_arr = realloc(ports_arr, capacity * sizeof(int));
                    }
                    ports_arr[count++] = p;
                }
            } else {
                int port = atoi(token);
                if (port > 0 && port <= 65535) {
                    if (count >= capacity) {
                        capacity *= 2;
                        ports_arr = realloc(ports_arr, capacity * sizeof(int));
                    }
                    ports_arr[count++] = port;
                }
            }
            token = strtok(NULL, ",");
        }
        free(str);
    }
    
    *ports = ports_arr;
    *port_count = count;
}
