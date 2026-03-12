#include "color_output.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char* get_state_color(port_state_t state) {
    switch (state) {
        case PORT_OPEN: return COLOR_GREEN;
        case PORT_CLOSED: return COLOR_RED;
        case PORT_FILTERED: return COLOR_YELLOW;
        case PORT_OPEN_FILTERED: return COLOR_MAGENTA;
        case PORT_UNFILTERED: return COLOR_CYAN;
        default: return COLOR_WHITE;
    }
}

static const char* get_state_string(port_state_t state) {
    switch (state) {
        case PORT_OPEN: return "OPEN";
        case PORT_CLOSED: return "CLOSED";
        case PORT_FILTERED: return "FILTERED";
        case PORT_OPEN_FILTERED: return "OPEN|FILTERED";
        case PORT_UNFILTERED: return "UNFILTERED";
        default: return "UNKNOWN";
    }
}

void print_color_result(const char *ip, scan_result_t *result, output_format_t format, int color) {
    const char *color_start = color ? get_state_color(result->state) : "";
    const char *color_end = color ? COLOR_RESET : "";
    
    if (format == FORMAT_NORMAL) {
        printf("%s%-8d/%-4s %-12s %s%s", 
               color_start,
               result->port, "tcp", 
               get_state_string(result->state),
               result->service,
               color_end);
        if (result->version[0] != '\0') {
            printf(" %s", result->version);
        }
        if (result->os_guess[0] != '\0' && color) {
            printf(" %s[%s]%s", COLOR_CYAN, result->os_guess, COLOR_RESET);
        }
        printf("\n");
    }
}

void print_color_table_header(int color) {
    if (!color) {
        printf("PORT     STATE         SERVICE          VERSION\n");
        printf("-------- ------------- ---------------- ---------------------\n");
        return;
    }
    
    printf(COLOR_BOLD "PORT     STATE         SERVICE          VERSION" COLOR_RESET "\n");
    printf("-------- ------------- ---------------- ---------------------\n");
}

void print_color_table_row(const char *ip, scan_result_t *result, int color) {
    const char *color_start = color ? get_state_color(result->state) : "";
    const char *color_end = color ? COLOR_RESET : "";
    
    printf("%s%-8d/tcp %-12s %-15s %s%s", 
           color_start,
           result->port,
           get_state_string(result->state),
           result->service,
           result->version[0] ? result->version : "-",
           color_end);
    
    if (color && result->os_guess[0] != '\0') {
        printf(" %s[%s]%s", COLOR_CYAN, result->os_guess, COLOR_RESET);
    }
    printf("\n");
}

void print_csv_header(FILE *fp) {
    fprintf(fp, "IP,Port,Protocol,State,Service,Version,Response_Time_ms,TTL,Window,OS_Guess\n");
}

void print_csv_result(FILE *fp, const char *ip, scan_result_t *result) {
    fprintf(fp, "%s,%d,tcp,%s,%s,%s,%.2f,%d,%d,%s\n",
            ip,
            result->port,
            get_state_string(result->state),
            result->service,
            result->version,
            result->response_time,
            result->ttl,
            result->window,
            result->os_guess);
}

void print_json_result(FILE *fp, const char *ip, scan_result_t *result, int first) {
    if (!first) fprintf(fp, ",\n");
    fprintf(fp, "  {\"port\": %d, \"protocol\": \"tcp\", \"state\": \"%s\", \"service\": \"%s\", "
            "\"version\": \"%s\", \"response_time\": %.2f, \"ttl\": %d, \"window\": %d, \"os_guess\": \"%s\"}",
            result->port,
            get_state_string(result->state),
            result->service,
            result->version,
            result->response_time,
            result->ttl,
            result->window,
            result->os_guess);
}

void print_grepable_result(FILE *fp, const char *ip, scan_result_t *result) {
    fprintf(fp, "PORT|%d/tcp|%s|%s", result->port, get_state_string(result->state), result->service);
    if (result->version[0] != '\0') {
        fprintf(fp, "|%s", result->version);
    }
    fprintf(fp, "|responsetime=%.2f|os=%s\n", result->response_time, result->os_guess);
}

void print_xml_result(FILE *fp, const char *ip, scan_result_t *result) {
    fprintf(fp, "  <port><protocol>tcp</protocol><portid>%d</portid>"
            "<state state=\"%s\"/><service name=\"%s\"/><version>%s</version>"
            "<os>%s</os></port>\n",
            result->port,
            get_state_string(result->state),
            result->service,
            result->version,
            result->os_guess);
}
