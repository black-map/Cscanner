#ifndef COLOR_OUTPUT_H
#define COLOR_OUTPUT_H

#include "../include/common.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

void print_color_result(const char *ip, scan_result_t *result, output_format_t format, int color);
void print_color_table_header(int color);
void print_color_table_row(const char *ip, scan_result_t *result, int color);
void print_csv_header(FILE *fp);
void print_csv_result(FILE *fp, const char *ip, scan_result_t *result);
void print_json_result(FILE *fp, const char *ip, scan_result_t *result, int first);
void print_grepable_result(FILE *fp, const char *ip, scan_result_t *result);
void print_xml_result(FILE *fp, const char *ip, scan_result_t *result);

#endif
