#include "os_fingerprint.h"
#include "../include/scanners.h"
#include "../include/raw_socket.h"
#include "../include/packet_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define TCP_HEADER_MIN_LEN 20

static uint32_t generate_seq() {
    return (uint32_t)(rand() % 0xFFFFFFFF);
}

void os_fingerprint(const char *target_ip, int port, int timeout,
                    uint8_t *ttl, uint16_t *window, char *os_guess) {
    *ttl = 64;
    *window = 0;
    os_guess[0] = '\0';
    
    raw_socket_t *sock = raw_socket_create(true);
    if (!sock) return;
    
    uint32_t dst_ip = inet_addr(target_ip);
    uint32_t src_ip = sock->source_ip ? sock->source_ip : inet_addr("0.0.0.0");
    uint16_t src_port = 12345 + (rand() % 10000);
    
    packet_config_t config = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = port,
        .seq = generate_seq(),
        .ack = 0,
        .flags = TH_SYN,
        .window = 65535,
        .ttl = 64,
        .tos = 0
    };
    
    char tcp_buffer[TCP_HEADER_MIN_LEN];
    char ip_buffer[128];
    
    int tcp_len = build_tcp_packet(&config, tcp_buffer, sizeof(tcp_buffer));
    if (tcp_len < 0) {
        raw_socket_destroy(sock);
        return;
    }
    
    int total_len = build_ip_packet(&config, tcp_buffer, tcp_len, ip_buffer, sizeof(ip_buffer));
    if (total_len < 0) {
        raw_socket_destroy(sock);
        return;
    }
    
    raw_socket_send(sock, ip_buffer, total_len, dst_ip, port);
    
    char response[128];
    int recv_len = raw_socket_receive(sock, response, sizeof(response), timeout);
    raw_socket_destroy(sock);
    
    if (recv_len > 0) {
        struct iphdr *resp_ip = (struct iphdr *)response;
        if (resp_ip->protocol == IPPROTO_TCP) {
            struct tcphdr *resp_tcp = (struct tcphdr *)(response + resp_ip->ihl * 4);
            
            *ttl = resp_ip->ttl;
            *window = resp_tcp->th_win;
            
            const char *os_ttl = guess_os_from_ttl(resp_ip->ttl);
            const char *os_win = guess_os_from_window(resp_tcp->th_win);
            
            snprintf(os_guess, 128, "%s (%s)", os_ttl, os_win);
        }
    }
}

const char* guess_os_from_ttl(uint8_t ttl) {
    if (ttl <= 32) return "Linux 2.4/2.6";
    if (ttl <= 64) return "Linux 3+/Windows/FreeBSD";
    if (ttl <= 128) return "Linux 2.2/MacOS/Oracle";
    if (ttl <= 255) return " Solaris/AIX/OpenBSD";
    return "Unknown";
}

const char* guess_os_from_window(uint16_t window) {
    if (window == 65535) return "Windows/BSD";
    if (window == 16384) return "Linux";
    if (window == 5840) return "Linux 2.4";
    if (window == 65535 || window == 4128) return "Windows XP/2003";
    if (window == 65535 || window == 8192) return "Windows Vista/7";
    if (window == 14600) return "MacOS";
    return "Generic";
}
