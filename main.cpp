/**
 * VUT FIT Projekt ISA 2020
 * Varianta: Monitoring SSL spojení
 * Autor: Monika Burešová
 * Login: xbures32
 */

// http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/



#include <iostream>
#include <vector>
#include <string>
#include "args.hpp"
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <ctime>

using namespace std;

bool file = false;
bool iface = false;

typedef struct TLS_conn {
//    unsigned int timestamp_sec{};
//    unsigned int timestamp_milisec{};
    struct timeval timestamp{};
    bool client_hello = false;
    bool server_hello = false;
    bool first_fin = false;
    u_int TCPpacketCount = 0; // TCP packets counter
    uint32_t client_ip{};
    uint32_t server_ip{};
    struct in6_addr client_ip6{};
    struct in6_addr server_ip6{};
    uint16_t client_port{};
    vector<u_char> SNI;
    u_int bytes = 0;
    double duration{};
    bool already_print = false;

} TLS_connection;

vector<TLS_connection> connections;


//https://www.tcpdump.org/pcap.html

/*
 * https://www.cloudflare.com/learning/ssl/what-is-sni/
 * https://stackoverflow.com/questions/17832592/extract-server-name-indication-sni-from-tls-client-hello
 */
void find_SNI(vector<u_char> clientHello, int record_header_index, int session_index) {

    uint8_t handshake_type_index = record_header_index + 5; // 0x01
    uint8_t  session_id_index = handshake_type_index + 32 + 5 + 1; // 5 - handshake header + client version, 32 - client random
    uint8_t  session_id_length = clientHello[session_id_index];


    uint8_t  cipher_suites_length_index = session_id_index + session_id_length + 1;
    uint8_t  cipher_suites_length = (clientHello[cipher_suites_length_index] << 8) + clientHello[cipher_suites_length_index+1];


    uint8_t compression_method_index = cipher_suites_length_index + cipher_suites_length + 2; // 2 - bytes holding cipher_suites_length
    uint8_t compression_method_length = clientHello[compression_method_index];


    uint8_t extensions_length_index = compression_method_index + compression_method_length + 1;
    unsigned int extensions_length = (clientHello[extensions_length_index] << 8) + clientHello[extensions_length_index+1];


    unsigned int concrete_extension_length = 0;

    for (unsigned int i = extensions_length_index + 2; i < clientHello.size(); i += 4 + concrete_extension_length) { // 4 - 2 bytes for extension type and 2 bytes for length
        if ((clientHello[i]) == 0x00 && (clientHello[i+1] == 0x00 && (clientHello[i+6] == 0x00))) { // 0x00 0x00 indicates server name extension
            u_short SN_length = (clientHello[i+7] << 8) + clientHello[i+8];

            for (int j = 0; j < SN_length; j++) {
                connections[session_index].SNI.push_back(clientHello[i+9+j]);
            }
        }
        else {
            concrete_extension_length = (clientHello[i+2] << 8) + clientHello[i+3];
        }
    }

}

void print_ip(const uint32_t in) {
    struct sockaddr_in addr{};
    addr.sin_addr.s_addr = in;
    printf("%s,", inet_ntoa(addr.sin_addr));
}

void print_ip6(const struct in6_addr in) {
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (void *)&in, ipstr, sizeof(ipstr));
    printf("%s,", ipstr);
}

void print_timestamp(int session_index) {
    struct tm *local;
    char date[80];

    local = localtime(&connections[session_index].timestamp.tv_sec);

    strftime(date, 80, "%Y-%m-%d %X.", local);
    printf("%s%06ld ", date, connections[session_index].timestamp.tv_usec);
}

void print_connection(int i, double timestamp_lastTCP, int ip_version) {
    double timestamp;

    timestamp = (double) connections[i].timestamp.tv_sec * 1000000000 + (double) connections[i].timestamp.tv_usec * 1000;

    connections[i].duration =  (timestamp_lastTCP - timestamp) / 1000000000;

    print_timestamp(i);
    if(ip_version == 6) {
        print_ip6(connections[i].client_ip6); // print source ipv6
        printf("%d,", ntohs(connections[i].client_port)); // source port
        print_ip6(connections[i].server_ip6); // destination ipv6
    }
    else if(ip_version == 4) {
        print_ip(connections[i].client_ip); // print source ipv4
        printf("%d,", ntohs(connections[i].client_port)); // source port
        print_ip(connections[i].server_ip); // destination ipv4
    }

    for (unsigned char j : connections[i].SNI) {
        printf("%c", j);
    }
    printf(",%d,", connections[i].bytes);
    printf("%d,", connections[i].TCPpacketCount);
    printf("%.6f\n", connections[i].duration);
}


int main(int argc, char **argv) {

    unsigned int total_header_len; //ethernet header + ip header + tcp header
    string given_iface; // iface from argument
    string given_file; // file path from argument

    u_int ALLpacketsCount = 0;

    vector<u_char> payload;
    vector<u_char> clientHello;
    vector<u_char> SNI;

    pcap_t *pcap;


    char errbuff[PCAP_ERRBUF_SIZE];

    // parse arguments
    args(argc, argv, &iface, &given_iface, &file, &given_file);

    /* FILE SNIFFING
     * =======================================================================
     */
    if (file) {
        //https://www.rhyous.com/2011/11/13/how-to-read-a-pcap-file-from-wireshark-with-c/
        pcap = pcap_open_offline_with_tstamp_precision(given_file.c_str(), PCAP_TSTAMP_PRECISION_NANO, errbuff);
        if (pcap == nullptr) {
            cerr << "Could not open file: " << given_file << endl;
            exit(1);
        }
    }
    /* INTERFACE SNIFFFING
     * =======================================================================
     */
    else if (iface) {
        pcap = pcap_open_live(given_iface.c_str(), 65536, 1, 1,  errbuff);
        if (pcap == nullptr) {
            cerr << "Could not open interface " << given_iface << endl;
            exit(1);
        }
    }

        struct pcap_pkthdr *header; // create header object
        const u_char *data; // create character array using a u_char

        while (pcap_next_ex(pcap, &header, &data) >= 0) {

            auto *eth_h = (struct ethhdr *) data;
            unsigned short ethhrdlen = sizeof(struct ethhdr);
            unsigned short iphdrlen;
            unsigned int tcphdrlen;

            auto *ip6h = (struct ip6_hdr *) (data + ethhrdlen); // data/buffer?
            auto *iph = (struct iphdr *) (data + ethhrdlen);

            if (header->len != header->caplen)
                printf("Warning capture size different than packet size> %ud bytes \n", header->len);

            switch (ntohs(eth_h->h_proto)) {
                case ETH_P_IPV6:
                    iphdrlen = sizeof(struct ip6_hdr);
                    break;

                case ETH_P_IP:
                    iphdrlen = iph->ihl * 4;
                    break;


            }

            ALLpacketsCount += 1;

            if (iph->protocol == 6 || ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6) { //TCP
                auto *tcph = (struct tcphdr *) (data + iphdrlen + ethhrdlen);
                tcphdrlen = (tcph->th_off * 4) - (tcph->th_x2 * 4);
                total_header_len = sizeof(ethhdr) + iphdrlen + tcphdrlen; // size of all headers: ether + ip + tcp

                // http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/


                /*
                 * FIRT TCP PACKET
                 * https://stackoverflow.com/questions/35385189/how-to-identify-initial-packet-in-tcp-3-way-handshake
                 */
                if ((tcph->ack == 0) && ((tcph->syn) == 1)) { // first part of threeway handshake

                    TLS_connection conn;
                    connections.push_back(conn);

                    connections.back().TCPpacketCount = 1;

                    switch (ntohs(eth_h->h_proto)) { // ETH_P_8021Q
                        case ETH_P_IPV6:
                            connections.back().client_ip6 = ip6h->ip6_src;
                            connections.back().server_ip6 = ip6h->ip6_dst;
                            break;

                        case ETH_P_IP:
                            connections.back().client_ip = iph->saddr;
                            connections.back().server_ip = iph->daddr;
                            break;

                    }

                    connections.back().client_port = tcph->source;

                    // timestamp from first TCP packet
                    connections.back().timestamp.tv_sec = header->ts.tv_sec;
                    connections.back().timestamp.tv_usec = header->ts.tv_usec / 1000;
                }
                else {
                    for (int i = 0; i < connections.size(); i++) {
                        if ((connections[i].client_port == tcph->source) || (connections[i].client_port == tcph->dest)) {

                            connections[i].TCPpacketCount += 1; // <packets>

                            // filling payload (without ethernet header, ip header, tcp header)
                            for (u_int j = total_header_len; (j < header->caplen); j++) {
                                payload.push_back(data[j]);
                            }
                            // if payload is not empty means this could be TLS paket
                            if (!payload.empty()) {
                                for (int j = 0; j < payload.size(); j++) {
                                    // Finding record header in payload
                                    if (((payload[j] >= 0x14) && (payload[j] <= 0x17)) && (payload[j + 1] == 0x03) && ((payload[j + 2] >= 0x01) && payload[j + 2] <= 0x04)) {
                                        u_short length = (payload[j + 3] << 8) + payload[j + 4]; // length value from record header
                                        connections[i].bytes += length;

                                        // indicating Client hello and finding SNI in Client hello
                                        if ((payload[j] == 0x16) && (payload[j + 5] == 0x01) &&
                                            !connections[i].client_hello) { // payload[i+5] is start of handshake header, 01 is client hello
                                            clientHello = payload;
                                            connections[i].client_hello = true;
                                            find_SNI(clientHello, j, i);
                                        }

                                        // indicating Server hello
                                        if ((payload[j] == 0x16) && (payload[j + 5] == 0x02)) {
                                            connections[i].server_hello = true;
                                        }
                                    }
                                }
                            }
                            // first FIN (from client)
                            if (tcph->fin == 1 && ((connections[i].client_port == tcph->source) || (connections[i].client_port == tcph->dest))) {
                                connections[i].first_fin = true;
                            }
                            /* second FIN (from server)
                             * if RST has arrived and TLS handshake has been done, connection is printed
                             */
                            if ((tcph->fin == 1 && (connections[i].client_port == tcph->dest) && connections[i].first_fin && !connections[i].already_print) || (tcph->rst == 1) && !connections[i].already_print) { // server FIN (second)
                                connections[i].already_print = true;
                                if (connections[i].client_hello && connections[i].server_hello) {

                                    // timestamp from second FIN or RST paket to calculate duration
                                    double timestamp_lastTCP = (double) header->ts.tv_sec * 1000000000 + header->ts.tv_usec;
                                    int ip_version;
                                    switch (ntohs(eth_h->h_proto)) {
                                        case ETH_P_IPV6:
                                            ip_version = 6;
                                            break;

                                        case ETH_P_IP:
                                            ip_version = 4;
                                            break;

                                    }
                                    print_connection(i, timestamp_lastTCP, ip_version);
                                }
                            }
                        }
                    }
                }
                payload.clear();
            }
        }

    return 0;
}
