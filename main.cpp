/**
 * VUT FIT Projekt ISA 2020
 * Varianta: Monitoring SSL spojení
 * Autor: Monika Burešová
 * Login: xbures32
 */

// https://github.com/x00Pavel/SSL-monitor
// http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session/
// https://stackoverflow.com/questions/35385189/how-to-identify-initial-packet-in-tcp-3-way-handshake
// https://www.cloudflare.com/learning/ssl/what-is-sni/
// https://stackoverflow.com/questions/17832592/extract-server-name-indication-sni-from-tls-client-hello

#include <iostream>
#include <vector>
#include<iterator>
#include <algorithm>
#include <string>
#include "args.hpp"
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>




#include <sys/time.h>


#include <ifaddrs.h>

#include <sys/types.h>

#include <ifaddrs.h>

#include <net/ethernet.h>

#include <arpa/inet.h> // for inet_ntoa()

using namespace std;

bool file = false;
bool iface = false;

typedef struct TLS_conn {
    unsigned int timestamp_sec;
    unsigned int timestamp_milisec;
    bool client_hello = false;
    bool server_hello = false;
    bool first_fin = false;
    u_int TCPpacketCount = 0; // TCP packets counter
    uint32_t client_ip;
    uint32_t server_ip;
    struct in6_addr client_ip6{};
    struct in6_addr server_ip6{};
    uint16_t client_port;
    vector<u_char> SNI;
    u_int bytes = 0;
    double duration;
    bool already_print = false;
//    double timestamp_lastTCP, timestamp, duration;

} TLS_connection;

vector<TLS_connection> connections;


//https://www.tcpdump.org/pcap.html


vector<u_char> find_SNI(vector<u_char> clientHello, vector<u_char>SNI, int record_header_index) {

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
            int SN_length = (clientHello[i+7] << 8) + clientHello[i+8];

            for (int j = 0; j < SN_length; j++) {
                SNI.push_back(clientHello[i+9+j]);
            }
        }
        else {
            concrete_extension_length = (clientHello[i+2] << 8) + clientHello[i+3];
        }
    }
    return SNI;

}




/*
 * Function converts timestamp from epoch (1970) time to human date format and print it.
 * https://github.com/sidsingh78/EPOCH-to-time-date-converter/blob/master/epoch_conv.c
 */
void print_timestamp(unsigned int timestamp_sec, unsigned int timestamp_milisec) {

    static unsigned char month_days[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

    unsigned char ntp_hour, ntp_minute, ntp_day, ntp_month, leap_days, ntp_seconds;

    unsigned short temp_days;

    unsigned int ntp_year, days_since_epoch, day_of_year;

    unsigned int epoch = timestamp_sec;

    leap_days = 0;

    // UTC time zone to CEST (+2h)
    epoch += 7200;

    ntp_seconds = epoch % 60;
    epoch /= 60;
    ntp_minute = epoch % 60;
    epoch /= 60;
    ntp_hour = epoch % 24;
    epoch /= 24;

    days_since_epoch = epoch; // number of days since epoch

    ntp_year = 1970 + (days_since_epoch/365); // ball parking year, may not be accurate!

    int i;
    for (i = 1972; i < ntp_year; i += 4) // calculating number of leap days since epoch
        if(((i%4 == 0) && (i%100 != 0)) || (i%400 == 0)) leap_days++;

    ntp_year = 1970 + ((days_since_epoch - leap_days)/365); // calculating accurate current year by (days_since_epoch - extra leap days)
    day_of_year = ((days_since_epoch - leap_days)%365)+1;

    if(((ntp_year%4 == 0) && (ntp_year%100 != 0)) || (ntp_year%400 == 0)) {
        month_days[1] = 29; // February = 29 days for leap years
    }
    else month_days[1] = 28;

    temp_days = 0;

    for (ntp_month = 0; ntp_month <= 11; ntp_month++) { // calculating current month
        if (day_of_year <= temp_days) break;
        temp_days = temp_days + month_days[ntp_month];
    }

    temp_days = temp_days - month_days[ntp_month-1]; // calculating current day
    ntp_day = day_of_year - temp_days;

    printf("%4d-%02d-%02d", ntp_year, ntp_month, ntp_day); // prints date
    printf(" %02d:%02d:%02d.%06u,", ntp_hour, ntp_minute, ntp_seconds, timestamp_milisec); // prints time

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

void print_connection(int i, double timestamp_lastTCP, int ip_version) {
    double timestamp;

    timestamp = (double) connections[i].timestamp_sec * 1000000000 + connections[i].timestamp_milisec * 1000;

    connections[i].duration = ((double) timestamp_lastTCP - (double) timestamp) / 1000000000;

    print_timestamp(connections[i].timestamp_sec, connections[i].timestamp_milisec);

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
//    u_int TCPpacketCount = 0; // TCP packets counter

//    int bytes = 0;

//    bool client_hello = false;
//    bool server_hello = false;
//    bool first_fin = false;



    vector<u_char> payload;
    vector<u_char> clientHello;
    vector<u_char> SNI;


//    unsigned int timestamp_sec;
//    unsigned int timestamp_milisec;

    char errbuff[PCAP_ERRBUF_SIZE];

    // parse arguments
    args(argc, argv, &iface, &given_iface, &file, &given_file);

    /* FILE SNIFFING
     * =======================================================================
     */
    if (file) {
        cout << "work with file " + given_file << endl;

        //https://www.rhyous.com/2011/11/13/how-to-read-a-pcap-file-from-wireshark-with-c/

        pcap_t *pcap = pcap_open_offline_with_tstamp_precision(given_file.c_str(), PCAP_TSTAMP_PRECISION_NANO, errbuff);
        if (pcap == nullptr) {
            cerr << "Could not open file: " << given_file << endl;
        }

        struct pcap_pkthdr *header; // create header object
        const u_char *data; // create character array using a u_char



        while (pcap_next_ex(pcap, &header, &data) >= 0) {



            auto *eth_h = (struct ethhdr *) data;
            unsigned short ethhrdlen = sizeof(struct ethhdr);
            unsigned short iphdrlen;
            unsigned int tcphdrlen;

//            if (ntohs(eth_h->h_proto) == ETH_P_8021Q) {
//                ethhrdlen += 4;
//            }

            auto *ip6h = (struct ip6_hdr *) (data + ethhrdlen); // data/buffer?
            auto *iph = (struct iphdr *) (data + ethhrdlen);

//            uint32_t client_ip;
//            uint32_t server_ip;
//
//            struct in6_addr client_ip6{};
//            struct in6_addr server_ip6{};

//            uint16_t client_port;


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
                 */
                if ((tcph->ack == 0) && (tcph->syn) == 1) { // first part of threeway handshake


//                    SNI.clear();
                    TLS_connection conn;
                    connections.push_back(conn);
//                    SNI.clear();
//                    bytes = 0;
                    connections.back().TCPpacketCount = 1;
//                    first_fin = false;
//                    client_hello = false;
//                    server_hello = false;

                    switch (ntohs(eth_h->h_proto)) {
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

                    // timestamp from ethernet header
                    connections.back().timestamp_sec = header->ts.tv_sec;
                    connections.back().timestamp_milisec = header->ts.tv_usec / 1000;





                }

                else {
                    for (int i = 0; i < connections.size(); i++) {
                        if ((connections[i].client_port == tcph->source) || (connections[i].client_port == tcph->dest)) {
//                        printf("\nthis is still the same session | packet: %d \n", TCPpacketCount);
//
//                        printf("FIN FLAG: %d\n", tcph->fin );
//                        printf("ACK FLAG: %d\n", tcph->ack );
//                        printf("SYN FLAG: %d\n", tcph->syn );
                            connections[i].TCPpacketCount += 1; //=======================================<packets>

                            // PAYLOAD

                            for (u_int j = total_header_len; (j < header->caplen); j++) {
                                //if ((j % 16) == 0) printf("\n");
                                //printf("%.2x ", data[j]);
                                payload.push_back(data[j]);
                            }

                            if (!payload.empty()) {
                                for (int j = 0; j < payload.size(); j++) {
                                    // printing payload

//                                if ((i % 16) == 0) printf("\n");
//                                printf("%.2x ", payload[i]);

                                    // Finding record header in payload
                                    if (((payload[j] >= 0x14) && (payload[j] <= 0x17)) && (payload[j + 1] == 0x03) && ((payload[j + 2] >= 0x01) && payload[j + 2] <= 0x04)) {
                                        u_short length = (payload[j + 3] << 8) + payload[j + 4]; // length value from record header
                                        connections[i].bytes += length;

                                        // indicating Client hello
                                        if ((payload[j] == 0x16) && (payload[j + 5] == 0x01)) { // payload[i+5] is start of handshake header, 01 is client hello
                                            clientHello = payload;
                                            connections[i].client_hello = true;
                                            connections[i].SNI = find_SNI(clientHello, SNI, j);
                                        }
                                        // indicating Server hello
                                        if ((payload[j] == 0x16) && (payload[j + 5] == 0x02)) {
                                            connections[i].server_hello = true;
                                        }
                                    }
                                }

                            }

                            if (tcph->fin == 1 && (connections[i].client_port == tcph->source)) { // client FIN (first)
                                connections[i].first_fin = true;
                            }

                            if ((tcph->fin == 1 && (connections[i].client_port == tcph->dest) && connections[i].first_fin && !connections[i].already_print) || (tcph->rst == 1) && !connections[i].already_print) { // server FIN (second)

                                if (connections[i].client_hello && connections[i].server_hello) {
                                    connections[i].already_print = true;
                                    double timestamp_lastTCP = (double) header->ts.tv_sec * 1000000000 + (double) header->ts.tv_usec;
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
//
                                }


//                            SNI.clear();
//                            bytes = 0;
//                            TCPpacketCount = 0;
//                            client_hello = false;
//                            server_hello = false;
//                            first_fin = false;


                            }

                        }

                    }
                }


                payload.clear();

            }

        }
    }





    /* INTERFACE SNIFFFING
     * =======================================================================
     */

    if (iface)
        cout << "work with iface" << endl;

    return 0;
}
