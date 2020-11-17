/**
 * VUT FIT Projekt ISA 2020
 * Varianta: Monitoring SSL spojení
 * Autor: Monika Burešová
 * Login: xbures32
 */

#include "args.hpp"
#include <getopt.h>
#include <ifaddrs.h>

using namespace std;
string available_ifaces = "";

/*
 * get interfaces to print them in help
 */
void get_ifaces() {
    struct ifaddrs *addrs, *tmp;

    getifaddrs(&addrs);
    tmp = addrs;

    while(tmp) {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
            available_ifaces = available_ifaces + " " + tmp->ifa_name;
        tmp = tmp->ifa_next;
    }


    freeifaddrs(addrs);
}

/*
 * parsing arguments with getopt()
 */
void args(int argc, char **argv, bool *iface, string *given_iface, bool *file, string *given_file) {
    int opt;
    get_ifaces();
    string help = "Usage: ./sslsniff [-r file] [-i interface]\n"
                  "       for interface sniffing use sudo\n"
                  "Output: <timestamp>,<client ip>,<client port>,<server ip>,<SNI>,<bytes>,<packets>,<duration sec>\n"
                  "        <bytes> - sum of SSL bytes\n"
                  "        <packets> - sum of TCP packets of SSL session\n"
                  "Available interfaces:" + available_ifaces;


    if (argc == 1) {
        cerr << "Arguments needed" << endl;
        cout << help << endl;
        exit(1);
    }

    if (argc > 3) {
        cerr << "Too many arguments" << endl;
        cout << help << endl;
        exit(1);
    }

    while ((opt = getopt (argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r':
                *file = true;
                *given_file = optarg;
                break;
            case 'i':
                *iface = true;
                *given_iface = optarg;
                break;

            default:
                cout << help << endl;
                exit(1);
        }
    }

}