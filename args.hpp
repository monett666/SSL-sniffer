/**
 * VUT FIT Projekt ISA 2020
 * Varianta: Monitoring SSL spojení
 * Autor: Monika Burešová
 * Login: xbures32
 */

#ifndef ARGS_H
#define ARGS_H

#include <iostream>
#include <getopt.h>
#include <ifaddrs.h>

using namespace std;

void get_ifaces();
void args(int argc, char **argv, bool *iface, string *given_iface, bool *file, string *given_file);
#endif