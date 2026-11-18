#include <cstdio>
#include <cstring>
#include "util.h"

void greet(const char* name) {
    char buf[8];
    strcpy(buf, name);               // CWE-120 buffer overflow (attacker-controlled)
    printf("hello %s\n", buf);
}

void log_line(const char* msg) {
    printf(msg);                     // CWE-134 format string
}
