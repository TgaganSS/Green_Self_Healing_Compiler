#include <cstdio>
#include <cstdlib>
#include "shapes.h"
#include "util.h"

int main(int argc, char** argv) {
    Shape s{3, 4};
    printf("area=%d perimeter=%d\n", area(s), perimeter(s));
    if (argc > 1) { greet(argv[1]); log_line(argv[1]); }
    int* p = new int[4];
    delete p;                        // CWE-762 new[] released with delete
    char* q = (char*)malloc(8);
    if (!q) return 1;
    free(q);
    free(q);                         // CWE-415 double free
    return 0;
}
