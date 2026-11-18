#include <iostream>
#include "mathx.h"

void run_a();
void run_b();

int main() {
    std::cout << square(3) << " " << cube(3) << "\n";
    run_a();
    run_b();
    return 0;
}
