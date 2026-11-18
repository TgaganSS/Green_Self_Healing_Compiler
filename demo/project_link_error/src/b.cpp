#include <iostream>

int helper() { return 2; }          // same function defined in a.cpp as well
void run_b() { std::cout << helper() << "\n"; }
