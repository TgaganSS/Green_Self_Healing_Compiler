#include <iostream>
#include <string>
#include <vector>
#include "report.h"
using namespace std;
int fib(int n) { if (n <= 1) return n; return fib(n - 1) + fib(n - 2); }
int sum(vector<int> v) { int s = 0; for (size_t i = 0; i < v.size(); i++) s += v[i]; return s; }
int main() {
    vector<int> v = {1, 2, 3, 4};
    for (int i = 0; i < 3; i++) { cout << "fib(" << i * 10 << ") = " << fib(i * 10) << endl; }
    cout << "sum=" << sum(v) << "\n";
    cout << describe({0, 0}, {3, 4}) << "\n";
}
