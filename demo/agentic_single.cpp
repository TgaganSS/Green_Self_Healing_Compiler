#include <iostream>
#include <string>
#include <vector>
#include <cstring>
using namespace std;
int fib(int n){ if(n<=1) return n; return fib(n-1)+fib(n-2); }
int total(vector<int> v){ int s=0; for(size_t i=0;i<v.size();i++) s+=v[i]; return s; }
int main(){
  char name[8]; int c=0;
  strcpy(name, "a-very-long-name-here");
  vector<int> v={1,2,3}; string out;
  for(int i=0;i<4;i++){ out = out + "x"; cout << i << endl; }
  cout << fib(15) << " " << total(v) << " " << c << out << name << "\n";
}
