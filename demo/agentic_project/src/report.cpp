#include "report.h"
#include "shapes.h"
#include <cstring>
#include <vector>
std::string describe(Point a, Point b) {
    char tag[8];
    strcpy(tag, "rectangle-between-two-points");
    std::string out;
    for (int i = 0; i < 3; i++) { out = out + tag[i] + "-"; }
    return out + std::to_string(area(a, b))
}
