#include "shapes.h"

int area(const Shape& s) { return s.w * s.h; }
int perimeter(const Shape& s) { return 2 * (s.w + s.h); }
