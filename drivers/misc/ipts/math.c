#include "math.h"
#include <linux/kernel.h>
/*
#define FACTOR 100000
#define TWO_PI (u32)M_PI*FACTOR
double sqrt(double arg )
{
  unsigned long x = (unsigned long)(arg * 1000000.0);
  x = int_sqrt(x);
  return (double)x / 1000.0;
}

float sqrtf(float arg )
{
  unsigned long x = (unsigned long)(arg * 10000.0);
  x = int_sqrt(x);
  return (float)x / 100.0;
}

float hypotf(float x, float y)
{
  double r = x*x + y*y;
  r = sqrt(r);
  return (float)r;
}

double sin(double arg)
{
  u32 rad = arg * FACTOR;

  return (double)fixp_sin32_rad(rad, TWO_PI);
}

double cos(double arg)
{
  u32 rad = arg * FACTOR;
  return (double)fixp_cos32_rad(rad, TWO_PI);
}

double m_arctan(double y, double x) {
    double theta = y / x;
    double theta2 = theta * theta;
    double theta3 = theta2 * theta;
    double theta5 = theta3 * theta2;
    double theta7 = theta5 * theta2;
    double theta9 = theta7 * theta2;
    return theta - theta3/3 + theta5 /5 - theta7 / 7 + theta9 /9;
}

double atan2(double y, double x) {
    if (y == 0 && x == 0)
      return 0;
    if (y == 0 && x > 0)
      return 0;
    if (y == 0 && x < 0)
      return M_PI;
    if (y > 0 && x == 0)
      return M_PI_2;
    if (y < 0 && x == 0)
      return - M_PI_2;
    if (y > 0 && x > 0){
        if (y == x)
          return M_PI_4;
        if (y > x)
          return M_PI_2 - m_arctan(x, y);
    }
    if (y > 0 && x < 0) {
        if (y == -x)
          return M_PI_2 + M_PI_4;
        if (y > -x)
          return M_PI_2 + m_arctan(-x, y);
        return M_PI - m_arctan(y, -x);
    }
    if (y < 0 && x < 0) {
        if (y == x)
          return - (M_PI_2 + M_PI_4);
        if (y < x)
          return - (M_PI_2 + m_arctan(x, y));
        return - M_PI + m_arctan(-y, -x);
    }
    if (y < 0 && x > 0) {
        if (y == -x)
          return - M_PI_4;
        if (-y > x)
          return - M_PI_2 + m_arctan(x, -y);
    }
    return m_arctan(y, x);
}

float atan2f(float y, float x)
{
  return (float)atan2(y,x);
}

float roundf(float arg)
{
    int _ceil = arg;
    float mid = _ceil + 0.5;
    return arg >=mid ? _ceil + 1.0 : _ceil;
}

int32_t fixed_exp2 (int32_t a)
{
    int32_t i, f, r, s;
    i = (a + 0x8000) & ~0xffff; // 0.5
    f = a - i;
    s = ((15 << 16) - i) >> 16;
    r = 0x00000e20;                 // 5.5171669058037949e-2
    r = (r * f + 0x3e1cc333) >> 17; // 2.4261112219321804e-1
    r = (r * f + 0x58bd46a6) >> 16; // 6.9326098546062365e-1
    r = r * f + 0x7ffde4a3;         // 9.9992807353939517e-1
    return (uint32_t)r >> s;
}
*/
int fix_hypot(int x, int y)
{
  return int_sqrt(x*x + y*y);
}

int fix_round_uint(int x){
  int tmp = x / 10 * 10;
  return x - tmp > 4 ? tmp + 10 : tmp;
}

int fix_round(int x){
  return x >= 0 ? fix_round_uint(x) : -1 * fix_round_uint(-1 * x);
}

int fix_div_round(int x, int y)
{
  return fix_round(x * 10 / y) / 10;
}

int fix_div_long_round(long x, long y)
{
  int tmp = x * 10 /y;
  return fix_round(tmp)/10;
}

int fix_zoom(int x, int origin_max, int new_max)
{
  return fix_round( x * new_max / origin_max);
}
