#include <stdint.h>
#define F (1 << 14)

// 헤더 파일에 함수를 구현하므로, thread.c 이외에서 include할 경우 에러가 발생할 수 있습니다.

int int_to_fp (int n);
int fp_to_int (int x);
int fp_to_int_round (int x);
int add_fp (int x, int y);
int sub_fp (int x, int y);
int add_mixed (int x, int n);
int sub_mixed (int x, int n);
int mult_fp (int x, int y);
int mult_mixed (int x, int n);
int div_fp (int x, int y);
int div_mixed (int x, int n);

int int_to_fp (int n) {
    return n * F;
}

int fp_to_int (int x) {
    return x / F;
}

int fp_to_int_round (int x) {
    if (x >= 0) return (x + F / 2) / F;
    else return (x - F / 2) / F;
}

int add_fp (int x, int y) {
    return x + y;
}

int sub_fp (int x, int y) {
    return x - y;
}

int add_mixed (int x, int n) {
    return x + n * F;
}

int sub_mixed (int x, int n) {
    return x - n * F;
}

int mult_fp (int x, int y) {
    return ((int64_t) x) * y / F;
}

int mult_mixed (int x, int n) {
    return x * n;
}

int div_fp (int x, int y) {
    return ((int64_t) x) * F / y;
}

int div_mixed (int x, int n) {
    return x / n;
}