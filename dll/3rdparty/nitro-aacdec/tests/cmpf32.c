/*
 * cmpf32 <a.raw> <b.raw> [tolerance]: compares two raw float32 files (the decoder's output and FFmpeg's own decode of the
 * same stream). Prints the lengths (in floats), the largest absolute difference over the common length and the rms of b, and
 * "CMPRESULT PASS" when the lengths are equal and the largest difference is below the tolerance (default 1e-5), else FAIL.
 * LICENSE: LGPL-2.1-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int main(int argc, char **argv)
{
    FILE *a, *b;
    float x, y;
    long na, nb, n = 0;
    double mx = 0, ss = 0, tol = argc > 3 ? atof(argv[3]) : 1e-5;

    if (argc < 3) { fprintf(stderr, "usage: cmpf32 a.raw b.raw [tolerance]\n"); return 2; }
    a = fopen(argv[1], "rb");
    b = fopen(argv[2], "rb");
    if (!a || !b) { printf("CMP open failed\nCMPRESULT FAIL\n"); return 2; }
    fseek(a, 0, SEEK_END); na = ftell(a) / 4; fseek(a, 0, SEEK_SET);
    fseek(b, 0, SEEK_END); nb = ftell(b) / 4; fseek(b, 0, SEEK_SET);
    while (n < na && n < nb && fread(&x, 4, 1, a) == 1 && fread(&y, 4, 1, b) == 1)
    {
        double d = fabs((double)x - y);
        if (d > mx) mx = d;
        ss += (double)y * y;
        n++;
    }
    printf("CMP floats a=%ld b=%ld common=%ld maxabsdiff=%.3e rms_b=%.4f\n", na, nb, n, mx, n ? sqrt(ss / n) : 0.0);
    printf("CMPRESULT %s\n", (na == nb && n && mx < tol) ? "PASS" : "FAIL");
    return 0;
}
