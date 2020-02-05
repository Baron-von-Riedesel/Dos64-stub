
/* small test program to test
 * - dos64stub compatibility with MS C.
 * - the micro-printf implementation in printf.asm
 */

#include <stdio.h>

int main() {

	/*
	 * vararg arguments are expanded to 32-bit if they are integers.
	 * addresses are always expanded to 64-bit.
	 */

	unsigned char uc = 'u';
	unsigned short uw = 12;
	unsigned ud = 123456;
	unsigned long long uq = 123456789012345;
	char sc = 's';
	short sw = -12;
	int sd = -123456;
	long long sq = -123456789012345;

	printf( "values 'u',12,123456 | 's',-12,-123456 (%%u | %%d): %u %u %u | %d %d %d\n", uc, uw, ud, sc, sw, sd );
	printf( "char/short/int, cast to long long, %%u | %%d: %u %u %u | %d %d %d\n", (unsigned long long)uc, (unsigned long long)uw, (unsigned long long)ud, (long long)sc, (long long)sw, (long long)sd );
	printf( "char/short/int, cast to long long, %%lu | %%ld: %lu %lu %lu | %ld %ld %ld\n", (unsigned long long)uc, (unsigned long long)uw, (unsigned long long)ud, (long long)sc, (long long)sw, (long long)sd );
	printf( "char/short/int, cast to long long, %%llu | %%lld: %llu %llu %llu | %lld %lld %lld\n", (unsigned long long)uc, (unsigned long long)uw, (unsigned long long)ud, (long long)sc, (long long)sw, (long long)sd );
	printf( "long long, %%u %%d | %%lu %%ld: %u %d | %lu %ld\n", uq, sq, uq, sq );
	printf( "long long, %%llu %%lld: %llu %lld\n", uq, sq );
	printf( "pointers: %p %p %p %p %p %p\n", &uc, &uw, &ud, &sc, &sw, &sd );
	printf( "string: >%s<\n", "this is TestC" );
	return 0;
}
