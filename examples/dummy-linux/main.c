#include <stdio.h>

#include <wireguard.h>

int main(int argc, char **argv)
{
	if (0 != wg_init()) {
		return 1;
	}

	printf("hello, world\n");

	return 0;
}