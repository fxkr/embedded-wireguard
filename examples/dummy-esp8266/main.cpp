#include <Arduino.h>

#include <wireguard.h>

void setup()
{
	if (0 != wg_init()) {
		// ignore
	}
}

void loop()
{
}