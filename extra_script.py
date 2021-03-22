"""
PlatformIO extra script.

https://docs.platformio.org/en/latest/projectconf/advanced_scripting.html
"""

Import("env")

env.Replace(SRC_FILTER=[
    "+<*>",
    "-<.git/>",
    "-<.svn/>",
    "-<example/>",
    "-<examples/>",
    "-<test/>",
    "-<tests/>",
    "-<wireguard/crypto_backend_*>",
    "-<wireguard/platform_backend_*>",
])

if env.get("PIOPLATFORM") == "native":
    env.Append(SRC_FILTER=[
        "+<wireguard/crypto_backend_sodium.c>",
        "+<wireguard/platform_backend_unix.c>",
    ])

elif env.get("PIOPLATFORM") == "espressif8266":
    env.Append(SRC_FILTER=[
        "+<wireguard/crypto_backend_arduinolib.cpp>",
        "+<wireguard/platform_backend_arduino.c>",
    ])
