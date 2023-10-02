# ExpressLRS WIFI Joystick for Linux

Based on https://github.com/GrantEdwards/uinput-joystick-demo

Receives data from a ExpressLRS TX Module https://github.com/ExpressLRS/ExpressLRS via UDP and creates a Joystick device

## Building

Install cmake + libcurl

```
cmake .
cmake --build .
./elrs-wifi-joystick
```