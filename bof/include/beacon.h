#pragma once

/*
 * Minimal Beacon API surface used by the Iteration 1 BOF.
 * Keep this file compatible with the official Cobalt Strike BOF template.
 */
#include <windows.h>

#ifdef PH_HARNESS
#define PH_IMPORT
#else
#define PH_IMPORT __declspec(dllimport)
#endif

#define CALLBACK_OUTPUT       0x0
#define CALLBACK_OUTPUT_OEM   0x1e
#define CALLBACK_ERROR        0x0d
#define CALLBACK_OUTPUT_UTF8  0x20

PH_IMPORT void BeaconOutput(int type, const char *data, int len);
PH_IMPORT void BeaconPrintf(int type, const char *fmt, ...);

