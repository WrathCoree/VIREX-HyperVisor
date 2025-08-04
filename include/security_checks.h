#ifndef SECURITY_CHECKS_H
#define SECURITY_CHECKS_H

#include <ntddk.h>

// Status codes for custom security detections.
#define STATUS_DETECTED_PATCH ((NTSTATUS)0xC00002D3L)
#define STATUS_DETECTED_HOOK  ((NTSTATUS)0xC00002D4L)

// Public Function Prototypes
NTSTATUS VhCheckNtoskrnlPatches();
NTSTATUS VhCheckDriverObjects();

#endif
