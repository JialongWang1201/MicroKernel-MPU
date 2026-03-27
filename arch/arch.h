/* arch/arch.h — MkdbgArch plugin interface
 *
 * Each supported MCU architecture is registered as a MkdbgArch entry in
 * arch_registry.c.  mkdbg selects the active arch via --arch <name>.
 *
 * To add a new architecture:
 *   1. Create arch/your_arch.c with a static decode_crash function.
 *   2. Define  const MkdbgArch your_arch_arch = { .name = "your-arch", ... };
 *   3. Add &your_arch_arch to the arches[] array in arch_registry.c.
 *   4. Add your_arch.c to the mkdbg-native source list in CMakeLists.txt.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "mkdbg.h"   /* WireCrashReport, WIRE_* constants */

/* MkdbgCrashReport aliases WireCrashReport for the arch layer. */
typedef WireCrashReport MkdbgCrashReport;

typedef struct {
    const char *name;  /* arch name matched by --arch flag, e.g. "cortex-m" */

    /*
     * Decode a raw crash payload into *out.
     *
     * raw: arch-defined binary blob (each implementation documents its format)
     * len: byte count of raw
     * out: pre-zeroed output struct; caller owns lifetime
     *
     * Returns 0 on success, -1 on error (bad length, parse failure, etc.).
     */
    int (*decode_crash)(const uint8_t *raw, size_t len, MkdbgCrashReport *out);
} MkdbgArch;

/* Returns the registered arch whose name matches (case-sensitive), or NULL. */
const MkdbgArch *mkdbg_arch_find(const char *name);
