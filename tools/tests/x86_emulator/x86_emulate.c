#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <public/xen.h>

#define cpu_has_amd_erratum(nr) 0

#include "x86_emulate/x86_emulate.h"
#include "x86_emulate/x86_emulate.c"
