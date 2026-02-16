#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef struct PhalanxEngine PhalanxEngine;

PhalanxEngine *phalanx_engine_new(const char *storage_path);

void phalanx_engine_free(PhalanxEngine *ptr);
