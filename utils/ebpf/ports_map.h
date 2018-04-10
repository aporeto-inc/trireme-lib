#ifndef PORTS_MAP
#define PORTS_MAP

#include <stdint.h>

/* Account on a per flow basis. Assume source is external and dest
 * is local in the map. */
struct ports_key {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t source;
	uint16_t dest;
};

struct ports_value {
	uint64_t bytes;
	uint64_t fin;
};

#endif
