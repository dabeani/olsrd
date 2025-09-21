/* Forwarding stub to make "pud/src/receiver.h" available when building
 * plugins that include core headers which reference it via
 * #include "pud/src/receiver.h" in src/olsr_cfg.h.
 *
 * This file simply includes the authoritative header in lib/pud/src.
 * It keeps the build rules unchanged and avoids editing Makefiles.
 */

#ifndef _PUD_SRC_RECEIVER_H_STUB
#define _PUD_SRC_RECEIVER_H_STUB

#include "../../../lib/pud/src/receiver.h"

#endif /* _PUD_SRC_RECEIVER_H_STUB */
