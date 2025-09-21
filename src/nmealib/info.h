/* Minimal stub of <nmealib/info.h> placed under src/ so that includes like
 * #include <nmealib/info.h> resolve when compiling plugins against the
 * in-tree headers. Matches the minimal opaque definition used previously.
 */

#ifndef _NMEALIB_INFO_H
#define _NMEALIB_INFO_H

typedef struct {
  void *reserved;
} NmeaInfo;

#endif /* _NMEALIB_INFO_H */
