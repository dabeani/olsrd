/* Minimal stub of <nmealib/info.h> kept inside the plugin to avoid touching
 * the top-level src/ tree. This provides an opaque NmeaInfo type used by
 * headers that reference <nmealib/info.h> when building the plugin.
 */

#ifndef _NMEALIB_INFO_H
#define _NMEALIB_INFO_H

typedef struct {
  void *reserved;
} NmeaInfo;

#endif /* _NMEALIB_INFO_H */
