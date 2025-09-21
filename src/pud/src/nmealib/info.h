/* Minimal stub of <nmealib/info.h> to satisfy builds when nmealib is not
 * available on the build host. This provides an opaque NmeaInfo type used by
 * pud/posAvg.h. It intentionally omits any real parsing functionality.
 */

#ifndef _NMEALIB_INFO_H_STUB
#define _NMEALIB_INFO_H_STUB

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque placeholder for NMEA parsed information */
typedef struct {
  /* keep empty: consumers only store/copy this in our build */
  void *reserved;
} NmeaInfo;

#ifdef __cplusplus
}
#endif

#endif /* _NMEALIB_INFO_H_STUB */
