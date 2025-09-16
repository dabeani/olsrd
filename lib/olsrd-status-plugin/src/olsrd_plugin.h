/* Minimal stub of olsrd_plugin.h for local builds/testing when olsrd headers
 * are not installed on the system. This provides only the symbols used by
 * the olsrd-status-plugin and is intentionally small and non-invasive.
 */
#ifndef OLSRD_PLUGIN_H
#define OLSRD_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* addon passed to parameter setters; real olsrd has a richer type but plugin
 * only uses it as an opaque argument and marks it unused, so a minimal type
 * is fine for builds.
 */
typedef struct set_plugin_parameter_addon {
  int _dummy;
} set_plugin_parameter_addon;

typedef int (*set_plugin_parameter_fn)(const char *value, void *data, set_plugin_parameter_addon addon);

struct olsrd_plugin_parameters {
  const char *name;
  set_plugin_parameter_fn set_plugin_parameter;
  void *data;
  set_plugin_parameter_addon addon;
};

/* Lifecycle functions that the plugin implements/uses. Signatures kept
 * compatible with the plugin's definitions in this tree.
 */
void olsrd_get_plugin_parameters(const struct olsrd_plugin_parameters **params, int *size);
int olsrd_plugin_interface_version(void);
int olsrd_plugin_init(void);
void olsrd_plugin_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* OLSRD_PLUGIN_H */
