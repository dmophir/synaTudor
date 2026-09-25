#ifndef TUDOR_MOC_PYEMBED_H
#define TUDOR_MOC_PYEMBED_H

#include <glib.h>

/* Thin C API over an embedded CPython interpreter that drives pydrv's SensorMatcher /
 * SensorDB2. Every function acquires the Python GIL internally (via PyGILState), so they
 * are safe to call from either fprintd's main thread or an operation worker thread. On a
 * Python-side failure they set *error (domain FP_DEVICE_ERROR) and return FALSE / NULL.
 *
 * The "handle" is the opaque object returned by pyembed_open() (a Python dict holding the
 * sensor/comm/matcher/db2); it is passed back into every other call. */

gboolean pyembed_global_init(GError **error);
void     pyembed_global_shutdown(void);

gpointer pyembed_open(int bus, int addr, gchar **sensor_id_hex_out, GError **error);
gboolean pyembed_close(gpointer handle, GError **error);

/* number of on-chip templates, or -1 on error */
gint     pyembed_db_num_templates(gpointer handle, GError **error);

gboolean pyembed_enroll_start(gpointer handle, GError **error);
void     pyembed_enroll_end(gpointer handle);   /* best-effort; never fails hard */

/* capture one frame then add_image, in a single pydrv call (mirrors enroll_loop body):
 *   1 = image added (progress/tuid out), 0 = no finger, -1 = cancelled, -2 = error */
gint     pyembed_enroll_step(gpointer handle, double budget_s, gint *progress, guint8 tuid[16], gboolean *have_tuid, GError **error);

/* commit the just-enrolled template; returns the STABLE parent-user key (16B) in out_key,
 * which is what the FpPrint is bound to (the template tuid churns under adaptive update). */
gboolean pyembed_enroll_commit(gpointer handle, const guint8 tuid[16], const char *user_id_str, guint8 out_key[16], GError **error);

/* capture one frame then identify against the given TUID set (concatenated 16B each;
 * verify=1 TUID, identify=N, empty=>all), in a single pydrv call. Returns:
 *   1 = finger processed, 0 = no finger, -1 = cancelled, -2 = error.
 * On code==1, *matched / tuid / *score are set. */
gint     pyembed_verify_once(gpointer handle, double budget_s, const guint8 *tuids_blob, gsize blob_len, gboolean *matched, guint8 tuid[16], guint32 *score, GError **error);

/* fills *tuids_out with a GArray of 16-byte TUIDs (caller g_array_unref) */
gboolean pyembed_list_templates(gpointer handle, GArray **tuids_out, GError **error);
gboolean pyembed_delete_template(gpointer handle, const guint8 tuid[16], GError **error);

/* set/clear the wrapper's cooperative cancel flag (acquires GIL) */
void     pyembed_set_cancel(gboolean v);

#endif
