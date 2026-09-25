#ifndef TUDOR_MOC_H
#define TUDOR_MOC_H

#include <stdbool.h>
#include <glib.h>
#include "drivers_api.h"

/*
 * Synaptics Tudor Match-on-Chip (MOC) libfprint TOD driver.
 *
 * Base class: FpDevice (NOT FpImageDevice) -- the sensor matches on-chip and never
 * returns a raw image to the host. Enroll/verify/identify/list/delete/clear-storage are
 * implemented by embedding CPython and driving the validated pydrv SensorMatcher /
 * SensorDB2 over the already-established TLS channel (see pydrv/tudor/sensor/moc.py,
 * db2.py). All blocking pydrv work runs on a per-operation worker GThread; results and
 * progress are marshalled back to fprintd's GMainContext via g_idle so that every
 * fpi_device_* call happens on the main thread.
 *
 * FpPrint <-> on-chip template mapping: the FpPrint "fpi-data" GVariant is JUST the
 * 16-byte stable parent-USER uid ("ay") -- NOT the template tuid, and NOT the old
 * (y @ay @ay) tuple. The on-chip template tuid churns via the adaptive update after a
 * matching verify, and the WINBIO user-id is not host-readable, so neither can be a
 * stable/reproducible host key. Keying on the user uid makes an enrolled print and its
 * `list` counterpart compare equal (fp_print_equal over the whole variant) so fprintd
 * does not prune it. verify/identify resolve the matched template back to its parent
 * user; the sensor's DB2 store is authoritative for what is enrolled. See device.c
 * (tudor_print_data / tudor_print_get_tuid) for the implementation.
 */

#define TUDOR_MOC_VID 0x06cb
#define TUDOR_MOC_PID_00BC 0x00bc
#define TUDOR_MOC_PID_00A9 0x00a9

/* Enroll: the sensor drives progress 12..100 over ~8 add-image steps; we advertise this
 * many libfprint enroll stages and map stat.progress onto them (ceil), so the reported
 * stage reaches the max exactly when progress hits 100. */
#define TUDOR_MOC_ENROLL_STAGES 15

/* Minimum score to accept a match. The firmware already gates match vs. 0x0509 no-match
 * internally, so 0 means "trust the firmware's decision"; raise to add a host-side floor. */
#define TUDOR_MOC_SCORE_THRESHOLD 0

#define TUID_SIZE 16

struct _FpiDeviceTudorMoc {
  FpDevice parent;

  /* Embedded-Python handle returned by wrapper open_device() (a dict of
   * sensor/comm/matcher/db2). NULL when closed. Touched only under the Python GIL. */
  gpointer py_handle;
  gboolean opened;

  gchar sensor_id_hex[40];        /* filled at open from sensor.id.hex() */

  /* Current operation worker. Exactly one op runs at a time (libfprint serialises). */
  GThread *worker;
  guint enroll_stage;             /* stages reported so far (main thread) */

  /* Cancellation: set by the cancel vfunc; read by the worker/pydrv poll loop via the
   * embedded wrapper's cancel flag. */
  volatile gboolean canceling;
};

G_DECLARE_FINAL_TYPE(FpiDeviceTudorMoc, fpi_device_tudor_moc, FPI, DEVICE_TUDOR_MOC, FpDevice)
#define FPI_TYPE_DEVICE_TUDOR_MOC (fpi_device_tudor_moc_get_type())

#endif
