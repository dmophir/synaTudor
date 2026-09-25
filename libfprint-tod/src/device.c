#include <gio/gio.h>
#include "tudor-moc.h"
#include "pyembed.h"

/*
 * FpDevice-based Match-on-Chip driver. All blocking pydrv work happens on a per-operation
 * worker GThread; the worker never touches libfprint objects directly -- it marshals
 * progress / finger-status / completion onto fprintd's main context via g_idle, so every
 * fpi_device_* call runs on the main thread.
 */

G_DEFINE_TYPE(FpiDeviceTudorMoc, fpi_device_tudor_moc, FP_TYPE_DEVICE)

/* TOD entry point: libfprint calls this to obtain the driver's GType. */
GType fpi_tod_shared_driver_get_type(void) {
  return FPI_TYPE_DEVICE_TUDOR_MOC;
}

static const FpIdEntry id_table[] = {
  { .vid = TUDOR_MOC_VID, .pid = TUDOR_MOC_PID_00BC },
  { .vid = TUDOR_MOC_VID, .pid = TUDOR_MOC_PID_00A9 },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

/* ------------------------------------------------------------------ *
 *  FpPrint <-> on-chip template mapping
 *    fpi-data = (y @ay @ay) = (finger_index, tuid[16], user_id)
 * ------------------------------------------------------------------ */

/* fpi-data is JUST the 16-byte stable user key, as a byte array ("ay"). It deliberately
 * excludes the finger index and the WINBIO user-id string: the on-chip payload is not
 * host-readable, so `list` cannot reconstruct those, and fprintd's device-sync compares
 * the whole fpi-data GVariant (fp_print_equal). Keying only on the reproducible user UID
 * makes an enrolled print and its `list` counterpart compare equal (no false prune). */
static GVariant *tudor_print_data(const guint8 key[16]) {
  return g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, key, TUID_SIZE, 1);
}

static gboolean tudor_print_get_tuid(FpPrint *print, guint8 key_out[16]) {
  g_autoptr(GVariant) data = NULL;
  gsize n = 0;
  const guint8 *p;

  if (!print) return FALSE;
  g_object_get(print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type(data, G_VARIANT_TYPE("ay"))) return FALSE;
  p = g_variant_get_fixed_array(data, &n, 1);
  if (n != TUID_SIZE) return FALSE;
  memcpy(key_out, p, TUID_SIZE);
  return TRUE;
}

static FpPrint *tudor_new_print_for_tuid(FpDevice *dev, const guint8 key[16], const char *user_id) {
  FpPrint *print = fp_print_new(dev);
  fpi_print_set_type(print, FPI_PRINT_RAW);
  fpi_print_set_device_stored(print, TRUE);
  g_object_set(print, "fpi-data", tudor_print_data(key), NULL);
  if (user_id && *user_id)
    fpi_print_fill_from_user_id(print, user_id);
  return print;
}

/* ------------------------------------------------------------------ *
 *  worker/main marshalling helpers
 * ------------------------------------------------------------------ */

typedef struct {
  FpiDeviceTudorMoc *self;
  GError *error;                 /* transferred to main on completion */

  /* open */
  int usb_bus, usb_addr;

  /* enroll */
  guint8 tuid[16];
  gboolean have_tuid;
  gchar *user_id;                /* fprintd-generated id (built on main thread) */
  gint last_stage;              /* last progress stage posted (monotonic guard) */

  /* verify / identify */
  gboolean got_finger;
  gboolean matched;
  guint8 match_tuid[16];
  guint32 score;
  GArray *target_tuids;          /* 16-byte TUIDs to match against (verify=1, identify=N) */

  /* list */
  GArray *tuids;                 /* 16-byte elements */
} OpCtx;

static OpCtx *opctx_new(FpiDeviceTudorMoc *self) {
  OpCtx *c = g_new0(OpCtx, 1);
  c->self = self;
  return c;
}

static void opctx_free(OpCtx *c) {
  g_clear_error(&c->error);
  g_free(c->user_id);
  if (c->tuids) g_array_unref(c->tuids);
  if (c->target_tuids) g_array_unref(c->target_tuids);
  g_free(c);
}

/* progress marshalling (enroll) */
typedef struct { FpiDeviceTudorMoc *self; guint stage; } ProgressMsg;
static gboolean idle_progress(gpointer d) {
  ProgressMsg *m = d;
  fpi_device_enroll_progress(FP_DEVICE(m->self), m->stage, NULL, NULL);
  g_free(m);
  return G_SOURCE_REMOVE;
}
static void post_progress(FpiDeviceTudorMoc *self, guint stage) {
  ProgressMsg *m = g_new0(ProgressMsg, 1);
  m->self = self; m->stage = stage;
  g_idle_add(idle_progress, m);
}

/* finger-status marshalling */
typedef struct { FpiDeviceTudorMoc *self; FpFingerStatusFlags add, del; } FingerMsg;
static gboolean idle_finger(gpointer d) {
  FingerMsg *m = d;
  fpi_device_report_finger_status_changes(FP_DEVICE(m->self), m->add, m->del);
  g_free(m);
  return G_SOURCE_REMOVE;
}
static void post_finger(FpiDeviceTudorMoc *self, FpFingerStatusFlags add, FpFingerStatusFlags del) {
  FingerMsg *m = g_new0(FingerMsg, 1);
  m->self = self; m->add = add; m->del = del;
  g_idle_add(idle_finger, m);
}

static GError *cancelled_error(void) {
  return g_error_new_literal(G_IO_ERROR, G_IO_ERROR_CANCELLED, "operation cancelled");
}

/* ------------------------------------------------------------------ *
 *  open / close
 * ------------------------------------------------------------------ */

static gboolean idle_open_done(gpointer d) {
  OpCtx *c = d;
  FpiDeviceTudorMoc *self = c->self;
  g_thread_join(self->worker);
  self->worker = NULL;
  if (!c->error) self->opened = TRUE;
  fpi_device_open_complete(FP_DEVICE(self), c->error);
  c->error = NULL;
  opctx_free(c);
  return G_SOURCE_REMOVE;
}

static gpointer open_worker(gpointer data) {
  OpCtx *c = data;
  FpiDeviceTudorMoc *self = c->self;

  if (!pyembed_global_init(&c->error)) goto done;

  gchar *idhex = NULL;
  self->py_handle = pyembed_open(c->usb_bus, c->usb_addr, &idhex, &c->error);
  if (self->py_handle && idhex) {
    g_strlcpy(self->sensor_id_hex, idhex, sizeof(self->sensor_id_hex));
  }
  g_free(idhex);

done:
  g_idle_add(idle_open_done, c);
  return NULL;
}

static void dev_open(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  GUsbDevice *usb = fpi_device_get_usb_device(dev);
  OpCtx *c = opctx_new(self);
  g_assert(self->worker == NULL);
  c->usb_bus = g_usb_device_get_bus(usb);
  c->usb_addr = g_usb_device_get_address(usb);
  self->worker = g_thread_new("tudor-moc-open", open_worker, c);
}

static gboolean idle_close_done(gpointer d) {
  OpCtx *c = d;
  FpiDeviceTudorMoc *self = c->self;
  g_thread_join(self->worker);
  self->worker = NULL;
  self->opened = FALSE;
  fpi_device_close_complete(FP_DEVICE(self), c->error);
  c->error = NULL;
  opctx_free(c);
  return G_SOURCE_REMOVE;
}

static gpointer close_worker(gpointer data) {
  OpCtx *c = data;
  FpiDeviceTudorMoc *self = c->self;
  if (self->py_handle) {
    pyembed_close(self->py_handle, &c->error);
    self->py_handle = NULL;
  }
  g_idle_add(idle_close_done, c);
  return NULL;
}

static void dev_close(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  g_assert(self->worker == NULL);
  self->worker = g_thread_new("tudor-moc-close", close_worker, opctx_new(self));
}

/* ------------------------------------------------------------------ *
 *  probe
 * ------------------------------------------------------------------ */

static void dev_probe(FpDevice *dev) {
  /* Match-on-chip: no image geometry to discover. Advertise our enroll stage count and
   * let the id_table gate VID/PID. The heavy TLS bring-up happens in open(). */
  fpi_device_set_nr_enroll_stages(dev, TUDOR_MOC_ENROLL_STAGES);
  fpi_device_probe_complete(dev, NULL, NULL, NULL);
}

/* ------------------------------------------------------------------ *
 *  enroll
 * ------------------------------------------------------------------ */

/* map firmware progress (12..100) onto our advertised enroll stage count */
static guint progress_to_stage(gint progress) {
  guint s = (guint)((progress * TUDOR_MOC_ENROLL_STAGES + 99) / 100);
  if (s < 1) s = 1;
  if (s > TUDOR_MOC_ENROLL_STAGES) s = TUDOR_MOC_ENROLL_STAGES;
  return s;
}

static gboolean idle_enroll_done(gpointer d) {
  OpCtx *c = d;
  FpiDeviceTudorMoc *self = c->self;
  FpDevice *dev = FP_DEVICE(self);
  g_thread_join(self->worker);
  self->worker = NULL;

  if (c->error) {
    fpi_device_enroll_complete(dev, NULL, c->error);
    c->error = NULL;
  } else {
    FpPrint *print = NULL;
    fpi_device_get_enroll_data(dev, &print);
    fpi_print_set_type(print, FPI_PRINT_RAW);
    fpi_print_set_device_stored(print, TRUE);
    g_object_set(print, "fpi-data", tudor_print_data(c->tuid), NULL);
    fpi_device_enroll_complete(dev, g_object_ref(print), NULL);
  }
  opctx_free(c);
  return G_SOURCE_REMOVE;
}

static gpointer enroll_worker(gpointer data) {
  OpCtx *c = data;
  FpiDeviceTudorMoc *self = c->self;
  gpointer h = self->py_handle;
  gboolean committed = FALSE;

  if (!pyembed_enroll_start(h, &c->error)) goto out;

  for (int img = 0; img < 25; img++) {
    post_finger(self, FP_FINGER_STATUS_NEEDED, FP_FINGER_STATUS_NONE);
    gint progress = 0;
    gboolean have_tuid = FALSE;
    gint code = pyembed_enroll_step(h, 30.0, &progress, c->tuid, &have_tuid, &c->error);
    post_finger(self, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_NEEDED);
    if (code == -2) goto out_end;                             /* error (set) */
    if (code == -1) { c->error = cancelled_error(); goto out_end; }
    if (code == 0) {                                          /* no finger within budget */
      c->error = fpi_device_error_new_msg(FP_DEVICE_ERROR_GENERAL, "no finger detected");
      goto out_end;
    }
    if (have_tuid) c->have_tuid = TRUE;
    {
      guint stage = progress_to_stage(progress);
      if ((gint)stage > c->last_stage) { c->last_stage = stage; post_progress(self, stage); }
    }

    if (progress >= 100) {
      if (!c->have_tuid) {
        c->error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "enroll reached 100%% without a TUID");
        goto out_end;
      }
      /* commit under a host-synthesized identity; store the STABLE parent-user key
       * (not the volatile template tuid) in the FpPrint. */
      guint8 key[16];
      if (!pyembed_enroll_commit(h, c->tuid, c->user_id ? c->user_id : "", key, &c->error)) goto out_end;
      memcpy(c->tuid, key, 16);
      committed = TRUE;
      break;
    }
  }
  if (!committed && !c->error)
    c->error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "enroll did not complete");

out_end:
  pyembed_enroll_end(h);
out:
  g_idle_add(idle_enroll_done, c);
  return NULL;
}

static void dev_enroll(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  FpPrint *print = NULL;
  OpCtx *c;

  g_assert(self->worker == NULL);
  self->canceling = FALSE;
  pyembed_set_cancel(FALSE);

  c = opctx_new(self);
  fpi_device_get_enroll_data(dev, &print);
  c->user_id = fpi_print_generate_user_id(print);   /* main thread */
  self->worker = g_thread_new("tudor-moc-enroll", enroll_worker, c);
}

/* ------------------------------------------------------------------ *
 *  verify / identify (single vfunc, like goodixmoc)
 * ------------------------------------------------------------------ */

static gboolean idle_verify_done(gpointer d) {
  OpCtx *c = d;
  FpiDeviceTudorMoc *self = c->self;
  FpDevice *dev = FP_DEVICE(self);
  FpiDeviceAction action = fpi_device_get_current_action(dev);
  g_thread_join(self->worker);
  self->worker = NULL;

  if (c->error) {
    /* A retry-domain error (e.g. no finger within the capture window) is reported as a
     * retryable match error, not a terminal failure, so fprintd/PAM can prompt again. */
    if (c->error->domain == FP_DEVICE_RETRY) {
      if (action == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_report(dev, FPI_MATCH_ERROR, NULL, g_steal_pointer(&c->error));
      else
        fpi_device_identify_report(dev, NULL, NULL, g_steal_pointer(&c->error));
      if (action == FPI_DEVICE_ACTION_VERIFY) fpi_device_verify_complete(dev, NULL);
      else fpi_device_identify_complete(dev, NULL);
    } else {
      if (action == FPI_DEVICE_ACTION_VERIFY) fpi_device_verify_complete(dev, c->error);
      else fpi_device_identify_complete(dev, c->error);
      c->error = NULL;
    }
    opctx_free(c);
    return G_SOURCE_REMOVE;
  }

  /* Resolve the matched TUID back to a stored FpPrint. */
  FpPrint *found = NULL;
  gboolean host_ok = c->matched;
#if TUDOR_MOC_SCORE_THRESHOLD > 0
  host_ok = host_ok && (c->score >= (guint32)TUDOR_MOC_SCORE_THRESHOLD);
#endif

  if (host_ok) {
    if (action == FPI_DEVICE_ACTION_VERIFY) {
      FpPrint *vprint = NULL;
      fpi_device_get_verify_data(dev, &vprint);
      guint8 t[16];
      if (vprint && tudor_print_get_tuid(vprint, t) && memcmp(t, c->match_tuid, 16) == 0)
        found = vprint;
    } else {
      GPtrArray *prints = NULL;
      fpi_device_get_identify_data(dev, &prints);
      for (guint i = 0; prints && i < prints->len; i++) {
        FpPrint *p = g_ptr_array_index(prints, i);
        guint8 t[16];
        if (tudor_print_get_tuid(p, t) && memcmp(t, c->match_tuid, 16) == 0) { found = p; break; }
      }
    }
  }

  if (action == FPI_DEVICE_ACTION_VERIFY) {
    fpi_device_verify_report(dev, found ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, found, NULL);
    fpi_device_verify_complete(dev, NULL);
  } else {
    fpi_device_identify_report(dev, found, found, NULL);
    fpi_device_identify_complete(dev, NULL);
  }
  opctx_free(c);
  return G_SOURCE_REMOVE;
}

static gpointer verify_worker(gpointer data) {
  OpCtx *c = data;
  FpiDeviceTudorMoc *self = c->self;
  gpointer h = self->py_handle;
  const guint8 *blob = c->target_tuids ? (const guint8 *)c->target_tuids->data : NULL;
  gsize blob_len = c->target_tuids ? (gsize)c->target_tuids->len * 16 : 0;

  post_finger(self, FP_FINGER_STATUS_NEEDED, FP_FINGER_STATUS_NONE);
  gint code = pyembed_verify_once(h, 30.0, blob, blob_len, &c->matched, c->match_tuid, &c->score, &c->error);
  post_finger(self, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_NEEDED);
  if (code == -1) c->error = cancelled_error();
  else if (code == 0) c->error = fpi_device_retry_new_msg(FP_DEVICE_RETRY_GENERAL, "no finger detected");
  /* code == -2 leaves c->error set by pyembed; code == 1 => matched/score populated */

  g_idle_add(idle_verify_done, c);
  return NULL;
}

/* collect the TUID(s) of the print(s) this action should match against */
static void collect_target_tuids(FpDevice *dev, OpCtx *c) {
  FpiDeviceAction action = fpi_device_get_current_action(dev);
  c->target_tuids = g_array_new(FALSE, FALSE, 16);
  guint8 t[16];
  if (action == FPI_DEVICE_ACTION_VERIFY) {
    FpPrint *p = NULL;
    fpi_device_get_verify_data(dev, &p);
    if (p && tudor_print_get_tuid(p, t)) g_array_append_vals(c->target_tuids, t, 1);
  } else {
    GPtrArray *prints = NULL;
    fpi_device_get_identify_data(dev, &prints);
    for (guint i = 0; prints && i < prints->len; i++)
      if (tudor_print_get_tuid(g_ptr_array_index(prints, i), t)) g_array_append_vals(c->target_tuids, t, 1);
  }
}

static void dev_verify_identify(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  OpCtx *c;
  g_assert(self->worker == NULL);
  self->canceling = FALSE;
  pyembed_set_cancel(FALSE);
  c = opctx_new(self);
  collect_target_tuids(dev, c);
  self->worker = g_thread_new("tudor-moc-verify", verify_worker, c);
}

/* ------------------------------------------------------------------ *
 *  list
 * ------------------------------------------------------------------ */

static gboolean idle_list_done(gpointer d) {
  OpCtx *c = d;
  FpiDeviceTudorMoc *self = c->self;
  FpDevice *dev = FP_DEVICE(self);
  g_thread_join(self->worker);
  self->worker = NULL;

  if (c->error) {
    fpi_device_list_complete(dev, NULL, c->error);
    c->error = NULL;
    opctx_free(c);
    return G_SOURCE_REMOVE;
  }

  GPtrArray *result = g_ptr_array_new_with_free_func(g_object_unref);
  for (guint i = 0; c->tuids && i < c->tuids->len; i++) {
    const guint8 *t = (const guint8 *)c->tuids->data + (gsize)i * 16;
    FpPrint *print = tudor_new_print_for_tuid(dev, t, NULL);
    g_ptr_array_add(result, g_object_ref_sink(print));
  }
  fpi_device_list_complete(dev, result, NULL);
  opctx_free(c);
  return G_SOURCE_REMOVE;
}

static gpointer list_worker(gpointer data) {
  OpCtx *c = data;
  FpiDeviceTudorMoc *self = c->self;
  pyembed_list_templates(self->py_handle, &c->tuids, &c->error);
  g_idle_add(idle_list_done, c);
  return NULL;
}

static void dev_list(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  g_assert(self->worker == NULL);
  self->worker = g_thread_new("tudor-moc-list", list_worker, opctx_new(self));
}

/* ------------------------------------------------------------------ *
 *  delete
 * ------------------------------------------------------------------ */

static gboolean idle_delete_done(gpointer d) {
  OpCtx *c = d;
  FpiDeviceTudorMoc *self = c->self;
  g_thread_join(self->worker);
  self->worker = NULL;
  fpi_device_delete_complete(FP_DEVICE(self), c->error);
  c->error = NULL;
  opctx_free(c);
  return G_SOURCE_REMOVE;
}

static gpointer delete_worker(gpointer data) {
  OpCtx *c = data;
  FpiDeviceTudorMoc *self = c->self;
  pyembed_delete_template(self->py_handle, c->tuid, &c->error);
  g_idle_add(idle_delete_done, c);
  return NULL;
}

static void dev_delete(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  FpPrint *print = NULL;
  OpCtx *c;

  g_assert(self->worker == NULL);
  fpi_device_get_delete_data(dev, &print);

  c = opctx_new(self);
  if (!tudor_print_get_tuid(print, c->tuid)) {
    fpi_device_delete_complete(dev, fpi_device_error_new(FP_DEVICE_ERROR_DATA_INVALID));
    opctx_free(c);
    return;
  }
  self->worker = g_thread_new("tudor-moc-delete", delete_worker, c);
}

/* ------------------------------------------------------------------ *
 *  clear-storage (delete every on-chip template + prune empty users)
 * ------------------------------------------------------------------ */

static gboolean idle_clear_done(gpointer d) {
  OpCtx *c = d;
  FpiDeviceTudorMoc *self = c->self;
  g_thread_join(self->worker);
  self->worker = NULL;
  fpi_device_clear_storage_complete(FP_DEVICE(self), c->error);
  c->error = NULL;
  opctx_free(c);
  return G_SOURCE_REMOVE;
}

static gpointer clear_worker(gpointer data) {
  OpCtx *c = data;
  FpiDeviceTudorMoc *self = c->self;
  gpointer h = self->py_handle;
  GArray *tuids = NULL;

  if (!pyembed_list_templates(h, &tuids, &c->error)) goto out;
  for (guint i = 0; i < tuids->len; i++) {
    const guint8 *t = (const guint8 *)tuids->data + (gsize)i * 16;
    if (!pyembed_delete_template(h, t, &c->error)) break;
  }
  g_array_unref(tuids);

out:
  g_idle_add(idle_clear_done, c);
  return NULL;
}

static void dev_clear_storage(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  g_assert(self->worker == NULL);
  self->worker = g_thread_new("tudor-moc-clear", clear_worker, opctx_new(self));
}

/* ------------------------------------------------------------------ *
 *  cancel / suspend / resume
 * ------------------------------------------------------------------ */

static void dev_cancel(FpDevice *dev) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(dev);
  self->canceling = TRUE;
  pyembed_set_cancel(TRUE);   /* cooperative: pydrv poll loops abort at the next check */
}

static void dev_suspend(FpDevice *dev) {
  /* The on-chip session survives; nothing to tear down. If the sensor is actually reset
   * across a real system suspend, the next op's TLS error will surface and libfprint will
   * recover by close/reopen. */
  fpi_device_suspend_complete(dev, NULL);
}

static void dev_resume(FpDevice *dev) {
  fpi_device_resume_complete(dev, NULL);
}

/* ------------------------------------------------------------------ *
 *  GObject / class
 * ------------------------------------------------------------------ */

static void fpi_device_tudor_moc_init(FpiDeviceTudorMoc *self) {
  self->py_handle = NULL;
  self->opened = FALSE;
  self->worker = NULL;
  self->canceling = FALSE;
  self->sensor_id_hex[0] = 0;
}

static void fpi_device_tudor_moc_finalize(GObject *obj) {
  FpiDeviceTudorMoc *self = FPI_DEVICE_TUDOR_MOC(obj);
  if (self->py_handle) {
    pyembed_close(self->py_handle, NULL);
    self->py_handle = NULL;
  }
  pyembed_global_shutdown();
  G_OBJECT_CLASS(fpi_device_tudor_moc_parent_class)->finalize(obj);
}

static void fpi_device_tudor_moc_class_init(FpiDeviceTudorMocClass *klass) {
  G_OBJECT_CLASS(klass)->finalize = fpi_device_tudor_moc_finalize;

  FpDeviceClass *dev_class = FP_DEVICE_CLASS(klass);
  dev_class->id = "tudor_moc";
  dev_class->full_name = "Synaptics Tudor MOC";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = TUDOR_MOC_ENROLL_STAGES;

  dev_class->probe = dev_probe;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify_identify;
  dev_class->identify = dev_verify_identify;
  dev_class->list = dev_list;
  dev_class->delete = dev_delete;
  dev_class->clear_storage = dev_clear_storage;
  dev_class->cancel = dev_cancel;
  dev_class->suspend = dev_suspend;
  dev_class->resume = dev_resume;

  fpi_device_class_auto_initialize_features(dev_class);
}
