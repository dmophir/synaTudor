/* Standalone libfprint self-test for the tudor-moc TOD driver. Runs as a normal C process
 * (Python lives only inside the driver, like fprintd) so we can validate open/list/enroll/
 * verify/identify/delete without fprintd's sandbox.
 *
 * Build:  gcc moc_selftest.c -o moc_selftest $(pkg-config --cflags --libs libfprint-2)
 * Run:    FP_TOD_DRIVERS_DIR=../build TUDOR_PYDRV_PATH=../../pydrv ./moc_selftest <cmd>
 *   cmd = list | enroll | verify | identify | delete-all
 */
#include <fprint.h>
#include <stdio.h>
#include <string.h>

static FpDevice *first_device(FpContext *ctx) {
  fp_context_enumerate(ctx);
  GPtrArray *devs = fp_context_get_devices(ctx);
  if (!devs || devs->len == 0) { g_printerr("no fprint devices found\n"); return NULL; }
  FpDevice *dev = g_ptr_array_index(devs, 0);
  g_printerr("device: name='%s' driver='%s'\n", fp_device_get_name(dev), fp_device_get_driver(dev));
  return dev;
}

static void enroll_progress(FpDevice *dev, gint completed, FpPrint *print, gpointer u, GError *err) {
  (void)dev; (void)print; (void)u;
  g_printerr("  enroll progress: %d/%d%s\n", completed, fp_device_get_nr_enroll_stages(dev),
             err ? err->message : "");
}

static void print_tuid(FpPrint *p) {
  /* fpi-data is the 16-byte stable USER key only ("ay"), not the old (y@ay@ay) tuple:
   * the on-chip WINBIO user-id is not host-readable and the template tuid churns via the
   * adaptive update, so the driver keys prints on the parent-user uid (see device.c). */
  g_autoptr(GVariant) data = NULL;
  g_object_get(p, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type(data, G_VARIANT_TYPE("ay"))) { g_printerr("  (no key)\n"); return; }
  gsize n = 0;
  const guint8 *k = g_variant_get_fixed_array(data, &n, 1);
  g_autoptr(GString) s = g_string_new("");
  for (gsize i=0;i<n;i++) g_string_append_printf(s, "%02x", k[i]);
  g_printerr("  userkey=%s\n", s->str);
}

int main(int argc, char **argv) {
  const char *cmd = argc > 1 ? argv[1] : "list";
  const char *fpfile = "/tmp/opencode/moc_test.fp";
  GError *err = NULL;

  g_autoptr(FpContext) ctx = fp_context_new();
  FpDevice *dev = first_device(ctx);
  if (!dev) return 1;

  if (!fp_device_open_sync(dev, NULL, &err)) {
    g_printerr("open FAILED: %s\n", err->message); return 1;
  }
  g_printerr("open OK\n");
  int rc = 0;

  if (!strcmp(cmd, "list")) {
    GPtrArray *prints = fp_device_list_prints_sync(dev, NULL, &err);
    if (!prints) { g_printerr("list FAILED: %s\n", err ? err->message : "?"); rc = 1; }
    else { g_printerr("list OK: %u on-chip template(s)\n", prints->len);
           for (guint i=0;i<prints->len;i++) print_tuid(g_ptr_array_index(prints,i)); }
  } else if (!strcmp(cmd, "enroll")) {
    FpPrint *tmpl = fp_print_new(dev);
    fp_print_set_finger(tmpl, FP_FINGER_RIGHT_INDEX);
    fp_print_set_username(tmpl, g_get_user_name());
    g_printerr("ENROLL: press your finger repeatedly...\n");
    FpPrint *res = fp_device_enroll_sync(dev, tmpl, NULL, enroll_progress, NULL, &err);
    if (!res) { g_printerr("enroll FAILED: %s\n", err ? err->message : "?"); rc = 1; }
    else {
      g_printerr("enroll OK\n"); print_tuid(res);
      guchar *buf=NULL; gsize len=0;
      if (fp_print_serialize(res, &buf, &len, &err)) {
        g_file_set_contents(fpfile, (char*)buf, len, NULL);
        g_printerr("saved enrolled print -> %s (%zu bytes)\n", fpfile, len);
        g_free(buf);
      }
    }
  } else if (!strcmp(cmd, "verify")) {
    gchar *buf=NULL; gsize len=0;
    if (!g_file_get_contents(fpfile, &buf, &len, &err)) { g_printerr("need %s (run enroll first): %s\n", fpfile, err->message); return 1; }
    FpPrint *enrolled = fp_print_deserialize((guchar*)buf, len, &err); g_free(buf);
    if (!enrolled) { g_printerr("deserialize FAILED: %s\n", err->message); return 1; }
    g_printerr("VERIFY: press your finger...\n");
    gboolean match=FALSE; FpPrint *out=NULL;
    if (!fp_device_verify_sync(dev, enrolled, NULL, NULL, NULL, &match, &out, &err))
      { g_printerr("verify FAILED: %s\n", err ? err->message : "?"); rc = 1; }
    else g_printerr("verify result: %s\n", match ? "MATCH" : "NO MATCH");
  } else if (!strcmp(cmd, "identify")) {
    gchar *buf=NULL; gsize len=0;
    if (!g_file_get_contents(fpfile, &buf, &len, &err)) { g_printerr("need %s (run enroll first): %s\n", fpfile, err->message); return 1; }
    FpPrint *enrolled = fp_print_deserialize((guchar*)buf, len, &err); g_free(buf);
    GPtrArray *gallery = g_ptr_array_new_with_free_func(g_object_unref);
    g_ptr_array_add(gallery, enrolled);
    g_printerr("IDENTIFY: press your finger...\n");
    gboolean match=FALSE; FpPrint *matched=NULL, *out=NULL;
    if (!fp_device_identify_sync(dev, gallery, NULL, NULL, NULL, &matched, &out, &err))
      { g_printerr("identify FAILED: %s\n", err ? err->message : "?"); rc = 1; }
    else g_printerr("identify result: %s\n", matched ? "MATCH" : "NO MATCH");
    g_ptr_array_unref(gallery);
  } else if (!strcmp(cmd, "verify-onchip") || !strcmp(cmd, "identify-onchip") || !strcmp(cmd, "identify-loop")) {
    /* Build the gallery/template straight from the device's on-chip list (no prior enroll
     * or saved .fp needed). Good for a quick 1-press verify against existing templates. */
    GPtrArray *prints = fp_device_list_prints_sync(dev, NULL, &err);
    if (!prints || prints->len == 0) { g_printerr("no on-chip templates to match against\n"); rc = 1; }
    else if (!strcmp(cmd, "verify-onchip")) {
      FpPrint *enrolled = g_ptr_array_index(prints, 0);
      g_printerr("VERIFY against on-chip tuid: press your finger...\n");
      gboolean match=FALSE; FpPrint *out=NULL;
      if (!fp_device_verify_sync(dev, enrolled, NULL, NULL, NULL, &match, &out, &err))
        { g_printerr("verify FAILED: %s\n", err ? err->message : "?"); rc = 1; }
      else g_printerr("verify result: %s\n", match ? "MATCH" : "NO MATCH");
    } else {
      int rounds = !strcmp(cmd, "identify-loop") ? 3 : 1;
      for (int r = 0; r < rounds; r++) {
        g_clear_error(&err);
        g_printerr("IDENTIFY round %d/%d against %u on-chip template(s): press your finger...\n", r+1, rounds, prints->len);
        FpPrint *matched=NULL, *out=NULL;
        if (!fp_device_identify_sync(dev, prints, NULL, NULL, NULL, &matched, &out, &err))
          { g_printerr("  identify FAILED: %s\n", err ? err->message : "?"); }
        else { g_printerr("  identify result: %s\n", matched ? "MATCH" : "NO MATCH");
               if (matched) print_tuid(matched); }
      }
    }
  } else if (!strcmp(cmd, "delete-all")) {
    if (!fp_device_clear_storage_sync(dev, NULL, &err)) { g_printerr("clear FAILED: %s\n", err ? err->message : "?"); rc = 1; }
    else g_printerr("clear_storage OK\n");
  } else {
    g_printerr("unknown cmd '%s'\n", cmd); rc = 2;
  }

  fp_device_close_sync(dev, NULL, NULL);
  return rc;
}
