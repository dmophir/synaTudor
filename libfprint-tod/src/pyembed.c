#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <dlfcn.h>
#include "pyembed.h"
#include "drivers_api.h"

/* The TOD loader dlopen()s this module with RTLD_LOCAL, so libpython's symbols are not in
 * the global namespace -- Python's own C extension modules (array, _hashlib, ...) then fail
 * to load with "undefined symbol: PyUnicode_FromFormat". Re-open libpython with RTLD_GLOBAL
 * before Py_Initialize to promote its symbols to the global scope. */
#define _TUDOR_STR(x) #x
#define _TUDOR_XSTR(x) _TUDOR_STR(x)
static const char *LIBPYTHON_SONAMES[] = {
  "libpython" _TUDOR_XSTR(PY_MAJOR_VERSION) "." _TUDOR_XSTR(PY_MINOR_VERSION) ".so.1.0",
  "libpython" _TUDOR_XSTR(PY_MAJOR_VERSION) "." _TUDOR_XSTR(PY_MINOR_VERSION) ".so",
  NULL
};

static void promote_libpython_global(void) {
  for (int i = 0; LIBPYTHON_SONAMES[i]; i++) {
    if (dlopen(LIBPYTHON_SONAMES[i], RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD))
      return;   /* already mapped: reopen with GLOBAL merges it into the global scope */
  }
  for (int i = 0; LIBPYTHON_SONAMES[i]; i++) {
    if (dlopen(LIBPYTHON_SONAMES[i], RTLD_LAZY | RTLD_GLOBAL))
      return;
  }
}

/* Path to the pydrv package (dir containing the `tudor` package). Overridable at runtime
 * via $TUDOR_PYDRV_PATH; the build bakes in a default via -DTUDOR_PYDRV_PATH=... */
#ifndef TUDOR_PYDRV_PATH
#define TUDOR_PYDRV_PATH "/usr/lib/tudor-moc/pydrv"
#endif

/* Embedded wrapper module: opens the sensor via pydrv and exposes flat functions the C
 * side calls. Keeps all pydrv/TLS/USB knowledge in Python. The cancel flag is a 1-element
 * list so C can flip it (set_cancel) while an enroll/verify poll loop reads it. */
static const char *WRAPPER_SRC =
  "import hashlib\n"
  "import os, sys, time\n"
  "import usb.core\n"
  "import tudor\n"
  "import tudor.sensor as ts\n"
  "from tudor.comm import USBCommunication\n"
  "from tudor.paths import resolve_pdata\n"
  "\n"
  "_DBG = bool(os.environ.get('TUDOR_MOC_DEBUG'))\n"
  "def _dbg(m):\n"
  "    if _DBG: sys.stderr.write('[tudor-moc] ' + m + '\\n'); sys.stderr.flush()\n"
  "if _DBG:\n"
  "    import logging\n"
  "    logging.getLogger().addHandler(logging.StreamHandler(sys.stderr))\n"
  "    logging.getLogger().setLevel(1)\n"
  "\n"
  "# The on-chip TEMPLATE tuid is rewritten by the sensor's adaptive update after a match,\n"
  "# so it is NOT a stable host key. The parent USER uid is stable across updates, so the\n"
  "# driver keys FpPrints by user uid and always resolves the user's CURRENT templates.\n"
  "def _templates_by_user(h):\n"
  "    db2 = h['db2']\n"
  "    return {bytes(u): [bytes(t) for t in db2.list_templates(u)] for u in db2.list_users()}\n"
  "\n"
  "def _user_of_template(h, tuid):\n"
  "    for u, tl in _templates_by_user(h).items():\n"
  "        if tuid in tl: return u\n"
  "    return None\n"
  "\n"
  "_CANCEL = [False]\n"
  "def set_cancel(v):\n"
  "    _CANCEL[0] = bool(v)\n"
  "def _sc():\n"
  "    return _CANCEL[0]\n"
  "\n"
  "def open_device(bus, addr):\n"
  "    dev = usb.core.find(custom_match=lambda d: d.bus == bus and d.address == addr)\n"
  "    if dev is None: raise ValueError('USB device not found (bus %d addr %d)' % (bus, addr))\n"
  "    comm = USBCommunication(dev)\n"
  "    # Self-heal: a prior interrupted session can leave the sensor in a half-open TLS\n"
  "    # state (plaintext GET_VERSION -> 15 03 03 alert), which makes initialize() time out.\n"
  "    # Retry with a USB reset + short idle so PAM/fprintd auth recovers instead of failing.\n"
  "    last = None\n"
  "    for attempt in range(3):\n"
  "        try:\n"
  "            sensor = ts.Sensor(comm)\n"
  "            with open(resolve_pdata(sensor.id.hex()), 'rb') as f:\n"
  "                sensor.initialize(ts.SensorPairingData.load(f))\n"
  "            return {'sensor': sensor, 'comm': comm, 'matcher': ts.SensorMatcher(sensor), 'db2': ts.SensorDB2(sensor)}\n"
  "        except Exception as e:\n"
  "            last = e\n"
  "            _dbg('open attempt %d failed: %r; USB reset + idle then retry' % (attempt, e))\n"
  "            try: dev.reset()\n"
  "            except Exception: pass\n"
  "            time.sleep(2.0)\n"
  "    raise last\n"
  "\n"
  "def close_device(h):\n"
  "    try: h['sensor'].uninitialize()\n"
  "    finally: h['comm'].close()\n"
  "\n"
  "def sensor_id_hex(h):\n"
  "    return h['sensor'].id.hex()\n"
  "\n"
  "def db_num_templates(h):\n"
  "    return int(h['db2'].get_db_info().num_current_templates)\n"
  "\n"
  "def enroll_start(h):\n"
  "    _CANCEL[0] = False\n"
  "    h['matcher'].enroll_start()\n"
  "\n"
  "def enroll_end(h):\n"
  "    try: h['matcher'].enroll_end()\n"
  "    except Exception: pass\n"
  "    try: h['sensor'].event_handler.set_event_mask([])\n"
  "    except Exception: pass\n"
  "\n"
  "def capture_frame(h, budget):\n"
  "    try:\n"
  "        ev = h['matcher'].capture_one_frame(finger_budget_s=budget, should_cancel=_sc)\n"
  "    except ts.CaptureCancelled:\n"
  "        return -1\n"
  "    return 1 if ev is not None else 0\n"
  "\n"
  "def enroll_step(h, budget):\n"
  "    # capture one frame then immediately add_image, mirroring SensorMatcher.enroll_loop\n"
  "    try:\n"
  "        ev = h['matcher'].capture_one_frame(finger_budget_s=budget, should_cancel=_sc)\n"
  "    except ts.CaptureCancelled:\n"
  "        return (-1, 0, None)\n"
  "    if ev is None:\n"
  "        return (0, 0, None)\n"
  "    stat, tuid = h['matcher'].enroll_add_image()\n"
  "    return (1, int(stat.progress), bytes(tuid) if any(tuid) else None)\n"
  "\n"
  "def verify_once(h, budget, keys_blob):\n"
  "    # keys_blob = concatenated 16B USER uids to match against (verify=1, identify=N);\n"
  "    # empty => match against ALL enrolled users. Resolves each user's CURRENT templates.\n"
  "    keys = [keys_blob[i:i+16] for i in range(0, len(keys_blob), 16)]\n"
  "    u2t = _templates_by_user(h)\n"
  "    if keys:\n"
  "        t2u = {t: u for u in keys for t in u2t.get(u, [])}\n"
  "    else:\n"
  "        t2u = {t: u for u, tl in u2t.items() for t in tl}\n"
  "    tmpls = list(t2u.keys())\n"
  "    try:\n"
  "        ev = h['matcher'].capture_one_frame(finger_budget_s=budget, should_cancel=_sc)\n"
  "    except ts.CaptureCancelled:\n"
  "        _dbg('verify: cancelled'); return (-1, False, None, 0)\n"
  "    if ev is None:\n"
  "        _dbg('verify: no finger'); return (0, False, None, 0)\n"
  "    if keys and not tmpls:\n"
  "        _dbg('verify: enrolled user has no on-chip template'); return (1, False, None, 0)\n"
  "    mr = h['matcher'].identify(template_uids=tmpls if tmpls else None)\n"
  "    _dbg('verify: identify(n=%d) -> %r' % (len(tmpls), mr))\n"
  "    if mr is None:\n"
  "        return (1, False, None, 0)\n"
  "    mt = bytes(mr.matched_tuid)\n"
  "    key = t2u.get(mt) or _user_of_template(h, mt)\n"
  "    return (1, key is not None, key, int(mr.score))\n"
  "\n"
  "def enroll_commit(h, tuid, user_id_str):\n"
  "    d = hashlib.sha256(user_id_str.encode('utf-8')).digest()\n"
  "    rid = 1000 + (int.from_bytes(d[:4], 'little') % 0x7fff0000)\n"
  "    sid = ts.make_linux_sid(rid)\n"
  "    h['matcher'].enroll_commit(bytes(tuid), user_id=sid, identity_type=ts.WINBIO_ID_TYPE_SID)\n"
  "    # the stable host key is the parent USER uid of the just-committed template\n"
  "    return _user_of_template(h, bytes(tuid))\n"
  "\n"
  "def list_templates(h):\n"
  "    # one key (stable USER uid) per enrolled finger (a user that has >=1 template)\n"
  "    return [u for u, tl in _templates_by_user(h).items() if tl]\n"
  "\n"
  "def delete_template(h, key):\n"
  "    # key is a USER uid: delete all its templates (each prunes the user once empty),\n"
  "    # then make sure the user object itself is gone.\n"
  "    db2 = h['db2']; key = bytes(key)\n"
  "    for t in [bytes(t) for t in db2.list_templates(key)]:\n"
  "        db2.delete_template(t)\n"
  "    try:\n"
  "        if not db2.list_templates(key):\n"
  "            db2.delete_object(ts.DB2_CAT_USER, key)\n"
  "    except tudor.comm.CommandFailedException:\n"
  "        pass\n"
  "    return 0\n";

static gboolean g_initialized = FALSE;
static PyObject *g_wrapper = NULL;             /* wrapper module (strong ref) */

/* --- helpers (all assume the GIL is held) --- */

static void set_py_error(GError **error, FpDeviceError code, const char *ctx) {
  PyObject *etype = NULL, *eval = NULL, *etb = NULL;
  PyErr_Fetch(&etype, &eval, &etb);
  PyErr_NormalizeException(&etype, &eval, &etb);
  gchar *msg = NULL;
  if (eval) {
    PyObject *s = PyObject_Str(eval);
    if (s) {
      const char *u = PyUnicode_AsUTF8(s);
      msg = g_strdup(u ? u : "");
      Py_DECREF(s);
    }
  }
  g_set_error(error, FP_DEVICE_ERROR, code, "%s: %s", ctx, msg ? msg : "(python error)");
  g_free(msg);
  Py_XDECREF(etype); Py_XDECREF(eval); Py_XDECREF(etb);
}

/* Call wrapper.<fn>(*args). fmt must build a tuple (start with '(') or be NULL for none.
 * Returns a new reference to the result, or NULL with the Python error set. */
static PyObject *wrapper_call(const char *fn, const char *fmt, ...) {
  PyObject *func = PyObject_GetAttrString(g_wrapper, fn);
  if (!func || !PyCallable_Check(func)) {
    Py_XDECREF(func);
    PyErr_Format(PyExc_AttributeError, "wrapper function '%s' missing/not callable", fn);
    return NULL;
  }
  PyObject *args;
  if (fmt && *fmt) {
    va_list va; va_start(va, fmt);
    args = Py_VaBuildValue(fmt, va);
    va_end(va);
    if (!args) { Py_DECREF(func); return NULL; }
  } else {
    args = PyTuple_New(0);
  }
  PyObject *res = PyObject_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);
  return res;
}

/* --- global lifecycle --- */

gboolean pyembed_global_init(GError **error) {
  if (g_initialized) return TRUE;

  promote_libpython_global();
  Py_InitializeEx(0);

  /* sys.path: prepend $TUDOR_PYDRV_PATH (if set) then the compiled default. */
  PyObject *sys_path = PySys_GetObject("path");   /* borrowed */
  const char *env = g_getenv("TUDOR_PYDRV_PATH");
  if (env && *env) {
    PyObject *p = PyUnicode_FromString(env);
    PyList_Insert(sys_path, 0, p);
    Py_DECREF(p);
  }
  PyObject *dflt = PyUnicode_FromString(TUDOR_PYDRV_PATH);
  PyList_Insert(sys_path, 0, dflt);
  Py_DECREF(dflt);

  PyObject *code = Py_CompileString(WRAPPER_SRC, "tudor_moc_wrapper.py", Py_file_input);
  if (!code) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "compile wrapper"); goto fail; }
  PyObject *mod = PyImport_ExecCodeModule("tudor_moc_wrapper", code);
  Py_DECREF(code);
  if (!mod) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "import wrapper (is pydrv on TUDOR_PYDRV_PATH?)"); goto fail; }
  g_wrapper = mod;   /* keep a strong ref */

  g_initialized = TRUE;
  /* Release the GIL so worker threads can PyGILState_Ensure. */
  PyEval_SaveThread();
  return TRUE;

fail:
  /* Leave the interpreter initialized-but-unusable; do NOT Py_Finalize with C extensions
   * (pyusb/cryptography) partially loaded. The caller surfaces the error. */
  return FALSE;
}

void pyembed_global_shutdown(void) {
  /* Intentional no-op: fprintd is long-lived and Py_Finalize() with pyusb/cryptography
   * loaded is unreliable. The interpreter is torn down by process exit. */
}

/* --- device ops --- */

gpointer pyembed_open(int bus, int addr, gchar **sensor_id_hex_out, GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  PyObject *h = wrapper_call("open_device", "(ii)", bus, addr);
  if (!h) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "open_device"); PyGILState_Release(gil); return NULL; }
  if (sensor_id_hex_out) {
    PyObject *idr = wrapper_call("sensor_id_hex", "(O)", h);
    if (idr) {
      const char *u = PyUnicode_AsUTF8(idr);
      *sensor_id_hex_out = g_strdup(u ? u : "");
      Py_DECREF(idr);
    } else {
      PyErr_Clear();
      *sensor_id_hex_out = g_strdup("");
    }
  }
  PyGILState_Release(gil);
  return h;   /* strong ref handed to caller */
}

gboolean pyembed_close(gpointer handle, GError **error) {
  if (!handle) return TRUE;
  PyGILState_STATE gil = PyGILState_Ensure();
  PyObject *r = wrapper_call("close_device", "(O)", (PyObject *)handle);
  gboolean ok = (r != NULL);
  if (!ok) set_py_error(error, FP_DEVICE_ERROR_GENERAL, "close_device");
  Py_XDECREF(r);
  Py_DECREF((PyObject *)handle);   /* drop the ref from open */
  PyGILState_Release(gil);
  return ok;
}

gint pyembed_db_num_templates(gpointer handle, GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  PyObject *r = wrapper_call("db_num_templates", "(O)", (PyObject *)handle);
  gint n = -1;
  if (r) { n = (gint)PyLong_AsLong(r); Py_DECREF(r); }
  else set_py_error(error, FP_DEVICE_ERROR_GENERAL, "db_num_templates");
  PyGILState_Release(gil);
  return n;
}

gboolean pyembed_enroll_start(gpointer handle, GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  PyObject *r = wrapper_call("enroll_start", "(O)", (PyObject *)handle);
  gboolean ok = (r != NULL);
  if (!ok) set_py_error(error, FP_DEVICE_ERROR_GENERAL, "enroll_start");
  Py_XDECREF(r);
  PyGILState_Release(gil);
  return ok;
}

void pyembed_enroll_end(gpointer handle) {
  PyGILState_STATE gil = PyGILState_Ensure();
  PyObject *r = wrapper_call("enroll_end", "(O)", (PyObject *)handle);
  if (!r) PyErr_Clear();
  Py_XDECREF(r);
  PyGILState_Release(gil);
}

gint pyembed_enroll_step(gpointer handle, double budget_s, gint *progress, guint8 tuid[16], gboolean *have_tuid, GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  gint code = -2;
  *have_tuid = FALSE;
  *progress = 0;
  PyObject *r = wrapper_call("enroll_step", "(Od)", (PyObject *)handle, budget_s);
  if (!r) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "enroll_step"); goto out; }
  {
    PyObject *pycode = NULL, *pyprog = NULL, *pytuid = NULL;
    if (!PyArg_ParseTuple(r, "OOO", &pycode, &pyprog, &pytuid)) {
      set_py_error(error, FP_DEVICE_ERROR_GENERAL, "enroll_step result");
      goto out_dec;
    }
    code = (gint)PyLong_AsLong(pycode);
    *progress = (gint)PyLong_AsLong(pyprog);
    if (pytuid != Py_None) {
      char *buf = NULL; Py_ssize_t len = 0;
      if (PyBytes_AsStringAndSize(pytuid, &buf, &len) == 0 && len == 16) {
        memcpy(tuid, buf, 16);
        *have_tuid = TRUE;
      }
    }
  }
out_dec:
  Py_DECREF(r);
out:
  PyGILState_Release(gil);
  return code;
}

gboolean pyembed_enroll_commit(gpointer handle, const guint8 tuid[16], const char *user_id_str, guint8 out_key[16], GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  gboolean ok = FALSE;
  PyObject *r = wrapper_call("enroll_commit", "(Oy#s)",
                             (PyObject *)handle,
                             (const char *)tuid, (Py_ssize_t)16,
                             user_id_str ? user_id_str : "");
  if (!r) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "enroll_commit"); goto out; }
  if (r != Py_None) {
    char *buf = NULL; Py_ssize_t len = 0;
    if (PyBytes_AsStringAndSize(r, &buf, &len) == 0 && len == 16) { memcpy(out_key, buf, 16); ok = TRUE; }
  }
  if (!ok)
    g_set_error(error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "enroll_commit: could not resolve enrolled user key");
  Py_XDECREF(r);
out:
  PyGILState_Release(gil);
  return ok;
}

gint pyembed_verify_once(gpointer handle, double budget_s, const guint8 *tuids_blob, gsize blob_len, gboolean *matched, guint8 tuid[16], guint32 *score, GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  gint code = -2;
  *matched = FALSE; *score = 0;
  PyObject *r = wrapper_call("verify_once", "(Ody#)", (PyObject *)handle, budget_s,
                             (const char *)(tuids_blob ? tuids_blob : (const guint8 *)""),
                             (Py_ssize_t)blob_len);
  if (!r) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "verify_once"); goto out; }
  {
    PyObject *pycode = NULL, *pym = NULL, *pytuid = NULL, *pysc = NULL;
    if (!PyArg_ParseTuple(r, "OOOO", &pycode, &pym, &pytuid, &pysc)) {
      set_py_error(error, FP_DEVICE_ERROR_GENERAL, "verify_once result");
      goto out_dec;
    }
    code = (gint)PyLong_AsLong(pycode);
    *matched = PyObject_IsTrue(pym) ? TRUE : FALSE;
    *score = (guint32)PyLong_AsUnsignedLongMask(pysc);
    if (*matched && pytuid != Py_None) {
      char *buf = NULL; Py_ssize_t len = 0;
      if (PyBytes_AsStringAndSize(pytuid, &buf, &len) == 0 && len == 16)
        memcpy(tuid, buf, 16);
    }
  }
out_dec:
  Py_DECREF(r);
out:
  PyGILState_Release(gil);
  return code;
}

gboolean pyembed_list_templates(gpointer handle, GArray **tuids_out, GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  gboolean ok = FALSE;
  GArray *arr = g_array_new(FALSE, FALSE, 16);
  PyObject *r = wrapper_call("list_templates", "(O)", (PyObject *)handle);
  if (!r) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "list_templates"); goto out; }
  {
    PyObject *it = PyObject_GetIter(r);
    if (!it) { set_py_error(error, FP_DEVICE_ERROR_GENERAL, "list_templates iter"); goto out_dec; }
    PyObject *item;
    while ((item = PyIter_Next(it)) != NULL) {
      char *buf = NULL; Py_ssize_t len = 0;
      if (PyBytes_AsStringAndSize(item, &buf, &len) == 0 && len == 16)
        g_array_append_vals(arr, buf, 1);   /* element size is 16 */
      Py_DECREF(item);
    }
    Py_DECREF(it);
    ok = !PyErr_Occurred();
    if (!ok) set_py_error(error, FP_DEVICE_ERROR_GENERAL, "list_templates elem");
  }
out_dec:
  Py_DECREF(r);
out:
  if (ok) { *tuids_out = arr; }
  else { g_array_unref(arr); }
  PyGILState_Release(gil);
  return ok;
}

gboolean pyembed_delete_template(gpointer handle, const guint8 tuid[16], GError **error) {
  PyGILState_STATE gil = PyGILState_Ensure();
  PyObject *r = wrapper_call("delete_template", "(Oy#)", (PyObject *)handle, (const char *)tuid, (Py_ssize_t)16);
  gboolean ok = (r != NULL);
  if (!ok) set_py_error(error, FP_DEVICE_ERROR_GENERAL, "delete_template");
  Py_XDECREF(r);
  PyGILState_Release(gil);
  return ok;
}

void pyembed_set_cancel(gboolean v) {
  PyGILState_STATE gil = PyGILState_Ensure();
  PyObject *r = wrapper_call("set_cancel", "(O)", v ? Py_True : Py_False);
  if (!r) PyErr_Clear();
  Py_XDECREF(r);
  PyGILState_Release(gil);
}
