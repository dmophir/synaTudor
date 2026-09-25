from __future__ import annotations

import os

#Central resolver for where tudor keeps host-side state (pairing data + host template
#registry). Historically this was hardcoded to /etc/tudor (root-only). To allow running
#the driver / diagnostics as a normal user, the location is now overridable:
#
#  1. $TUDOR_STATE_DIR                      (explicit override; used as-is)
#  2. $XDG_CONFIG_HOME/tudor or ~/.config/tudor   (per-user state)
#  3. /etc/tudor                            (system default; what root/fprintd uses)
#
#For READS we search all candidates in order and return the first that actually contains
#the file, so a user copy shadows the system one without extra config. For WRITES we pick
#the first candidate directory that is writable (creating a per-user dir if needed).

SYSTEM_STATE_DIR = "/etc/tudor"


def _user_config_dir() -> str:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "tudor")
    return os.path.join(os.path.expanduser("~"), ".config", "tudor")


def candidate_dirs() -> list:
    """Ordered list of directories to consult for tudor state."""
    override = os.environ.get("TUDOR_STATE_DIR")
    if override:
        return [override]
    return [_user_config_dir(), SYSTEM_STATE_DIR]


def find_existing(filename : str):
    """Return the first candidate_dir/<filename> that exists, or None."""
    for d in candidate_dirs():
        p = os.path.join(d, filename)
        if os.path.exists(p):
            return p
    return None


def write_dir() -> str:
    """Best directory to write state into: the explicit override, else the first
    candidate whose parent we can create/write, else the system dir. Does not create it."""
    for d in candidate_dirs():
        parent = os.path.dirname(os.path.abspath(d)) or "/"
        if os.path.isdir(d) and os.access(d, os.W_OK):
            return d
        if os.access(parent, os.W_OK):
            return d
    return SYSTEM_STATE_DIR


def resolve_pdata(sensor_id_hex : str) -> str:
    """Path to the sensor pairing data file for a given sensor id (hex). Returns an
    existing file if found across the candidates, otherwise the default location under
    the first candidate dir (so callers get a sensible path even when absent)."""
    fn = "%s.pdata" % sensor_id_hex
    found = find_existing(fn)
    if found is not None:
        return found
    return os.path.join(candidate_dirs()[0], fn)
