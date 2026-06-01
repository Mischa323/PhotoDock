Import("env")
import shutil
import os
import json
import hashlib
import datetime
import subprocess

# After every successful build, copy the freshly built binaries into the repo's
# firmware_build/ folder so the "manual flash" option always uses the latest
# firmware, AND auto-record a firmware-changelog entry from the latest git commit
# so the changelog is never forgotten / never goes stale behind a pushed build.
#
# With more than one board target we keep each board's binaries in their own
# subfolder (firmware_build/<model>/) so they don't overwrite each other. The
# PhotoPainter also still copies to the firmware_build/ root for backward
# compatibility with the current single-binary OTA endpoint.
ENV_MODEL = {
    "esp32s3-photopainter": "photopainter",
    "reterminal-e1001":     "reterminal-e1001",
}
# Map the build's model dir to the model key used in firmware-changelog.json.
MODEL_KEY = {
    "photopainter":     "PhotoPainter-E6",
    "reterminal-e1001": "reTerminal-E1001",
}


def _git(project_dir, *args):
    try:
        out = subprocess.check_output(["git"] + list(args), cwd=project_dir,
                                      stderr=subprocess.DEVNULL, timeout=5)
        return out.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _firmware_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()[:16]   # matches the server's version id
    except Exception:
        return ""


def update_changelog(project_dir, model_dir, firmware_bin):
    """Record/refresh a changelog entry for this build, once per git commit."""
    key = MODEL_KEY.get(model_dir)
    if not key:
        return
    clog_path = os.path.join(project_dir, "firmware-changelog.json")
    if not os.path.exists(clog_path):
        return

    commit = _git(project_dir, "rev-parse", "--short", "HEAD")
    if not commit:
        return   # not a git checkout — nothing to attribute the build to
    build_hash = _firmware_hash(firmware_bin)
    subject = _git(project_dir, "log", "-1", "--format=%s")
    body    = _git(project_dir, "log", "-1", "--format=%b")

    try:
        with open(clog_path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return

    model = doc.setdefault("models", {}).setdefault(key, {"name": key, "releases": []})
    releases = model.setdefault("releases", [])
    top = releases[0] if releases else None

    if top and top.get("commit") == commit:
        # Same commit, just a rebuild. Stamp the hash once (the binary's hash
        # changes every build, so don't churn the file on every rebuild).
        top.setdefault("buildHash", build_hash)
    elif top and not top.get("buildHash"):
        # A hand-written entry not yet tied to a build — link it to this one so we
        # don't create a duplicate. (Write a nice entry, build, it gets stamped.)
        top["commit"]    = commit
        top["buildHash"] = build_hash
    else:
        # New commit -> new auto entry from the commit message (minus git trailers).
        TRAILERS = ("co-authored-by:", "signed-off-by:", "co-developed-by:", "🤖")
        changes = []
        for ln in body.splitlines():
            s = ln.strip(" -*\t")
            if not s or s.lower().startswith(TRAILERS):
                continue
            changes.append(s)
        if not changes:
            changes = [subject or "Firmware update"]
        today = datetime.date.today().isoformat()
        releases.insert(0, {
            "version":   "%s-%s" % (today.replace("-", "."), commit),
            "date":      today,
            "commit":    commit,
            "buildHash": build_hash,
            "title":     subject or "Firmware update",
            "changes":   changes,
            "auto":      True,
        })

    try:
        with open(clog_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print("Changelog: recorded %s build %s (commit %s)" % (key, build_hash, commit))
    except Exception as e:
        print("Changelog: skipped (%s)" % e)


def has_baked_credentials(project_dir):
    """True if config.h bakes a non-empty Wi-Fi password — such a binary must NOT
    be published to the network-served firmware_build/ folder."""
    cfg = os.path.join(project_dir, "src", "config.h")
    try:
        import re
        with open(cfg, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
        m = re.search(r'#define\s+DEFAULT_WIFI_PASS\s+"([^"]*)"', txt)
        return bool(m and m.group(1).strip())
    except Exception:
        return False


FW_PARTS = ("firmware.bin", "bootloader.bin", "partitions.bin", "boot_app0.bin")


def archive_existing(dest):
    """Before overwriting, keep the current binaries under dest/archive/<hash>/ so
    they can be reverted to. Mirrors the server's filesystem-based version history."""
    bin_path = os.path.join(dest, "firmware.bin")
    if not os.path.exists(bin_path):
        return
    h = _firmware_hash(bin_path)
    if not h:
        return
    arch_root = os.path.join(dest, "archive")
    arch_dir  = os.path.join(arch_root, h)
    if not os.path.exists(os.path.join(arch_dir, "firmware.bin")):
        os.makedirs(arch_dir, exist_ok=True)
        for name in FW_PARTS:
            src = os.path.join(dest, name)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(arch_dir, name))
        print("Archived previous build %s" % h)
    # Keep the 10 most recent archived versions.
    try:
        items = sorted(os.listdir(arch_root),
                       key=lambda n: os.path.getmtime(os.path.join(arch_root, n)),
                       reverse=True)
        for old in items[10:]:
            shutil.rmtree(os.path.join(arch_root, old), ignore_errors=True)
    except Exception:
        pass


def copy_firmware(source, target, env):
    build_dir   = env.subst("$BUILD_DIR")
    project_dir = env.subst("$PROJECT_DIR")
    root  = os.path.normpath(os.path.join(project_dir, "..", "firmware_build"))
    model = ENV_MODEL.get(env.subst("$PIOENV"), env.subst("$PIOENV"))

    # SECURITY: firmware_build/ is served over the network (OTA + browser flash).
    # If this build baked real Wi-Fi credentials into the binary, do NOT publish
    # it there — it would expose the Wi-Fi password. The local .pio build is still
    # produced for USB upload (`pio run -t upload`). For network-servable firmware
    # use the dashboard Build or Settings -> Firmware source -> Pull & rebuild,
    # which build with an empty config.
    if has_baked_credentials(project_dir):
        print("=" * 64)
        print("copy_firmware: SKIPPED publishing to firmware_build/ — config.h has")
        print("  baked Wi-Fi credentials. The local build is still usable for USB")
        print("  upload. Use the dashboard Build / Pull & rebuild for served firmware.")
        print("=" * 64)
        return

    dests = [os.path.join(root, model)]
    if model == "photopainter":
        dests.append(root)   # keep the legacy root path working

    for dest in dests:
        os.makedirs(dest, exist_ok=True)
        archive_existing(dest)
        for name in FW_PARTS:
            src = os.path.join(build_dir, name)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(dest, name))
                print("Copied %s -> %s" % (name, dest))

    # Auto-maintain the changelog (best effort — never fail the build).
    try:
        update_changelog(project_dir, model, os.path.join(build_dir, "firmware.bin"))
    except Exception as e:
        print("Changelog: skipped (%s)" % e)


env.AddPostAction("$BUILD_DIR/firmware.bin", copy_firmware)
