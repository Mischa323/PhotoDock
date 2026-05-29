Import("env")
import shutil
import os

# After every successful build, copy the freshly built binaries into the
# repo's firmware_build/ folder so the "manual flash" option always uses the
# latest firmware (instead of a stale, previously committed .bin).
def copy_firmware(source, target, env):
    build_dir = env.subst("$BUILD_DIR")
    dest = os.path.join(env.subst("$PROJECT_DIR"), "..", "firmware_build")
    dest = os.path.normpath(dest)
    os.makedirs(dest, exist_ok=True)
    for name in ("firmware.bin", "bootloader.bin", "partitions.bin"):
        src = os.path.join(build_dir, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(dest, name))
            print("Copied %s -> %s" % (name, dest))

env.AddPostAction("$BUILD_DIR/firmware.bin", copy_firmware)
