"""Fork-only guard: fail if the test APK still points at the official Tasks app.

A test build with its own package name crashes with a SecurityException when any module still
uses the official app's providers, so check both places that has gone wrong before.
"""
import struct, sys, zipfile

def uleb(d, o):
    r = s = 0
    while True:
        b = d[o]; o += 1; r |= (b & 0x7f) << s; s += 7
        if b < 0x80:
            return r, o

def application_ids(d):
    """Yield (class, value) for every static String field named APPLICATION_ID."""
    u32 = lambda o: struct.unpack_from('<I', d, o)[0]
    str_off, type_off, field_off = u32(0x3c), u32(0x44), u32(0x54)
    cls_n, cls_off = u32(0x60), u32(0x64)
    def s(i):
        o = u32(str_off + 4 * i); _, o = uleb(d, o); return d[o:d.index(b'\0', o)].decode('utf-8', 'replace')
    for c in range(cls_n):
        base = cls_off + 32 * c
        data, sv = u32(base + 24), u32(base + 28)
        if not data or not sv:
            continue
        o = data; sf, o = uleb(d, o)
        if not sf:
            continue
        _, o = uleb(d, o); _, o = uleb(d, o); _, o = uleb(d, o)
        fields, idx = [], 0
        for _ in range(sf):
            diff, o = uleb(d, o); idx += diff; _, o = uleb(d, o); fields.append(idx)
        n, o = uleb(d, sv)
        for k in range(min(n, len(fields))):
            vt = d[o]; o += 1; typ, arg = vt & 0x1f, vt >> 5
            value = None
            if typ == 0x17:
                value = s(int.from_bytes(d[o:o + arg + 1], 'little'))
            if typ in (0x1c, 0x1d):
                break
            if typ not in (0x1e, 0x1f):
                o += arg + 1
            name = s(struct.unpack_from('<I', d, field_off + 8 * fields[k] + 4)[0])
            if name == 'APPLICATION_ID' and value is not None:
                yield s(u32(type_off + 4 * u32(base))), value


EXPECTED = "org.tasks.mdtest"
# Both the app and the kmp module derive provider authorities from their own APPLICATION_ID.
MODULES = ("Lorg/tasks/BuildConfig;", "Lorg/tasks/kmp/BuildConfig;")
# Hard-coded authority resources. ical4android's code also names the official app's provider in
# an unused table, so code is checked through BuildConfig instead of string matching.
OFFICIAL_RESOURCES = [b"org.tasks.opentasks", b"org.tasks.api"]

problems = []
ids = {}
with zipfile.ZipFile(sys.argv[1]) as z:
    for name in z.namelist():
        data = z.read(name)
        if name.endswith(".dex"):
            ids.update(application_ids(data))
        elif name in ("resources.arsc", "AndroidManifest.xml"):
            for s in OFFICIAL_RESOURCES:
                if s + b"\0" in data or s.decode().encode("utf-16-le") + b"\0\0" in data:
                    problems.append(f"{name} contains {s.decode()}")
for module in MODULES:
    if ids.get(module) != EXPECTED:
        problems.append(f"{module} APPLICATION_ID is {ids.get(module)!r}, expected {EXPECTED!r}")
print("\n".join(problems) or "APK only points at its own providers")
sys.exit(1 if problems else 0)
