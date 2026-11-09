#!/usr/bin/env python3
"""find.py NLSGEN_DIR CLDR.zip LOCALE TARGET...  : list CLDR leaf values (any package, locale chain) equal to TARGET
(raw, or after ldml_to_win). Discovery tool: which CLDR field could carry a given value."""
import sys, json, os, importlib.util
spec = importlib.util.spec_from_file_location("nlsgen", os.path.join(sys.argv[1], "nlsgen.py"))
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
c = g.Cldr(sys.argv[2])
loc = sys.argv[3]
targets = [t.encode().decode("unicode_escape").encode("latin-1").decode("utf-8") if "\\x" in t else t for t in sys.argv[4:]]
ch = c.chain(loc) + (["en"] if not loc.startswith("en") else [])


def walk(d, p):
    if isinstance(d, dict):
        for k, v in d.items():
            yield from walk(v, p + [k])
    else:
        yield p, d


for l in ch:
    for n in sorted(c.names):
        if "/main/%s/" % l in n and n.endswith(".json") and ("cldr-cal-" not in n or "islamic" in n or "persian" in n or "buddhist" in n):
            d = json.loads(c.z.read(n).decode("utf-8"))
            for p, v in walk(d, []):
                if not isinstance(v, str):
                    continue
                if "ca-gregorian" in n and "/dayPeriods/" in "/".join(p) and False: pass
                for t in targets:
                    if v == t or g.ldml_to_win(v) == t or v.replace(" ", " ").replace(" ", " ") == t:
                        print(l, n.split("/")[0].replace("cldr-", ""), "/".join(p[2:]), "=", repr(v))
