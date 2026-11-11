#!/usr/bin/env python3
# PROJECT:     NitroOS branding layer
# LICENSE:     MIT (https://spdx.org/licenses/MIT)
# PURPOSE:     Flag user-visible links and addresses that still point at the ReactOS project
#              (reactos.org / reactos.com) in resource, setup and source files.
# USAGE:       python3 media/branding/check-help-links.py [--root DIR]   (exit 1 when something is flagged)
#
# Help, support and bug-report links come from BRAND_SUPPORT_URL / BRAND_ISSUES_URL (sdk/include/reactos/version.cmake,
# buildno.h). Comments, copyright/credit lines and the allow-listed paths below stay as they are: ReactOS credits are kept.
# The check also verifies that the run-time-parsed iexplore.inf start page equals the NITRO_SUPPORT_URL default.
import os, re, subprocess, sys

EXT = {".rc", ".inf", ".h", ".c", ".cpp", ".hpp", ".cmake", ".in", ".ini", ".reg", ".mc", ".idl", ".xml", ".htm", ".html",
       ".manifest", ".cmd", ".bat", ".js", ".vbs", ".url", ".rgs", ".dlg"}
# Path prefixes that are not user-visible help links of the product (test code, docs, upstream build/CI files, examples,
# translator/author credits, theme author metadata, vendored code).
ALLOW = ("modules/rostests/", "modules/rosapps/", "sdk/tools/", "dll/3rdparty/", "media/doc/", "media/themes/",
         "boot/freeldr/", "boot/bootdata/bootcdregtest/", "dll/win32/rasdlg/", "dll/win32/netid/", "base/applications/msconfig_new/",
         ".github/", ".gitpod", "Doxyfile", "INSTALL", "README", "CREDITS", "media/branding/", "ntoskrnl/", "drivers/")
LINK = re.compile(r"(https?://[^\s\"'<>]*reactos\.(org|com)|www\.reactos\.(org|com)|jira\.reactos\.org|ros-dev@reactos\.org)", re.I)
CREDIT = re.compile(r"copyright|translator|programmer|author|\(c\)|contributor|written by|maintainer", re.I)

def files(root):
    out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True).stdout.split("\n")
    return [f for f in out if f and os.path.splitext(f)[1].lower() in EXT and not f.startswith(ALLOW)]

def main():
    root = "."
    if "--root" in sys.argv:
        root = sys.argv[sys.argv.index("--root") + 1]
    bad = []
    for f in files(root):
        try:
            data = open(os.path.join(root, f), "rb").read().decode("latin-1")
        except OSError:
            continue
        incomment = False
        for n, line in enumerate(data.split("\n"), 1):
            st = line.strip()
            was = incomment
            if "/*" in st and "*/" not in st[st.index("/*"):]:
                incomment = True
            if "*/" in st:
                incomment = False
            if was or st.startswith(("//", ";", "#", "*", "/*", "REM ", "rem ")):
                continue
            if LINK.search(line) and not CREDIT.search(line):
                bad.append("%s:%d: %s" % (f, n, st[:150]))
    # iexplore.inf is parsed at run time: its literal must be the NITRO_SUPPORT_URL default
    try:
        cm = open(os.path.join(root, "sdk/include/reactos/version.cmake")).read()
        url = re.search(r'set\(NITRO_SUPPORT_URL "([^"]+)"', cm).group(1)
        inf = open(os.path.join(root, "base/applications/iexplore/iexplore.inf"), "rb").read().decode("latin-1")
        for key in ("Start Page", "Default_Page_URL"):
            m = re.search(r'^HK.*"%s",2,"([^"]+)"\s*$' % key, inf, re.M)
            if m and m.group(1) != url:
                bad.append("base/applications/iexplore/iexplore.inf: %s is %s, NITRO_SUPPORT_URL default is %s" % (key, m.group(1), url))
    except (OSError, AttributeError):
        bad.append("could not read NITRO_SUPPORT_URL / iexplore.inf")
    for b in bad:
        print(b)
    print("check-help-links: %d finding(s)" % len(bad))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
