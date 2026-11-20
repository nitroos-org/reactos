<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/nitroos-org/releases/main/docs/img/brand/lockup-1280.png">
    <img alt="NitroOS" src="https://raw.githubusercontent.com/nitroos-org/releases/main/docs/img/brand/lockup-light-1280.png" width="480">
  </picture>
</p>

<div align="center">

### An open-source, Windows-compatible operating system, built on ReactOS

[![Latest release](https://img.shields.io/github/v/release/nitroos-org/releases?label=Release&style=for-the-badge&color=0B6E4F)](https://github.com/nitroos-org/releases/releases/latest)
[![Download](https://img.shields.io/badge/Download-ISO-0B6E4F?style=for-the-badge)](https://github.com/nitroos-org/releases#download)
[![Licence: GPL 2.0 or later](https://img.shields.io/badge/Licence-GPL_2.0_or_later-555555?style=for-the-badge)](#licence)

<img src="https://img.shields.io/github/last-commit/nitroos-org/reactos/main?style=flat-square" alt="Last commit">
<img src="https://img.shields.io/github/issues/nitroos-org/reactos?style=flat-square" alt="Issues">
<img src="https://img.shields.io/github/stars/nitroos-org/reactos?style=flat-square" alt="Stars">

[Website](https://nitroos.org) ·
[Downloads and release notes](https://github.com/nitroos-org/releases) ·
[Changelog](https://github.com/nitroos-org/releases/blob/main/CHANGELOG.md) ·
[Benchmarks](https://github.com/nitroos-org/releases/blob/main/BENCHMARKS.md) ·
[How we test](TESTING.md)

</div>

> [!IMPORTANT]
> NitroOS is alpha software. Run it in a virtual machine, not on a disk with data you care about. We test it under QEMU/KVM; other hypervisors and real hardware are not covered yet.

> [!NOTE]
> NitroOS is based on [ReactOS](https://reactos.org) and is not affiliated with or endorsed by the ReactOS project. ReactOS is a trademark of the ReactOS project. Please report NitroOS problems here, not to ReactOS.

<p align="center">
  <a href="https://nitroos.org"><img width="900" alt="NitroOS running Chrome, the About dialog and Visual Studio Code" src="https://raw.githubusercontent.com/nitroos-org/releases/main/docs/img/hero.webp"></a>
</p>

This repository holds the **source code** of NitroOS: ReactOS, plus the NitroOS changes on top. Releases, installation images, the changelog and the benchmarks are in [nitroos-org/releases](https://github.com/nitroos-org/releases).

---

## Contents

- [What NitroOS adds](#what-nitroos-adds)
- [Platforms](#platforms)
- [Try it](#try-it)
- [Build it yourself](#build-it-yourself)
- [Where things are](#where-things-are)
- [How we check that it behaves like Windows](#how-we-check-that-it-behaves-like-windows)
- [Contributing](#contributing)
- [How NitroOS is built, and the use of AI](#how-nitroos-is-built-and-the-use-of-ai)
- [Relationship to ReactOS](#relationship-to-reactos)
- [Licence](#licence)

---

## What NitroOS adds

NitroOS takes ReactOS and adds what you need to use it every day. The table is a summary as of the latest release; the [feature list](https://github.com/nitroos-org/releases/blob/main/FEATURES.md) has all of it, and the [release page](https://github.com/nitroos-org/releases#screenshots) has screenshots.

| Area | What you get |
| --- | --- |
| **Current programs** | Chrome, Firefox, Edge, Visual Studio Code and PowerShell 7 install and work. |
| **32-bit and 64-bit together** | The 64-bit version also runs 32-bit programs, as Windows does. |
| **.NET and PowerShell** | Programs written for .NET Framework 4.8 run, and PowerShell 7 comes preinstalled. |
| **All your CPUs and memory** | Multi-processor support is on by default, and on 64-bit unused memory is moved to a paging file. |
| **NTFS by default** | A read/write NTFS driver with a journal that recovers the disk after a power cut. |
| **Networking** | IPv6 on by default, and a firewall that is switched on from the first boot. |
| **Optional features** | One dialog installs extras such as .NET Framework 4.8, Firefox, the Scoop package manager and software 3D graphics. |
| **Reports as Windows 10** | Installers that check the Windows version carry on instead of refusing. |

> [!TIP]
> Every release lists what changed, one line per change with a link to its commit, in the [changelog](https://github.com/nitroos-org/releases/blob/main/CHANGELOG.md). The limitations we know about are [listed openly](https://github.com/nitroos-org/releases#known-limitations) too.

---

## Platforms

| Version | Installation image | Build from source | Notes |
| --- | :---: | :---: | --- |
| **64-bit (amd64)** | ✓ | ✓ | Also runs 32-bit programs. The one to choose unless you need a 32-bit system. |
| **32-bit (i386)** | ✓ | ✓ | For 32-bit machines and virtual machines. |

Both install from a CD image onto a virtual machine that boots with BIOS. Installing on UEFI machines is being worked on for the next release.

---

## Try it

1. **Download** the ISO of the [latest release](https://github.com/nitroos-org/releases#download) and check it against `SHA256SUMS`.
2. **Create a virtual machine.** We test with QEMU/KVM: 2 to 4 CPUs, 2 to 4 GB of memory, an IDE disk of 8 GB or more and an `e1000` network card.

   ```sh
   qemu-img create -f raw nitroos.img 20G
   qemu-system-x86_64 -machine pc,accel=kvm -cpu host -smp 4 -m 4096 \
     -drive file=nitroos.img,format=raw,if=ide \
     -drive file=NITROOS.iso,media=cdrom,if=ide \
     -boot order=d -netdev user,id=n0 -device e1000,netdev=n0 \
     -device VGA -usb -device usb-tablet
   ```

3. **Install.** Boot from the ISO, choose **Install** and accept the defaults. Setup restarts once and then starts the desktop.

> [!CAUTION]
> Setup can delete and format partitions. Install into a virtual machine with its own empty disk.

The [quick start](https://github.com/nitroos-org/releases#quick-start) on the release page has the remaining steps: the first boot, the screen resolution and installing more software.

---

## Build it yourself

NitroOS builds the same way ReactOS does, with the ReactOS Build Environment (RosBE), on Linux or Windows.

### 1. Get the build environment

Install [RosBE](https://reactos.org/wiki/Build_Environment) and open its shell. It provides the compilers, CMake and Ninja.

### 2. Get the source

```sh
git clone https://github.com/nitroos-org/reactos.git
cd reactos
```

To build a release exactly as published, check out its tag, for example `git checkout nitro-2026.11-2`. The `main` branch is where development happens.

### 3. Configure

Run `configure.sh` (or `configure.cmd` on Windows) from the RosBE shell of the architecture you want. It creates the output folder `output-MinGW-<architecture>`.

```sh
./configure.sh -DCMAKE_BUILD_TYPE=Release
```

| Option | What it does |
| --- | --- |
| `-DCMAKE_BUILD_TYPE=Release` | An optimised build. Without it you get a Debug build, with assertions and debug output. |
| `-DBUILD_WOW64_ENABLED=ON -DSYSWOW64=ON` | On 64-bit: also build what is needed to run 32-bit programs. The released 64-bit ISO is built this way. |
| `-D<name>=<value>` | Any other setting, passed straight to CMake. |

> [!WARNING]
> Build the 64-bit Release version with both WoW64 options. A 64-bit Release build without `SYSWOW64` hangs during unattended installation.

### 4. Build

```sh
cd output-MinGW-amd64
ninja bootcd
```

| Command | Creates | Use it to |
| --- | --- | --- |
| `ninja bootcd` | `bootcd.iso` | Install NitroOS in a virtual machine. |
| `ninja bootcdregtest` | `bootcdregtest.iso` | Install unattended and run the test suites. |
| `ninja <module>` | One program, library or driver | Rebuild only what you changed. |

---

## Where things are

The layout is ReactOS's, so anything you know about the ReactOS tree applies here.

```text
reactos/
├── base/          # Applications, services, Setup and the shell
├── boot/          # FreeLoader, boot data and boot images
├── dll/           # User-mode DLLs: ntdll, the Win32 libraries, control panels
├── drivers/       # Kernel-mode drivers: buses, storage, file systems, network, input
├── hal/           # Hardware abstraction layers
├── media/         # Fonts, themes, INF files and documentation
├── modules/
│   └── rostests/  # The test suites: API tests, kernel-mode tests, Wine tests
├── ntoskrnl/      # The kernel and executive
├── sdk/           # Headers, libraries and build tools
├── subsystems/    # CSRSS and the other subsystems
├── win32ss/       # win32k, USER, GDI and display drivers
├── configure.sh   # Sets up a build on Linux
└── configure.cmd  # Sets up a build on Windows
```

---

## How we check that it behaves like Windows

"Compatible" has to mean something you can check. For NitroOS it means: a program that calls a Windows interface gets the answer Windows gives. We check that the same way throughout.

1. **Measure Windows first.** When we are not sure what Windows does, we write a small test program and run it on a reference Windows installation, treating Windows as a black box: we look only at what a program can observe, such as return values, error codes and output.
2. **Write the measured answers into a test.** The answers become checks in a test program in [`modules/rostests`](modules/rostests). The same test program runs on Windows and on NitroOS.
3. **Compare check by check, not by totals.** A change is accepted when the checks it is about now match Windows, and no other check changed. If a check fails on Windows too, the check is wrong, not the system.
4. **Then use real programs.** Tests can pass while a program still breaks, so browsers, development tools, .NET programs and installers are run before a change is accepted and again before each release.

NitroOS adds about 1,900 test files to the ones ReactOS already has, most of them API tests written this way. [TESTING.md](TESTING.md) describes the method, the test suites and how to run them.

---

## Contributing

Patches are welcome. Open a pull request here, and report bugs in [Issues](https://github.com/nitroos-org/reactos/issues).

- Sign off every commit (`git commit -s`); this certifies that you have the right to submit it, as the [Developer Certificate of Origin](https://developercertificate.org/) describes.
- Include a reproducer or a test with a fix.
- Report security problems privately to **security@nitroos.org**, not in a public issue.

The full rules are in the organisation's [contributing guide](https://github.com/nitroos-org/.github/blob/main/CONTRIBUTING.md) and [security policy](https://github.com/nitroos-org/.github/blob/main/SECURITY.md).

> [!WARNING]
> **Legal notice:** if you have seen proprietary Microsoft Windows source code (including but not limited to the leaked Windows NT 3.5, NT 4, 2000 source code and the Windows Research Kernel), we cannot accept your contribution, because of the risk of copyright violation.

---

## How NitroOS is built, and the use of AI

We say this plainly: NitroOS is developed with AI coding agents under the direction of a human maintainer, who decides what gets built and owns every release.

- Every change is reviewed by a different AI model than the one that wrote it, then built and tested before it is accepted.
- We use only public sources: Microsoft's public documentation, Wine, public headers and black-box measurements on Windows. We never use leaked source code, and we never copy code or data out of Microsoft programs.
- A fix counts only after a test or a real program shows it working.

The [AI policy](https://github.com/nitroos-org/.github/blob/main/AI-POLICY.md) has the details: who does what, the checks before a change lands and before a release, and the rules for patches.

> [!TIP]
> If you use AI in your own patch, you are welcome here. Say so in the pull request; we hold it to the same bar as everything else.

---

## Relationship to ReactOS

NitroOS is built on [ReactOS](https://reactos.org). The kernel, the Win32 subsystem and most of the user mode come from the ReactOS project and its contributors, who have been building them since 1998. We merge the latest ReactOS code regularly and keep our changes as a patch set on top of it.

**Our end goal is to merge all relevant work back into ReactOS.** ReactOS does not accept AI-generated code today, and we respect that: we do not submit our changes upstream. If its policy changes, we want this work there.

- ReactOS's own introduction to this source tree is kept as [README.ReactOS.md](README.ReactOS.md).
- [UPSTREAM.md](https://github.com/nitroos-org/releases/blob/main/UPSTREAM.md) explains what we change and why.
- The people and projects NitroOS depends on are thanked in the [credits](https://github.com/nitroos-org/releases#credits) and in [CREDITS](CREDITS).

---

## Licence

NitroOS uses the same licences as ReactOS, mainly [GPL-2.0-or-later](COPYING). Each file keeps its own licence and copyright notices; the LGPL and other texts those files refer to are in [COPYING.LIB](COPYING.LIB), [COPYING3](COPYING3), [COPYING3.LIB](COPYING3.LIB) and [COPYING.ARM](COPYING.ARM). Third-party components, with their versions and licences, are listed in [`media/doc/3rd Party Files.txt`](media/doc/3rd%20Party%20Files.txt).

NitroOS is an independent project. It is not affiliated with, endorsed by or sponsored by Microsoft or by the ReactOS project. Windows is a registered trademark of Microsoft Corporation. ReactOS is a trademark of the ReactOS project.
