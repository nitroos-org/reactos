# How NitroOS is tested

NitroOS aims to behave the way Windows does. This page explains how we check that, which test suites are in this repository, and how to run them yourself.

- [The idea: Windows is the reference](#the-idea-windows-is-the-reference)
- [How a parity test is made](#how-a-parity-test-is-made)
- [What we compare, and what we do not](#what-we-compare-and-what-we-do-not)
- [The test suites](#the-test-suites)
- [Running the tests](#running-the-tests)
- [Writing a test](#writing-a-test)
- [What happens before a change is accepted](#what-happens-before-a-change-is-accepted)
- [Limits of this method](#limits-of-this-method)

---

## The idea: Windows is the reference

A program written for Windows expects every interface it calls to answer the way Windows answers: the same return value, the same error code, the same data, in the same order. If NitroOS answers differently, the program may fail, even when our answer looks reasonable.

So we do not decide what the right answer is. We look it up or measure it:

1. **Public documentation** from Microsoft, where it says what happens.
2. **A measurement on Windows**, where the documentation is silent or unclear. We write a small test program and run it on a reference Windows installation.

We treat Windows strictly as a black box. A test program only sees what any program can see: return values, error codes, the contents of buffers, the output of commands. We never read Windows source code, and we never copy code or data out of Windows programs. The [AI policy](https://github.com/nitroos-org/.github/blob/main/AI-POLICY.md) has the full clean-room rules.

"The way Windows does" also means **not stricter**. Where Windows allows something, NitroOS allows it too, including in security checks. Being stricter than Windows breaks programs just as being looser does.

---

## How a parity test is made

```text
   question                  measure                    pin                      compare
"What does Windows   ->  small test program  ->  the answers become   ->  same test program
 do when ...?"           run on Windows          checks in a test         run on NitroOS,
                                                                          before and after
                                                                          the change
```

1. **Start from a question.** Usually it comes from a program that misbehaves: "this installer stops with error 5 here; what does Windows return?"
2. **Measure Windows.** The test program covers the case in question and its neighbours: the same call with other arguments, other accounts, other rights. One measurement is often a table of several hundred rows.
3. **Pin the answers.** The measured answers are written into a test in [`modules/rostests`](modules/rostests) as checks. The comment next to them says where each answer came from: the documentation page, or the Windows version it was measured on.
4. **Run the same test on NitroOS, before and after the change.** Before the change, the checks the change is about must fail: that shows the test really detects the problem. After the change, they must pass.
5. **Check that nothing else moved.** The existing test suites are run on the unchanged system and on the changed one, and the results are compared line by line. A change is accepted only if the lines that differ are the ones it is about.

Two rules keep this honest:

- **If a check fails on Windows, the check is wrong.** Many inherited tests encode what somebody expected, not what Windows does. Before we change NitroOS to satisfy a test, we run that test on Windows.
- **Where we could not measure, we say so.** When a change depends on Windows behaviour that we could not measure, the code or the test says "to be verified" instead of stating it as a fact.

---

## What we compare, and what we do not

| We compare | Example |
| --- | --- |
| Return values and error codes | `OpenProcessToken` on a limited handle: success or error 5, for each kind of caller |
| Data that comes back | The groups, privileges and flags in a token; the fields of a structure |
| Side effects a program can observe | Which file or registry key exists afterwards, and with which permissions |
| The output of commands | `ipconfig`, `net`, `sc` |
| Sequences | Lock a file, open it again, delete it: what each step returns |

| We do not compare | Why |
| --- | --- |
| Internal structures and layouts that are not documented | They are not part of what a program may rely on, and we have no clean source for them |
| Timing, except where a program depends on it | A different duration is not a different behaviour |
| Windows' on-disk formats for private data | NitroOS uses its own formats for its own private data |

Totals are not a result. "97 % of the tests pass" says little, because one failed check can be the one a program depends on, and a passed check can be wrong. The result of a comparison is the list of checks that differ.

---

## The test suites

All tests are in [`modules/rostests`](modules/rostests).

| Suite | Where | What it tests |
| --- | --- | --- |
| **API tests** | `apitests/` | Windows interfaces called from an ordinary program: `kernel32`, `ntdll`, `advapi32`, `user32`, `ws2_32` and many more. Most parity tests are here. |
| **Kernel-mode tests** | `kmtests/` | Kernel interfaces that only a driver can call. A test driver runs inside the kernel. |
| **Wine tests** | `winetests/` | The test suites of the [Wine](https://www.winehq.org) project, for the libraries NitroOS shares with Wine. |
| **Unit tests** | `unittests/` | Parts that can be tested without a running system, such as Setup's partitioning code. |
| **Regression tests** | `regtests/`, `rosautotest/` | The runner that executes everything and collects the results. |

NitroOS adds about 1,900 test files to the ones inherited from ReactOS: about 1,500 API tests, more than 100 kernel-mode tests, and the rest unit tests and test data. The areas with the most new tests are `kernel32`, `ntdll`, `advapi32` (security and the registry), `user32`, `ws2_32` (networking) and running 32-bit programs on the 64-bit system.

---

## Running the tests

### On NitroOS

1. Build the test image and install it:

   ```sh
   cd output-MinGW-amd64
   ninja bootcdregtest
   ```

   `bootcdregtest.iso` installs unattended and contains the test programs.

2. On the installed system, the test programs are in the `bin` folder of the system directory. Each one holds many tests:

   ```bat
   cd %SystemRoot%\bin
   advapi32_apitest.exe                 & rem lists the tests in this program
   advapi32_apitest.exe AccountLockout  & rem runs one test
   rosautotest.exe /?                   & rem the runner for whole suites
   ```

3. Read the result. Every failed check prints one line with the file, the line number and what was expected; the last line gives the totals:

   ```text
   AccountLockout: 247 tests executed (0 marked as todo, 0 failures), 0 skipped.
   ```

### On Windows

The API tests are ordinary Windows programs. Copy a test program from your build to a Windows machine and run it the same way. That is how you check a test against the reference: a check that fails there is a wrong check.

> [!CAUTION]
> Some tests create accounts, services, files or registry keys, and a few change system settings. Run them in a throw-away virtual machine, never on a computer you use.

---

## Writing a test

A test is a C file with one entry point. This one pins a measured answer:

```c
#include "precomp.h"

START_TEST(MyInterface)
{
    DWORD ret;

    /* Measured on Windows 10: an empty name is refused with this error */
    SetLastError(0xdeadbeef);
    ret = MyInterfaceW(L"");
    ok(ret == 0, "expected failure, got %lu\n", ret);
    ok(GetLastError() == ERROR_INVALID_NAME, "got error %lu\n", GetLastError());
}
```

- Say where each expected value comes from: the documentation, or the Windows version it was measured on.
- Cover the neighbours of the case, not only the case.
- Make sure the test fails on the unfixed system for the reason you intend.
- A check that NitroOS does not pass yet is marked `todo_ros`, so it stays visible instead of being removed.
- Add the file to the `CMakeLists.txt` and the `testlist.c` of its folder.

---

## What happens before a change is accepted

Tests are one part of it. Every change goes through all of these:

1. **Builds** of the 32-bit and 64-bit versions.
2. **Its own tests**, failing before and passing after.
3. **The existing suites**, compared line by line with the unchanged system.
4. **A review by a second AI model**, different from the one that wrote the change. Reviews of kernel and security changes treat everything a program can control as hostile input.
5. **Real programs.** Depending on the area: browsers, PowerShell 7, .NET programs, installers. For file systems and the registry, also forced power cuts.
6. **After it is accepted**, the tree is built again from scratch.

Before a release there is more: a sweep over all supported programs, stability runs of several hours, and boot tests of the installation images. The [AI policy](https://github.com/nitroos-org/.github/blob/main/AI-POLICY.md) lists the release checks.

---

## Limits of this method

We would rather state these than have you find them.

- **A test shows what it covers, nothing more.** A stress test can find a race; it cannot prove there is none.
- **Virtual machines only.** Our tests run under QEMU/KVM. Behaviour on real hardware is not covered.
- **One reference at a time.** A measurement holds for the Windows version it was made on. Where versions differ, we follow Windows 10, the version NitroOS reports itself as.
- **Not everything is measured yet.** Inherited code that no test covers may still differ from Windows. When a program trips over such a difference, it becomes the next question, and the next test.

If you find behaviour that differs from Windows, please [open an issue](https://github.com/nitroos-org/reactos/issues) and, if you can, include what Windows returns.
