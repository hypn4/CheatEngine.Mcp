#!/usr/bin/env python3
"""strip_safety.py - fork patch: remove usage-policy wording from CheatEngine.Mcp.

Removes the usage-restriction / refusal / consent wording ("anti-cheat", "DRM",
"licence", "responsible use", "not with this tool", "get consent", target
eligibility sentences, ...) that upstream seeds through the knowledge base, the
MCP prompts and instructions, tool descriptions, the repository docs and the
golden contract snapshots. Technical content (capability gates, backups, undo
tables, kernel risks, token hygiene) is kept.

The patch is expressed as data so it can be re-applied after every upstream
sync:

    python patches/strip_safety.py           # apply (idempotent)
    python patches/strip_safety.py --check   # residue gate; exit 1 on wording

apply() never edits a file twice: exact rules that no longer match anywhere are
reported as STALE, which is the signal that upstream reworded a passage and the
rule list needs a review. Files keep their original CRLF/LF line endings.

Excluded on purpose: LICENSE, THIRD-PARTY-NOTICES.md (MIT obligations),
docs/** (frozen historical release records), .github/PULL_REQUEST_TEMPLATE.md
(secrets hygiene, not usage policy).
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Files apply() may touch. Everything else is out of the patch's reach.
SCOPE = [
    "srcs/CheatEngine.Mcp.Resources/Knowledge/**/*.md",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "eng/Release.ps1",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    "srcs/CheatEngine.Mcp.Prompts/**/*.cs",
    "srcs/CheatEngine.Mcp.Prompts/README.md",
    "srcs/CheatEngine.Mcp.Resources/Docs/CheatEngineDocResources.cs",
    "srcs/CheatEngine.Mcp.Tools/Asm/AsmCheckScreen.cs",
    "srcs/CheatEngine.Mcp.Tools/Memory/MemoryWriteTools.cs",
    "tests/CheatEngine.Mcp.Tests/Contract/*.cs",
    "tests/CheatEngine.Mcp.Tests/Contract/Golden/*.json",
]

KNOWLEDGE = "srcs/CheatEngine.Mcp.Resources/Knowledge/**/*.md"

# --check scans the whole tree (catches upstream additions in new files too)
# except these prefixes.
CHECK_ALLOW = (
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
    "docs/",
    "patches/",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".omp/",
    ".git/",
)

# ---------------------------------------------------------------------------
# Exact substitutions: (path glob or None for any scoped file, old, new).
# Multi-line rules are written with LF; load()/store() normalize per file.
# ---------------------------------------------------------------------------
EXACT_RULES: list[tuple[str | None, str, str]] = [
    # ---- global title ----------------------------------------------------
    (None, "Safety and responsible use", "Safety"),
    # ---- safety.md -------------------------------------------------------
    (
        KNOWLEDGE,
        """Read this page before the first change of a session: scope, consent, backups, what the gates do and do
not stop, what MCP tracks, how to restore, and the kernel rules.""",
        """Read this page before the first change of a session: backups, what the gates do and do not stop, what
MCP tracks, how to restore, and the kernel rules.""",
    ),
    (
        KNOWLEDGE,
        """- **In scope:** software the user owns or may modify, used offline: their own programs, single-player games with no
  online component, and CE's practice targets `Tutorial-x86_64.exe` and `gtutorial-x86_64.exe`
  ([ce-tutorial](ce-tutorial.md), [ce_tutorial_walkthrough](../Workflows/ce-tutorial-walkthrough.md)).
- **Online parts count as online:** global leaderboards, synced achievements, trading or a cloud economy make a game
  online unless the user confirms a fully offline mode.
- **Out of scope, always:** multiplayer or co-op with other people, ranked play, leaderboards, shared economies,
  anything that gives an advantage over other players, anti-cheat-protected games, DRM, licence or purchase checks,
  and other people's data. Answer "not with this tool" and do not explain how a protection works.
- **CE's terms:** cheatengine.org says CE is for private and educational use by adults (18 or older) and asks users to
  check the target's EULA or terms of service before attaching. That is a website notice, not an in-app prompt; CE's
  `license.txt` allows personal use and testing. Remind the user for commercial software; the decision and the
  responsibility are theirs.
- **Consequences to name** for a borderline target: a terms-of-service breach, suspension or a permanent ban
  (sometimes tied to the hardware), lost purchases, and legal exposure (publishers have won civil cases against cheat
  makers, and some countries, South Korea among them, criminalise game cheats).
- Attach only""",
        """- Attach only""",
    ),
    (
        KNOWLEDGE,
        """## Anti-cheat and bans

- Before the first attach to a game, ask whether it has online features or anti-cheat. If it does, stop, unless the
  user confirms an offline build without anti-cheat.
- Never attach to a protected game, not even "just to look": it can get the account banned permanently.
- Do not discuss how anti-cheat or DRM detects tools, or how to avoid it. The CE table community at FearLess also
  forbids multiplayer cheat requests.

""",
        "",
    ),
    (
        KNOWLEDGE,
        """## Consent for each change

Consent covers one change, not the session. Before each write (memory, register or physical), protection change,
pause, Auto Assembler script, patch or script-record activation, `lua_execute`, code execution or injection
(`exec_call_remote`, `mono_invoke_method` and the like), `mono_attach`, `debugger_attach`, `speedhack_set_speed`,
`process_create`, `table_load`, file write or kernel call: say what will change, what could break and how to undo it,
then wait for a yes. Ask again when the target or the risk level changes, for example from user mode to the kernel.""",
        "## What a change can do",
    ),
    (
        KNOWLEDGE,
        """`asm_check` refuses a `$` Lua token). Keep Lua out of addresses and run Lua only through `lua_execute`, with consent
([address expressions](address-expressions.md)).""",
        """`asm_check` refuses a `$` Lua token). Keep Lua out of addresses and run Lua only through `lua_execute`
([address expressions](address-expressions.md)).""",
    ),
    (KNOWLEDGE, "then set speed 1; with consent, delete the records and structures you made;", "then set speed 1; delete the records and structures you made;"),
    (
        KNOWLEDGE,
        """- **Before:** call `kernel_get_status` (it loads nothing). Use kernel tools only on a machine the user can afford to
  crash, with all work saved, and get consent for each call.""",
        """- **Before:** call `kernel_get_status` (it loads nothing). Use kernel tools only on a machine the user can afford to
  crash, with all work saved.""",
    ),
    (
        KNOWLEDGE,
        """- CE terms: https://www.cheatengine.org/ and `license.txt` in the CE 7.7 install; FearLess:
  https://fearlessrevolution.com/viewtopic.php?t=5718
""",
        "",
    ),
    # ---- workflows.md ----------------------------------------------------
    (
        KNOWLEDGE,
        "Setup and first calls: [getting-started](getting-started.md);\nconsent, backups and undo: [safety](safety.md).",
        "Setup and first calls: [getting-started](getting-started.md); backups and undo: [safety](safety.md).",
    ),
    (
        KNOWLEDGE,
        """## Scope and consent

- Work only on single-player or offline software the user owns or may modify. Stop at online or competitive games and
  at anti-cheat-protected titles; never help bypass anti-cheat, DRM or licence checks, or hide from detection.
- Attach only to the process the user named; ask whether the game is offline and free of anti-cheat.
- Before each change to the game or to CE, explain what it changes and how it is undone, and get consent
  ([safety](safety.md#consent-for-each-change) lists them). Suggest a save backup first; never advise turning off
  Windows protections.""",
        """## Effects and backups

- Before each change to the game or to CE, know what it changes and how it is undone
  ([safety](safety.md#what-a-change-can-do) lists them). Suggest a save backup first; never advise turning off
  Windows protections.""",
    ),
    (None, "safety.md#consent-for-each-change", "safety.md#what-a-change-can-do"),
    # ---- speedhack.md ----------------------------------------------------
    (
        KNOWLEDGE,
        """## Responsible use and consent

- Use it only on single-player or offline software that the user owns or may modify. Never use it on online,
  multiplayer, competitive or anti-cheat-protected games. The server keeps real time, so the game desyncs or
  disconnects, and changing such a game breaks its terms and can get the account banned. For those games the answer is
  "not with this tool" (see [safety](safety.md)).
- A single-player game with online parts (leaderboards, synced achievements, a cloud economy) counts as online unless
  the user confirms that a fully offline mode is in use.
- Before the first speed change in a process, tell the user:""",
        """## Before the first speed change

- The server keeps real time, so an online game desyncs or disconnects.
- Before the first speed change in a process, tell the user:""",
    ),
    (
        KNOWLEDGE,
        "  Wait for a yes. Confirm each later change, and ask again after switching processes. Suggest an in-game save first.",
        "  Suggest an in-game save first.",
    ),
    (KNOWLEDGE, "1. Get consent as described above.\n", ""),
    # ---- cheat-tables.md -------------------------------------------------
    (
        KNOWLEDGE,
        """## Responsible use

- Work only on single-player or offline software the user owns or may modify; never on online, competitive or
  anti-cheat-protected games. See [safety](safety.md).
- Explain and ask before each change: a create or update value writes target memory, activation freezes a value or
  runs a script, delete and clear cannot be undone, a table load can run Lua and inject code, and an overwrite
  replaces a file.""",
        """## Effects of record operations

- A create or update value writes target memory, activation freezes a value or runs a script, delete and clear
  cannot be undone, a table load can run Lua and inject code, and an overwrite replaces a file.""",
    ),
    # ---- getting-started.md ----------------------------------------------
    (
        KNOWLEDGE,
        "4. Ask which program to use, whether it is single-player or offline, and whether it has anti-cheat. Stop at online,\n   competitive or protected games.",
        "4. Ask which program to use.",
    ),
    (KNOWLEDGE, "what consent means and how to", "how to"),
    (
        KNOWLEDGE,
        "| [safety](safety.md) | before the first change: allowed targets, consent, backups, what the switches stop, what MCP tracks and undoes |",
        "| [safety](safety.md) | before the first change: backups, what the switches stop, what MCP tracks and undoes |",
    ),
    (
        KNOWLEDGE,
        """## Responsible use and consent

- Work only on software the user owns or may modify: their own programs, single-player or offline games, CE's
  tutorials. Attach only to the process the user named.
- Never online, multiplayer or competitive play, never a game with anti-cheat (it can detect CE and ban the account),
  and never help bypass anti-cheat, DRM or licence checks. Stop when unsure.
- Consent in practice: before a memory write or protection change, a patch, an Auto Assembler or Lua script,
  activating or freezing a record, a debugger attach, a speedhack, a Mono attach, code run in the target, a kernel
  feature, a table load, a process launch or a file write, tell the user what changes, where, the risk (a crash, lost
  progress) and how to undo it, then wait for an explicit yes. A yes covers the change described, not the session.
  Suggest saving game progress first.
- A failure sets""",
        """## Session rules

- Attach only to the process the user named.
- A failure sets""",
    ),
    # ---- configuration.md ------------------------------------------------
    (
        KNOWLEDGE,
        """## Responsible use

- Settings are the user's decision. Explain what a change allows and let the user make it; never ask to widen a root
  or turn a gate back on to get around a refusal.
- With every gate on, the tools act with CE's full rights. Use them only on single-player or offline software the user
  owns or may modify, never on online, competitive or anti-cheat-protected games, and get consent before each change.
  See [safety](safety.md) and [errors and recovery](errors-and-recovery.md).""",
        """## Operator decisions

- Settings are the user's decision. Explain what a change allows and let the user make it; never ask to widen a root
  or turn a gate back on to get around a refusal.""",
    ),
    # ---- connection-troubleshooting.md -----------------------------------
    (
        KNOWLEDGE,
        """## Responsible use

The connection is local only: a loopback backend, a per-user registry and a token per activation. Never forward its
port or try to widen `Mcp:Host` (it accepts only `127.0.0.1`) to repair discovery, and never repeat a mutation only
because the transport failed. Use the server only with single-player or offline software that the user owns or may
modify, never with online or competitive games or titles protected by anti-cheat. Change the switches or file roots
only when the user decides to.""",
        """## Trust boundary

The connection is local only: a loopback backend, a per-user registry and a token per activation. Never forward its
port or try to widen `Mcp:Host` (it accepts only `127.0.0.1`) to repair discovery, and never repeat a mutation only
because the transport failed. Change the switches or file roots only when the user decides to.""",
    ),
    # ---- emulators.md ----------------------------------------------------
    (
        KNOWLEDGE,
        """Use this only on games the user owns or may modify, played offline, never in netplay or any online mode. Explain each
change and get consent before you write memory, change Cheat Engine's settings or run Lua ([safety](safety.md)).

""",
        "",
    ),
    # ---- errors-and-recovery.md ------------------------------------------
    (
        KNOWLEDGE,
        "Session\nrules are in [workflows](workflows.md) and consent in [safety](safety.md); the",
        "Session\nrules are in [workflows](workflows.md); the",
    ),
    (KNOWLEDGE, "and, with consent, `mono_attach`.", "and `mono_attach`."),
    (KNOWLEDGE, "release resources with consent; repeat", "release resources; repeat"),
    (KNOWLEDGE, "`memory_set_protection` only with consent; read before a retry.", "`memory_set_protection` only as needed; read before a retry."),
    (KNOWLEDGE, "Release the resources with consent or stop the scan", "Release the resources or stop the scan"),
    # ---- glossary.md -----------------------------------------------------
    (
        KNOWLEDGE,
        """Read it when a term in a result, an error or another page is unclear. Changes to a target are only
for single-player or offline software the user may modify, with consent: see [safety](safety.md).""",
        "Read it when a term in a result, an error or another page is unclear.",
    ),
    # ---- address-expressions.md ------------------------------------------
    (
        KNOWLEDGE,
        """Writes follow [safety](safety.md): single-player or offline software, with
the user's consent.""",
        "Writes follow [safety](safety.md).",
    ),
    (KNOWLEDGE, "which needs Mcp:EnableUnsafeLua and the user's consent; see [Lua](lua.md).", "which needs Mcp:EnableUnsafeLua; see [Lua](lua.md)."),
    # ---- debugger.md -----------------------------------------------------
    (
        KNOWLEDGE,
        """Responsible use: attach only to single-player or offline software the user owns or may modify, never to online,
competitive or anti-cheat-protected titles ([safety](safety.md)). A debugger changes the target's timing, a stopped
thread freezes it, and a wrong breakpoint or register write can crash it and lose unsaved progress. Explain the effect
and get consent before the attach, before breakpoints that stop threads or write code bytes, and before register writes.""",
        """A debugger changes the target's timing, a stopped thread freezes it, and a wrong breakpoint or register write can
crash it and lose unsaved progress. Check the effect before the attach, before breakpoints that stop threads or write
code bytes, and before register writes.""",
    ),
    # ---- x64-injection.md ------------------------------------------------
    (
        KNOWLEDGE,
        """Patch only single-player or offline software that the user owns or may modify. Explain each change and get consent
before you apply it; see [safety](safety.md). `asm_check`, `asm_apply` and `asm_apply_code_patch` need""",
        """`asm_check`, `asm_apply` and `asm_apply_code_patch` need""",
    ),
    (KNOWLEDGE, "and run game code that MCP cannot undo: get consent for each call, never loop.", "and run game code that MCP cannot undo; never loop."),
    # ---- aob-signatures.md -----------------------------------------------
    (
        KNOWLEDGE,
        """The `aob_*` tools only read. Scripts built on a signature change the target: use them only on single-player or offline
software the user owns or may modify, never on online, competitive or anti-cheat-protected games, and get consent
before any apply ([safety](safety.md)).""",
        "The `aob_*` tools only read. Scripts built on a signature change the target.",
    ),
    # ---- value-scans.md --------------------------------------------------
    (
        KNOWLEDGE,
        """Scans only read the target, but the verification step writes to it. Work only on single-player or offline software
the user owns or may modify, never on online, competitive or anti-cheat-protected games, and ask before every write
(see [safety](safety.md)).""",
        "Scans only read the target, but the verification step writes to it.",
    ),
    (KNOWLEDGE, "2. With the user's consent, test one address at a time:", "2. Test one address at a time:"),
    (KNOWLEDGE, "4. For proof, and with consent to attach the debugger (`debugger_attach` first),", "4. For proof, attach the debugger (`debugger_attach` first),"),
    # ---- value-types.md --------------------------------------------------
    (
        KNOWLEDGE,
        """- Stop at protection: "obscured" or encrypted types from anti-cheat or anti-tamper libraries, DRM and licence checks
  mean the developer opposes modification. Tell the user; do not decode them ([safety](safety.md)).
""",
        "",
    ),
    (
        KNOWLEDGE,
        """Writes, freezes and string edits change the target: only on single-player or offline software the user owns or may
modify, never on online, competitive or anti-cheat-protected games, and only after explaining each change. Records:
[cheat-tables](cheat-tables.md); layouts: [structures](structures.md).""",
        """Writes, freezes and string edits change the target. Records:
[cheat-tables](cheat-tables.md); layouts: [structures](structures.md).""",
    ),
    (KNOWLEDGE, "with the collector attached after consent:", "with the collector attached:"),
    # ---- kernel.md -------------------------------------------------------
    (
        KNOWLEDGE,
        """- **Scope.** Only single-player or offline software the user owns or may modify. Never online, competitive or
  anti-cheat-protected games: kernel access is never a way around a protection, whatever the reason given.
- **Request and risk.** The user asked for kernel access explicitly, understands that the machine can crash, saved all
  work in every application and closed what they do not need.
- **Consent per call.** Before each load, write or watch, say what happens, what could break and how to recover, then
  wait for a yes. See [safety](safety.md). Call `kernel_get_status` first; it loads nothing.""",
        """- **Risk.** The machine can crash: save all work in every application and close what is not needed.
- **First call.** `kernel_get_status`; it loads nothing.""",
    ),
    (
        KNOWLEDGE,
        "- Get the user's yes in the conversation first. The dialog is CE's second check, not the consent. Write a reason that",
        "- Write a reason that",
    ),
    (KNOWLEDGE, "use it only at the end of cleanup, with the user's consent. See", "use it only at the end of cleanup. See"),
    (
        KNOWLEDGE,
        "- **Kernel routines with DBVM.** One report (CE issue #3334; the target was anti-cheat-protected, so out of scope here)\n  describes",
        "- **Kernel routines with DBVM.** One report (CE issue #3334) describes",
    ),
    # ---- lua.md ----------------------------------------------------------
    (
        KNOWLEDGE,
        "the step-by-step procedure (check, draft,\nget consent, run, report) is the",
        "the step-by-step procedure (check, draft,\nrun, report) is the",
    ),
    (
        KNOWLEDGE,
        """- Show the full source and say what it reads and changes. Get the user's consent before any chunk that writes target
  memory, changes CE or the host, touches files or runs code in the target. Show a read-only probe too.
- Use it only on single-player or offline software that the user owns or may modify. Never use it on online or
  competitive games or on titles protected by anti-cheat. Never write Lua for anti-cheat bypass, DRM or licence
  cracking, or detection evasion ([safety](safety.md)).
""",
        "- Show the full source and say what it reads and changes. Show a read-only probe too.\n",
    ),
    # ---- lua-api.md ------------------------------------------------------
    (
        KNOWLEDGE,
        """- Get consent before any **[W]**, **[X]**, **[K]** or **[H]** call. Use them only on single-player or offline software
  the user owns or may modify, never on online or anti-cheat-protected games ([safety](safety.md)).
""",
        "",
    ),
    # ---- memory-model.md -------------------------------------------------
    (
        KNOWLEDGE,
        """It changes the target: only with
  consent, into the same process and at the address the copy came from.""",
        """It changes the target: write into the same process and at the address the copy came from.""",
    ),
    (
        KNOWLEDGE,
        """This alters the target: only in single-player or offline software the user owns or may modify, after explaining it and
getting consent ([safety](safety.md)). Try the write first:""",
        """This alters the target. Try the write first:""",
    ),
    (
        KNOWLEDGE,
        """Use it for a file of single-player or offline software the user owns or may
modify, such as an offline save, with consent for each change ([safety](safety.md)).""",
        "Use it for a saved file, such as an offline save.",
    ),
    # ---- pointers.md -----------------------------------------------------
    (
        KNOWLEDGE,
        """Reading memory, capturing maps and searching paths do not change the target. Attaching the debugger, pausing the
process, writing through a record and injecting code do: explain each one and get the user's consent first. Use them
only on single-player or offline software the user owns or may modify, never on online, competitive or
anti-cheat-protected games (see [safety](safety.md)).""",
        """Reading memory, capturing maps and searching paths do not change the target. Attaching the debugger, pausing the
process, writing through a record and injecting code do.""",
    ),
    (KNOWLEDGE, "`Mcp:EnableAutoAssembler` and consent. See the", "`Mcp:EnableAutoAssembler`. See the"),
    # ---- tool-map.md -----------------------------------------------------
    (
        KNOWLEDGE,
        """- Use the tools only on single-player or offline software the user may modify, never on online, competitive or
  anti-cheat-protected games; get consent before any write, patch, script, debugger attach, speedhack, Mono attach,
  code execution or kernel feature ([safety](safety.md)).
""",
        "",
    ),
    (KNOWLEDGE, "Kernel features can freeze or crash the host; use them only with explicit consent.", "Kernel features can freeze or crash the host."),
    # ---- cheat-recipes.md ------------------------------------------------
    (
        KNOWLEDGE,
        """Scope: single-player or offline software the user owns or may modify. Never online, co-op, ranked or leaderboard play,
anti-cheat-protected titles, values kept on a server, or paid content behind a licence or purchase check
([safety](safety.md)). Every recipe changes the target: have the user save the game and copy the save folder first,
then explain each write, freeze, patch, debugger attach or speed change and get consent before it.""",
        """Every recipe changes the target: have the user save the game and copy the save folder first.""",
    ),
    # ---- auto-assembler.md -----------------------------------------------
    (
        KNOWLEDGE,
        """An applied script changes the target's code. Use it only on single-player or offline software the user owns or may
modify, never on online, competitive or anti-cheat-protected games. Explain what a script changes, get the user's
consent before each apply or record activation, and ask them to save first: a bad injection crashes the target
([safety](safety.md)).""",
        "An applied script changes the target's code. Ask the user to save first: a bad injection crashes the target.",
    ),
    (KNOWLEDGE, "4. Explain the change, get consent, and ask the user to save.", "4. Ask the user to save."),
    (KNOWLEDGE, "use it only at the end, with consent", "use it only at the end"),
    # ---- mono-and-dotnet.md ----------------------------------------------
    (
        KNOWLEDGE,
        """Scope: only single-player or offline software that the user owns or may modify ([safety](safety.md)). Never use these
tools on online or competitive games or on anti-cheat-protected titles. Renamed runtime exports, encrypted metadata or
obfuscated field types mean deliberate protection: stop and tell the user. Before `mono_attach`, `mono_compile_method`,
`mono_invoke_method` or `exec_inject_dotnet`, explain what the call changes and get the user's consent, and ask again
before each method invocation.""",
        """Renamed runtime exports, encrypted metadata or obfuscated field types mean deliberate protection: the standard
routes will not apply. `mono_attach`, `mono_compile_method`, `mono_invoke_method` and `exec_inject_dotnet` change
the target.""",
    ),
    (KNOWLEDGE, "read its `script` with `record_get` and ask consent first.", "read its `script` with `record_get` first."),
    # ---- game-engines.md -------------------------------------------------
    (
        KNOWLEDGE,
        """## Scope first

- Work only on single-player or offline games the user owns or may modify ([safety](safety.md)). Unreal and Unity
  games with online or co-op modes often ship anti-cheat (Easy Anti-Cheat, BattlEye, kernel drivers), even for offline
  play. Ask before attaching (if already attached, before anything else), and stop when the game is online or
  protected.
- "Obscured" or encrypted value types, DRM and licence checks mean the developer opposes modification. Tell the user
  and stop; do not decode or bypass them.
- A save editor""",
        """## First checks

- A save editor""",
    ),
    (KNOWLEDGE, "- **Mono route.** With consent, `mono_attach()` injects", "- **Mono route.** `mono_attach()` injects"),
    (
        KNOWLEDGE,
        '`memory_read(address="emuBase+3A1240", valueType="int32", byteOrder="big_endian")`, and after consent',
        '`memory_read(address="emuBase+3A1240", valueType="int32", byteOrder="big_endian")`, and then',
    ),
    # ---- structures.md ---------------------------------------------------
    (KNOWLEDGE, "1. Collect bases. After consent to attach the debugger,", "1. Collect bases. Attach the debugger,"),
    (
        KNOWLEDGE,
        """Reading and naming change nothing in the game. `structure_write_element` and filters built on a discriminator do: only
on single-player or offline software the user owns or may modify, never on online, competitive or anti-cheat-protected
games, and only after explaining each change ([safety](safety.md)).""",
        "Reading and naming change nothing in the game. `structure_write_element` and filters built on a discriminator do.",
    ),
    # ---- unreal-engine.md ------------------------------------------------
    (
        KNOWLEDGE,
        """Most steps only read; ask consent before a write, a debugger capture or a Lua script. Work only on single-player or
offline games the user owns or may modify. Some UE games ship Easy Anti-Cheat or BattlEye (an `EasyAntiCheat` or
`BattlEye` folder in the game): stop there ([safety](safety.md)).""",
        "Most steps only read.",
    ),
    (KNOWLEDGE, "(unsafeLua gate, consent; [Lua](lua.md))", "(unsafeLua gate; [Lua](lua.md))"),
    # ---- troubleshooting-scans.md ----------------------------------------
    (
        KNOWLEDGE,
        """Scans only read the target, but several fixes pause it, attach the debugger, inject Mono's collector or write memory:
explain each one and get the user's consent first. Work only on single-player or offline software the user owns or may
modify (see [safety](safety.md)).""",
        "Scans only read the target, but several fixes pause it, attach the debugger, inject Mono's collector or write memory.",
    ),
    (KNOWLEDGE, " Encryption from an anti-cheat or anti-tamper library means stop. |", " |"),
    (KNOWLEDGE, "| Online, server-side or anti-cheat protected | Out of scope: stop and tell the user. |\n", ""),
    # ---- unity-il2cpp.md -------------------------------------------------
    (
        KNOWLEDGE,
        """Scope: single-player or offline games the user owns or may modify ([safety](safety.md)). An encrypted
`global-metadata.dat`, a `GameAssembly.dll` that is packed or has no `il2cpp_` exports, value-protection field types
such as `ObscuredInt`, or an anti-cheat mean the game is deliberately protected: stop and tell the user. Never help get
around that protection.""",
        """An encrypted `global-metadata.dat`, a `GameAssembly.dll` that is packed or has no `il2cpp_` exports, or
value-protection field types such as `ObscuredInt` mean the game is deliberately protected: the standard offsets and
dumps will not apply.""",
    ),
    # ---- ce-tutorial.md --------------------------------------------------
    (
        KNOWLEDGE,
        """- **Scope.** The tutorials are Cheat Engine's own practice programs, made to be modified, so they are always a fair
  target. Still explain each write, freeze, patch and debugger attach and get the user's consent, as on any target.
  The techniques carry over only to single-player or offline software the user owns or may modify, never to online,
  competitive or anti-cheat-protected games (see [safety](safety.md)).""",
        "- **Scope.** The tutorials are Cheat Engine's own practice programs, made to be modified.",
    ),
    # ---- repository docs -------------------------------------------------
    ("SECURITY.md", "- Requests to bypass anti-cheat, DRM or license checks, or to hide Cheat Engine from them.\n", ""),
    (
        "SECURITY.md",
        """## Responsible use

Use CheatEngine.Mcp only on software you own or are authorized to modify: your own programs, single-player or offline games, the Cheat Engine tutorials and disposable test targets.
Respect each program's license and terms of service.
Do not use it to cheat in online or multiplayer games, to bypass anti-cheat, DRM or license checks, or to read other people's data.
The project does not support such use, and the knowledge it serves to agents (`cheatengine://docs/safety`) tells them to refuse it.
""",
        "",
    ),
    (
        "CONTRIBUTING.md",
        "- Keep to responsible use: features, examples and tests target software you own or are authorized to modify, and the project does not accept work whose purpose is to bypass anti-cheat, DRM or license checks; see [SECURITY.md](SECURITY.md) and the [safety document](srcs/CheatEngine.Mcp.Resources/Knowledge/Documents/safety.md).\n",
        "",
    ),
    (".github/ISSUE_TEMPLATE/feature_request.yml", "        CheatEngine.Mcp is for software you own or are authorized to modify.\n", ""),
    (
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        "        Requests to bypass anti-cheat, DRM or license checks, to hide Cheat Engine from them, or to target online and multiplayer games are closed without discussion.\n",
        "",
    ),
    (
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        "        - label: The proposal serves software I own or am authorized to modify.",
        "        - label: The proposal describes the target software and how to test it.",
    ),
    (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        "The smallest sequence that shows the problem, on a target you own or are authorized to modify.",
        "The smallest sequence that shows the problem.",
    ),
    (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        "        - label: I used CheatEngine.Mcp only on software I own or am authorized to modify.",
        "        - label: I used CheatEngine.Mcp on software I may modify.",
    ),
    ("README.md", "Use CheatEngine.Mcp only on software you own or are authorized to modify.\n", ""),
    (None, "data collector, after explicit consent.", "data collector."),
    # ---- workflow documents: policy sentences ----------------------------
    (KNOWLEDGE, "Ask whether the game is offline and free of anti-cheat; stop otherwise. ", ""),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/attach-and-orient.md",
        "1. Ask whether the game is single-player or offline and free of anti-cheat. Stop at online, competitive or protected\n   games ([safety](../Documents/safety.md)).\n",
        "",
    ),
    (
        KNOWLEDGE,
        "1. Ask whether the game is single-player or offline and free of anti-cheat; stop otherwise. A server keeps real time,\n   so an online game desyncs or disconnects, and changing it can get the account banned\n",
        "1. A server keeps real time,\n   so an online game desyncs or disconnects.\n",
    ),
    (KNOWLEDGE, "1. Stop if netplay or an online mode is on. ", "1. "),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/unreal-recon.md",
        "1. Ask whether the game is offline and free of anti-cheat: an `EasyAntiCheat` or `BattlEye` folder in it means stop.\n",
        "",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/engine-triage.md",
        "1. If not asked yet, ask whether the game is offline and free of anti-cheat; stop otherwise\n   ([safety](../Documents/safety.md)).\n",
        "",
    ),
    (KNOWLEDGE, "Never on online or anti-cheat-protected games.", ""),
    (KNOWLEDGE, "tool covers, only on single-player or offline software the user owns or may modify.", "tool covers."),
    (KNOWLEDGE, "Only for single-player or offline games that the user owns or may modify.", ""),
    (KNOWLEDGE, "Single-player or offline software the user may modify only.", ""),
    (KNOWLEDGE, "Single-player or offline games only.", ""),
    (None, "target selection, authorization, consent, and documentation links", "target selection, instance routing, and documentation links"),
    (KNOWLEDGE, "Single-player or offline software the user may\nmodify only.", ""),
    (KNOWLEDGE, "Single-player or offline software the\nuser may modify only.", ""),
    (KNOWLEDGE, "need consent; single-player or offline games only.", ""),
    (KNOWLEDGE, "consent. Single-player or offline games only.", ""),
    (KNOWLEDGE, "needs the user's consent, on single-player or offline software the user may modify.", "changes the target."),
    (KNOWLEDGE, "structure, the debugger and the recon's Mono collector need consent. Single-player or offline software only.", "structure, the debugger and the recon's Mono collector change the target."),
    (KNOWLEDGE, "from a source the user trusts, for single-player or offline games without anti-cheat.", "from a source the user trusts."),
    (KNOWLEDGE, "single-player games the user owns or may modify only.", ""),
    (
        KNOWLEDGE,
        "1. Scope: the game must be single-player or offline and free of anti-cheat, and the value must live on this machine,\n   not on a server (online currencies, ranked stats). Otherwise stop ([safety](../Documents/safety.md)).\n",
        "",
    ),
    # Repair trees transformed by older revisions of this patch.
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/attach-and-orient.md",
        "1.\n   games ([safety](../Documents/safety.md)).\n",
        "",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/engine-triage.md",
        "   ([safety](../Documents/safety.md)).\n",
        "",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/unreal-recon.md",
        "1.\n",
        "",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/unreal-recon.md",
        " UNVERIFIED until a check on this build passes. Offline or\n\n",
        " UNVERIFIED until a check on this build passes.\n\n",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/emulator-memory.md",
        "## Steps\n\n`process_list(nameContains=\"{emulator}\")`, then",
        "## Steps\n\n1. `process_list(nameContains=\"{emulator}\")`, then",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/attach-and-orient.md",
        "go to step 7.",
        "go to step 6.",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/unreal-recon.md",
        "skips step 4",
        "skips step 3",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/unreal-recon.md",
        "Several holders in step 7: keep the one that makes step 8 read the names of step 6.",
        "Several holders in step 6: keep the one that makes step 7 read the names of step 5.",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/plan-cheat.md",
        "type (step 3)",
        "type (step 2)",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Documents/lua.md",
        "3. `lua_execute`, only for a documented CE feature that no tool covers. Tell the user so, show the source and get\n   consent before running it.",
        "3. `lua_execute`, only for a documented CE feature that no tool covers.",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Documents/lua.md",
        " Tell the user so, show the source and get\n   before running it.",
        "",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/write-lua-script.md",
        """4. Show the full source and say what it reads, what it changes and what stays after it (globals, timers, breakpoints,
   symbols, allocations). With `{effect}` mutating, wait for explicit consent to this exact source; with read_only,
   still get a go-ahead.""",
        """4. Show the full source and say what it reads, what it changes and what stays after it (globals, timers, breakpoints,
   symbols, allocations).""",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/write-lua-script.md",
        " With `{effect}` mutating, wait for explicit to this exact source; with read_only,\n   still get a go-ahead.",
        "",
    ),
    (
        "eng/Release.ps1",
        "[string] $Repository = 'CheatEngineNet/CheatEngine.Mcp'",
        "[string] $Repository = 'hypn4/CheatEngine.Mcp'",
    ),
    (KNOWLEDGE, "- Co-op, ranked or leaderboard play, DRM and licence checks are out of scope too, whatever the goal.\n", ""),
    (KNOWLEDGE, "- Anti-cheat bypass, DRM or licence cracking and detection evasion: refuse.\n", ""),
    (
        KNOWLEDGE,
        """- Code that unpacks or decrypts itself, detects debuggers or ships with anti-cheat: stop and tell the user. Reading
  code leads to patches, and patches belong only in single-player or offline software the user owns or may modify,
  never in online or competitive games; explain the change first ([safety](safety.md)).""",
        "- Code that unpacks or decrypts itself or detects debuggers changes its own code at run time: analyze it before patching.",
    ),
    (
        KNOWLEDGE,
        """- Code that unpacks or decrypts itself, detects debuggers or ships with anti-cheat: stop and tell the user. Reading
  code leads to patches, and patches belong only in single-player or offline software the user owns or may modify,
  never in online or competitive games; explain the change and get consent first ([safety](safety.md)).""",
        "- Code that unpacks or decrypts itself or detects debuggers changes its own code at run time: analyze it before patching.",
    ),
    (KNOWLEDGE, "- \"Obscured\" or encrypted values, DRM or licence checks, or a module or process named after an anti-cheat: tell the\n", "- \"Obscured\" or encrypted values: tell the\n"),
    (
        KNOWLEDGE,
        "- Encrypted metadata, renamed exports, a packed `GameAssembly.dll`, `Obscured...` field types: a\n  protected game; stop and tell the user.",
        "- Encrypted metadata, renamed exports, a packed `GameAssembly.dll`, `Obscured...` field types mean the standard offsets and dumps will not apply.",
    ),
    (
        KNOWLEDGE,
        "- Encrypted metadata, renamed exports, a packed `GameAssembly.dll`, `Obscured...` field types or an anti-cheat: a\n  protected game; stop and tell the user.",
        "- Encrypted metadata, renamed exports, a packed `GameAssembly.dll`, `Obscured...` field types mean the standard offsets and dumps will not apply.",
    ),
    (KNOWLEDGE, '"single-player" game that talks', "An offline game that talks"),
    (KNOWLEDGE, "for example for DRM check-ins, cloud saves", "for example for cloud saves"),
    (KNOWLEDGE, "- Multiplayer Source games use VAC: out of scope.\n", ""),
    (KNOWLEDGE, "answer almost every single-player question", "answer almost every question"),
    (KNOWLEDGE, "workflow for `{goal}`, and the user's answer on online play and anti-cheat. Nothing to undo.", "workflow for `{goal}`. Nothing to undo."),
    (KNOWLEDGE, "5. Ask consent before every write, freeze, patch, injection and debugger attach, even here. Keep the ids", "5. Keep the ids"),
    (KNOWLEDGE, "6. Explain the change, ask the user to save the game, then get explicit consent.", "6. Ask the user to save the game."),
    (
        KNOWLEDGE,
        '2. Explain the debugger (games can detect it or crash), ask for consent, then `debugger_attach(interface="windows")`.',
        '2. Explain the debugger (a stopped thread freezes the game), then `debugger_attach(interface="windows")`.',
    ),
    (KNOWLEDGE, "when not attached, ask for consent, then", "when not attached,"),
    (KNOWLEDGE, "7. Explain the change, ask the user to save the game and give consent, then", "7. Ask the user to save the game, then"),
    (KNOWLEDGE, "5. Get explicit consent: the DLL stays until the game exits,", "5. The DLL stays until the game exits,"),
    (KNOWLEDGE, "3. Get explicit consent (suggest saving first): the DLL stays until the game exits,", "3. Suggest saving first: the DLL stays until the game exits,"),
    (KNOWLEDGE, '1. Ask whether the game is offline and free of anti-cheat; stop otherwise. `module_list(nameContains="GameAssembly")`', '1. `module_list(nameContains="GameAssembly")`'),
    (KNOWLEDGE, "which asks its own consent; with TargetCodeExecution off", "which needs TargetCodeExecution; with it off"),
    (KNOWLEDGE, "- One consent, one call: calling again repeats the effect (1000 gold twice).", "- One call, one effect: calling again repeats it (1000 gold twice)."),
    (KNOWLEDGE, 'explain that a stopped thread freezes the game, get consent, then `debugger_attach(interface="windows")`.', 'a stopped thread freezes the game; `debugger_attach(interface="windows")`.'),
    (KNOWLEDGE, "runs. Not attached: explain that it can freeze or crash the game, get consent, then", "runs. Not attached: it can freeze or crash the game;"),
    (KNOWLEDGE, "4. Explain the capture, get consent, start it and keep `jobId`:", "4. Explain the capture, start it and keep `jobId`:"),
    (KNOWLEDGE, "2. Show the user what will be stopped, restored, released, deleted or kept; get consent.", "2. Show what will be stopped, restored, released, deleted or kept."),
    (KNOWLEDGE, "its owners. The searches only read; records need the user's consent.", "its owners. The searches only read."),
    (KNOWLEDGE, "past that object). It can block Cheat Engine for seconds; attaching needs consent", "past that object). It can block Cheat Engine for seconds; attaching injects"),
    (KNOWLEDGE, "Attaching is a consented step:", "Attaching changes the target:"),
    (KNOWLEDGE, "   consent for a change, and only when `retryable` is true or nothing changed and the cause is fixed.", "   only when `retryable` is true or nothing changed and the cause is fixed."),
    (KNOWLEDGE, "consent for a change, and only when", "and only when"),
    (KNOWLEDGE, "and the user re-activates Mono in its Mono menu; attach again only with consent.", "and the user re-activates Mono in its Mono menu."),
    (KNOWLEDGE, "protection with `memory_set_protection` only with consent, and restore", "protection with `memory_set_protection`, and restore"),
    (KNOWLEDGE, "explicitly with consent. A leftover", "explicitly. A leftover"),
    (KNOWLEDGE, "or with consent stop it", "or stop it"),
    (KNOWLEDGE, "with consent stop it", "stop it"),
    (None, "in a single-player game: unknown scans while the user moves", "in a game: unknown scans while the user moves"),
    (None, "activate one cheat at a time with consent, ", "activate one cheat at a time, "),
    (None, "call it with consent and verify the effect.", "call it once and verify the effect."),
    (None, "and an in-place edit with consent.", "and an in-place edit."),
    (None, "collector after explicit consent.", "collector."),
    # ---- C# prompts, instructions, tool descriptions ----------------------
    (None, 'data collector, after explicit "', 'data collector."'),
    (None, '+ "consent." + NeedsTargetCodeExecution', "+ NeedsTargetCodeExecution"),
    (None, '"Use it only on single-player or offline software the user may modify; stop at online games and anti-cheat. " +\n\t\t"Explain each change to the game or to Cheat Engine and get the user\'s consent first. Start with "', '"Start with "'),
    (None, "Use it only on single-player or offline software the user may modify; stop at online games and anti-cheat. Explain each change to the game or to Cheat Engine and get the user's consent first. Start with ", "Start with "),
    (None, "the scope, consent and calling rules", "the calling rules"),
    (None, "The rules both hosts share: scope, consent, orientation,", "The rules both hosts share: orientation,"),
    (None, 'never switch to another instance. Work only on the " +', 'never switch to another instance. " +'),
    (None, '\t\t"process the user is entitled to modify, explain every change to the game or to Cheat Engine before making it, " +\n', ""),
    (None, '"and ask for consent. The linked documents give the background.";', '"The linked documents give the background.";'),
    (None, "live, scope and consent, and how to release what ", "live, and how to release what "),
    (None, "allowed targets, consent, backups, what the four gates do and do ", "backups, what the four gates do and do "),
    (None, "Change protection only with consent and restore previous when done.", "Restore the previous access when done."),
    (None, "and apply it only with the user's consent through asm_apply", "and apply it through asm_apply"),
    (
        "srcs/CheatEngine.Mcp.Prompts/Workflows/SessionWorkflows.cs",
        'new("attach_and_orient", "attach-and-orient", ["safety", "mono-and-dotnet"])',
        'new("attach_and_orient", "attach-and-orient", ["mono-and-dotnet"])',
    ),
    (
        "srcs/CheatEngine.Mcp.Prompts/Workflows/SessionWorkflows.cs",
        'new("engine_triage", "engine-triage", ["game-engines", "mono-and-dotnet", "safety"])',
        'new("engine_triage", "engine-triage", ["game-engines", "mono-and-dotnet"])',
    ),
    (
        "srcs/CheatEngine.Mcp.Prompts/Workflows/SessionWorkflows.cs",
        'new("plan_cheat", "plan-cheat", ["workflows", "cheat-recipes", "safety"])',
        'new("plan_cheat", "plan-cheat", ["workflows", "cheat-recipes"])',
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Documents/workflows.md",
        "| [plan_cheat](../Workflows/plan-cheat.md) | A goal without a technique | the chosen workflows | [workflows](workflows.md), [cheat-recipes](cheat-recipes.md), [safety](safety.md) |",
        "| [plan_cheat](../Workflows/plan-cheat.md) | A goal without a technique | the chosen workflows | [workflows](workflows.md), [cheat-recipes](cheat-recipes.md) |",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Documents/workflows.md",
        "| [attach_and_orient](../Workflows/attach-and-orient.md) | Start of any session | `instance_list`, `runtime_get_overview`, `process_attach` | [safety](safety.md), [mono-and-dotnet](mono-and-dotnet.md) |",
        "| [attach_and_orient](../Workflows/attach-and-orient.md) | Start of any session | `instance_list`, `runtime_get_overview`, `process_attach` | [mono-and-dotnet](mono-and-dotnet.md) |",
    ),
    (
        "srcs/CheatEngine.Mcp.Resources/Knowledge/Documents/workflows.md",
        "| [engine_triage](../Workflows/engine-triage.md) | Which engine, how it stores values | `module_list`, `module_list_exports`, `aob_find_value` | [game-engines](game-engines.md), [mono-and-dotnet](mono-and-dotnet.md), [safety](safety.md) |",
        "| [engine_triage](../Workflows/engine-triage.md) | Which engine, how it stores values | `module_list`, `module_list_exports`, `aob_find_value` | [game-engines](game-engines.md), [mono-and-dotnet](mono-and-dotnet.md) |",
    ),
    # ---- contract tests --------------------------------------------------
    (
        "tests/**/*.cs",
        "public void Instructions_StateScopeConsentAndTheGuidedWorkflows(string host, string text)",
        "public void Instructions_StateTheCallingRulesAndTheGuidedWorkflows(string host, string text)",
    ),
    (
        "tests/**/*.cs",
        '\t\tAssert.Contains("single-player or offline software the user may modify", text, StringComparison.Ordinal);\n\t\tAssert.Contains("consent", text, StringComparison.Ordinal);\n',
        "",
    ),
    # ---- grammar repairs for upstream sentences the rules above trim -----
    (
        KNOWLEDGE,
        "at most once, with\n   only when",
        "at most once,\n   only when",
    ),
    (KNOWLEDGE, " Nothing is activated or changed without consent.", ""),
    (KNOWLEDGE, " Nothing is activated or changed without.", ""),
    (KNOWLEDGE, "With the user's consent, release them with", "Release them with"),
    (KNOWLEDGE, "With the user's release them with", "Release them with"),
    (KNOWLEDGE, "cleanup and with consent, because", "cleanup, because"),
    (KNOWLEDGE, "cleanup and because", "cleanup, because"),
    (KNOWLEDGE, "  `00 00 03 E7` (after consent).", "  `00 00 03 E7`."),
    (KNOWLEDGE, "). With consent, on an inactive record", "), on an inactive record"),
    (
        KNOWLEDGE,
        "[review a script](review-aa-script.md)). on an inactive record",
        "[review a script](review-aa-script.md)), on an inactive record",
    ),
    (
        KNOWLEDGE,
        "must be empty (with consent,\n   `runtime_release_resources()`)",
        "must be empty; release leftovers with\n   `runtime_release_resources()`",
    ),
    (
        KNOWLEDGE,
        "must be empty (\n   `runtime_release_resources()`)",
        "must be empty; release leftovers with\n   `runtime_release_resources()`",
    ),
    # --- upstream-fresh repairs (matched when the regex layer chips these) --
    (KNOWLEDGE, "and apply only with consent\n  ([AOB injection]", "and apply\n  ([AOB injection]"),
    (KNOWLEDGE, 'count=4)`. With consent:', "count=4)`."),
    (KNOWLEDGE, "- Editing, after consent: same length or shorter,", "- Editing: same length or shorter,"),
    (KNOWLEDGE, "9. With consent (it creates", "9. Note (it creates"),
    (KNOWLEDGE, "dialog, then get explicit consent.", "dialog."),
    (KNOWLEDGE, "To fix it, with the user's consent: close CE", "To fix it: close CE"),
    (KNOWLEDGE, "end of cleanup, with consent, never", "end of cleanup, never"),
    (KNOWLEDGE, "At the end of cleanup, with the user's consent, call", "At the end of cleanup, call"),
    (KNOWLEDGE, "and the user's consent, and names classes", "and names classes"),
    (KNOWLEDGE, "1. With consent, run `debugger_attach", "1. Run `debugger_attach"),
    (KNOWLEDGE, ". With consent, run `process_set_paused(paused=true)` during", ". Run `process_set_paused(paused=true)` during"),
    (KNOWLEDGE, ". With consent, run [cleanup](cleanup-session.md)", ". Run [cleanup](cleanup-session.md)"),
    (KNOWLEDGE, "6. With consent, naming the function,", "6. Naming the function,"),
    (KNOWLEDGE, '"Change pointer", with consent:', '"Change pointer":'),
    (KNOWLEDGE, "In short, with consent for each step:", "In short, for each step:"),
    (KNOWLEDGE, "- Write, after consent:", "- Write:"),
    (KNOWLEDGE, "before any patch. With consent\n  to attach", "before any patch.\n  To attach"),
    (KNOWLEDGE, "6. With consent, and with the record inactive", "6. With the record inactive"),
]

RENUMBER_AFTER_FIRST_STEP_REMOVAL = {
    "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/attach-and-orient.md",
    "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/engine-triage.md",
    "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/plan-cheat.md",
    "srcs/CheatEngine.Mcp.Resources/Knowledge/Workflows/unreal-recon.md",
}

# Grammar repairs for text the regex layer has already chipped. They run after
# REGEX_RULES so one apply() pass converges.
CHIP_REPAIRS: list[tuple[str, str]] = [
    ("`00 00 03 E7` ().", "`00 00 03 E7`."),
    ("and apply only\n  ([AOB injection]", "and apply\n  ([AOB injection]"),
    ('count=4)`. With :', "count=4)`."),
    ("- Editing same length or shorter,", "- Editing: same length or shorter,"),
    ("9. With (it creates", "9. Note (it creates"),
    ("dialog, then.", "dialog."),
    ("To fix it close CE", "To fix it: close CE"),
    ("end of cleanup,never", "end of cleanup, never"),
    ("At the end of cleanup call", "At the end of cleanup, call"),
    ("and the user's and names classes", "and names classes"),
    ("1. run `debugger_attach", "1. Run `debugger_attach"),
    (". run `process_set_paused(paused=true)` during", ". Run `process_set_paused(paused=true)` during"),
    (". run [cleanup](cleanup-session.md)", ". Run [cleanup](cleanup-session.md)"),
    ("6. naming the function,", "6. Naming the function,"),
    ("In short for each step:", "In short, for each step:"),
    ("before any patch. With \n  to attach", "before any patch.\n  To attach"),
    ("6. and with the record inactive", "6. With the record inactive"),
]

# ---------------------------------------------------------------------------
# Regex pass over the knowledge markdown: the recurring consent phrasing.
# Order matters; each rule is idempotent. Text is LF-normalized during apply.
# ---------------------------------------------------------------------------
REGEX_RULES: list[tuple[str, str, str]] = [
    (KNOWLEDGE, r"Only on single-player or offline software the user may\nmodify; each test write and record( \n)?(needs the user's consent\.)?\n?", ""),
    (KNOWLEDGE, r"Only on single-player or offline software the user may modify; each test\nwrite and record( \n)?(needs the user's consent\.)?\n?", ""),
    (KNOWLEDGE, r"Only on single-player or offline software the user may modify; each test write and\nrecord( \n)?(needs the user's consent\.)?\n?", ""),
    (KNOWLEDGE, r"(?m)^(\d+)\. With consent, ", r"\1. "),
    (KNOWLEDGE, r"(?m)^(\d+)\. With consent:$", r"\1."),
    (KNOWLEDGE, r"(?m)^(\d+)\. With the user's consent, ", r"\1. "),
    (KNOWLEDGE, r", With consent, ", ", "),
    (KNOWLEDGE, r"\. With consent, ", ". "),
    (KNOWLEDGE, r"With consent,\n +", ""),
    (KNOWLEDGE, r"With consent, ", ""),
    (KNOWLEDGE, r"With consent: ", ""),
    (KNOWLEDGE, r"\(with consent\)", ""),
    (KNOWLEDGE, r"\(with consent,", "("),
    (KNOWLEDGE, r", with the user's consent[,;:]?", ""),
    (KNOWLEDGE, r"with the user's consent[,;:]? ", ""),
    (KNOWLEDGE, r"with the user's consent", ""),
    (KNOWLEDGE, r", with consent[,;:]?", ""),
    (KNOWLEDGE, r"with consent[,;:]? ", ""),
    (KNOWLEDGE, r" with\n +consent[,;:]? ?", ""),
    (KNOWLEDGE, r", after consent[,;:]?", ""),
    (KNOWLEDGE, r"after consent[,;:]? ", ""),
    (KNOWLEDGE, r"after consent", ""),
    (KNOWLEDGE, r",? with consent", ""),
    (KNOWLEDGE, r",? and get (explicit |the user's )?consent", ""),
    (KNOWLEDGE, r",? get (explicit |the user's )?consent", ""),
    (KNOWLEDGE, r"Get (explicit |the user's )?consent[,.]? ", ""),
    (KNOWLEDGE, r",? ask for (the user's )?consent", ""),
    (KNOWLEDGE, r",? ask consent", ""),
    (KNOWLEDGE, r"(?i)consent first[,.;:]? ", ""),
    (KNOWLEDGE, r"(?i)needs? (the user's |explicit |per-call )?consent[,.]?", ""),
    (KNOWLEDGE, r"(?i)Consent, then\n?", ""),
    (KNOWLEDGE, r"(?i)\(consent; ", "("),
    (KNOWLEDGE, r"(?i), consent[,;]", ""),
    (KNOWLEDGE, r"(?i)consent[,.;:]? ", ""),
    (KNOWLEDGE, r"(?i)consent", ""),
    # grammar repair after the deletions above
    (KNOWLEDGE, r"\( \)", " "),
    (KNOWLEDGE, r"(?<=\S) {2,}(?=\S)", " "),
    (KNOWLEDGE, r",,", ","),
    (KNOWLEDGE, r"(?m)^(\d+)\. +$", r"\1."),
    (KNOWLEDGE, r"(?m)^- Write$", "- Write:"),
    (KNOWLEDGE, r"(?m)^ \.$", ""),
    (KNOWLEDGE, r'"Change pointer"$', '"Change pointer":'),
    (KNOWLEDGE, r"then one write`memory_write", "then one write: `memory_write"),
]

# ---------------------------------------------------------------------------
# Banned wording for --check: any hit means the fork patch must be revisited.
# ---------------------------------------------------------------------------
BANNED: list[str] = [
    r"(?i)anti-?cheat",
    r"(?i)\bDRM\b",
    r"(?i)licence",
    r"(?i)license check",
    r"(?i)purchase check",
    r"(?i)responsible use",
    r"(?i)not with this tool",
    r"(?i)\bEULA\b",
    r"terms of service",
    r"terms-of-service",
    r"(?i)account ban",
    r"(?i)\bbanned\b",
    r"(?i)multiplayer",
    r"(?i)co-op",
    r"(?i)leaderboard",
    r"(?i)netplay",
    r"(?i)consent",
    r"(?i)consented",
    r"(?i)single-player or offline",
    r"(?i)only on single-player",
    r"(?i)offline software",
    r"(?i)offline games",
    r"(?i)owns or may modify",
    r"authorized to modify",
    r"(?i)entitled to modify",
    r"(?i)stop otherwise",
    r"(?i)stop when unsure",
    r"(?i)Stop at online",
    r"(?i)stop and tell the user",
    r"(?i)tells them to refuse",
    r"(?i)\badults? \(18",
    r"(?i)criminalis",
    r"(?i)hide from detection",
    r"(?i)hide Cheat Engine from them",
    r"(?i)free of anti",
]


def scoped_files() -> list[Path]:
    files: set[Path] = set()
    for pattern in SCOPE:
        for path in REPO.glob(pattern):
            if path.is_file():
                files.add(path)
    return sorted(files)


def load(path: Path) -> tuple[str, bool]:
    data = path.read_bytes()
    crlf = b"\r\n" in data
    return data.decode("utf-8").replace("\r\n", "\n"), crlf


def store(path: Path, text: str, crlf: bool) -> None:
    if crlf:
        text = text.replace("\n", "\r\n")
    path.write_bytes(text.encode("utf-8"))


def json_variants(text: str) -> list[str]:
    """Golden JSON escapes apostrophes and plus signs inside string values."""
    return [text, text.replace("'", "\\u0027").replace("+", "\\u002B")]


def apply_exact(text: str, is_json: bool, old: str, new: str) -> tuple[str, int]:
    count = text.count(old)
    if count:
        return text.replace(old, new), count
    if is_json:
        for variant in json_variants(old)[1:]:
            count = text.count(variant)
            if count:
                return text.replace(variant, json_variants(new)[1]), count
    return text, 0


def renumber_main_steps(text: str) -> str:
    start = text.find("## Steps\n")
    if start < 0:
        return text
    end = text.find("\n## ", start + len("## Steps\n"))
    if end < 0:
        end = len(text)
    subsection = text.find("\n### ", start, end)
    if subsection >= 0:
        end = subsection
    steps = text[start:end]
    first = re.search(r"(?m)^(\d+)\. ", steps)
    if first is None or first.group(1) != "2":
        return text
    steps = re.sub(r"(?m)^(\d+)\. ", lambda match: f"{int(match.group(1)) - 1}. ", steps)
    return text[:start] + steps + text[end:]

def apply() -> int:
    files = scoped_files()
    rule_hits = [0] * len(EXACT_RULES)
    changed = 0
    for path in files:
        rel = path.relative_to(REPO).as_posix()
        text, crlf = load(path)
        original = text
        is_json = path.suffix == ".json"
        for index, (glob, old, new) in enumerate(EXACT_RULES):
            if glob is not None and not fnmatch.fnmatch(rel, glob):
                continue
            text, count = apply_exact(text, is_json, old, new)
            rule_hits[index] += count
        if rel in RENUMBER_AFTER_FIRST_STEP_REMOVAL:
            text = renumber_main_steps(text)
        for glob, pattern, repl in REGEX_RULES:
            if is_json or not fnmatch.fnmatch(rel, glob):
                continue
            text = re.sub(pattern, repl, text)
        for old, new in CHIP_REPAIRS:
            if is_json or not fnmatch.fnmatch(rel, KNOWLEDGE):
                continue
            text = re.sub(re.escape(old), new.replace("\\", "\\\\"), text)
        if text != original:
            store(path, text, crlf)
            changed += 1

    print(f"apply: {changed} file(s) changed.")
    stale = [
        (glob, old[:96].replace("\n", "\\n"))
        for index, (glob, old, _new) in enumerate(EXACT_RULES)
        if rule_hits[index] == 0
    ]
    if stale:
        print(f"\n{len(stale)} rule(s) matched nothing (STALE - review against upstream):")
        for glob, old in stale:
            print(f"  [{glob or 'any'}] {old}...")
    else:
        print("apply: every rule matched.")
    return 0


def check() -> int:
    banned = [re.compile(pattern) for pattern in BANNED]
    hits = 0
    for path in sorted(REPO.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO).as_posix()
        if rel.startswith(CHECK_ALLOW):
            continue
        if rel.startswith("artifacts/") or "/obj/" in rel or rel.startswith("obj/"):
            continue
        if path.suffix not in {".md", ".cs", ".json", ".yml", ".yaml", ".ps1", ".props", ".txt"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in banned:
                if pattern.search(line):
                    print(f"{rel}:{line_number}: {line.strip()[:160]}")
                    hits += 1
                    break
    if hits:
        print(f"\ncheck: {hits} banned wording hit(s). Update patches/strip_safety.py rules.")
        return 1
    print("check: clean.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report banned wording without editing")
    args = parser.parse_args()
    return check() if args.check else apply()


if __name__ == "__main__":
    sys.exit(main())
