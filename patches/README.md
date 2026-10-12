# Fork patch: strip usage-policy wording

`strip_safety.py` removes the usage-restriction wording that upstream
(CheatEngineNet/CheatEngine.Mcp) carries through the knowledge base, the MCP
prompts and server instructions, tool descriptions, the repository docs and the
golden contract snapshots: anti-cheat / DRM / licence refusals, target
eligibility sentences ("only on single-player or offline software ..."),
"responsible use" sections and consent nagging. Technical content (capability
gates, backups, undo tables, kernel risks, token hygiene) is preserved, as are
LICENSE and THIRD-PARTY-NOTICES.md (MIT obligations), the frozen historical
records under `docs/`, and the PR-template secrets checklist.

## Usage

```sh
python patches/strip_safety.py           # apply (idempotent, keeps CRLF)
python patches/strip_safety.py --check   # residue gate; exit 1 on leftover wording
```

`apply` reports every exact rule that matched nothing as `STALE`. A STALE rule
means upstream reworded (or removed) the passage it targets: review that
passage, update the rule, and re-run. Rules are plain data at the top of the
script (`EXACT_RULES`, `REGEX_RULES`, `CHIP_REPAIRS`, `BANNED`), so extending
the patch is a data change, not a code change.

## Upstream sync workflow

```sh
git fetch upstream && git merge upstream/main   # or rebase
python3 patches/strip_safety.py                 # re-apply; fix reported STALE rules
python3 patches/strip_safety.py --check         # must end "check: clean."
dotnet build CheatEngine.Mcp.slnx
dotnet test CheatEngine.Mcp.slnx --filter-not-trait Category=LiveQualification \
    --filter-not-trait Category=NativeLua --fail-skips on
git commit -m "Apply strip-safety fork patch (upstream <sha>)"
```

The golden snapshots under `tests/CheatEngine.Mcp.Tests/Contract/Golden/` embed
the instructions and descriptions the script scrubs, so `apply` rewrites the
same substrings inside them. `backend-*` and `gateway-tools.json` are asserted
by in-process tests; on Windows they can be regenerated exactly with
`CHEATENGINE_MCP_UPDATE_GOLDEN=1 dotnet test ...`. `gateway-initialize`,
`gateway-resources` and `gateway-prompts` are only produced by the gateway
executable test (win-x64): CI is their final verifier.

## Platform notes

- The `CheatEngine.Client.Hosting` build tasks are Windows-only. On macOS build
  with `-p:CheatEngineClientSkipPluginProjectValidation=true`.
- Tests that compose the real plugin manifest depend on Costura's embedded
  native loader, which does not support osx-arm64; run the portable suite on
  Windows or CI. Pure-string tests (`ServerInstructionsTests`,
  `ThirdPartyNoticesTests`, most of `ToolCatalogContractTests`) run anywhere.
- Restore quirk seen once: NU1403 on `Microsoft.NET.ILLink.Tasks` clears with
  `dotnet restore --force-evaluate`.
