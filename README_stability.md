# Rome 2 Stability Fix

A small `version.dll` proxy for **Total War: Rome II** that tries to stop the game from crashing while loading a battle after several battles in one session.

## The problem

Rome II is a 32-bit game, so it has about 4 GB of address space. Each battle loads and frees many large blocks. After a few battles the free space is cut into small pieces. The next battle needs one big contiguous block, finds none, and the game crashes, even though plenty of memory is free in total.

## What it does

The DLL hooks the game's memory calls (ntdll) and keeps the big blocks together:

- **Address reserve (192 MB):** held back at start and handed to the game at once if it cannot get a big block otherwise.
- **Big blocks from the top:** large reservations go to the top of the address space, so the middle stays in one piece.
- **Parked holes:** a big block the game frees is kept reserved for its next big request.
- **Failed mappings logged in full:** with the caller, sizes and what was in the way.
- **NVIDIA shader cache kept small:** the driver maps its cache file into the game. The file is emptied at every start, and views over a size limit are refused.
- **A log** (`rome2_stability.log`) with free address space, the largest free block, and any rescue the mod had to make.

It does not change graphics or gameplay.

## Requirements

- Total War: Rome II (Steam), 32-bit, Windows 10 or 11 (64-bit Windows).
- The shader cache part is for **NVIDIA** drivers. On AMD or Intel it does nothing. The address-space part does not depend on the graphics card.

## Install

1. Copy `version.dll` into the game folder, next to `empire.retail.dll`, for example `...\steamapps\common\Total War Rome II\`.
2. Start the game. On first start the mod creates `rome2_stability.ini` and `rome2_stability.log` next to the DLL.

To uninstall, delete `version.dll` (and, if you like, the `.ini` and `.log`).

It can run next to a `dinput8.dll` performance mod. They use different file names.

## Settings

`rome2_stability.ini` (restart the game after a change; delete it to restore the defaults):

| Key | Default | Meaning |
| --- | --- | --- |
| `address_reserve_mb` | `192` | Address space held back (0 to 512 MB). `0` turns **all** hooks off, so the DLL only forwards calls. |
| `large_top_down` | `1` | Put big reservations (8 MB+) at the top of the address space. |
| `park_big_holes` | `1` | Keep big blocks (32 MB+) the game frees reserved for its next big request. |
| `clear_shader_cache` | `1` | Delete the NVIDIA shader cache file(s) at every game start. |
| `shader_cache_view_limit_mb` | `32` | The driver may not map a cache file bigger than this into the game (`0` = no limit). |
| `shader_cache_in_game` | `1` | `1` = cache views up to the limit are allowed. `0` = the driver gets no view at all. **Keep `1`:** with `0`, NVIDIA driver 32.0.16.1088 crashed the game at start in `NvMemMapStorage.dll`. |
| `address_space_trace` | `1` | Detailed address-space trace in the log (costs a little time; turn it off once everything runs well). |

## Reading the log

`rome2_stability.log` (next to the DLL). Each game start appends a new section, headed `new session <date>`. Above 16 MB the old log is moved to `rome2_stability.log.old` and a new one is started, so it cannot grow without limit:

- `hooks: ... hooked` shows that the five hooks were installed. If a hook says "not the expected stub", nothing was changed for that call.
- `memory:` appears once a minute: free address space and the **largest free piece**.
- `address reserve: GIVEN BACK` means the mod rescued a big request that would otherwise have failed.
- `WARNING: the largest free piece is under 100 MB` means a crash is likely at the next battle load. Save and restart the game.
- `MAP FAIL` lines describe a failed file mapping, with caller and what was in the way.
- `shader cache view ... allowed` or `REFUSED` shows what the NVIDIA driver asked for.

## Troubleshooting

- **The game does not start:** remove `version.dll` and check that it starts without it. Then check `shader_cache_in_game=1` in the ini.
- **No `rome2_stability.log` appears:** the DLL is not being loaded. Check that `version.dll` is in the same folder as `empire.retail.dll`.
- **A crash:** keep the log and the newest `crash_*.dmp` the game wrote. The log masks your user name in paths, but the dump may contain more.

## Build

Needs Python and the Zig compiler package (it cross-compiles 32-bit Windows DLLs, no Visual Studio needed):

```powershell
pip install ziglang
python -m ziglang cc -target x86-windows-gnu -O2 -fno-omit-frame-pointer -shared -s -o version.dll stability.c version.def
```

`-fno-omit-frame-pointer` is needed, because the log reads stack frames to name the code that made a call.

`stability.c` starts with a short "how it works" overview and has comments above each function.

## Known limitations

- **The numbers are Attila's.** The 192 MB reserve and the 8 / 32 / 256 MB limits come from the Attila version and have not been tuned for Rome II.
- **The battle-exit crash fix was not ported.** The Attila version also skips a game function that could crash when leaving a battle quickly. That patch depends on Attila's code and has no Rome II equivalent yet.
- **Mid-session cache growth.** The NVIDIA driver can grow its cache file during a session. In Attila, refusing a larger view at that moment crashed the driver. This mod keeps the file small by emptying it at each start, but the risk remains with `shader_cache_in_game=1`.
- **Hooking depends on the expected ntdll code.** If a Windows update or another tool changes it, the hooks are skipped and the log says so.
- **Not tested** in multiplayer, or with graphics drivers other than NVIDIA 32.0.16.1088.

## Credits

Derived from the **Attila Stability Fix 1.9** for Total War: Attila (a `xinput1_3.dll` proxy) by **MassDragon67**: <https://www.nexusmods.com/totalwarattila/mods/174>. The memory handling is that mod's work; this port changes the proxy DLL, removes the Attila-specific patch, and adds the Rome II logging and defaults.

Written with the help of Claude (AI assistant).

## Disclaimer

This is an unofficial mod. Use it at your own risk. It is not affiliated with Creative Assembly, SEGA or NVIDIA.
