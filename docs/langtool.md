# CM 01/02 language database and editor expansion

## Status

The expanded editor supports **2047-byte translation payloads**, including
longer annotated/escaped representations in the editing controls. The patch
includes the native database library, editor storage, keyboard editing,
horizontal scrolling, import/export, and pre-write size/argument checks.

This is an experimental compatibility patch for the exact executable identified
below, not an official game update. Work on database copies and retain backups:
the editor's **Write Current Record** action writes the selected file in place.
The original source/key remains read-only.

## Creating and using the expanded executable

The patch application requires Python 3's standard library only:

```sh
python tools/patch_langtool.py /path/to/original/langtool.exe \
  /path/to/game/langtool-expanded.exe
```

The output must be a new path. Keep the executable beside the original, with
the game's `Data` font files available, and launch it with the game directory
as its working directory. Use **Edit LDB** to open a copied database.
This executable targets the 2048-byte layout only; do not use it on an older
550-byte-layout database. Header version 1 alone does not distinguish them.

Click a translation to edit it. Home/End, Left/Right, Backspace, Delete, and
ordinary character input operate on the complete text; the visible portion
scrolls with the caret. Enter finishes the edit. Newlines are displayed as
literal `\n`. The limit applies to the decoded, compact disk payload, not its
longer display representation. Oversized edits are refused before writing.
Read-only source labels and other non-editable captions are clipped previews;
the underlying keys are not truncated.

## Why the original editor fails

The supplied `langtool.exe` uses 550-byte text fields. The installed
`language.ldb` and game executable use 2048-byte fields, including the terminating
NUL. Both layouts retain header version 1, so the editor accepts the header but
reads subsequent fields and records at incorrect offsets.

The observed game reports version 3.9.68. This establishes the installed layout,
not the historical patch that introduced it.

Artifact identities:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `langtool.exe` | 598016 | `b51d99260742857c454a7f4d67a029dd2fb4f9e7200ebda0c9a965860b7911ba` |
| `cm0102.exe` | 7192576 | `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86` |
| `Data/language.ldb` | 204672142 | `7f6fcec87709fc0072e05a44fa7f781978f2abd247630e1d977f74ecac449b59` |

## `language.ldb` layout

All integers below are little-endian 32-bit values.

| Header offset | Value |
| --- | --- |
| 0 | Version: 1 in the supplied file |
| 4 | Record count: 9807 |
| 8 | Language-column count: 10 |
| 12 | Language IDs: `0, 2, 3, 4, 5, 6, 7, 8, 9, 10` |

IDs identify UK English, French, German, Italian, Spanish, Danish, Dutch,
Norwegian, Portuguese, and Swedish, respectively. The header is 52 bytes.

Each record contains:

| Relative offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 2048 | Annotated source/key string |
| 2048 | 30 | Printf conversion list, separated with `~` |
| 2078 | 9 * 2088 | Non-English translations |

Each translation has 2048 text bytes followed by ten signed argument indices
(40 bytes). An active byte `0x08` substitutes an argument; its corresponding
index selects an argument from the annotated source. Indices allow translations
to reorder arguments. Unused entries commonly contain -1.

Record stride is 20870 bytes. Record `i` starts at `52 + i * 20870`.
In general, for `N` columns, header size is `12 + 4*N` and record stride is
`2048 + 30 + (N-1)*2088`. The old editor's stride was `N*590 - 10`.

Strings are NUL-terminated 8-bit text; observed Western bytes are consistent
with Windows-1252, but the header does not declare an encoding. Bytes following
the first NUL can contain stale data and are not extra text fields. The maximum
payload is **2047 bytes**, not 2048 characters. Grammar markup uses braces and
brackets. The source's `<...>` spans describe substitution arguments.

Every source/translation field in the supplied file is terminated. The longest
active source is 524 bytes and compact translation is 544 bytes; thus the
installed data alone cannot demonstrate that an editor supports the new limit.

`.lng` files are different: they translate entity names such as clubs, nations,
cities, competitions and stadiums. They are not the news/UI template database
and must not be widened using this patch.

## Implementation

`tools/patch_langtool.py` applies reviewed same-length instruction patches,
then appends separate writable `.lgdata` and executable/readable `.lgcode`
sections. Original code addresses remain stable. Expanded stack frames use
page probes; stack reserve is increased to 8 MiB. The patch builder never
changes its input executable or touches a database. Input SHA-256, size and
every changed original byte are checked, and an existing output path is refused.

The disk slot remains 2048 bytes. An annotated in-memory translation can be
larger because a single compact `0x08` becomes an entire source descriptor.
Translation storage and shared scratch buffers therefore use 32768 bytes
instead of merely substituting 2048 for every occurrence of 550.

The generic GUI has a separate 256-byte inline caption and two 256-byte
keyboard-edit temporaries. Merely increasing the editor's field limits would
overflow them. Full editable translations instead live in persistent 65536-byte
slots, independently of constructor/save stack layouts. Native hooks retain
bounded captions, implement scrolling keyboard edits against the full text,
and make the save handler decode the same persistent slots. Ordinary short
legacy input controls continue through their original handlers. A legacy
input control outside the expanded translation editor explicitly refuses a
long caption update it cannot represent safely.

Escaping deliberately retains the original tool's behavior: only literal `\n`
is decoded as a newline; other/trailing backslashes are left intact. A literal
backslash followed by `n` is therefore ambiguous, as in the original editor.

Before any record bytes are written, the writer validates all columns,
decoded lengths, references to source arguments, and the 29-byte printf-list
payload limit. Fixed-width output is zero-padded rather than copying beyond a
trimmed string into unrelated memory.

ASCII import uses separate 4096-byte packed working slots, not the 2048-byte
disk stride. Its annotated input/copy buffers are larger still. A preflight
pass rejects oversized fields before creating the destination file. Leading
separator spaces no longer consume the last source byte or replace the disk
terminator when importing a 2047-byte payload.

The original parser cannot reliably represent adjacent or repeated argument
descriptions; the guarded writer refuses these rather than damaging the
database. Malformed/nested/unterminated argument markup is also refused.
The installed database contains three malformed source keys (record indices
8183, 8291 and 8860); editing those requires separate compatibility work.
Source keys must not be "corrected" casually: the game uses them for lookup.

## Reproducing the development manifest

Applying a completed manifest uses Python's standard library only. Generating
and verifying it additionally requires `i686-w64-mingw32-gcc`,
`i686-w64-mingw32-nm`, and Python packages `capstone`, `pefile`, and `unicorn`.
Keep build products outside the repository:

```sh
python tools/langtool/build_manifest.py /path/to/original/langtool.exe \
  /tmp/langtool-manifest.json --work-dir /tmp/langtool-build

python tools/langtool/verify_native.py /path/to/original/langtool.exe \
  /tmp/langtool-manifest.json --database /path/to/Data/language.ldb

python -m unittest discover -s tests -p 'test_patch_langtool.py'
```

The native verifier executes the patched x86 reader/writer with deterministic
CRT I/O hooks, guarded allocations and stack/callee-saved-register checks.
Coverage includes 2047-byte source/all-nine-translation payloads, 4091-byte
annotated translations, argument reordering, refusal before writes, and
semantic round trips of selected installed records with untouched neighbors.
It also checks full-length ASCII import, the original 11-language library
case, and 32767/65534-byte newline encode/decode boundaries with overflow
rejection before changing the destination.
Oversized ASCII imports must fail before creating an output file. Widget
regressions exercise the actual initializer, setter and keyboard hooks,
callee cleanup/register preservation, caption bounds, and all eleven native
language-row offset calculations.
Padding need not match the input; active strings and argument maps must.
This does not substitute for GUI editing/save validation.

An isolated Wine launch with copied game fonts exercised the real editor.
Its native export processed all 9807 installed records: all 98070 fields were
present, and 98043 fields were compared byte-for-byte with expected escaped
text. The remaining 27 translations belong to the three malformed source keys
and were excluded from that comparison. The final executable reproduced that
entire export byte-for-byte.

Native GUI checks also covered:

- Editing the final byte of a 2047-byte translation while retaining every other
  translation and the neighboring record.
- Refusing a 2048-byte edit with an explicit error and a byte-identical file.
- Saving nine 2047-newline translations through their 4094-byte displays.
- Importing full-width plain and annotated records, then editing a 4091-byte
  annotated translation while preserving its compact text and argument maps.
- Opening the installed database copy, saving its first record without semantic
  changes, and navigating to its last record.
- Running the secondary duplicate-record check on the full-width fixture.

Not every secondary grammar/reporting path has been exercised interactively.
The original grammar/argument restrictions described above remain intentional.
Version-2 databases, disk-full/short-write recovery, and non-Western encodings
are not established by these checks. Wine can leave stale background glyphs
when changing screens; this was not treated as evidence of string truncation.

## Reverse-engineering evidence

Static observations came from REA/Ghidra and byte-level checks of the supplied
artifacts. Important editor functions are the reader at `0x415b70`, writer at
`0x415dd0`, argument extractor at `0x416230`, and runtime loader at `0x412400`.
The game's loader at `0x66eb40` reads the correct 2048-byte layout.

Representative REA Evidence IDs:

| Observation | Evidence |
| --- | --- |
| Original editor reader | `ev_33571e9e4eea9726783821c4ff15258bf8580309778490caadaf8a7d3aea7fd2` |
| Original editor writer | `ev_48e67ba0ce8cb3389ff401ed5f24545678119be0af5823ca7b98e3ced0991362` |
| Game's 2048-byte loader | `ev_d03aa3a84a463fccc89c1fb9337b23a4c30be5f8d3827a71f98eaa39a6e91cb6` |
| GUI initializer's inline caption copy (`0x411300`) | `ev_8012079a8e5895c37b131c4525e72f0e40203c90ef37108ac9aba74e8992f39f` |
| GUI keyboard handler's 256-byte locals (`0x4050c0`) | `ev_c3edc656ddb917d840e83dace2d12e471cd0668abe63f6db86289a681c50691d` |
| GUI caption setter (`0x411ea0`) | `ev_6158f68728d7c1a4c27af66553e41b8fa47aa76d000d18a099f8daf765d38674` |

These are static evidence identities, not claims that the unmodified editor
successfully loaded or saved the supplied database.
