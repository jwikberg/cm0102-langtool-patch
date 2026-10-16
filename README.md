# Championship Manager 01/02 3.9.68 langtool patch

## Language editor expansion

The original language editor expects 550-byte text fields, while the examined
game installation, reporting version **3.9.68**, uses 2048-byte fields. Both
database layouts use header version 1, so the original editor accepts the
header but reads the data at incorrect offsets.

The experimental patch expands the native reader/writer, working buffers, and
editing controls. It supports:

- Translation payloads of up to **2047 bytes**, plus the terminating NUL.
- Longer annotated argument strings and escaped newline displays.
- Full-length keyboard editing with horizontal scrolling.
- Import/export and validation that refuses oversized or unsupported edits
  before writing record data.

See [the language database documentation](docs/langtool.md) for the file format,
supported executable hashes, implementation details, and verification coverage.
The separate entity-name `.lng` files are not the same format as `language.ldb`.

## Quick start

You need an unmodified, supported `langtool.exe` from your own game installation
and Python 3. Applying the included patch requires only Python's standard library.

From the repository root:

```sh
python tools/patch_langtool.py /path/to/original/langtool.exe \
  /path/to/game/langtool-expanded.exe
```

Alternatively, with [uv](https://docs.astral.sh/uv/) installed:

```sh
uv run tools/patch_langtool.py /path/to/original/langtool.exe \
  /path/to/game/langtool-expanded.exe
```

The patcher uses only Python's standard library, so `uv` does not need to
install any project dependencies.

The patcher checks the executable's SHA-256, size, and original instruction
bytes. It creates a separate executable and refuses to overwrite an existing
output file.

Run the expanded executable on Windows or under Wine, with the game directory
as its working directory and the game's `Data` font files available. Choose
**Edit LDB** and open a **copy** of your database.

**Keep backups.** The patcher does not modify a database, but the editor's
**Write Current Record** action writes the selected file in place.

### Compatibility and limitations

The expanded editor targets the **2048-byte-field layout only**, not older
550-byte-layout databases. Source/key strings remain read-only because the
game uses them for lookup.

Malformed, adjacent, or repeated argument descriptions that the original parser
cannot handle reliably are refused rather than written unsafely. Some secondary
grammar/reporting paths remain unverified interactively. Read the
[detailed limitations](docs/langtool.md) before working with valuable data.

## Repository layout

| Path | Purpose |
| --- | --- |
| [`docs/langtool.md`](docs/langtool.md) | Database format, findings, usage, and limitations |
| [`tools/patch_langtool.py`](tools/patch_langtool.py) | Standard-library executable patcher |
| [`tools/langtool-expansion.json`](tools/langtool-expansion.json) | Reproducible instruction patches and compiled native hooks |
| [`tools/langtool/`](tools/langtool/) | Manifest generator, C hooks, UI patches, and native x86 verifier |
| [`tests/`](tests/) | PE patch-builder regression tests |

## Development

Run the patch-builder tests with Python's standard library:

```sh
python -m unittest discover -s tests -p 'test_patch_langtool.py'
```

Regenerating and verifying the native patch additionally requires
`i686-w64-mingw32-gcc`, `i686-w64-mingw32-nm`, and the Python packages
`capstone`, `pefile`, and `unicorn`. Keep generated build products outside the
repository:

```sh
python tools/langtool/build_manifest.py /path/to/original/langtool.exe \
  /tmp/langtool-manifest.json --work-dir /tmp/langtool-build

python tools/langtool/verify_native.py /path/to/original/langtool.exe \
  /tmp/langtool-manifest.json --database /path/to/Data/language.ldb
```

The native verifier executes patched x86 code with deterministic I/O hooks,
guarded allocations, and stack/register checks. It complements, rather than
replaces, testing the actual editor.

## License

Repository-authored code and documentation are provided under the
[MIT License](LICENSE). Original game software and assets remain subject to
their respective owners' rights. This is an unofficial project.
