# The LZMA SDK's decoder

Version patches (`runtime/version_patch.h`, `tools/versionpatch.py`) compress their streams with LZMA, which this
decoder decompresses: `LzmaDec.c` and `LzmaDec.h`, and the headers they include (`7zTypes.h`, `Compiler.h`,
`Precomp.h`), from the `C/` folder of 7-Zip 26.05 (https://github.com/ip7z/7zip, tag 26.05, commit
b88c6bc09339de32f7d18bbab900686b244f42ba, 2026-10-21), unmodified.

`CMakeLists.txt` builds them into a library of their own, `lzmadec`, without warnings, for the runtime (the game's
executable), the launcher and `runtime_tests`; `tools/versionpatch_fuzz` fuzzes them with the patch reader.

The LZMA SDK is in the public domain, as each file's header says, so a release needs no notice for it.
