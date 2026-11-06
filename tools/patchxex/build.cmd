@echo off
rem Builds patchxex.exe from XenonRecomp's XEX patcher (XenonUtils' xex_patcher.cpp, Xenia's), libmspack's LZX decoder
rem and tiny-AES-c, in the XenonRecomp checkout (XENONRECOMP_ROOT, else a sibling of this repo).
call "%~dp0..\env.cmd" || exit /b 1
set "XR=%XENONRECOMP_ROOT%"
set TP=%XR%\thirdparty
clang-cl /nologo /std:c++20 /O2 /EHsc /MT /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /W0 ^
  /I"%XR%\XenonUtils" /I"%TP%\libmspack\libmspack\mspack" /I"%TP%\tiny-AES-c" /I"%TP%\TinySHA1" /I"%TP%\simde" ^
  "%~dp0patchxex.cpp" "%XR%\XenonUtils\xex_patcher.cpp" "%XR%\XenonUtils\memory_mapped_file.cpp" ^
  "%TP%\libmspack\libmspack\mspack\lzxd.c" "%TP%\tiny-AES-c\aes.c" /Fe"%~dp0patchxex.exe" /Fo"%~dp0\" || exit /b 1
echo built %~dp0patchxex.exe
