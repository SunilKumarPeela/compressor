@echo off
setlocal
if not exist build-tests mkdir build-tests
cl /nologo /std:c++20 /utf-8 /EHsc /W4 /WX /sdl ^
  /DUNICODE /D_UNICODE /Od /Zi ^
  /Isrc src\point_core.cpp tests\schema_mapping_test.cpp ^
  /Fe:build-tests\schema_mapping_test.exe ^
  /link bcrypt.lib
if errorlevel 1 exit /b 1
build-tests\schema_mapping_test.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /EHsc /W4 /WX /sdl ^
  /DUNICODE /D_UNICODE /Od /Zi ^
  /Isrc src\point_fast_compression.cpp tests\fast_compression_test.cpp ^
  /Fe:build-tests\fast_compression_test.exe
if errorlevel 1 exit /b 1
build-tests\fast_compression_test.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /utf-8 /EHsc /W4 /WX /sdl ^
  /DUNICODE /D_UNICODE /Od /Zi ^
  /Isrc src\point_fast_compression.cpp src\point_compliance.cpp ^
  tests\dpapi_compression_integration_test.cpp ^
  /Fe:build-tests\dpapi_compression_integration_test.exe ^
  /link advapi32.lib crypt32.lib
if errorlevel 1 exit /b 1
build-tests\dpapi_compression_integration_test.exe
if errorlevel 1 exit /b 1
echo All Point core and fast compression tests passed.
