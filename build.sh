clang++ -flto -O3 -arch x86_64 -arch arm64 -o bin/integrity_check integrity_check.cpp
clang++ -flto -O3 -arch x86_64 -arch arm64 -dynamiclib -o bin/example_dylib.dylib example_dylib.cpp
clang++ -o bin/hash_embedder hash_embedder.cpp
./bin/hash_embedder bin/example_dylib.dylib
./bin/hash_embedder bin/integrity_check
strip -SXTNx bin/example_dylib.dylib
strip -SXTNx bin/integrity_check
codesign -fs - bin/example_dylib.dylib
codesign -fs - bin/integrity_check
lipo bin/integrity_check -thin x86_64 -output bin/integrity_check_x86_64
lipo bin/integrity_check -thin arm64 -output bin/integrity_check_arm64
lipo bin/example_dylib.dylib -thin x86_64 -output bin/example_dylib_x86_64.dylib
lipo bin/example_dylib.dylib -thin arm64 -output bin/example_dylib_arm64.dylib
DYLD_INSERT_LIBRARIES=bin/example_dylib_x86_64.dylib bin/integrity_check_x86_64
DYLD_INSERT_LIBRARIES=bin/example_dylib_arm64.dylib bin/integrity_check_arm64
