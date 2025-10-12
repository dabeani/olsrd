This folder is intended to hold external dependencies as git submodules for reproducible builds.

Recommended submodules:

  git submodule add https://github.com/ARMmbed/mbedtls.git lib/extern/mbedtls
  git submodule add https://github.com/curl/curl.git lib/extern/curl

Usage:

  # clone recursively including submodules
  git clone --recurse-submodules <repo>

  # or after clone
  git submodule update --init --recursive

Why submodules?
- Keeps external code out of main repository history.
- Allows pinning to exact commits for reproducible builds.
- Easy to update with `git submodule update --remote` when you want newer upstream.

If submodules are not present, the build script will fall back to cloning the upstream repos into `build_external/` automatically.