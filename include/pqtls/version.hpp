#pragma once

#include <string>

#include "pqtls/build_info.hpp"

namespace pqtls {

/// Semantic version of this build, taken from the repository VERSION file.
[[nodiscard]] inline const char* version() noexcept {
    return build_info::kVersion;
}

/// Short git commit of the working tree the binary was built from, or
/// "unknown" when the build happened outside a git checkout (e.g. a tarball).
[[nodiscard]] inline const char* git_commit() noexcept {
    return build_info::kGitCommit;
}

/// One-line human-readable identification used by `--version`.
[[nodiscard]] std::string version_banner();

}  // namespace pqtls
