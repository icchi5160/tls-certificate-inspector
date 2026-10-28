// SPDX-License-Identifier: GPL-3.0-only

#pragma once

#include "certificate_info.hpp"

namespace inspector {
Options parse_arguments(int argc, char** argv);
Result inspect(const Options& options);
} // namespace inspector
