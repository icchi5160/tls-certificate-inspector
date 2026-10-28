// SPDX-License-Identifier: GPL-3.0-only

#pragma once

#include "certificate_info.hpp"

namespace inspector {
std::string format_json(const Result& result);
std::string format_text(const Result& result);
std::string usage();
} // namespace inspector
