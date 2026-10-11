#pragma once

#include <string>

#include "pipeline.hpp"

namespace pipeline {

void run_compression(context& ctx, const std::string& output_dir = "artifacts", int compression_level = 6);

}  // namespace pipeline