#pragma once

#if defined(STDB_USE_FMT_MODULE)
#ifndef STDB_FMT_IMPORTED
#define STDB_FMT_IMPORTED 1
import fmt;
#endif
#else
#include <fmt/format.h>
#include <fmt/ostream.h>
#endif
