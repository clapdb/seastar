// -*- mode:C++; tab-width:8; c-basic-offset:4; indent-tabs-mode:nil -*-
/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2021 Kefu Chai <tchaikov@gmail.com>
 */

#pragma once

#ifdef SEASTAR_HAVE_SPDK

#include <seastar/util/program-options.hh>

struct spdk_thread;

namespace seastar::spdk {

struct spdk_options : public program_options::option_group {
    program_options::value<> spdk_pmd;
    program_options::value<std::string> spdk_rpc_socket;
    program_options::value<std::string> spdk_config;
    program_options::value<> spdk_json_ignore_init_errors;
    program_options::value<std::string> spdk_iova_mode;
    program_options::value<std::string> spdk_huge_dir;
    program_options::value<> spdk_huge_unlink;
    program_options::value<std::string> spdk_mem_size;
    program_options::value<> spdk_no_pci;
    program_options::value<> spdk_single_file_segments;
    program_options::value<std::string> spdk_pci_blocked;
    program_options::value<std::string> spdk_pci_allowed;

    explicit spdk_options(program_options::option_group* parent_group);
};

}  // namespace seastar::spdk

#endif // SEASTAR_HAVE_SPDK
