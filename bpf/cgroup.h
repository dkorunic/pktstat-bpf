// @license
// Copyright (C) 2025  Dinko Korunic
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//go:build ignore

#pragma once

#define PATH_MAX 4096
#define CGROUP_FSMAGIC 0x27e0eb    // cgroup v1
#define CGROUP2_FSMAGIC 0x63677270 // cgroup v2

union kernfs_node_id {
  struct {
    u32 ino;
    u32 generation;
  };
  u64 id;
};

struct kernfs_node___older_v55 {
  const char *name;
  union kernfs_node_id id;
};

struct kernfs_node___rh8 {
  const char *name;
  union {
    u64 id;
    struct {
      union kernfs_node_id id;
    } rh_kabi_hidden_172;
    union {};
  };
};
