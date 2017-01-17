/*
 *   Copyright 2017 Simon Schmidt
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
#pragma once
#include <net/config.h>

#ifdef NET_DO_LOG
#include <stdio.h>
#define NET_LOG(...) printf(__VA_ARGS__)
#else
#define NET_LOG(...) (void)0
#endif

#ifdef NET_ASSERTIONS
#include <stdio.h>
#include <stdlib.h>
#define NET_ASSERT(n,...) do if(!(n)){ printf("" __VA_ARGS__); abort(); }while(0)
#else
#define NET_ASSERT(...) (void)0
#endif
