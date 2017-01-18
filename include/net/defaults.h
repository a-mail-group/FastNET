/*
 *   Copyright 2017 Simon Schmidt
 *   Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
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


/* Default TTL. */
#define DATAGRAM_TTL           64

/* Default TTL for Multicast datagrams.
 * RFC112 6.1: If the upper-layer protocol
 * chooses not to specify a time-to-live, it should
 * default to 1 for all multicast IP datagrams, so that an explicit
 * choice is required to multicast beyond a single network.
 */
#define DATAGRAM_TTL_MULTICAST 1
