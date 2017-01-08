/*
 *   Copyright 2016 Simon Schmidt
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
#include <net/nif.h>
#include <net/types.h>

#define NET_NIFTAB_MAX_NIFS 128

typedef struct {
	nif_t      table[NET_NIFTAB_MAX_NIFS];
	int        max;
	netpp_cb_t function;
} nif_table_t;

/*
 * Opens a device to include into the given NIF-TABLE.
 *
 * Returns non-0 on success, 0 on failure.
 */
int fastnet_openpktio(nif_table_t* table,const char* dev,odp_pool_t pool);

