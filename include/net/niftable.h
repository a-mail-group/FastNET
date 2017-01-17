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
#include <net/nif.h>
#include <net/types.h>

#define NET_NIFTAB_MAX_NIFS 128
#define NET_MAXTHREAD 128

typedef struct {
	nif_t          table[NET_NIFTAB_MAX_NIFS];
	int            max;
	netpp_cb_t     function;
	odp_cpumask_t  cpumask;
	int            workers;
	odp_instance_t instance;
} nif_table_t;

void fastnet_tlp_init();

int fastnet_pools_init(uint32_t pktsize,uint32_t pktnum,uint32_t poutsize,uint32_t poutnum);

int fastnet_niftable_prepare(nif_table_t* table,odp_instance_t instance);

/*
 * Opens a device to include into the given NIF-TABLE.
 *
 * Returns non-0 on success, 0 on failure.
 */
nif_t* fastnet_openpktio(nif_table_t* table,const char* dev);


void fastnet_runthreads(nif_table_t* table);
