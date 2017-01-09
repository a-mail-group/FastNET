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
#include <odp/helper/linux.h>
#include <net/niftable.h>
#include <net/nethread.h>

#if 0
#include <stdio.h>
#define DEBUG(x) printf(#x " = %d\n",x)
#define DBGPF(...) printf(__VA_ARGS__)
#else
#define DEBUG(x) (void)0
#define DBGPF(...) (void)0
#endif

void fastnet_runthreads(nif_table_t* table){
	int i,p,n;
	odp_cpumask_t TM;
	odph_odpthread_t threads[NET_MAXTHREAD];
	odph_odpthread_params_t tpar;
	
	tpar.start = fastnet_eventlist;
	tpar.arg = table;
	tpar.instance = table->instance;
	tpar.thr_type = ODP_THREAD_WORKER;
	
	n = table->workers;
	DEBUG(table->workers);
	DBGPF("Start IO Threads!\n");
	p = odp_cpumask_first(&(table->cpumask));
	for (i = 0; i < n; ++i) {
		odp_cpumask_zero(&TM);
		odp_cpumask_set(&TM,p);
		odph_odpthreads_create(&threads[i],&TM,&tpar);
		
		p = odp_cpumask_next(&(table->cpumask), p);
	}
	DBGPF("Wait for IO Threads!\n");
	for (i = 0; i < n; ++i)
		odph_odpthreads_join(&threads[i]);
	DBGPF("Finish!\n");
}

