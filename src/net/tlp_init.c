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
#include <net/in_tlp.h>
#include <stdlib.h>

#if 1
#define ASSERT(i) if(!(i)) abort()
#else
#endif

static void init(){
	int i;
	int idefault = -1;
	
	ASSERT(fn_in_protocols_n>0);
	
	for(i=0;i<fn_in_protocols_n;++i){
		if(fn_in_protocols[i].in_pt!=INPT_DEFAULT) continue;
		idefault = i;
		break;
	}
	ASSERT(i >= 0);
	
}


void fastnet_tlp_init(){
	init();
}
