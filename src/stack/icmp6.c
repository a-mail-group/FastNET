/*
 *
 * Copyright 2016 Simon Schmidt
 * Copyright 2011-2015 by Andrey Butok. FNET Community.
 * Copyright 2008-2010 by Andrey Butok. Freescale Semiconductor, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "ipv6.h"
#include "icmp6.h"
#include "ip_addr_ext.h"
#include "prot.h"
#include <odp/helper/icmp.h>
#include <odp/helper/ip.h>
#include "generic.h"

/*
 * This file is derived from FNET as of version 3.0.0
 */
