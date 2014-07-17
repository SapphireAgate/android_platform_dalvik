/*
 * Copyright (c) 2010 The Pennsylvania State University
 * Systems and Internet Infrastructure Security Laboratory
 *
 * Authors: William Enck <enck@cse.psu.edu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Dalvik interpreter public definitions.
 */
#ifndef _DALVIK_INTERP_TAINT
#define _DALVIK_INTERP_TAINT

/* The Taint structure */
typedef struct Taint {
    u4 tag;
} Taint;

/* The Taint markings */

#define TAINT_CLEAR         ((u4)NULL) /* No taint */

#endif /*_DALVIK_INTERP_TAINT*/
