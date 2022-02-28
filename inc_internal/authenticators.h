/*
Copyright (c) 2020 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef ZITI_SDK_AUTHENTICATORS_H
#define ZITI_SDK_AUTHENTICATORS_H

#include "zt_internal.h"
#include "utils.h"


#ifdef __cplusplus
extern "C" {
#endif

extern void ziti_send_event(ziti_context ztx, const ziti_event_t *e);

void ziti_extend_cert_authenticator(ziti_context ztx, char* csr_pem, void* ctx);

void ziti_verify_extend_cert_authenticator(ziti_context ztx, char* new_cert, void* ctx);

#ifdef __cplusplus
}
#endif


#endif //ZITI_SDK_AUTHENTICATORS_H
