/*
Copyright (c) 2019-2020 NetFoundry, Inc.

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

#include "authenticators.h"

typedef struct authenticator_ctx_s {
    ziti_context ztx;
    void* ctx;
    char* csr_pem;
    char* authenticator_id;
} authenticator_ctx;

static void send_error_event(authenticator_ctx* authenticator_ctx, int err){
    ziti_context ztx = authenticator_ctx->ztx;

    ziti_event_t ev = {
            .type = ZitiAuthenticatorEvent,
            .event.authenticator = {
                    .ctx = authenticator_ctx->ctx,
                    .error = err,
                    .is_verified = false,
                    .authenticator_id = authenticator_ctx->authenticator_id,
            }
    };

    ziti_send_event(ztx, &ev);
}

const char* CAN_NOT_UPDATE_AUTHENTICATOR = "CAN_NOT_UPDATE_AUTHENTICATOR";
const char* UNAUTHORIZED = "UNAUTHORIZED";

static void extend_cb(ziti_extend_cert_authenticator_resp* resp, const ziti_error* err, void* ctx) {
    authenticator_ctx* wrapped_ctx = (authenticator_ctx*)ctx;
    ziti_context ztx = wrapped_ctx->ztx;


    if(err){
        ZTX_LOG(ERROR, "error response returned when attempting to extend authenticator: %d %s: %s", err->http_code, err->code, err->message);
        if(err->http_code == 404) {
            send_error_event(wrapped_ctx, ZITI_NOT_FOUND);
        } else if(strncmp(err->code, CAN_NOT_UPDATE_AUTHENTICATOR, strlen(CAN_NOT_UPDATE_AUTHENTICATOR)) == 0){
            send_error_event(wrapped_ctx, ZITI_INVALID_AUTHENTICATOR_TYPE);
        } else if (strncmp(err->code, UNAUTHORIZED, strlen(UNAUTHORIZED)) == 0){
            send_error_event(wrapped_ctx, ZITI_INVALID_AUTHENTICATOR_CERT);
        } else {
            send_error_event(wrapped_ctx, ZITI_WTF);
        }

        return;
    } else {
        ZTX_LOG(INFO, "certificate authenticator extension occurred for id: %s, raising event", wrapped_ctx->authenticator_id);
        ziti_event_t ev = {
                .type = ZitiAuthenticatorEvent,
                .event.authenticator = {
                        .ctx = wrapped_ctx->ctx,
                        .authenticator_id = wrapped_ctx->authenticator_id,
                        .error = ZITI_OK,
                        .is_verified = false,
                        .new_client_cert_pem = resp->client_cert_pem
                }
        };

        ziti_send_event(wrapped_ctx->ztx, &ev);
    }

    FREE(wrapped_ctx->authenticator_id);
    FREE(wrapped_ctx->csr_pem);
    FREE(wrapped_ctx);

    free_ziti_extend_cert_authenticator_resp(resp);
}

static void verify_cb(void* empty, const ziti_error* err, void* ctx){
    authenticator_ctx* wrapped_ctx = (authenticator_ctx*)ctx;
    ziti_context ztx = wrapped_ctx->ztx;

    if(err) {
        ZTX_LOG(ERROR, "error response returned when attempting to verify extended authenticator: %d %s: %s", err->http_code, err->code, err->message);
        if(err->http_code == 404) {
            send_error_event(wrapped_ctx, ZITI_NOT_FOUND);
        } else if(strncmp(err->code, CAN_NOT_UPDATE_AUTHENTICATOR, strlen(CAN_NOT_UPDATE_AUTHENTICATOR)) == 0){
            send_error_event(wrapped_ctx, ZITI_INVALID_AUTHENTICATOR_TYPE);
        } else if (strncmp(err->code, UNAUTHORIZED, strlen(UNAUTHORIZED)) == 0){
            send_error_event(wrapped_ctx, ZITI_INVALID_AUTHENTICATOR_CERT);
        } else {
            send_error_event(wrapped_ctx, ZITI_WTF);
        }
    } else {
        ZTX_LOG(INFO, "certificate authenticator extension verified successfully for id: %s, raising event", wrapped_ctx->authenticator_id);
        ziti_event_t ev = {
                .type = ZitiAuthenticatorEvent,
                .event.authenticator = {
                        .ctx = wrapped_ctx->ctx,
                        .authenticator_id = wrapped_ctx->authenticator_id,
                        .error = ZITI_OK,
                        .is_verified = true,
                        .new_client_cert_pem = NULL,
                }
        };

        ziti_send_event(wrapped_ctx->ztx, &ev);
    }

    FREE(wrapped_ctx->authenticator_id);
    FREE(wrapped_ctx);
}

void ziti_extend_cert_authenticator(ziti_context ztx, char* csr_pem, void *ctx) {
    ZTX_LOG(INFO, "attempting to extend certificate authenticator id: %s", ztx->api_session->authenticator_id);
    NEWP(wrapped_ctx, authenticator_ctx);
    wrapped_ctx->ztx = ztx;
    wrapped_ctx->ctx = ctx;
    wrapped_ctx->authenticator_id = strdup(ztx->api_session->authenticator_id);
    wrapped_ctx->csr_pem = strdup(csr_pem);

    ziti_ctrl_extend_cert_authenticator(&wrapped_ctx->ztx->controller, wrapped_ctx->authenticator_id,
                                        wrapped_ctx->csr_pem,
                                        extend_cb, wrapped_ctx);
}

void ziti_verify_extend_cert_authenticator(ziti_context ztx, char *new_cert, void *ctx) {
    ZTX_LOG(INFO, "attempting to verify certificate authenticator %s", ztx->api_session->authenticator_id);

    NEWP(wrapped_ctx, authenticator_ctx);
    wrapped_ctx->ztx = ztx;
    wrapped_ctx->ctx = ctx;
    wrapped_ctx->authenticator_id = strdup(ztx->api_session->authenticator_id);

    ziti_ctrl_verify_extend_cert_authenticator(&ztx->controller, wrapped_ctx->authenticator_id, new_cert, verify_cb, wrapped_ctx);
}