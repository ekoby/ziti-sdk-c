/*
Copyright (c) 2020 NetFoundry, Inc.

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


#ifndef ZITI_SDK_ZITI_EVENTS_H
#define ZITI_SDK_ZITI_EVENTS_H

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief Ziti Event Types.
 *
 * \see ziti_event_t
 * \see ziti_options.events
 */
typedef enum {
    ZitiContextEvent = 1,
    ZitiRouterEvent = 1 << 1,
    ZitiServiceEvent = 1 << 2,
    ZitiMfaAuthEvent = 1 << 3,
    ZitiAPIEvent = 1 << 4,
    ZitiAuthenticatorEvent = 1 << 5,
} ziti_event_type;

/**
 * \brief Ziti Edge Router status.
 *
 * \see ziti_router_event
 */
typedef enum {
    EdgeRouterAdded,
    EdgeRouterConnected,
    EdgeRouterDisconnected,
    EdgeRouterRemoved,
    EdgeRouterUnavailable,
} ziti_router_status;

/**
 * \brief Context event.
 *
 * Informational event to notify app about issues communicating with Ziti controller.
 */
struct ziti_context_event {
    int ctrl_status;
    const char *err;
};

struct ziti_api_event {
    const char *new_ctrl_address;
};
/**
 * \brief Edge Router Event.
 *
 * Informational event to notify app about status of edge router connections.
 */
struct ziti_router_event {
    ziti_router_status status;
    const char *name;
    const char *address;
    const char *version;
};

/**
 * \brief Ziti Service Status event.
 *
 * Event notifying app about service access changes.
 * Each field is a NULL-terminated array of `ziti_service*`.
 *
 * \see ziti_service
 */
struct ziti_service_event {

    /** Services no longer available in the Ziti Context */
    ziti_service_array removed;

    /** Modified services -- name, permissions, configs, etc */
    ziti_service_array changed;

    /** Newly available services in the Ziti Context */
    ziti_service_array added;
};

/**
 * \brief Ziti Authentication Query MFA Event
 *
 * Event notifying the app that an active API Session requires
 * its identity's current MFA one-time-code (TOTP) to be
 * submitted. All MFA codes can be provided via
 * `ziti_mfa_auth(...)`
 */
struct ziti_mfa_auth_event {
    ziti_auth_query_mfa *auth_query_mfa;
};

/**
 * \brief Ziti Extend Certificate Authenticator event notifies of changes to an authenticators state
 *
 * The event contains `original_fingerprint` (SHA1) to identify the certificate being replaced.
 * Additionally the `is_verified` bool determines whether the  client certificate is awaiting or
 * has completed verification. If `is_verified` is false, `ziti_verify_extend_cert_authenticator()`
 * must be invoked to have the client certificate become active.
 *
 * Under normal operation `error` is set to `ZITI_OK`, otherwise an error has occurred.
 */
struct ziti_extend_certificate_authenticator_event {
    void* ctx;
    char* authenticator_id;
    char* new_client_cert_pem;
    bool is_verified;
    int error;
};

/**
 * \brief Object passed to `ziti_options.event_cb`.
 *
 * \note event data becomes invalid as soon as callback returns.
 * App must copy data if it's needed for further processing.
 */
typedef struct ziti_event_s {
    ziti_event_type type;
    union {
        struct ziti_context_event ctx;
        struct ziti_router_event router;
        struct ziti_service_event service;
        struct ziti_mfa_auth_event mfa_auth_event;
        struct ziti_api_event api;
        struct ziti_extend_certificate_authenticator_event authenticator;
    } event;
} ziti_event_t;

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_EVENTS_H
