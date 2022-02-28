/*
Copyright 2019-2020 NetFoundry, Inc.

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
#ifndef ZT_SDK_ERROR_DEFS_H

// @cond
#define ZT_SDK_ERROR_DEFS_H
// @endcond

#define ZITI_ERRORS(XX) \
    /** The expected outcome of a successful operation */ \
    XX(OK, "OK") \
    /** The provided configuration was not found */ \
    XX(CONFIG_NOT_FOUND, "Configuration not found") \
    /** The provided JWT was not found */ \
    XX(JWT_NOT_FOUND, "JWT not found") \
    /** The provided JWT is not accepted by controller */ \
    XX(JWT_INVALID, "JWT not accepted by controller") \
    /** The provided JWT has invalid format */ \
    XX(JWT_INVALID_FORMAT, "JWT has invalid format") \
    /** PKCS7/ASN.1 parsing failed */ \
    XX(PKCS7_ASN1_PARSING_FAILED, "PKCS7/ASN.1 parsing failed") \
    /** unsupported JWT signing algorithm */ \
    XX(JWT_SIGNING_ALG_UNSUPPORTED, "unsupported JWT signing algorithm") \
    /** JWT verification failed */ \
    XX(JWT_VERIFICATION_FAILED, "JWT verification failed") \
    /** unsupported enrollment method */ \
    XX(ENROLLMENT_METHOD_UNSUPPORTED, "unsupported enrollment method") \
    /** enrollment method requires client certificate */ \
    XX(ENROLLMENT_CERTIFICATE_REQUIRED, "enrollment method requires certificate") \
    /** Attempt to generate an private key failed */ \
    XX(KEY_GENERATION_FAILED, "error generating private key") \
    /** Attempt to load TLS key failed */ \
    XX(KEY_LOAD_FAILED, "error loading TLS key") \
    /** Attempt to generate a CSR failed */ \
    XX(CSR_GENERATION_FAILED, "error generating a CSR") \
    /** Some or all of the provided configuration is incorrect */ \
    XX(INVALID_CONFIG, "Configuration is invalid") \
    /** Returned when the identity does not have the correct level of access needed.
    Common causes are:
    * no policy exists granting the identity access
    * the certificates presented are incorrect, out of date, or invalid
    */ \
    XX(NOT_AUTHORIZED, "Not Authorized") \
    /** The SDK has attempted to communicate to the Ziti Controller but the controller
    is offline or did not respond to the request*/ \
    XX(CONTROLLER_UNAVAILABLE, "Ziti Controller is not available") \
    /** The SDK cannot send data to the Ziti Network because an Edge Router was not available. Common causes are:
    * the identity connecting is not associated with any Edge Routers
    * the Edge Router in use is no longer responding */ \
    XX(GATEWAY_UNAVAILABLE, "Ziti Edge Router is not available") \
    /** The SDK cannot send data to the Ziti Network because the requested service was not available. Common causes are:
    * the service does not exist
    * the identity connecting is not associated with the given service
    */ \
    XX(SERVICE_UNAVAILABLE, "Service not available") \
    /** The connection has been closed gracefully */ \
    XX(EOF, "Connection closed") \
    /** A connect or write operation did not complete in the alloted timeout. #DEFAULT_TIMEOUT */ \
    XX(TIMEOUT, "Operation did not complete in time") \
    /** The connection has been closed abnormally. */ \
    XX(CONNABORT, "Connection to edge router terminated") \
    /** SDK detected invalid state, most likely caaused by improper use. */ \
    XX(INVALID_STATE, "invalid state") \
    /** SDK detected invalid cryptographic state of Ziti connection */ \
    XX(CRYPTO_FAIL, "crypto failure") \
    /** connection was closed */ \
    XX(CONN_CLOSED, "connection is closed") \
    /** failed posture check */ \
    XX(INVALID_POSTURE, "failed posture check") \
    /** attempted to start MFA enrollment when it already has been started or completed */ \
    XX(MFA_EXISTS, "an MFA enrollment already exists") \
    /** attempted to use an MFA token that is invalid */ \
    XX(MFA_INVALID_TOKEN, "the token provided was invalid") \
    /** attempted to verify or retrieve details of an MFA enrollment that has not been completed */ \
    XX(MFA_NOT_ENROLLED, "the current identity has not completed MFA enrollment") \
    /** not found, usually indicates stale reference or permission */ \
    XX(NOT_FOUND, "entity no longer exists or is no longer accessible") \
    /** operation attempted while ziti_context is not enabled */ \
    XX(DISABLED, "ziti context is disabled") \
    /** returned when authentication is attempted but there is an existing api session waiting for auth queries to pass */ \
    XX(PARTIALLY_AUTHENTICATED, "api session is partially authenticated, waiting for auth query resolution")               \
    /** returned during certificate authenticator extension processing if an extendable authenticator is not found */\
    XX(COULD_NOT_RETREIVE_AUTHENTICATOR, "a valid certificate based authenticator could not be retrieved")                 \
    /** returned during certificate authenticator extension if the authenticator cannot be extended because it is the wrong type (i.e. UPDB or 3rd party)*/ \
    XX(INVALID_AUTHENTICATOR_TYPE, "the authenticator could not be extended as it is the incorrect type")                  \
    /** returned during certificate authentication extension when the current client cert does not match the authenticator*/ \
    XX(INVALID_AUTHENTICATOR_CERT, "the authenticator could not be extended as the current client certificate does not match") \
    /** Inspired by the Android SDK: What a Terrible Failure. A condition that should never happen. */ \
    XX(WTF, "WTF: programming error") \


#endif //ZT_SDK_ERROR_DEFS_H
