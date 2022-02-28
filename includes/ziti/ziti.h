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

/**
 * @file ziti.h
 * @brief Defines the macros, functions, typedefs and constants required to interface with a Ziti Network.
 */

#ifndef ZITI_ZITI_H
#define ZITI_ZITI_H

#include <stdint.h>
#include <uv.h>
#include <uv_mbed/tls_engine.h>
#include "errors.h"

#include "externs.h"
#include "ziti_model.h"
#include "enums.h"
#include "ziti_events.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
* Flag indicating service `Dial` permission
*/
#define ZITI_CAN_DIAL 1U

/**
* Flag indicating service `Bind` permission
*/
#define ZITI_CAN_BIND 2U

/**
 * The default timeout in milliseconds for connections and write operations to succeed.
 */
#define ZITI_DEFAULT_TIMEOUT 10000

/**
 * @brief Represents the Ziti Edge identity context.
 *
 * The Ziti C SDK will use this pointer to initialize and track the memory needed during
 * normal usage. This structure is opaque to the API user but is necessary for normal Ziti
 * SDK operation. After a successful initialization via ziti_init() the pointer will be
 * initialized. The context is necessary for many of the C SDK functions and is passed
 * as a parameter in many of the callbacks. ziti_shutdown() should be invoked when the Ziti
 * connections are no longer needed. The Ziti C SDK will reclaim any allocated memory at this
 * time.
 *
 * @see ziti_init(), ziti_shutdown()
 */
typedef struct ziti_ctx *ziti_context;

/**
 * @brief Represents a Ziti connection.
 *
 * The heart of Ziti is around reading and writing data securely and efficiently. In order
 * to do that a connection is required which will allow a developer to do so. This pointer
 * is passed to numerous Ziti C SDK functions and is returned in many callbacks. This structure
 * is an opaque handle to the state necessary for the Ziti C SDK to function properly.
 *
 * A connection is initialized by passing a pointer to ziti_conn_init(). The connection will need
 * to be freed when no longer needed.
 *
 * @see ziti_conn_init(), ziti_close()
 */
typedef struct ziti_conn *ziti_connection;

/**
 * @brief Service status callback.
 *
 * This callback is invoked on the conclusion of ziti_service_available(). The result of the function
 * may be an error condition so it is important to verify the status code in this callback. In the
 * event the service does not exist or the identity has not been given the access to the service the
 * #ZITI_SERVICE_UNAVAILABLE error code will be returned otherwise #ZITI_OK is expected.
 *
 * @see ziti_service_available(), ZITI_ERRORS
 */
typedef void (*ziti_service_cb)(ziti_context ztx, ziti_service *, int status, void *data);

/**
 * @brief Posture response MAC address callback
 *
 * This callback should be invoked after gathering the relevant MAC Addresses
 * available during a ziti_pq_mac_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param mac_addresses an array of the mac addresses the host currently has access to. Values should be hex strings. Nil signifies not supported.
 * @param num_mac the size of the mac_addresses array
 *
 * @see ziti_pq_mac_cb()
 */
typedef void (*ziti_pr_mac_cb)(ziti_context ztx, const char *id, char **mac_addresses, int num_mac);

/**
 * @brief Posture Query for MAC addresses callback
 *
 * This callback is invoked when the MAC addresses of the current host are needed.
 * The callback will be supplied a followup callback to supply an array of
 * MAC Addresses.
 *
 * @see ziti_pr_mac_cb
 */
typedef void (*ziti_pq_mac_cb)(ziti_context ztx, const char *id, ziti_pr_mac_cb response_cb);

/**
 * @brief Posture response Domain callback
 *
 * This callback should be invoked after gathering the relevant Domain
 * of the host during a ziti_pq_domain_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param domain the domain the host has joint or nil if not supported
 *
 *  @see ziti_pq_domain_cb()
 */
typedef void (*ziti_pr_domain_cb)(ziti_context ztx, const char *id, const char *domain);

/**
 *  @brief Posture Query for Domain callback
 *
 * This callback is invoked when the Domain of the current host is needed.
 * The callback will be supplied a followup callback to supply the host's domain.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param response_cb the callback to invoke to supply values
 *
 * @see ziti_pr_domain_cb
 */
typedef void (*ziti_pq_domain_cb)(ziti_context ztx, const char *id, ziti_pr_domain_cb response_cb);

/**
 * @brief Posture response OS callback
 *
 * This callback should be invoked after gathering the relevant OS versions
 * of the host during a ziti_pq_os_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param os_type the OS type: Windows, Linux, Android, macOS, iOS
 * @param os_version the OS version or kernel version
 * @param os_build the build of the OS or nil if not supported
 *
 * @see ziti_pq_os_cb()
 */
typedef void (*ziti_pr_os_cb)(ziti_context ztx, const char *id, const char *os_type, const char *os_version,
                              const char *os_build);

/**
 *  @brief Posture Query for OS callback
 *
 * This callback is invoked when the OS version info of the current host is needed.
 * The callback will be supplied a followup callback to supply the host's OS information.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param response_cb the callback to invoke to supply values
 *
 * @see ziti_pr_os_cb
 */
typedef void (*ziti_pq_os_cb)(ziti_context ztx, const char *id, ziti_pr_os_cb response_cb);


/**
 *  @brief Posture response process callback
 *
 *  This callback should be invoked after gathering the relevant process information
 *  from the host during a ziti_pq_process_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param path the path of the inspect process
 * @param is_running if the process is running
 * @param sha_512_hash the sha512 hash of the process's binary file
 * @param signers sha1 hex string fingerprints of the binary or nil if not supported
 * @param num_signers the number of signers
 *
 *  @see ziti_pq_process_cb()
 */
typedef void(*ziti_pr_process_cb)(ziti_context ztx, const char *id, const char *path, bool is_running,
                                  const char *sha_512_hash,
                                  char **signers, int num_signers);

/**
 *  @brief Posture Query for process callback
 *
 * This callback is invoked when process info is needed from the host.
 * The callback will be supplied a followup callback to supply the process's status
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param path the process path to inspect
 * @param response_cb the callback to invoke
 *
 * @see ziti_pr_process_cb
 */
typedef void (*ziti_pq_process_cb)(ziti_context ztx, const char *id, const char *path,
                                   ziti_pr_process_cb response_cb);

/**
 * @brief Ziti Event callback.
 *
 * This callback is invoked when certain changes happen for a given ziti context.
 * Subscription to events is managed by setting desired types on `ziti_options.events` field.
 *
 * @see ziti_event_type
 * @see ziti_event_t
 * @see ziti_options.event_cb
 * @see ziti_options.events
 */
typedef void (*ziti_event_cb)(ziti_context ztx, const ziti_event_t *event);

/**
 * @brief ziti_context initialization options
 *
 * @see ziti_init_opts()
 */
typedef struct ziti_options_s {
    const char *config;
    const char *controller;
    tls_context *tls;

    bool disabled; // if true initial state will be disabled
    const char **config_types;

    unsigned int api_page_size;
    long refresh_interval; //the duration in seconds between checking for updates from the controller
    rate_type metrics_type; //an enum describing the metrics to collect

    int router_keepalive;

    //posture query cbs
    ziti_pq_mac_cb pq_mac_cb;
    ziti_pq_os_cb pq_os_cb;
    ziti_pq_process_cb pq_process_cb;
    ziti_pq_domain_cb pq_domain_cb;

    void *app_ctx;

    /**
     * \brief subscribed event types.
     */
    unsigned int events;

    /**
     * \brief callback invoked is response to subscribed events.
     */
    ziti_event_cb event_cb;
} ziti_options;

typedef struct ziti_enroll_opts_s {
    const char *jwt;
    const char *enroll_key;
    const char *enroll_cert;
    const char *enroll_name;
    const char *jwt_content;
} ziti_enroll_opts;

typedef struct ziti_dial_opts_s {
    int connect_timeout_seconds;
    char *identity;
    void *app_data;
    size_t app_data_sz;
} ziti_dial_opts;

typedef struct ziti_client_ctx_s {
    char *caller_id;
    uint8_t *app_data;
    size_t app_data_sz;
} ziti_client_ctx;

typedef enum ziti_terminator_precedence_e {
    PRECEDENCE_DEFAULT = 0,
    PRECEDENCE_REQUIRED,
    PRECEDENCE_FAILED
} ziti_terminator_precedence;

typedef struct ziti_listen_opts_s {
    uint16_t terminator_cost;
    uint8_t terminator_precedence;
    int connect_timeout_seconds;
    //int max_connections;  // todo implement
    char *identity;
    bool bind_using_edge_identity;
} ziti_listen_opts;

/**
 * @brief Data callback.
 *
 * This callback is invoked when data arrives at the Ziti C SDK. Data arrives in the Ziti C SDK
 * either as a response to a Ziti connection from an ziti_dial() or as an incoming request via
 * ziti_accept.
 * Return value should indicate how much data was consumed by the application. This callback will
 * be called again at some later time and as many times as needed for application to accept the rest.
 *
 * @param conn The Ziti connection which received the data
 * @param data incoming data buffer
 * @param length size of data or error code as defined in #ZITI_ERRORS (will receive #ZITI_EOF
 *               when connection is closed)
 *
 * @return indicate how much data was consumed
 * @see ziti_dial(), ziti_accept(), ZITI_ERRORS
 */
typedef ssize_t (*ziti_data_cb)(ziti_connection conn, uint8_t *data, ssize_t length);

/**
 * @brief Connection callback.
 * 
 * This callback is invoked after ziti_dial() or ziti_accept() is completed.  The result of the
 * function may be an error condition so it is important to verify the status code in this callback.
 * If successful the status will be set to #ZITI_OK.
 *
 * @param conn the Ziti connection struct
 * @param status the result of the function. #ZITI_OK if successful otherwise see #ZITI_ERRORS
 *
 * @see ziti_dial(), ziti_accept(), ZITI_ERRORS
 */
typedef void (*ziti_conn_cb)(ziti_connection conn, int status);

/**
 * @brief Callback called when client connects to a service hosted by given context
 *
 * This callback is invoked after ziti_listen() is completed. The result of the function may be an
 * error condition so it is important to verify the status code in this callback. If successful
 * the status will be set to #ZITI_OK otherwise the value will be a value defined in #ZITI_ERRORS
 *
 * Generally this callback is used for any preparations necessary before accepting incoming data
 * from the Ziti network.
 *
 * @param serv hosting connection, initialized with ziti_listen()
 * @param client client connection - generally passed to ziti_accept() in this function
 * @param status #ZITI_OK or error
 * @param ctx object containing application data passed by dialing identity, \see ziti_dial_opts.
 *            the reference to this object is only valid for the duration of the callback.
 *
 * @see ziti_listen(), ZITI_ERRORS
 */
typedef void (*ziti_client_cb)(ziti_connection serv, ziti_connection client, int status, ziti_client_ctx *ctx);

/**
 * @brief Defines the ziti_listen_cb.
 * 
 * A convenience to make the API align better when a human looks at it and as a place to change the listen
 * callback in the unlikely event it is needed.
 *
 * @see ziti_listen()
 */
typedef ziti_conn_cb ziti_listen_cb;

/**
 * @brief Callback called after ziti_write() is complete.
 *
 * This callback is triggered on the completion of ziti_write(). The result of the ziti_write() function may be
 * an error condition so it is important to verify the provided status code in this callback.
 *
 * This callback is often used to free or reinitialize the buffer associated with the ziti_write() invocation.
 * It is important to not free this memory until after data has been written to the wire else the results of
 * the write operation may be unexpected.
 *
 * @see ziti_write(), ZITI_ERRORS
 */
typedef void (*ziti_write_cb)(ziti_connection conn, ssize_t status, void *write_ctx);

/**
 * @brief Callback called after ziti_enroll() is complete.
 *
 * This callback is invoked on the conclusion of the ziti_enroll() function. The result of the
 * ziti_enroll() function may be an error condition so it is important to verify the provided
 * status code in this callback.
 *
 * This callback also receives a Ziti identity json salvo if the enrollment was successful. 
 * This identity should be persisted into a file, and used in subsequent calls to ziti_init().
 *
 * @param cfg identity config object, NULL if enrollment fails for any reason
 * @param status enrollment success or error code
 * @param err_message description of error, or NULL if enrollment succeeded
 * @param enroll_ctx additional context to be passed into #ziti_enroll_cb callback
 *
 * @see ziti_enroll(), ZITI_ERRORS
 */
typedef void (*ziti_enroll_cb)(ziti_config *cfg, int status, char *err_message, void *enroll_ctx);

/**
 * @brief Callback called after connection was closed.
 *
 * @param conn connection that was closed
 *
 * @see ziti_close()
 */
typedef void (*ziti_close_cb)(ziti_connection conn);

/**
 * @brief Performs a Ziti enrollment.
 * 
 * This function is used to enroll a Ziti Edge identity. The Ziti C SDK is based around the [libuv](http://libuv.org/)
 * library and maintains similar semantics.  This function is used to setup the chain of callbacks
 * needed once the loop begins to execute.
 *
 * @param opt enrollment options
 * @param loop libuv event loop
 * @param enroll_cb callback to be called when enrollment is complete
 * @param enroll_ctx additional context to be passed into #ziti_enroll_cb callback

 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_enroll(ziti_enroll_opts *opts, uv_loop_t *loop, ziti_enroll_cb enroll_cb, void *enroll_ctx);

/**
 * Provide app information to Ziti SDK.
 *
 * App information is reported to Ziti Controller. Supplying this information is optional.
 */
ZITI_FUNC
extern void ziti_set_app_info(const char *app_id, const char *app_version);

/**
 * @brief Initializes a Ziti Edge identity.
 * 
 * This function is used to initialize a Ziti Edge identity. The Ziti C SDK is based around the [libuv](http://libuv.org/)
 * library and maintains similar semantics.  This function is used to setup the chain of callbacks
 * needed once the loop begins to execute.
 *
 * This function will initialize the Ziti C SDK using the default TLS engine [mbed](https://tls.mbed.org/). If a
 * different TLS engine is desired use ziti_init_opts().
 *
 * @param config location of identity configuration
 * @param loop libuv event loop
 * @param event_cb callback to be called for subscribed events
 * @param events event subscriptions, should be composed of `ziti_event_type` values
 * @param app_ctx additional context to be passed into #ziti_init_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_init_opts()
 * @deprecated
 */
ZITI_FUNC
extern int ziti_init(const char *config, uv_loop_t *loop, ziti_event_cb evnt_cb, int events, void *app_ctx);

/**
 * @brief Initialize Ziti Edge identity context with the provided options.
 *
 * This function is a more flexible version of ziti_init() with the ability to specify tls_context, controller,
 * and refresh options.
 *
 * @param options options to initialize with
 * @param loop libuv event loop
 * @param init_ctx additional context to be passed into the #ziti_options.ziti_init_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_init()
 */
ZITI_FUNC
extern int ziti_init_opts(ziti_options *options, uv_loop_t *loop);

/**
 * return if context is enabled
 * @param ztx ziti context
 * @return
 */
ZITI_FUNC
extern bool ziti_is_enabled(ziti_context ztx);

/**
 * Enable or disable given Ziti context.
 * @param ztx
 * @param enabled
 */
ZITI_FUNC
extern void ziti_set_enabled(ziti_context ztx, bool enabled);

/**
 * @brief returns ziti_options.app_ctx for the given Ziti context.
 *
 * @param ztx
 * @return application context that was used during ziti_init
 */
ZITI_FUNC
extern void *ziti_app_ctx(ziti_context ztx);

/**
 * @brief return SDK version
 * @return SDK version
 */
ZITI_FUNC
extern const ziti_version *ziti_get_version();

/**
 * @brief return Ziti controller version for given context
 * @param ztx ziti context
 * @return controller version
 */
ZITI_FUNC
extern const ziti_version *ziti_get_controller_version(ziti_context ztx);

/**
 * @brief controller URL of the given context
 * @param ztx ziti context
 * @return controller URL
 */
ZITI_FUNC
extern const char *ziti_get_controller(ziti_context ztx);

/**
 * @brief Ziti identity of the given context.
 * @param ztx ziti context
 * @return ziti identity
 */
ZITI_FUNC
extern const ziti_identity *ziti_get_identity(ziti_context ztx);

/**
 * @brief Retrieve current transfer rates. Rates are in bytes/second.
 *
 * Calculation is using 1 minute EWMA.
 * @param ztx ziti context
 * @param up rate of bytes going up
 * @param down rate of bytes going down
 */
ZITI_FUNC
extern void ziti_get_transfer_rates(ziti_context ztx, double *up, double *down);

/**
 * @brief Sets connect and write timeouts(in millis).
 *
 * The #ZITI_DEFAULT_TIMEOUT is used if this function is not invoked prior to initializing connections. This value is only
 * referenced when initializing new connections via ziti_conn_init(). Any connection initialized before this function will
 * have the whatever timeout was set at the time of initialization.
 *
 * Note: There is no check to verify the timeout specified is not "too small". Setting this value to a very small value
 * may lead to a large number of timeouts.
 * 
 * @param ztx the Ziti Edge identity context to set a timeout on
 * @param timeout the value in milliseconds of the timeout (must be > 0)
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_set_timeout(ziti_context ztx, int timeout);

/**
 * @brief Shutdown Ziti Edge identity context and reclaim the memory from the provided #ziti_context.
 * 
 * @param ztx the Ziti Edge identity context to be shut down. this reference is not safe to use after this call
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_shutdown(ziti_context ztx);

/**
 * @brief Shutdown Ziti Edge identity context and reclaim the memory from the provided #ziti_context.
 *
 * This function will output debugging information to standard out. The output from this command may
 * be useful when submitting issues.
 *
 * this method is designed to be suitable to use with `fprintf()` like this:
 * \code
 *     ziti_dump(ztx, fprintf, stderr);
 * \endcode
 *
 * @param ztx the Ziti Edge identity context to print debug information for
 * @param printer function to be called for output
 * @param ctx first argument passed into `printer` function
*/
ZITI_FUNC
extern void ziti_dump(ziti_context ztx, int (*printer)(void *ctx, const char *fmt, ...), void *ctx);

ZITI_FUNC
const char *ziti_get_appdata_raw(ziti_context ztx, const char *key);

ZITI_FUNC
int ziti_get_appdata(ziti_context ztx, const char *key, void *data,
                     int (*parse_func)(void *, const char *, size_t));

/**
 * @brief Initializes a connection.
 *
 * This function takes an uninitialized #ziti_connection and prepares it to be used in the Ziti C SDK
 * and allows for additional context to be carried forward.
 *
 * @param ztx the Ziti Edge identity context to initialize the connection with
 * @param conn an uninitialized #ziti_connection to be initialized
 * @param data additional context to carry forward in ziti_dial() and ziti_listen() related callbacks
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_dial(), ziti_listen(), ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_conn_init(ziti_context ztx, ziti_connection *conn, void *data);

/**
 * @brief Return Ziti context for given connection.
 *
 * @param conn ziti connection
 * @return ziti context connection belongs to
 */
ZITI_FUNC
extern ziti_context ziti_conn_context(ziti_connection conn);

/**
 * @brief Retrieves any custom data associated with the given #ziti_connection.
 * 
 * This function returns the custom data associated to the #ziti_connection supplied
 * in the ziti_conn_init() function.
 *
 * @param conn the #ziti_connection to retrieve the context from
 *
 * @return custom data passed into ziti_conn_init()
 */
ZITI_FUNC
extern void *ziti_conn_data(ziti_connection conn);

/**
 * @brief Set or clear custom data associated with the given #ziti_connection.
 *
 * This function associates the custom data to the #ziti_connection. Pass NULL to clear associated data.
 *
 * @param conn the #ziti_connection to set the context to
 * @param data custom data
 *
 * @see ziti_conn_data(), ziti_conn_init()
 */
ZITI_FUNC
extern void ziti_conn_set_data(ziti_connection conn, void *data);

/**
 * @brief Get the identity of the client that initiated the #ziti_connection.
 *
 * @return identity of the client that requested the connection.
 */
ZITI_FUNC
extern const char *ziti_conn_source_identity(ziti_connection conn);

/**
 * @brief Checks availability of the service for the given edge context.
 *
 * Checks to see if a given #ziti_context has a service available by the name supplied. The supplied name
 * is case sensitive. This function is not synchronous - the #ziti_service_cb specified is invoked at the
 * end of the function invocation with the result.
 *
 * @param ztx the Ziti Edge identity context to use to check for the service's availability on
 * @param service the name of the service to check
 * @param cb callback called with #ZITI_OK or #ZITI_SERVICE_NOT_AVAILABLE
 * @param ctx additional context to be passed to the #ziti_service_cb
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_service_available(ziti_context ztx, const char *service, ziti_service_cb cb, void *ctx);

/**
 * @brief Establishes connection to a Ziti service.
 *
 * Before any bytes can be sent over the Ziti Network a #ziti_connection must be dialed to a service. This
 * function will attempt to dial the service with the given name. The result of the service dial will be
 * called back using the provided #ziti_conn_cb.
 *
 * If the dial succeeds the provided #ziti_data_cb is used to handle bytes returned from the service. If the
 * dial fails only the #ziti_conn_cb will be invoked with the corresponding #ZITI_ERRORS code.
 *
 * @param conn the #ziti_connection to use in the dial operation
 * @param service the name of the service to dial
 * @param cb invoked after the dial operation completes
 * @param data_cb invoked if the dial operation succeeds with data received over the connection
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_dial(), ziti_write()
 */
ZITI_FUNC
extern int ziti_dial(ziti_connection conn, const char *service, ziti_conn_cb cb, ziti_data_cb data_cb);

ZITI_FUNC
extern int ziti_dial_with_options(ziti_connection conn, const char *service, ziti_dial_opts *dial_opts, ziti_conn_cb cb,
                                  ziti_data_cb data_cb);

/**
 * @brief Start accepting ziti client connections.
 *
 * This function is invoked to tell the Ziti SDK to accept connections from other Ziti clients for the
 * provided service name. The identity configured in the Ziti C SDK will need to be configured to host
 * the service via the Ziti Controller.
 *
 * When this function completes the #ziti_listen_cb callback will be invoked. This callback is what will
 * verify the success or failure of the listen operation.
 *
 * Once successfully listening the #ziti_client_cb will be invoked when a Ziti client attempts to dial
 * this service name.
 *
 * @param serv_conn the #ziti_connection acting as a server which will be hosting the service
 * @param service the name of the service to be hosted
 * @param lcb invoked after the function completes
 * @param cb a callback invoked when when client is attempting to connect to advertised service
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_accept()
 */
ZITI_FUNC
extern int ziti_listen(ziti_connection serv_conn, const char *service, ziti_listen_cb lcb, ziti_client_cb cb);

ZITI_FUNC
extern int ziti_listen_with_options(ziti_connection serv_conn, const char *service, ziti_listen_opts *listen_opts,
                                    ziti_listen_cb lcb, ziti_client_cb cb);

/**
 * @brief Completes client connection.
 *
 * After a client connects to a hosted Ziti service this function is invoked to finish the connection
 * establishment.  This function will establish the callbacks necessary to send data to the connecting
 * client or to process data sent by the client.
 *
 * After this function completes the #ziti_conn_cb callback is invoked. The callback will contain the
 * status of the function call as well so it's important to verify the status.
 *
 * Data sent by the client is processed in the #ziti_data_cb callback. Every invocation of the callback
 * could indicate an error or that the connection is no longer usable so it is important to check the
 * status of the function each time it is invoked.
 *
 * @param clt a #ziti_connection representing the incoming client connection
 * @param cb a callback invoked when the function completes
 * @param data_cb a callback invoked each time the client sends data
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_listen()
 */
ZITI_FUNC
extern int ziti_accept(ziti_connection clt, ziti_conn_cb cb, ziti_data_cb data_cb);

/**
 * @brief Closes the given connection.
 *
 * When no longer needed a [connection](#ziti_connection) should be closed to gracefully disconnect. This
 * function should be invoked after any status is returned which indicates an error situation.
 *
 * This method initiates the disconnect(if needed) and the release all associated resources.
 * After close_cb() is called, the ziti_connection handle is no longer valid.
 *
 * @param conn the #ziti_connection to be closed
 * @param close_cb callback called after connection is closed
 *
 * @return #ZITI_OK
 *         #ZITI_CONN_CLOSED if connection was already ziti_close() was already called on the given connection
 *         other #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_close(ziti_connection conn, ziti_close_cb close_cb);

/**
 * @brief Closes the outgoing (write) side of the given ziti connection.
 *
 * Any pending write requests will be able to complete. The `conn` should refer to a initialized ziti connection.
 *
 * This notifies peer ziti connection that no more data will be sent -- peer receives EOF.
 * Any further calls to `ziti_write()` will return an error.
 *
 * This leaves incoming(read) side of ziti connection open.
 *
 * @note this is roughly equivalent to calling `uv_shutdown()` on a duplex `uv_stream`, or
 *       `shutdown(sock, SHUT_WR)` on socket fd.
 *
 * @param conn the #ziti_connection to be closed
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_close_write(ziti_connection conn);

/**
 * @brief Send data to the connection peer.
 *
 * This function is invoked to send data from the Ziti C SDK to the peer on the other side of the Ziti connection. It is
 * used to send data over the given connection and to establish the callback invoked after the data is sent. It is
 * important to not free the buffer until the #ziti_write_cb callback is invoked. It is *only* safe to free the buffer in
 * the write callback.
 *
 * @param conn the #ziti_connection used to write data to
 * @param data a buffer of data to write over the provided #ziti_connection
 * @param length the length of data in the data buffer to send. Make sure to not specify 
 * @param write_cb a callback invoked after the function completes indicating the buffer can now be reclaimed
 * @param write_ctx additional context to be passed to the #ziti_write_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_write(ziti_connection conn, uint8_t *data, size_t length, ziti_write_cb write_cb, void *write_ctx);


/**
 * @brief Callback called after ziti_mfa_enroll()
 *
 * This function is invoked after a call to ziti_mfa_enroll. It will contain either
 * a status error or an mfa_enrollment struct that will be free'ed after the call
 * back finishes.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status an error code or #ZITI_OK
 * @param mfa_enrollment contents of the mfa enrollment or NULL if status is an error
 * @param ctx additional context to be passed into #ziti_mfa_enroll_cb callback
 *
 */
typedef void (*ziti_mfa_enroll_cb)(ziti_context ztx, int status, ziti_mfa_enrollment *mfa_enrollment, void *ctx);

/**
 * @brief Generic callback called after various MFA functions
 *
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status an error code or #ZITI_OK
 * @param ctx additional context to be passed into the original mfa call
 */
typedef void (*ziti_mfa_cb)(ziti_context ztx, int status, void *ctx);


/**
 * @brief Callback called after ziti_mfa_get_recovery_codes() and ziti_mfa_new_recovery_codes()
 *
 * This function is invoked after a call to get or regenerate mfa recovery codes.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status an error code or #ZITI_OK
 * @param recovery_codes null terminated array of recovery codes
 * @param ctx additional context to be passed into to the original call
 *
 */
typedef void (*ziti_mfa_recovery_codes_cb)(ziti_context ztx, int status, char **recovery_codes, void *ctx);

/**
 * @brief Attempts to initialize MFA enrollment
 *
 * Attempts to initialize enrollment. On success or failure the supplied enroll_cb
 * will be called with relevant status information. The supplied ztx must be have
 * passed a primary authentication mechanism (cert, updb, etc).
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param ziti_mfa_enroll_cb callback to receive MFA enrollment initialization status
 * @param ctx additional context to be passed into the enroll_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_enroll(ziti_context ztx, ziti_mfa_enroll_cb enroll_cb, void *ctx);

/**
 * @brief Attempts to remove MFA
 *
 * Attempts to remove MFA. On success or failure the supplied remove_cb
 * will be called with relevant status information. The supplied ztx must
 * be fully authenticated.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP or recovery code, may be empty string for MFA enrollments that have not completed via ziti_mfa_verify
 * @param remove_cb callback to receive MFA removal status
 * @param ctx additional context to be passed into the remove_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_remove(ziti_context ztx, char *code, ziti_mfa_cb remove_cb, void *ctx);

/**
 * @brief Attempts to verify MFA enrollment
 *
 * Attempts to verify MFA enrollment. On success or failure the supplied verify_cb
 * will be called with relevant status information. The supplied ztx must
 * be authenticated. After verification, MFA enrollment is complete.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a valid TOTP code, must not be a recovery code
 * @param remove_cb callback to receive MFA verify status
 * @param ctx additional context to be passed into the verify_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern void ziti_mfa_verify(ziti_context ztx, char *code, ziti_mfa_cb verify_cb, void *ctx);


/**
 * @brief Attempts to retrieve the current recovery codes for the identity
 *
 * Attempts to retrieve the recovery codes for the current identity. On success or failure the supplied get_cb
 * will be called with relevant status information. The supplied ztx must be fully authenticated.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP code, may be empty string for MFA enrollments that have not completed vi ziti_mfa_verify
 * @param remove_cb callback to receive the result status
 * @param ctx additional context to be passed into the get_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_get_recovery_codes(ziti_context ztx, char *code, ziti_mfa_recovery_codes_cb get_cb, void *ctx);

/**
 * @brief Attempts to generate new recovery codes and retrieve the new recovery codes for MFA
 *
 * Attempts to generate new recovery codes. All previous codes will become invalid and replaced with the new
 * recovery codes. On success or failure the supplied get_cb will be called with relevant status information.
 * The supplied ztx must be fully authenticated.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP code
 * @param new_cb callback to receive the result status
 * @param ctx additional context to be passed into the get_cb callback
 */
ZITI_FUNC
extern void ziti_mfa_new_recovery_codes(ziti_context ztx, char *code, ziti_mfa_recovery_codes_cb new_cb, void *ctx);

/**
 * @brief Attempt to submit an MFA code for evaluation
 *
 * Attempts submit an MFA code for evaluation. This should be done in response to
 * the `ZitiMfaAuthEvent` event or when posture check timeouts would occur for a
 * service.
 *
 * An error status will be returned if the request fails, #ZITI_OK is expected on success
 * via the `ziti_mfa_cb` provided.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param code a TOTP code
 * @param auth_cb callback to receive the result status
 * @param ctx additional context to be passed into the callback
 */
ZITI_FUNC
extern void ziti_mfa_auth(ziti_context ztx, const char *code, ziti_mfa_cb auth_cb, void *ctx);

/**
 * @brief Alerts that the host running the `ziti_context` has undergone a state change.
 *
 * Notifies that the host has undergone a state change: either woke or unlocked.
 * Being "woke" is defined as the screen dimming/shutting off
 * Being "unlocked" is defined as having the device unlocked via a security mechanism.
 *
 * At one time, a device may be "woken" and "unlocked".
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param woken whether the host device has been woke from sleep/hibernation
 * @param unlocked whether the host device has been unlocked
 */
ZITI_FUNC
extern void ziti_endpoint_state_change(ziti_context ztx, bool woken, bool unlocked);


/**
 * @brief Attempts extend the lifetime of a 1st party client certificate (issued by the Ziti Controller)
 *
 * Attempts to extend the current authenticator used for the ztx's authentication. If it is not a certificate
 * authenticator or it is not extendable, errors will be returned in subsequent events.
 *
 * Responses are provided via `ziti_extend_certificate_authenticator_event` events. On that event
 * check the `error` field for issues. If there are no errors persist the `new_client_cert_pem` field
 * and make a subsequent call to `ziti_verify_extend_cert_authenticator` to enable the new client certificate.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param csr a CSR representing the request for a new client certificate
 * @param ctx additional context to be passed back in raised events
 */
ZITI_FUNC
extern void ziti_extend_cert_authenticator(ziti_context ztx, char *csr_pem, void *ctx);


/**
 * @brief Called in response to a ziti_extend_certificate_authenticator_event to verify a new client certificate
 *
 * After calling `ziti_extend_cert_authenticator()` a `ziti_extend_certificate_authenticator_event` event is raised
 * with the `is_verified` flag as false. In order to have the new client cert provided in the event become active,
 * the controller requires that the client verify that it has received the new certificate. Calling this function
 * will cause the new client certificate to become active, inactivating the old certificate, and raises a subsequent
 * `ziti_extend_certificate_authenticator_event` with `is_verified` as true or errors set in the `error` field.
 *
 * `ziti_set_client_cert` should be called shortly after on success.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param new_cert the new client certificate that will become active on successful verification, provided in the extension event
 * @param ctx additional context to be passed back in raised events
 */
ZITI_FUNC
extern void ziti_verify_extend_cert_authenticator(ziti_context ztx, char *new_cert, void *ctx);

/**
 * @brief Updates the certificate context for the ZTX with a new client certificate and key.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param cert_buf a x509 certificate
 * @param cert_len the length of cert_buf
 * @param key_buf a private key
 * @param key_len the length of key_buf
 */
ZITI_FUNC
extern void ziti_set_client_cert(ziti_context ztx, const char *cert_buf, size_t cert_len, const char *key_buf, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_ZITI_H */
