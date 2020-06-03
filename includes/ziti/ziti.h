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


#ifdef __cplusplus
extern "C" {
#endif

/**
* Flag indicating service `Dial` permission
*/
#define ZITI_CAN_DIAL 1

/**
* Flag indicating service `Bind` permission
*/
#define ZITI_CAN_BIND 2

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
 * @brief Ziti Edge identity context init callback.
 *
 * This callback is invoked on the conclusion of the ziti_init() function. The result of the
 * ziti_init() function may be an error condition so it is important to verify the provided
 * status code in this callback.
 *
 * This callback also has the Ziti Edge identity context supplied. This context should be
 * stored as it is required in most Ziti C SDK function invocations and when no longer needed
 * this handle will need to be passed back to the Ziti C SDK so any resources may be freed.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param status #ZITI_OK or an error code
 * @param init_ctx custom data passed via ziti_init()
 *
 * @see ziti_init(), ZITI_ERRORS
 */
typedef void (*ziti_init_cb)(ziti_context ztx, int status, void *init_ctx);

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
 * @brief ziti_context initialization options
 *
 * @see ziti_init_opts()
 */
typedef struct ziti_options_s {
    const char *config;
    const char *controller;
    tls_context *tls;

    const char **config_types;
    ziti_init_cb init_cb;
    ziti_service_cb service_cb;

    long refresh_interval;
    void *ctx;
} ziti_options;

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
 *
 * @see ziti_listen(), ZITI_ERRORS
 */
typedef void (*ziti_client_cb)(ziti_connection serv, ziti_connection client, int status);

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
 * @param data identity json data buffer
 * @param length size of identity json or error code as defined in #ZITI_ERRORS
 * @param err_message description of error, or NULL if enrollment succeeded
 * @param enroll_ctx additional context to be passed into #ziti_enroll_cb callback
 *
 * @see ziti_enroll(), ZITI_ERRORS
 */
typedef void (*ziti_enroll_cb)(uint8_t *data, int length, char *err_message, void *enroll_ctx);

/**
 * @brief Performs a Ziti enrollment.
 * 
 * This function is used to enroll a Ziti Edge identity. The Ziti C SDK is based around the [libuv](http://libuv.org/)
 * library and maintains similar semantics.  This function is used to setup the chain of callbacks
 * needed once the loop begins to execute.
 *
 * @param jwt location of JWT file
 * @param loop libuv event loop
 * @param enroll_cb callback to be called when enrollment is complete
 * @param enroll_ctx additional context to be passed into #ziti_enroll_cb callback

 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int ziti_enroll(const char *jwt, uv_loop_t *loop, ziti_enroll_cb enroll_cb, void *enroll_ctx);

/**
 * @brief Performs a Ziti enrollment.
 * 
 * This function is used to enroll a Ziti Edge identity with a user supplied private key.
 *
 * @param jwt location of JWT file
 * @param pk_pem string containing PEM formatted private key
 * @param loop libuv event loop
 * @param enroll_cb callback to be called when enrollment is complete
 * @param enroll_ctx additional context to be passed into #ziti_enroll_cb callback

 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
extern int
ziti_enroll_with_key(const char *jwt, const char *pk_pem, uv_loop_t *loop, ziti_enroll_cb enroll_cb, void *ctx);

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
 * @param init_cb callback to be called when initialization is complete
 * @param init_ctx additional context to be passed into #ziti_init_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see ziti_init_opts()
 * @deprecated
 */
ZITI_FUNC
extern int ziti_init(const char *config, uv_loop_t *loop, ziti_init_cb init_cb, void *init_ctx);


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
extern int ziti_init_opts(ziti_options *options, uv_loop_t *loop, void *init_ctx);

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
 * @param ztx the Ziti Edge identity context to be shut down
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
 * @param ztx the Ziti Edge identity context to print debug information for
*/
ZITI_FUNC
extern void ziti_dump(ziti_context ztx);

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
 * @param conn the #ziti_connection to be closed
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 */
ZITI_FUNC
extern int ziti_close(ziti_connection *conn);

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

#ifdef __cplusplus
}
#endif

#endif /* ZITI_ZITI_H */