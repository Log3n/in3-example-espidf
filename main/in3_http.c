/*******************************************************************************
 * This file is part of the Incubed project.
 * Sources:  https://github.com/slockit/in3-example-espidf
 * 
 * Copyright (C) 2018-2019 slock.it GmbH, Blockchains LLC
 * 
 * 
 * COMMERCIAL LICENSE USAGE
 * 
 * Licensees holding a valid commercial license may use this file in accordance 
 * with the commercial license agreement provided with the Software or, alternatively, 
 * in accordance with the terms contained in a written agreement between you and 
 * slock.it GmbH/Blockchains LLC. For licensing terms and conditions or further 
 * information please contact slock.it at in3@slock.it.
 * 	
 * Alternatively, this file may be used under the AGPL license as follows:
 *    
 * AGPL LICENSE USAGE
 * 
 * This program is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Affero General Public License as published by the Free Software 
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
 * PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
 * [Permissions of this strong copyleft license are conditioned on making available 
 * complete source code of licensed works and modifications, which include larger 
 * works using a licensed work, under the same license. Copyright and license notices 
 * must be preserved. Contributors provide an express grant of patent rights.]
 * You should have received a copy of the GNU Affero General Public License along 
 * with this program. If not, see <https://www.gnu.org/licenses/>.
 *******************************************************************************/

#include <string.h>
#include <fcntl.h>
#include "esp_http_server.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_vfs.h"
#include "cJSON.h"
#include "esp_http_client.h"
#include <esp_log.h>
#include "freertos/task.h"
#include "lwip/apps/sntp.h"

#include <in3/client.h>   // the core client
#include <in3/eth_api.h>  // functions for direct api-access
#include <in3/in3_init.h> // if included the verifier will automaticly be initialized.
#include <in3/log.h>      // logging functions
#include <in3/signer.h>   // default signer implementation
#include <in3/utils.h>
#include <stdio.h>

#include <in3/stringbuilder.h> // stringbuilder tool for dynamic memory string handling

#include <in3-core/c/src/third-party/crypto/ecdsa.h>
#include "in3-core/c/src/third-party/crypto/secp256k1.h"

static const char *REST_TAG = "esp-rest";
//buffer to receive data from in3 http transport
static sb_t *http_in3_buffer = NULL;
// in3 client
static in3_t *c;
static const char *TAG = "IN3";

static TaskHandle_t xTaskToNotify = NULL;
static eth_tx_t *tx = NULL;

// header for in3 setup
void init_in3(void);
void in3_register_eth_full(void);
void in3_register_eth_basic(void);
/**
 * ESP HTTP Client configuration and request
 * **/
/* http client event handler  */
esp_err_t s_http_event_handler(esp_http_client_event_t *evt)
{
    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        if (http_in3_buffer != NULL)
            sb_free(http_in3_buffer);
        http_in3_buffer = sb_new("");
        ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        // fill the http response buffer with the http data chunks
        sb_add_range(http_in3_buffer, (char *)evt->data, 0, evt->data_len);
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;
    }
    return ESP_OK;
}
/* http client request to in3 servers*/
void send_request(char *url, char *payload)
{

    // setup post request and send with to in3 url and payload
    esp_http_client_handle_t client;
    esp_http_client_config_t configc = {
        .url = url,
        .transport_type = HTTP_TRANSPORT_OVER_TCP,
        .event_handler = s_http_event_handler,
    };
    client = esp_http_client_init(&configc);
    const char *post_data = payload;
    ESP_LOGI(TAG, "REQUEST %s %s\n", post_data, url);
    //esp_http_client_set_url(client, url);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");
    esp_http_client_set_header(client, "charsets", "utf-8");
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK)
    {
        esp_http_client_cleanup(client);
    }
    else
    {
        ESP_LOGE(TAG, "HTTP POST request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
    }
}

/**
 * FreeRTOS Tasks
 * **/
/* Freertos task for evm call requests */
void in3_task_verify(void *pvParameters)
{
    int result;

    cJSON *bodyRoot = (cJSON *)pvParameters;
    cJSON *json_signature = cJSON_GetObjectItemCaseSensitive(bodyRoot, "signature");
    cJSON *json_pubKey = cJSON_GetObjectItemCaseSensitive(bodyRoot, "pubKey");

    char *signature = cJSON_GetStringValue(json_signature);
    char *pubKey = cJSON_GetStringValue(json_pubKey);

    ESP_LOGI(TAG, "Post body pubKey: %s", pubKey);
    ESP_LOGI(TAG, "Post body signature: %s", signature);

    uint8_t *pub_key = malloc(65 * sizeof(char));
    hex_to_bytes(pubKey, -1, pub_key, 65);

    uint8_t *sig = malloc(65 * sizeof(char));
    hex_to_bytes(signature, -1, sig, 64);

    //uint8_t *msg = (uint8_t *)"{\"timestamp\":1598369310042,\"txHash\":\"0x09c244732eba5c87615b49ba9975203b76012e605834c3c67239ca5f2fb257b7\"}";
    uint8_t *msg = (uint8_t *)"Test";

    ESP_LOGI(TAG, "Post body signature: %s", msg);

    // uint8_t hash[32];
    // char *msg_hash = malloc(65 * sizeof(char));
    // hasher_Raw(HASHER_SHA3K, msg, sizeof(msg), hash);
    // bytes_to_hex(hash, sizeof(hash), msg_hash);
    // ESP_LOGI(TAG, "Post body signature hash: 0x%s", msg_hash);
    // free(msg_hash);

    result = ecdsa_verify(&secp256k1, HASHER_SHA3K, pub_key, sig, msg, sizeof(msg));
    ESP_LOGI(TAG, "verify result %d", result);

    // notify and exit task
    xTaskNotify(xTaskToNotify, result, eSetValueWithOverwrite);
    xTaskToNotify = NULL;

    // clean up resources
    free(sig);
    free((void *)pub_key);
    //free(msg);

    vTaskDelete(NULL);
}

void in3_task_get_tx(void *pvParameters)
{

    ESP_LOGI(TAG, "tx_hash: %s \n", (char *)pvParameters);

    bytes32_t tx_hash;
    uint8_t access = 0;
    // tx hash
    hex_to_bytes((char *)pvParameters, -1, tx_hash, 32); // kovan
    // get tx by hash
    tx = eth_getTransactionByHash(c, tx_hash);

    if (!tx)
    {
        ESP_LOGI(REST_TAG, "Could not get the tx: %s", eth_last_error());
    }
    else
    {
        // convert the response to a uint32_t,
        access = 1;
        ESP_LOGI(TAG, "tx received : %d \n", access);
    }

    // notify and exit task
    xTaskNotify(xTaskToNotify, access, eSetValueWithOverwrite);
    xTaskToNotify = NULL;

    // clean up resources
    //free(tx);
    vTaskDelete(NULL);
}

/* Freertos task for get block number requests */
void in3_task_blk_number(void *pvParameters)
{
    eth_block_t *block = eth_getBlockByNumber(c, BLKNUM(2707918), true);
    if (!block)
        ESP_LOGI(TAG, "Could not find the Block: %s\n", eth_last_error());
    else
    {
        ESP_LOGI(TAG, "Number of verified transactions in block: %d\n", block->tx_count);
        free(block);
    }
    vTaskDelete(NULL);
}

/**
 * Local ESP HTTP server 
 * **/
/* GET endpoint /api/access rest handler for in3 request */
static esp_err_t exec_get_handler(httpd_req_t *req)
{
    /* Destination buffer for content of HTTP POST request.
     * httpd_req_recv() accepts char* only, but content could
     * as well be any binary data (needs type casting).
     * In case of string data, null termination will be absent, and
     * content length would give length of string */
    char content[1024];

    /* Truncate if content length larger than the buffer */
    // size_t recv_size = MIN(req->content_len, sizeof(content));

    int ret = httpd_req_recv(req, content, sizeof(content));
    if (ret <= 0)
    { /* 0 return value indicates connection closed */
        /* Check if timeout occurred */
        if (ret == HTTPD_SOCK_ERR_TIMEOUT)
        {
            /* In case of timeout one can choose to retry calling
             * httpd_req_recv(), but to keep it simple, here we
             * respond with an HTTP 408 (Request Timeout) error */
            httpd_resp_send_408(req);
        }
        /* In case of error, returning ESP_FAIL will
         * ensure that the underlying socket is closed */
        return ESP_FAIL;
    }

    cJSON *bodyRoot = cJSON_Parse(content);
    cJSON *json_tx_hash = cJSON_GetObjectItemCaseSensitive(bodyRoot, "tx_hash");
    cJSON *json_timestamp = cJSON_GetObjectItemCaseSensitive(bodyRoot, "timestamp");
    char *tx_hash = cJSON_GetStringValue(json_tx_hash);
    char *timestamp = cJSON_GetStringValue(json_timestamp);
    ESP_LOGI(TAG, "Post body tx_hash=%s", tx_hash);
    ESP_LOGI(TAG, "Post body timestamp=%s", timestamp);
    //ESP_LOGI(TAG, "Post body timestamp=%ld", strtol(timestamp, NULL, 0));

    // verify
    time_t now;
    time(&now);
    ESP_LOGI(TAG, "current timestamp: %lu", now);

    // ensure that message is not being replayed
    if (abs(now - strtol(timestamp, NULL, 0)) >= 10)
    {
        // cleanup
        cJSON_Delete(bodyRoot);

        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t ulNotificationValue;
    // timeout at 10 seconds
    const TickType_t xMaxBlockTime = pdMS_TO_TICKS(10000);

    xTaskToNotify = xTaskGetCurrentTaskHandle();
    xTaskCreate(in3_task_verify, "verifyTask", 28048, (void *)bodyRoot, 7, NULL);

    ulNotificationValue = ulTaskNotifyTake(pdTRUE, xMaxBlockTime);

    httpd_resp_set_type(req, "application/json");
    cJSON *root = cJSON_CreateObject();

    /* At this point xTaskToNotify should be NULL as no transmission
    is in progress.  A mutex can be used to guard access to the
    peripheral if necessary. */
    //configASSERT(xTaskToNotify == NULL);

    /* Store the handle of the calling task. */
    //xTaskToNotify = xTaskGetCurrentTaskHandle();

    // trigger freertos task to process in3 calls and cache the result in
    //xTaskCreate(in3_task_get_tx, "getTxTask", 28048, tx_hash, 7, NULL);

    /* Wait to be notified that the transmission is complete.  Note the first
    parameter is pdTRUE, which has the effect of clearing the task's notification
    value back to 0, making the notification value act like a binary (rather than
    a counting) semaphore.  */
    //ulNotificationValue = ulTaskNotifyTake(pdTRUE,
    //                                      xMaxBlockTime);

    // ulNotificationValue = 0;

    // ESP_LOGI(REST_TAG, "access granted: %" PRIu32 "\n", ulNotificationValue);

    if (ulNotificationValue == 1 && tx)
    {
        /* The transmission ended as expected. */
        cJSON_AddStringToObject(root, "response", "success");
        // cJSON_AddNumberToObject(root, "block_number", tx->block_number);

        // char *from_hex = (char *)malloc(20 * sizeof(char) + 1);
        // //char *from_hex;
        // bytes_to_hex(tx->from, sizeof(tx->from) + 1, from_hex);
        // ESP_LOGI(TAG, "from: %s", from_hex);

        //free(*from_hex);
        //free(tx);
    }
    else
    {
        /* The call to ulTaskNotifyTake() timed out. */
        cJSON_AddStringToObject(root, "response", "failed");
    }

    const char *slock_ret = cJSON_Print(root);
    httpd_resp_sendstr(req, slock_ret);

    // cleanup resources
    free((void *)slock_ret);
    cJSON_Delete(root);
    cJSON_Delete(bodyRoot);
    return ESP_OK;
}

/* GET endpoint /api/retrieve rest handler for in3 requests */
static esp_err_t retrieve_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "response", http_in3_buffer->data);
    const char *slock_ret = cJSON_Print(root);
    httpd_resp_sendstr(req, slock_ret);
    free((void *)slock_ret);
    cJSON_Delete(root);
    return ESP_OK;
}
/* setup and init local http rest server */
esp_err_t start_rest_server(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;

    ESP_LOGI(REST_TAG, "Starting HTTP Server");
    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(REST_TAG, "Registering URI handlers");
        /* URI handler for fetching system info */
        httpd_uri_t exec_uri = {
            .uri = "/api/access",
            .method = HTTP_POST,
            .handler = exec_get_handler,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &exec_uri);
        httpd_uri_t retrieve_uri = {
            .uri = "/api/retrieve",
            .method = HTTP_GET,
            .handler = retrieve_get_handler,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &retrieve_uri);
        init_in3();
    }
    return ESP_OK;
}
/**
 * In3 Setup and usage
 * **/
/* Perform in3 requests for http transport */
static in3_ret_t transport_esphttp(in3_request_t *req)
{
    ESP_LOGI(REST_TAG, "in 3 transport");

    for (int i = 0; i < req->urls_len; i++)
    {
        ESP_LOGI(REST_TAG, "url:%s \n payload:%s \n", req->urls[i], req->payload);
        send_request(req->urls[i], req->payload);
        sb_add_range(&req->results[i].result, http_in3_buffer->data, 0, http_in3_buffer->len);
    }
    return 0;
}
/* Setup and init in3 */
void init_in3(void)
{
    in3_log_set_quiet(false);
    in3_log_set_level(LOG_TRACE);
    in3_register_eth_basic();
    // init in3
    c = in3_for_chain(ETH_CHAIN_ID_KOVAN);
    c->transport = transport_esphttp; // use esp_idf_http client to handle the requests
    c->request_count = 1;             // number of requests to sendp
    //c->use_binary = 1;
    c->proof = PROOF_STANDARD;
    c->max_attempts = 1;
    //c->flags         = FLAGS_STATS | FLAGS_INCLUDE_CODE; // no autoupdate nodelist
    c->flags = FLAGS_AUTO_UPDATE_LIST;
    //for (int i = 0; i < c->chains_length; i++) c->chains[i].nodelist_upd8_params = NULL;

    // setup time synchronization
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
}
