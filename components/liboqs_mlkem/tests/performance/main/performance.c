#include <stdio.h>
#include "mlkem768.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG "performance"
#define TASK_STACK_SIZE 16384  // Large enough stack for the operations

// Performance metrics structure
typedef struct {
    int64_t init_time_us;
    int64_t keypair_time_us;
    int64_t encaps_time_us;
    int64_t decaps_time_us;
    int64_t cleanup_time_us;
    int64_t total_time_us;
    UBaseType_t stack_high_water_mark;
    uint32_t heap_free_before;
    uint32_t heap_free_after;
    uint32_t heap_min_free_before;
    uint32_t heap_min_free_after;
} perf_metrics_t;

// Task function that runs the performance tests
static void performance_task(void *pvParameters)
{
    perf_metrics_t metrics = {0};
    int64_t start_time, end_time;
    
    ESP_LOGI(TAG, "=== ML-KEM-768 Performance Test ===");
    
    // Get initial heap stats
    metrics.heap_free_before = esp_get_free_heap_size();
    metrics.heap_min_free_before = esp_get_minimum_free_heap_size();
    
    ESP_LOGI(TAG, "Initial heap: free=%u bytes, min_free=%u bytes", 
             metrics.heap_free_before, metrics.heap_min_free_before);
    
    // Print utility function info
    ESP_LOGI(TAG, "Algorithm: %s", mlkem768_get_algorithm_name());
    ESP_LOGI(TAG, "Public key length: %zu bytes", mlkem768_get_public_key_len());
    ESP_LOGI(TAG, "Secret key length: %zu bytes", mlkem768_get_secret_key_len());
    ESP_LOGI(TAG, "Ciphertext length: %zu bytes", mlkem768_get_ciphertext_len());
    ESP_LOGI(TAG, "Shared secret length: %zu bytes", mlkem768_get_shared_secret_len());
    
    mlkem768_ctx_t ctx;
    
    // Measure total time
    start_time = esp_timer_get_time();
    
    // Test mlkem768_init
    ESP_LOGI(TAG, "Testing mlkem768_init...");
    int64_t t0 = esp_timer_get_time();
    int ret = mlkem768_init(&ctx);
    metrics.init_time_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG, "mlkem768_init failed!");
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "  Duration: %lld us (%.3f ms)", 
             (long long)metrics.init_time_us, (double)metrics.init_time_us / 1000.0);
    
    // Test mlkem768_keypair
    ESP_LOGI(TAG, "Testing mlkem768_keypair...");
    t0 = esp_timer_get_time();
    ret = mlkem768_keypair(&ctx);
    metrics.keypair_time_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG, "mlkem768_keypair failed!");
        mlkem768_cleanup(&ctx);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "  Duration: %lld us (%.3f ms)", 
             (long long)metrics.keypair_time_us, (double)metrics.keypair_time_us / 1000.0);
    
    // Test mlkem768_encaps
    ESP_LOGI(TAG, "Testing mlkem768_encaps...");
    t0 = esp_timer_get_time();
    ret = mlkem768_encaps(&ctx, ctx.public_key);
    metrics.encaps_time_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG, "mlkem768_encaps failed!");
        mlkem768_cleanup(&ctx);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "  Duration: %lld us (%.3f ms)", 
             (long long)metrics.encaps_time_us, (double)metrics.encaps_time_us / 1000.0);
    
    // Test mlkem768_decaps
    ESP_LOGI(TAG, "Testing mlkem768_decaps...");
    t0 = esp_timer_get_time();
    ret = mlkem768_decaps(&ctx, ctx.ciphertext);
    metrics.decaps_time_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG, "mlkem768_decaps failed!");
        mlkem768_cleanup(&ctx);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "  Duration: %lld us (%.3f ms)", 
             (long long)metrics.decaps_time_us, (double)metrics.decaps_time_us / 1000.0);
    
    // Test mlkem768_cleanup
    ESP_LOGI(TAG, "Testing mlkem768_cleanup...");
    t0 = esp_timer_get_time();
    ret = mlkem768_cleanup(&ctx);
    metrics.cleanup_time_us = esp_timer_get_time() - t0;
    if (ret != 0) {
        ESP_LOGE(TAG, "mlkem768_cleanup failed!");
    }
    ESP_LOGI(TAG, "  Duration: %lld us (%.3f ms)", 
             (long long)metrics.cleanup_time_us, (double)metrics.cleanup_time_us / 1000.0);
    
    end_time = esp_timer_get_time();
    metrics.total_time_us = end_time - start_time;
    
    // Get final heap stats
    metrics.heap_free_after = esp_get_free_heap_size();
    metrics.heap_min_free_after = esp_get_minimum_free_heap_size();
    
    // Get stack high water mark
    metrics.stack_high_water_mark = uxTaskGetStackHighWaterMark(NULL);
    
    // Print summary
    ESP_LOGI(TAG, "=== Performance Summary ===");
    ESP_LOGI(TAG, "Timing (microseconds):");
    ESP_LOGI(TAG, "  Init:     %lld us (%.3f ms)", 
             (long long)metrics.init_time_us, (double)metrics.init_time_us / 1000.0);
    ESP_LOGI(TAG, "  Keypair:  %lld us (%.3f ms)", 
             (long long)metrics.keypair_time_us, (double)metrics.keypair_time_us / 1000.0);
    ESP_LOGI(TAG, "  Encaps:   %lld us (%.3f ms)", 
             (long long)metrics.encaps_time_us, (double)metrics.encaps_time_us / 1000.0);
    ESP_LOGI(TAG, "  Decaps:   %lld us (%.3f ms)", 
             (long long)metrics.decaps_time_us, (double)metrics.decaps_time_us / 1000.0);
    ESP_LOGI(TAG, "  Cleanup:  %lld us (%.3f ms)", 
             (long long)metrics.cleanup_time_us, (double)metrics.cleanup_time_us / 1000.0);
    ESP_LOGI(TAG, "  Total:    %lld us (%.3f ms)", 
             (long long)metrics.total_time_us, (double)metrics.total_time_us / 1000.0);
    
    ESP_LOGI(TAG, "Stack Usage:");
    ESP_LOGI(TAG, "  Stack size: %d bytes", TASK_STACK_SIZE);
    ESP_LOGI(TAG, "  High water mark: %lu bytes", (unsigned long)metrics.stack_high_water_mark);
    ESP_LOGI(TAG, "  Used: %lu bytes", 
             (unsigned long)(TASK_STACK_SIZE - metrics.stack_high_water_mark));
    
    ESP_LOGI(TAG, "Heap Usage:");
    ESP_LOGI(TAG, "  Before - free: %u bytes, min_free: %u bytes", 
             metrics.heap_free_before, metrics.heap_min_free_before);
    ESP_LOGI(TAG, "  After  - free: %u bytes, min_free: %u bytes", 
             metrics.heap_free_after, metrics.heap_min_free_after);
    if (metrics.heap_free_before > metrics.heap_free_after) {
        uint32_t heap_used = metrics.heap_free_before - metrics.heap_free_after;
        ESP_LOGI(TAG, "  Peak usage: %u bytes", heap_used);
    }
    
    ESP_LOGI(TAG, "=== Test Complete ===");
    
    vTaskDelete(NULL);
}

void app_main(void)
{
    // Create a task to run the performance test
    // This allows us to measure stack usage accurately
    xTaskCreate(performance_task, "perf_task", TASK_STACK_SIZE, NULL, 5, NULL);
}
