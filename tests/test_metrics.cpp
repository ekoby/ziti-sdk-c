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

#include "catch2/catch.hpp"
#include <metrics.h>

extern "C" {
    extern void tick_all();
}

TEST_CASE("test-metrics") {
    rate_t exp;
    rate_t cma;

    metrics_rate_init(&exp, EWMA_1m);
    metrics_rate_init(&cma, MMA_1m);

    metrics_rate_update(&exp, 1000);
    metrics_rate_update(&cma, 1000);

    for (int i=0; i<100; i++) {
        tick_all();
        printf("%d:\tewma=%.10lf\tmma=%lf\n", i, metrics_rate_get(&exp), metrics_rate_get(&cma));
    }
};