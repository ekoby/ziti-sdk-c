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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSMN_PARENT_LINKS 1
#define JSMN_STATIC

#include <jsmn.h>

#include <nf/model_support.h>
#include <utils.h>

#if _WIN32
#include <time.h>
#define timegm(v) _mkgmtime(v)
#else
#define _GNU_SOURCE //add time.h include after defining _GNU_SOURCE
#include <time.h>
#endif


static int parse_obj(void *obj, const char *json, jsmntok_t *tok, type_meta *meta);

void model_dump(void *obj, int off, type_meta *meta) {
    // TODO
}

int model_parse_array(void ***arrp, const char *json, size_t len, type_meta *meta) {
    jsmn_parser parser;
    jsmn_init(&parser);
    jsmntok_t toks[1024];
    memset(toks, 0, sizeof(toks));
    jsmntok_t *tok = toks;
    jsmn_parse(&parser, json, len, toks, 1024);
    if (tok->type != JSMN_ARRAY) {
        return -1;
    }

    int children = tok->size;
    void **arr = calloc(toks[0].size + 1, sizeof(void *));
    tok++;
    for (int i = 0; i < children; i++) {
        void *el = calloc(1, meta->size);
        int rc = parse_obj(el, json, tok, meta);
        if (rc < 0) {
            model_free(el, meta);
            FREE(el);
            return rc;
        }
        arr[i] = el;
        tok += rc;
    }
    *arrp = arr;
    return 0;
}

int model_parse(void *obj, const char *json, size_t len, type_meta *meta) {
    jsmn_parser parser;
    jsmn_init(&parser);
    jsmntok_t toks[1024];
    memset(toks, 0, sizeof(toks));
    jsmn_parse(&parser, json, len, toks, 1024);
    int res = parse_obj(obj, json, toks, meta);
    return res > 0 ? 0 : res;
}

void model_free_array(void ***ap, type_meta *meta) {
    if (ap == NULL || *ap == NULL) { return; }

    void **el = *ap;
    while (*el != NULL) {
        model_free(*el, meta);
        free(*el);
        el++;
    }
    FREE(*ap);
}

void model_free(void *obj, type_meta *meta) {
    if (obj == NULL) { return; }

    if (meta->destroyer != NULL) {
        return meta->destroyer(obj);
    }

    for (int i = 0; i < meta->field_count; i++) {
        field_meta *fm = &meta->fields[i];
        void **f_addr = (void **) ((char *) obj + fm->offset);
        void *f_ptr = NULL;
        if (fm->mod == none_mod) {
            f_ptr = f_addr;
            model_free(f_ptr, fm->meta());
        }
        else if (fm->mod == ptr_mod) {
            f_ptr = (void *) (*f_addr);
            if (f_ptr != NULL) {
                model_free(f_ptr, fm->meta());
                free(f_ptr);
            }
        }
        else if (fm->mod == array_mod) {
            void **arr = (void **) (*f_addr);
            if (arr != NULL) {
                for (int idx = 0; arr[idx] != NULL; idx++) {
                    f_ptr = arr + idx;
                    if (fm->meta == get_string_meta) {
                        model_free(f_ptr, fm->meta());
                    }
                    else {
                        void *mem_ptr = (void *) (*(void **) f_ptr);
                        model_free(mem_ptr, fm->meta());
                        free(mem_ptr);
                    }
                }
                free(arr);
            }
        }
    }
}

static int parse_array(void **arr, const char *json, jsmntok_t *tok, type_meta *el_meta) {
    if (tok->type != JSMN_ARRAY) {
        fprintf(stderr, "unexpected token, array as expected\n");
        return -1;
    }
    int children = tok->size;
    void **elems = calloc(children + 1, sizeof(void *));
    *arr = elems;
    int idx;
    int rc = 0;
    int processed = 1;
    tok++;
    for (idx = 0; idx < children; idx++) {
        void *el;
        if (el_meta != get_string_meta()) {
            el = calloc(1, el_meta->size);
            elems[idx] = el;
        }
        else {
            el = &elems[idx];
        }
        if (el_meta->parser != NULL) {
            rc = el_meta->parser(el, json, tok);
        }
        else {
            rc = parse_obj(el, json, tok, el_meta);
        }
        if (rc < 0) {
            return rc;
        }
        tok += rc;
        processed += rc;
    }
    return processed;
}

static int parse_obj(void *obj, const char *json, jsmntok_t *tok, type_meta *meta) {
    memset(obj, 0, meta->size);
    if (tok->type != JSMN_OBJECT) {
        return -1;
    }
    int tokens_processed = 1;
    int children = tok->size;
    tok++;
    while (children != 0) {
        if (tok->type != JSMN_STRING) {
            ZITI_LOG(ERROR, "parsing[%s] error: unexpected token starting at `%.*s'\n", meta->name, 20, json + tok->start);
            return -1;
        }
        field_meta *fm = NULL;
        for (int i = 0; i < meta->field_count; i++) {
            if (strncmp(meta->fields[i].path, json + tok->start, tok->end - tok->start) == 0) {
                fm = &meta->fields[i];
                break;
            }
        }
        tokens_processed++;

        int rc;
        if (fm != NULL) {
            tok++;
            void *field = (char *) obj + fm->offset;
            if (fm->mod == array_mod) {
                rc = parse_array(field, json, tok, fm->meta());
            }
            else {
                char *memobj = NULL;
                if (fm->mod == none_mod) {
                    memobj = (char *) (field);
                }
                else if (fm->mod == ptr_mod) {
                    memobj = (char *) calloc(1, fm->meta()->size);
                    *(char **) field = memobj;
                }
                if (memobj == NULL) {
                    fprintf(stderr, "member[%s] not found\n", fm->name);
                    return -1;
                }

                if (fm->meta()->parser != NULL) {
                    rc = fm->meta()->parser(memobj, json, tok);
                }
                else {
                    rc = parse_obj(memobj, json, tok, fm->meta());
                }
            }
            if (rc < 0) {
                return rc;
            }
            tok += rc;
            tokens_processed += rc;
        }
        else {
            ZITI_LOG(TRACE, "skipping unmapped field[%.*s] while parsing %s", tok->end - tok->start, json + tok->start, meta->name);
            tok++;
            int end = tok->end;
            while (tok->type != JSMN_UNDEFINED && tok->start <= end) {
                tok++;
                tokens_processed++;
            }
        }
        children--;
    }
    return tokens_processed;
}


static int _parse_int(int *val, const char *json, jsmntok_t *tok) {
    if (tok->type == JSMN_PRIMITIVE) {
        char *end;
        int v = (int) strtol(&json[tok->start], &end, 10);
        if (end != &json[tok->end]) {
            fprintf(stderr, "did not consume all parsing int\n");
        }
        *val = v;
        return 1;
    }
    return -1;
}

static int _parse_bool(bool *val, const char *json, jsmntok_t *tok) {
    if (tok->type == JSMN_PRIMITIVE) {
        if (json[tok->start] == 't') {
            *val = true;
        }
        else if (json[tok->start] == 'f') {
            *val = false;
        }
        else {
            return -1;
        }
        return 1;
    }
    return -1;
}
static int _parse_json(char **val, const char *json, jsmntok_t *tok) {
    int json_len = tok->end - tok->start;
    *val = calloc(1, json_len + 1);
    strncpy(*val, json + tok->start, json_len);

    int processed = 0;
    jsmntok_t *t = tok;
    while (tok->type != JSMN_UNDEFINED && t->end <= tok->end) {
        processed++;
        t++;
    }

    return processed;
}

static int _parse_string(char **val, const char *json, jsmntok_t *tok) {
    if (tok->type == JSMN_STRING) {
        *val = (char *) calloc(1, tok->end - tok->start + 1);

        const char *endp = json + tok->end;
        char *out = *val;
        const char *in = json + tok->start;
        while (in < endp) {
            if (*in == '\\') {
                switch (*++in) {
                    case 'b':
                        *out++ = '\b';
                        break;
                    case 'r':
                        *out++ = '\r';
                        break;
                    case 't':
                        *out++ = '\t';
                        break;
                    case 'n':
                        *out++ = '\n';
                        break;
                    case '\\':
                        *out++ = '\\';
                        break;
                    case '"':
                        *out++ = '"';
                        break;
                    default:
                        *out++ = *in;
                        fprintf(stderr, "unhandled escape seq '\\%c'", *in);
                }
                in++;
            }
            else {
                *out++ = *in++;
            }
        }
        return 1;
    }
    return -1;
}

static int _parse_timeval(timestamp *t, const char *json, jsmntok_t *tok) {

    char *date_str = NULL;
    int rc = _parse_string(&date_str, json, tok);

    if (rc < 0) { return rc; }

    struct tm t2 = {0};
    // "2019-08-05T14:02:52.337619Z"
    rc = sscanf(date_str, "%d-%d-%dT%d:%d:%d.%ldZ",
                &t2.tm_year, &t2.tm_mon, &t2.tm_mday,
                &t2.tm_hour, &t2.tm_min, &t2.tm_sec, &t->tv_usec);
    t2.tm_year -= 1900;
    t2.tm_mon -= 1;

    t->tv_sec = timegm(&t2);

    free(date_str);
    return 1;
}

static void _free_noop(void *v) {}

static void _free_string(char **s) {
    if (*s != NULL) {
        free(*s);
        *s = NULL;
    }
}

struct model_map_entry {
    char *key;
    void *value;
    LIST_ENTRY(model_map_entry) _next;
};
typedef LIST_HEAD(mm_e, model_map_entry) entries_t;
void* model_map_set(model_map *m, const char *key, void *val) {
    if (m->entries == NULL) {
        m->entries = calloc(1, sizeof(entries_t));
    }

    struct model_map_entry *el;
    void *old_val = NULL;
    /* replace old value */
    LIST_FOREACH(el, (entries_t*)m->entries, _next) {
        if (strcmp(key, el->key) == 0) {
            old_val = el->value;
            el->value = val;
            return old_val;
        }
    }

    el = malloc(sizeof(struct model_map_entry));
    el->value = val;
    el->key = strdup(key);
    LIST_INSERT_HEAD((entries_t *)m->entries, el, _next);

    return NULL;
}

void* model_map_get(model_map *m, const char* key) {
    if (m->entries == NULL)
        return NULL;

    struct model_map_entry *el;
    LIST_FOREACH(el, (entries_t *) m->entries, _next) {
        if (strcmp(key, el->key) == 0) {
            return el->value;
        }
    }
    return NULL;
}

void *model_map_remove(model_map *m, const char *key) {
    if (m->entries == NULL) {
        return NULL;
    }

    void *val = NULL;
    struct model_map_entry *el;
    LIST_FOREACH(el, (entries_t *) m->entries, _next) {
        if (strcmp(key, el->key) == 0) {
            break;
        }
    }
    if (el != NULL) {
        val = el->value;
        LIST_REMOVE(el, _next);
        free(el->key);
        free(el);
    }
    return val;
}

void model_map_clear(model_map *map, _free_f free_func) {
    if (map->entries == NULL) { return; }

    while (!LIST_EMPTY((entries_t *) map->entries)) {
        struct model_map_entry *el = LIST_FIRST((entries_t *) map->entries);
        LIST_REMOVE(el, _next);
        FREE(el->key);
        if (free_func) {
            free_func(el->value);
        }
        FREE(el->value);
        FREE(el);
    }
    free(map->entries);
}

model_map_iter model_map_iterator(model_map *m) {
    if (m->entries == NULL) return NULL;
    return LIST_FIRST((entries_t*)m->entries);
}

const char *model_map_it_key(model_map_iter *it) {
    return it != NULL ? ((struct model_map_entry *) it)->key : NULL;
}

void *model_map_it_value(model_map_iter it) {
    return it != NULL ? ((struct model_map_entry *) it)->value : NULL;
}

model_map_iter model_map_it_next(model_map_iter it) {
    return it != NULL ? LIST_NEXT((struct model_map_entry *) it, _next) : NULL;
}

model_map_iter model_map_it_remove(model_map_iter it) {
    model_map_iter next = model_map_it_next(it);
    if (it != NULL) {
        struct model_map_entry *e = (struct model_map_entry *) it;
        LIST_REMOVE(e, _next);
        free(e->key);
        free(e);
    }
    return next;
}

static int _parse_map(model_map *m, const char *json, jsmntok_t *tok) {
    if (tok->type != JSMN_OBJECT) {
        ZITI_LOG(ERROR, "unexspected JSON token near '%.*s', expecting object", 20, json + tok->start);
        return -1;
    }

    int tokens_processed = 1;
    int children = tok->size;
    tok++;
    for (int i = 0; i < children; i++) {
        if (tok->type != JSMN_STRING) {
            ZITI_LOG(ERROR, "parsing[map] error: unexpected token starting at `%.*s'\n", 20, json + tok->start);
            return -1;
        }
        const char *key = json + tok->start;
        size_t keylen = tok->end - tok->start;

        tok++;
        tokens_processed++;
        char *value = NULL;
        int rc = _parse_json(&value, json , tok);
        if (rc < 0) {
            return rc;
        }
        tok += rc;
        tokens_processed += rc;
        char *k = calloc(1, keylen + 1);
        strncpy(k, key, keylen);
        model_map_set(m, k, value);
        free(k);
    }
    return tokens_processed;
}

static void _free_map(model_map *m) {
    model_map_clear(m, NULL);
}

static type_meta bool_META = {
        .size = sizeof(bool),
        .parser = (_parse_f) (_parse_bool),
        .destroyer = _free_noop,
};

static type_meta int_META = {
        .size = sizeof(int),
        .parser = (_parse_f) _parse_int,
        .destroyer = _free_noop,
};

static type_meta string_META = {
        .size = sizeof(char *),
        .parser = (_parse_f) _parse_string,
        .destroyer = (_free_f) _free_string,
};

static type_meta timestamp_META = {
        .size = sizeof(struct timeval),
        .parser = (_parse_f) _parse_timeval,
        .destroyer = (_free_f) _free_noop,
};

static type_meta json_META = {
        .size = sizeof(char *),
        .parser = (_parse_f) _parse_json,
        .destroyer = (_free_f) _free_string,
};

static type_meta map_META = {
        .size = sizeof(model_map),
        .parser = (_parse_f) _parse_map,
        .destroyer = (_free_f) _free_map,
};

type_meta *get_bool_meta() { return &bool_META; }

type_meta *get_int_meta() { return &int_META; }

type_meta *get_string_meta() { return &string_META; }

type_meta *get_timestamp_meta() { return &timestamp_META; }

type_meta *get_json_meta() { return &json_META; }

type_meta *get_model_map_meta() { return &map_META; }