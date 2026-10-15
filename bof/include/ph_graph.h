#pragma once

#include "ph_winapi.h"

typedef void (*PH_EMIT_FN)(void *context, const char *data, int length);

typedef struct _PH_JSON {
    char *buffer;
    int capacity;
    int length;
    int first;
} PH_JSON;

typedef struct _PH_GRAPH {
    PH_EMIT_FN emit;
    void *emit_context;
    char hostname[256];
    char username[256];
    char domain[256];
    char identity[512];
    char sid[192];
    BOOL is_admin;
    char current_user_id[33];
    char system_id[33];
    char admin_id[33];
    char computer_id[33];
    unsigned int node_count;
    unsigned int edge_count;
    unsigned int finding_count;
    unsigned int error_count;
} PH_GRAPH;

void ph_graph_init(PH_GRAPH *graph, PH_EMIT_FN emit, void *context);
void ph_collect(PH_GRAPH *graph);

void ph_zero(void *buffer, int length);
void ph_id(PH_GRAPH *graph, const char *type, const char *name, char out[33]);

void ph_json_init(PH_JSON *json, char *buffer, int capacity);
void ph_json_start_object(PH_JSON *json);
void ph_json_end_object(PH_JSON *json);
void ph_json_add_string(PH_JSON *json, const char *key, const char *value);
void ph_json_add_bool(PH_JSON *json, const char *key, BOOL value);
void ph_json_add_int(PH_JSON *json, const char *key, unsigned long value);
void ph_json_add_raw(PH_JSON *json, const char *key, const char *raw);
void ph_json_start_array(PH_JSON *json, const char *key);
void ph_json_end_array(PH_JSON *json);
void ph_json_array_string(PH_JSON *json, const char *value);

void ph_emit_node(PH_GRAPH *graph, const char *id, const char *kinds_json, const char *properties_json);
void ph_emit_edge(PH_GRAPH *graph, const char *start, const char *end, const char *kind, const char *properties_json);
void ph_emit_finding(PH_GRAPH *graph, const char *check, const char *severity, const char *description, const char *abuse_info);
void ph_emit_error(PH_GRAPH *graph, const char *check, const char *message);

