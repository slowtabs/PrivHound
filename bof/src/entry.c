#include "beacon.h"
#include "ph_graph.h"

static void ph_beacon_emit(void *context, const char *data, int length) {
    (void)context;
    BeaconOutput(CALLBACK_OUTPUT_UTF8, data, length);
}

/* Cobalt Strike BOF entry point. */
void go(char *args, int length) {
    PH_GRAPH graph;
    (void)args;
    (void)length;
    ph_graph_init(&graph, ph_beacon_emit, NULL);
    ph_collect(&graph);
}

