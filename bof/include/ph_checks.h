#pragma once

#include "ph_graph.h"

void ph_collect_core(PH_GRAPH *graph);
void ph_collect_token_privileges(PH_GRAPH *graph);
void ph_collect_services(PH_GRAPH *graph);
void ph_collect_unquoted_service_paths(PH_GRAPH *graph);
void ph_collect_writable_path(PH_GRAPH *graph);
void ph_collect_always_install_elevated(PH_GRAPH *graph);
void ph_collect_uac(PH_GRAPH *graph);

