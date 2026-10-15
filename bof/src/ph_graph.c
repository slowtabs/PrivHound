#include "ph_graph.h"

/* The BOF build intentionally avoids the C runtime. */
static int ph_strlen(const char *s) {
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

#ifdef _MSC_VER
#define PH_NOINLINE __declspec(noinline)
#else
#define PH_NOINLINE __attribute__((noinline))
#endif

PH_NOINLINE void ph_zero(void *p, int n) {
    volatile unsigned char *b = (volatile unsigned char *)p;
    while (n-- > 0) *b++ = 0;
}

static int ph_append(PH_JSON *json, const char *text, int length) {
    int available;
    if (!json || !json->buffer || json->capacity <= 0 || length < 0) return 0;
    available = json->capacity - json->length - 1;
    if (available <= 0) return 0;
    if (length > available) length = available;
    for (int i = 0; i < length; i++) json->buffer[json->length + i] = text[i];
    json->length += length;
    json->buffer[json->length] = 0;
    return length;
}

static void ph_char(PH_JSON *json, char c) {
    ph_append(json, &c, 1);
}

static void ph_literal(PH_JSON *json, const char *text) {
    ph_append(json, text, ph_strlen(text));
}

static void ph_escaped(PH_JSON *json, const char *value) {
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    ph_char(json, '"');
    while (*p) {
        switch (*p) {
        case '"': ph_literal(json, "\\\""); break;
        case '\\': ph_literal(json, "\\\\"); break;
        case '\b': ph_literal(json, "\\b"); break;
        case '\f': ph_literal(json, "\\f"); break;
        case '\n': ph_literal(json, "\\n"); break;
        case '\r': ph_literal(json, "\\r"); break;
        case '\t': ph_literal(json, "\\t"); break;
        default:
            if (*p < 0x20) {
                /* Control characters are rare in these fields; replace them. */
                ph_char(json, '?');
            } else {
                ph_char(json, (char)*p);
            }
            break;
        }
        p++;
    }
    ph_char(json, '"');
}

static void ph_key(PH_JSON *json, const char *key) {
    if (!json->first) ph_char(json, ',');
    json->first = 0;
    ph_escaped(json, key);
    ph_char(json, ':');
}

void ph_json_init(PH_JSON *json, char *buffer, int capacity) {
    if (!json) return;
    json->buffer = buffer;
    json->capacity = capacity;
    json->length = 0;
    json->first = 1;
    if (buffer && capacity > 0) buffer[0] = 0;
}

void ph_json_start_object(PH_JSON *json) {
    ph_char(json, '{');
    json->first = 1;
}

void ph_json_end_object(PH_JSON *json) { ph_char(json, '}'); }

void ph_json_add_string(PH_JSON *json, const char *key, const char *value) {
    ph_key(json, key);
    ph_escaped(json, value);
}

void ph_json_add_bool(PH_JSON *json, const char *key, BOOL value) {
    ph_key(json, key);
    ph_literal(json, value ? "true" : "false");
}

void ph_json_add_int(PH_JSON *json, const char *key, unsigned long value) {
    char digits[32];
    int i = 0;
    int start;
    ph_key(json, key);
    if (value == 0) {
        ph_char(json, '0');
        return;
    }
    while (value && i < (int)sizeof(digits)) {
        digits[i++] = (char)('0' + (value % 10));
        value /= 10;
    }
    for (start = i - 1; start >= 0; start--) ph_char(json, digits[start]);
}

void ph_json_add_raw(PH_JSON *json, const char *key, const char *raw) {
    ph_key(json, key);
    ph_literal(json, raw ? raw : "null");
}

void ph_json_start_array(PH_JSON *json, const char *key) {
    ph_key(json, key);
    ph_char(json, '[');
    json->first = 1;
}

void ph_json_end_array(PH_JSON *json) { ph_char(json, ']'); }

void ph_json_array_string(PH_JSON *json, const char *value) {
    if (!json->first) ph_char(json, ',');
    json->first = 0;
    ph_escaped(json, value);
}

/* Compact SHA-256 implementation for stable IDs compatible with New-PHId. */
typedef struct _PH_SHA256 {
    unsigned long state[8];
    unsigned long long bit_count;
    unsigned char block[64];
    unsigned int block_length;
} PH_SHA256;

static const unsigned long ph_sha_k[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

static unsigned long ph_rotr(unsigned long x, unsigned int n) { return (x >> n) | (x << (32 - n)); }
static unsigned long ph_ch(unsigned long x, unsigned long y, unsigned long z) { return (x & y) ^ (~x & z); }
static unsigned long ph_maj(unsigned long x, unsigned long y, unsigned long z) { return (x & y) ^ (x & z) ^ (y & z); }
static unsigned long ph_bs0(unsigned long x) { return ph_rotr(x,2) ^ ph_rotr(x,13) ^ ph_rotr(x,22); }
static unsigned long ph_bs1(unsigned long x) { return ph_rotr(x,6) ^ ph_rotr(x,11) ^ ph_rotr(x,25); }
static unsigned long ph_ss0(unsigned long x) { return ph_rotr(x,7) ^ ph_rotr(x,18) ^ (x >> 3); }
static unsigned long ph_ss1(unsigned long x) { return ph_rotr(x,17) ^ ph_rotr(x,19) ^ (x >> 10); }

static void ph_sha_transform(PH_SHA256 *ctx, const unsigned char block[64]) {
    unsigned long w[64];
    unsigned long a,b,c,d,e,f,g,h;
    unsigned long t1,t2;
    int i;
    for (i=0; i<16; i++) {
        w[i] = ((unsigned long)block[i*4] << 24) | ((unsigned long)block[i*4+1] << 16) |
               ((unsigned long)block[i*4+2] << 8) | (unsigned long)block[i*4+3];
    }
    for (i=16; i<64; i++) w[i] = ph_ss1(w[i-2]) + w[i-7] + ph_ss0(w[i-15]) + w[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i=0; i<64; i++) {
        t1 = h + ph_bs1(e) + ph_ch(e,f,g) + ph_sha_k[i] + w[i];
        t2 = ph_bs0(a) + ph_maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void ph_sha_init(PH_SHA256 *ctx) {
    ctx->state[0]=0x6a09e667UL; ctx->state[1]=0xbb67ae85UL; ctx->state[2]=0x3c6ef372UL; ctx->state[3]=0xa54ff53aUL;
    ctx->state[4]=0x510e527fUL; ctx->state[5]=0x9b05688cUL; ctx->state[6]=0x1f83d9abUL; ctx->state[7]=0x5be0cd19UL;
    ctx->bit_count=0; ctx->block_length=0;
}

static void ph_sha_update(PH_SHA256 *ctx, const unsigned char *data, int length) {
    int i;
    for (i=0; i<length; i++) {
        ctx->block[ctx->block_length++] = data[i];
        if (ctx->block_length == 64) {
            ph_sha_transform(ctx, ctx->block);
            ctx->bit_count += 512;
            ctx->block_length = 0;
        }
    }
}

static void ph_sha_final(PH_SHA256 *ctx, unsigned char digest[32]) {
    unsigned long long bits = ctx->bit_count + ((unsigned long long)ctx->block_length * 8ULL);
    int i;
    ctx->block[ctx->block_length++] = 0x80;
    while (ctx->block_length != 56) {
        if (ctx->block_length == 64) {
            ph_sha_transform(ctx, ctx->block);
            ctx->block_length = 0;
        }
        ctx->block[ctx->block_length++] = 0;
    }
    for (i=7; i>=0; i--) ctx->block[ctx->block_length++] = (unsigned char)(bits >> (i*8));
    ph_sha_transform(ctx, ctx->block);
    for (i=0; i<8; i++) {
        digest[i*4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i*4+1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i*4+2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i*4+3] = (unsigned char)ctx->state[i];
    }
}

static char ph_hex(unsigned char n) { return n < 10 ? (char)('0' + n) : (char)('A' + n - 10); }

void ph_id(PH_GRAPH *graph, const char *type, const char *name, char out[33]) {
    char input[1024];
    unsigned char digest[32];
    int offset = 0;
    PH_SHA256 ctx;
    const char *parts[3] = { graph ? graph->hostname : "", type ? type : "", name ? name : "" };
    for (int p=0; p<3; p++) {
        int n = ph_strlen(parts[p]);
        for (int i=0; i<n && offset < (int)sizeof(input)-1; i++) input[offset++] = parts[p][i];
        if (p < 2 && offset < (int)sizeof(input)-1) input[offset++] = '|';
    }
    input[offset] = 0;
    ph_sha_init(&ctx);
    ph_sha_update(&ctx, (const unsigned char *)input, offset);
    ph_sha_final(&ctx, digest);
    /* New-PHId uses the first 16 digest bytes (32 uppercase hex characters). */
    for (int i=0; i<16; i++) { out[i*2] = ph_hex((unsigned char)(digest[i] >> 4)); out[i*2+1] = ph_hex((unsigned char)(digest[i] & 0xf)); }
    out[32] = 0;
}

static void ph_emit_json(PH_GRAPH *graph, PH_JSON *json) {
    if (graph && graph->emit && json && json->buffer && json->length > 0) {
        if (json->length + 1 < json->capacity) {
            json->buffer[json->length++] = '\n';
            json->buffer[json->length] = 0;
        }
        graph->emit(graph->emit_context, json->buffer, json->length);
    }
}

void ph_emit_node(PH_GRAPH *graph, const char *id, const char *kinds_json, const char *properties_json) {
    char line[16384];
    PH_JSON j;
    ph_json_init(&j, line, sizeof(line)); ph_json_start_object(&j);
    ph_json_add_string(&j, "type", "node"); ph_json_add_string(&j, "id", id);
    ph_json_add_raw(&j, "kinds", kinds_json); ph_json_add_raw(&j, "properties", properties_json);
    ph_json_end_object(&j); ph_emit_json(graph, &j); if (graph) graph->node_count++;
}

void ph_emit_edge(PH_GRAPH *graph, const char *start, const char *end, const char *kind, const char *properties_json) {
    char line[8192];
    PH_JSON j;
    ph_json_init(&j, line, sizeof(line)); ph_json_start_object(&j);
    ph_json_add_string(&j, "type", "edge"); ph_json_add_string(&j, "start", start); ph_json_add_string(&j, "end", end);
    ph_json_add_string(&j, "kind", kind); ph_json_add_raw(&j, "properties", properties_json);
    ph_json_end_object(&j); ph_emit_json(graph, &j); if (graph) graph->edge_count++;
}

void ph_emit_finding(PH_GRAPH *graph, const char *check, const char *severity, const char *description, const char *abuse_info) {
    char line[8192];
    PH_JSON j;
    ph_json_init(&j, line, sizeof(line)); ph_json_start_object(&j);
    ph_json_add_string(&j, "type", "finding"); ph_json_add_string(&j, "check", check); ph_json_add_string(&j, "severity", severity);
    ph_json_add_string(&j, "description", description); ph_json_add_string(&j, "abuse_info", abuse_info);
    ph_json_end_object(&j); ph_emit_json(graph, &j); if (graph) graph->finding_count++;
}

void ph_emit_error(PH_GRAPH *graph, const char *check, const char *message) {
    char line[4096];
    PH_JSON j;
    ph_json_init(&j, line, sizeof(line)); ph_json_start_object(&j);
    ph_json_add_string(&j, "type", "error"); ph_json_add_string(&j, "check", check); ph_json_add_string(&j, "message", message);
    ph_json_end_object(&j); ph_emit_json(graph, &j); if (graph) graph->error_count++;
}

void ph_graph_init(PH_GRAPH *graph, PH_EMIT_FN emit, void *context) {
    if (!graph) return;
    ph_zero(graph, sizeof(*graph));
    graph->emit = emit;
    graph->emit_context = context;
}

