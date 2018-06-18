#ifndef PLUGNODE_PLUGNEL_H
#define PLUGNODE_PLUGNEL_H

#include <stdint.h>
#include <string>
#include <vector>

extern "C" {
typedef uint32_t Token;
struct Context;
struct Layer;
struct Frame;
struct Session;
struct SessionProfile;
struct Filter;
struct Iter;

struct Range {
  uint32_t start;
  uint32_t end;
};

const char *genet_embedded_js();

void genet_str_free(char *data);

Token genet_token_get(const char *str);
char *genet_token_string(Token id);

void genet_context_close_stream(Context *context);
char *genet_context_get_config(Context *context, const char *str);
void genet_context_free(Context *context);

Layer *genet_layer_new(Token id);
Token genet_layer_id(const Layer *layer);
Range genet_layer_range(const Layer *layer);
void genet_layer_set_range(Layer *layer, Range range);
uint8_t genet_layer_worker(const Layer *layer);
void genet_layer_set_worker(Layer *layer, uint8_t worker);
void genet_layer_add_tag(Layer *layer, Token tag);
const Layer *genet_layer_children(const Layer *layer, size_t *len);
void genet_layer_add_child_move(Layer *layer, Layer *child);
void genet_layer_free(Layer *layer);

Iter *genet_layer_tags(const Layer *layer);
uint8_t genet_layer_tags_next(Iter *iter, Token *dst);

uint32_t genet_frame_index(const Frame *frame);
Layer *genet_frame_root_mut(Frame *frame);

SessionProfile *genet_session_profile_new();
uint32_t
genet_session_profile_concurrency(const SessionProfile *SessionProfile);
void genet_session_profile_set_concurrency(SessionProfile *SessionProfile,
                                           uint32_t concurrency);
void genet_session_profile_add_link_layer(SessionProfile *SessionProfile,
                                          int32_t link,
                                          const char *id);
void genet_session_profile_set_config(SessionProfile *SessionProfile,
                                      const char *key,
                                      const char *value);
void genet_session_profile_free(SessionProfile *SessionProfile);

Session *genet_session_new(const SessionProfile *SessionProfile,
                           void (*callback)(void *, char *),
                           void *data);
Context *genet_session_context(Session *session);
void genet_session_push_frame(Session *session,
                              const char *data,
                              uint32_t len,
                              int32_t link);
void genet_session_frames(const Session *session,
                          uint32_t start,
                          uint32_t end,
                          size_t *len,
                          Frame const **dst);
void genet_session_filtered_frames(const Session *session,
                                   uint32_t id,
                                   uint32_t start,
                                   uint32_t end,
                                   size_t *len,
                                   Frame const **dst);
void genet_session_set_filter(Session *session, uint32_t id, Filter *filter);
uint32_t genet_session_len(const Session *session);
void genet_session_free(Session *session);
}

namespace genet_node {
class FilterIsolate;
}

struct FilterWorker;
struct Filter {
  FilterWorker *(*new_worker)(Filter *);
  void (*destroy)(Filter *);
  std::string data;
};

struct FilterWorker {
  uint8_t (*test)(FilterWorker *, const Frame *);
  void (*destroy)(FilterWorker *);
  genet_node::FilterIsolate *data;
};

#endif
