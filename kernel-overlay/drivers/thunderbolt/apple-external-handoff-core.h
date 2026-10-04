/* Actual one-way worker ordering, shared with failure/race harness. */
#ifndef APPLE_EXTERNAL_HANDOFF_CORE_H
#define APPLE_EXTERNAL_HANDOFF_CORE_H
struct external_steps {
 int (*wait_outer)(void *);
 int (*proof)(void *, unsigned);
 int (*host)(void *);
 int (*attach)(void *);
 int (*power)(void *);
 int (*dart)(void *);
 int (*finish)(void *);
 void *context;
 unsigned phase;
 bool attempted;
};
static int external_steps_run(struct external_steps *s)
{
 int ret;
 if (s->attempted) return -EALREADY;
 s->attempted=true;
 ret=s->wait_outer(s->context);if(ret)return ret;
 ret=s->proof(s->context,0);if(ret)return ret;
 s->phase=1;ret=s->host(s->context);if(ret)return ret;
 ret=s->proof(s->context,1);if(ret)return ret;
 s->phase=2;ret=s->attach(s->context);if(ret)return ret;
 ret=s->proof(s->context,1);if(ret)return ret;
 s->phase=3;ret=s->power(s->context);if(ret)return ret;
 ret=s->proof(s->context,1);if(ret)return ret;
 s->phase=4;ret=s->dart(s->context);if(ret)return ret;
 ret=s->proof(s->context,2);if(ret)return ret;
 s->phase=5;ret=s->finish(s->context);if(ret)return ret;
 ret=s->proof(s->context,2);if(ret)return ret;
 s->phase=6;return 0;
}
/* Diagnostic path shares the same proof-gated prefix, but child node stays
 * disabled: no provider, finish, tunnel or discovery callback is reachable. */
static int external_probe_steps_run(struct external_steps *s)
{
 int ret;
 if (s->attempted) return -EALREADY;
 s->attempted=true;
 ret=s->wait_outer(s->context);if(ret)return ret;
 ret=s->proof(s->context,0);if(ret)return ret;
 s->phase=1;ret=s->host(s->context);if(ret)return ret;
 ret=s->proof(s->context,1);if(ret)return ret;
 s->phase=2;ret=s->attach(s->context);if(ret)return ret;
 ret=s->proof(s->context,1);if(ret)return ret;
 s->phase=3;ret=s->power(s->context);if(ret)return ret;
 ret=s->proof(s->context,1);if(ret)return ret;
 s->phase=4;ret=s->dart(s->context);if(ret)return ret;
 ret=s->proof(s->context,1);if(ret)return ret;
 s->phase=6;return 0;
}
#endif
