/*
 * Multi-level security (MLS) policy operations.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *    Support for enhanced MLS infrastructure.
 *
 * Copyright (C) 2004-2006 Trusted Computer Solutions, Inc.
 */

#ifndef _SS_MLS_H_
#define _SS_MLS_H_

#include "context.h"
#include "policydb.h"

int mls_compute_context_len(struct context *context);
void mls_sid_to_context(struct context *context, char **scontext);
int mls_context_isvalid(struct policydb *p, struct context *c);
int mls_range_isvalid(struct policydb *p, struct mls_range *r);
int mls_level_isvalid(struct policydb *p, struct mls_level *l);

int mls_context_to_sid(char oldc, char **scontext, struct context *context,
                       struct sidtab *s);

int mls_convert_context(struct policydb *oldp, struct policydb *newp,
                                                    struct context *context);

int mls_compute_sid(struct context *scontext, struct context *tcontext,
                        u16 tclass, u32 specified, struct context *newcontext);

#endif    /* _SS_MLS_H */

