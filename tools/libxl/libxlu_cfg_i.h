/*
 * libxlu_cfg_i.h - xl configuration file parsing: parser-internal declarations
 *
 * Copyright (C) 2010      Citrix Ltd.
 * Author Ian Jackson <ian.jackson@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#ifndef LIBXLU_CFG_I_H
#define LIBXLU_CFG_I_H

#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxlu_internal.h"
#include "libxlu_cfg_y.h"

void xlu__cfg_set_free(XLU_ConfigSetting *set);
void xlu__cfg_set_store(CfgParseContext*, char *name,
                        XLU_ConfigValue *val, int lineno);
XLU_ConfigValue *xlu__cfg_string_mk(CfgParseContext *ctx,
                                    char *atom);
XLU_ConfigValue *xlu__cfg_list_mk(CfgParseContext *ctx, char *atom);
void xlu__cfg_list_append(CfgParseContext *ctx,
                          XLU_ConfigValue *list,
                          char *atom);
void xlu__cfg_value_free(XLU_ConfigValue *value);
char *xlu__cfgl_strdup(CfgParseContext*, const char *src);
char *xlu__cfgl_dequote(CfgParseContext*, const char *src);

void xlu__cfg_yyerror(YYLTYPE *locp, CfgParseContext*, char const *msg);
void xlu__cfgl_lexicalerror(CfgParseContext*, char const *msg);

void xlu__cfgl_likely_python(CfgParseContext *ctx);



/* Why oh why does bison not declare this in its autogenerated .h ? */
int xlu__cfg_yyparse(CfgParseContext *ctx);


#endif /*LIBXLU_CFG_I_H*/

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
