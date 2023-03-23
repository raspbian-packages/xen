#!/usr/bin/python

from __future__ import print_function

import sys
from functools import reduce

def read_levels():
	f = open('../../../libs/toollog/include/xentoollog.h', 'r')

	levels = []
	record = False
	for l in f.readlines():
		if 'XTL_NUM_LEVELS' in l:
			break
		if record == True:
			levels.append(l.split(',')[0].strip())
		if 'XTL_NONE' in l:
			record = True

	f.close()

	olevels = [level[4:].capitalize() for level in levels]

	return levels, olevels

# .ml

def gen_ml(olevels):
	s = ""

	s += "type level = \n"
	for level in olevels:
		s += '\t| %s\n' % level

	s += "\nlet level_to_string level =\n"
	s +=  "\tmatch level with\n"
	for level in olevels:
		s += '\t| %s -> "%s"\n' % (level, level)

	s += "\nlet level_to_prio level =\n"
	s += "\tmatch level with\n"
	for index,level in enumerate(olevels):
		s += '\t| %s -> %d\n' % (level, index)

	return s

# .mli

def gen_mli(olevels):
	s = ""

	s += "type level = \n"
	for level in olevels:
		s += '\t| %s\n' % level

	return s

# .c

def gen_c(level):
	s = ""

	s += "static value Val_level(xentoollog_level c_level)\n"
	s += "{\n"
	s += "\tswitch (c_level) {\n"
	s += "\tcase XTL_NONE: /* Not a real value */\n"
	s += '\t\tcaml_raise_sys_error(caml_copy_string("Val_level XTL_NONE"));\n'
	s += "\t\tbreak;\n"

	for index,level in enumerate(levels):
		s += "\tcase %s:\n\t\treturn Val_int(%d);\n" % (level, index)

	s += """\tcase XTL_NUM_LEVELS: /* Not a real value! */
	\t\tcaml_raise_sys_error(
	\t\t\tcaml_copy_string("Val_level XTL_NUM_LEVELS"));
	#if 0 /* Let the compiler catch this */
	\tdefault:
	\t\tcaml_raise_sys_error(caml_copy_string("Val_level Unknown"));
	\t\tbreak;
	#endif
	\t}
	\tabort();
	}
	"""

	return s

def autogen_header(open_comment, close_comment):
    s = open_comment + " AUTO-GENERATED FILE DO NOT EDIT " + close_comment + "\n"
    s += open_comment + " autogenerated by \n"
    s += reduce(lambda x,y: x + " ", range(len(open_comment + " ")), "")
    s += "%s" % " ".join(sys.argv)
    s += "\n " + close_comment + "\n\n"
    return s

if __name__ == '__main__':
	if len(sys.argv) < 3:
		print("Usage: genlevels.py <mli> <ml> <c-inc>", file=sys.stderr)
		sys.exit(1)

	levels, olevels = read_levels()

	_mli = sys.argv[1]
	mli = open(_mli, 'w')
	mli.write(autogen_header("(*", "*)"))

	_ml = sys.argv[2]
	ml = open(_ml, 'w')
	ml.write(autogen_header("(*", "*)"))

	_cinc = sys.argv[3]
	cinc = open(_cinc, 'w')
	cinc.write(autogen_header("/*", "*/"))

	mli.write(gen_mli(olevels))
	mli.write("\n")

	ml.write(gen_ml(olevels))
	ml.write("\n")

	cinc.write(gen_c(levels))
	cinc.write("\n")

	ml.write("(* END OF AUTO-GENERATED CODE *)\n")
	ml.close()
	mli.write("(* END OF AUTO-GENERATED CODE *)\n")
	mli.close()
	cinc.close()

