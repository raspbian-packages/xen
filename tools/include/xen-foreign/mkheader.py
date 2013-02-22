#!/usr/bin/python

import sys, re;
from structs import unions, structs, defines;

# command line arguments
arch    = sys.argv[1];
outfile = sys.argv[2];
infiles = sys.argv[3:];


###########################################################################
# configuration #2: architecture information

inttypes = {};
header = {};
footer = {};

#arm
inttypes["arm32"] = {
    "unsigned long" : "uint32_t",
    "long"          : "uint32_t",
    "xen_pfn_t"     : "uint64_t",
    "xen_ulong_t"   : "uint64_t",
};
header["arm32"] = """
#define __arm___ARM32 1
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define __DECL_REG(n64, n32) union { uint64_t n64; uint32_t n32; }
#else
# define __DECL_REG(n64, n32) uint64_t n64
#endif
""";
footer["arm32"] = """
#undef __DECL_REG
"""

inttypes["arm64"] = {
    "unsigned long" : "__danger_unsigned_long_on_arm64",
    "long"          : "__danger_long_on_arm64",
    "xen_pfn_t"     : "uint64_t",
    "xen_ulong_t"   : "uint64_t",
};
header["arm64"] = """
#define __aarch64___ARM64 1
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define __DECL_REG(n64, n32) union { uint64_t n64; uint32_t n32; }
#else
# define __DECL_REG(n64, n32) uint64_t n64
#endif
""";
footer["arm64"] = """
#undef __DECL_REG
"""

# x86_32
inttypes["x86_32"] = {
    "unsigned long" : "uint32_t",
    "long"          : "uint32_t",
    "xen_pfn_t"     : "uint32_t",
    "xen_ulong_t"   : "uint32_t",
};
header["x86_32"] = """
#define __i386___X86_32 1
#pragma pack(4)
""";
footer["x86_32"] = """
#pragma pack()
""";

# x86_64
inttypes["x86_64"] = {
    "unsigned long" : "__align8__ uint64_t",
    "long"          : "__align8__ uint64_t",
    "xen_pfn_t"     : "__align8__ uint64_t",
    "xen_ulong_t"   : "__align8__ uint64_t",
};
header["x86_64"] = """
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define __DECL_REG(name) union { uint64_t r ## name, e ## name; }
# define __align8__ __attribute__((aligned (8)))
#else
# define __DECL_REG(name) uint64_t r ## name
# define __align8__ FIXME
#endif
#define __x86_64___X86_64 1
""";
footer["x86_64"] = """
#undef __DECL_REG
"""

###########################################################################
# main

input  = "";
output = "";
fileid = re.sub("[-.]", "_", "__FOREIGN_%s__" % outfile.upper());

# read input header files
for name in infiles:
    f = open(name, "r");
    input += f.read();
    f.close();

# add header
output += """
/*
 * public xen defines and struct for %s
 * generated by %s -- DO NOT EDIT
 */

#ifndef %s
#define %s 1

""" % (arch, sys.argv[0], fileid, fileid)

if arch in header:
    output += header[arch];
    output += "\n";

# add defines to output
for line in re.findall("#define[^\n]+", input):
    for define in defines:
        regex = "#define\s+%s\\b" % define;
        match = re.search(regex, line);
        if None == match:
            continue;
        if define.upper()[0] == define[0]:
            replace = define + "_" + arch.upper();
        else:
            replace = define + "_" + arch;
        regex = "\\b%s\\b" % define;
        output += re.sub(regex, replace, line) + "\n";
output += "\n";

# delete defines, comments, empty lines
input = re.sub("#define[^\n]+\n", "", input);
input = re.compile("/\*(.*?)\*/", re.S).sub("", input)
input = re.compile("\n\s*\n", re.S).sub("\n", input);

# add unions to output
for union in unions:
    regex = "union\s+%s\s*\{(.*?)\n\};" % union;
    match = re.search(regex, input, re.S)
    if None == match:
        output += "#define %s_has_no_%s 1\n" % (arch, union);
    else:
        output += "union %s_%s {%s\n};\n" % (union, arch, match.group(1));
    output += "\n";

# add structs to output
for struct in structs:
    regex = "struct\s+%s\s*\{(.*?)\n\};" % struct;
    match = re.search(regex, input, re.S)
    if None == match:
        output += "#define %s_has_no_%s 1\n" % (arch, struct);
    else:
        output += "struct %s_%s {%s\n};\n" % (struct, arch, match.group(1));
        output += "typedef struct %s_%s %s_%s_t;\n" % (struct, arch, struct, arch);
    output += "\n";

# add footer
if arch in footer:
    output += footer[arch];
    output += "\n";
output += "#endif /* %s */\n" % fileid;

# replace: defines
for define in defines:
    if define.upper()[0] == define[0]:
        replace = define + "_" + arch.upper();
    else:
        replace = define + "_" + arch;
    output = re.sub("\\b%s\\b" % define, replace, output);

# replace: unions
for union in unions:
    output = re.sub("\\b(union\s+%s)\\b" % union, "\\1_%s" % arch, output);

# replace: structs + struct typedefs
for struct in structs:
    output = re.sub("\\b(struct\s+%s)\\b" % struct, "\\1_%s" % arch, output);
    output = re.sub("\\b(%s)_t\\b" % struct, "\\1_%s_t" % arch, output);

# replace: integer types
integers = inttypes[arch].keys();
integers.sort(lambda a, b: cmp(len(b),len(a)));
for type in integers:
    output = re.sub("\\b%s\\b" % type, inttypes[arch][type], output);

# print results
f = open(outfile, "w");
f.write(output);
f.close;

