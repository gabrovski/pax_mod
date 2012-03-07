#!/usr/bin/python2

import re

def parse_sec_ops(path):
    f = open(path)
    pat = re.compile('\t(.+?) \(\*(.+?)\) (\(.+?\));')

    for line in f:
        m = pat.search(line)
        if m != None:
            yield m.groups()
        elif '#' in line:
            yield line, '', ''
    f.close()

def write_mod(parse_gen, out):
    struct = 'static struct security_operations pax_mod_sec_ops = {\n'
    params = []

    w = open(out, 'w')
    w.write('#include <linux/security.h>\n'+
            '#include <linux/module.h>\n'+
            '#include <linux/kernel.h>\n\n\n')
    for ret, name, args in parse_gen:
        if '#' in ret:
            params.append(ret)
            continue

        params.append(('  .'+name+'  =  pax_mod_'+name+',\n'))

        w.write('static ')
        w.write(ret+' pax_mod_')
        w.write(name+' ')
        w.write(args+'\n{\n  ')
        
        if ret == 'int':
            w.write('return 0;\n')
        elif ret == 'void':
            w.write('return;\n')
        else:
            print 'unknown type'
            w.write('//return 0;\n')
        w.write('}\n\n')

    w.write(struct)
    w.write(''.join(params))
    w.write('};\n\n')
    
    w.write('int init_module() { return 0; }\n\n')
    w.write('void cleanup_module() { return; }\n\n')

    w.close()

if __name__ == '__main__':
    pg = parse_sec_ops('pmod.c')
    write_mod(pg, 'pax_mod.c')
