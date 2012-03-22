import re

def parse_patch(path):
    f = open(path)

    seen = set()

    file_pat = re.compile('diff .+? .+? .+?/(.+?) ')
    line_pat = re.compile('\@\@ .+?\+(.+?),')
    
    res = dict()

    for line in f:
        
        m = file_pat.search(line)
        if m != None:
            file = m.group(1)
            if ('.c' not in file or
                ('x86' not in file and
                'arch' in file) or
                'drivers' in file or
                'arch' in file or
                'sound' in file or
                'net' in file or
                'tools' in file or
                'scripts' in file or
                'block' in file or 
                'apic' in file or
                'boot' in file or
                'kvm' in file or
                'Kconfig' in file or
                'usr' in file or
                'virt' in file or
                'trace' in file or
                #'fs' in file or
                'init' in file or
                'main' in file or
                'process' in file or
                'krpob' in file or
                'ia32' in file or
                'torture' in file):# or
                #'kernel' in file or
                #'lib' in file):
                file = None
                continue

            print file
            if file not in res:
                res[file] = []
        
        m = line_pat.search(line)
        if file != None and m != None:
            line = int(m.group(1))-1 #line index
            res[file].append(line)

            
        else:
            continue

    f.close()
    return res

def _add_prev(res_lines, lines, curr, stop):
    while curr <= stop:
        res_lines.append(lines[curr])
        curr+=1
    return curr

def write_hooks(res, inp, out):
    '''one little hell to write'''
    funcname_pat = re.compile('^[a-zA-Z].+? \**([^ ]+)\(')
    non_func_pat = re.compile('^[a-zA-z]|^[a-zA-z].+?;\n')

    funcs = dict()

    for file in res.keys():
        r = open(inp+file)
        lines = r.readlines()
        r.close()

        res_lines = []
        curr = 0
        seen = set()
        
        for offset in sorted(res[file]):            
            #get function name
            funcname_i = offset
            m = None
            while m == None:
                #careful not to wrap around
                if funcname_i < 0:
                    break

                #careful not to enter a different function
                if lines[funcname_i] == '}\n':
                    break
                
                #ignore non-functions
                if non_func_pat.search(lines[funcname_i]) != None:
                    break

                funcname_i -= 1
                m = funcname_pat.search(lines[funcname_i])
                
            if m == None: #not a function
                curr = _add_prev(res_lines, lines, curr, offset)
                continue
            else:
                funcname = m.group(1)
                
            #not a function but a struct
            if 'struct' in lines[funcname_i].split(' ')[:3]:
                curr = _add_prev(res_lines, lines, curr, offset)
                continue

            if 'mmap_init' in funcname:
                print funcname, curr, funcname_i

            #add lines before name
            curr = _add_prev(res_lines, lines, curr, funcname_i)
            
            #find end of function
            if funcname not in seen:
                seen.add(funcname)
                                
                #add hook
                krum_hook = funcname.replace(funcname, '\tsecurity_krum_'+funcname)+'();\n'
                
                #make sure this is actually function by going past {
                stop = curr
                while lines[stop] != '{\n' and lines[stop][len(lines[stop])-2] != ';':
                    stop+=1
                curr = _add_prev(res_lines, lines, curr, stop)
                
                if lines[stop][-2] == ';':
                    continue

                if '{' in lines[stop] and '}' in lines[stop]:
                    continue

                #only add int and void types
                type = lines[funcname_i].split(funcname)[0]
                if ('int' not in type and 'void' not in type) or 'void *' in type:
                    continue
                
                decl = ''.join(lines[funcname_i:stop+1])
                if '{' in decl and '}' in decl:
                    continue

                if 'inline' in type:
                    continue

                if 'fast' in funcname or 'user' in funcname:
                    continue

                funcs[funcname] = decl
                res_lines.append('#ifdef __LINUX_SECURITY_H\n')
                res_lines.append(krum_hook)
                res_lines.append('#endif\n')

        while curr < len(lines):
            res_lines.append(lines[curr])
            curr+=1

        #write out changes
        w = open(out+file, 'w')
        #w.write('#include <linux/security.h>\n')
        w.write(''.join(res_lines))
        w.close()

    return funcs


def write_capability_c(funcs, inp, out):
    r = open(inp)
    lines = r.readlines()
    r.close()

    res_lines = []
    curr = 0
    
    while 'set_to_cap_if_null(' not in lines[curr]:
        res_lines.append(lines[curr])
        curr+=1

    for funcname, func_decl in funcs.items():
        '''
        type, decl = func_decl.split(funcname)
        decl = funcname + decl
        if 'int' in type:
            type = 'int'
        else:
            type = 'void'

        krum_hook = decl.replace(funcname, 'cap_krum_'+funcname)
        krum_hook = 'static ' + type + ' ' + krum_hook
        '''
        krum_hook = 'static void cap_krum_' + funcname+'(void) \n{\n\n}\n\n'
        res_lines.append(krum_hook)
        
        '''if type == 'int':
            res_lines.append('\treturn 0;\n}\n\n')
        else:
            res_lines.append('\treturn ;\n}\n\n')
            '''
            
    while curr < len(lines)-1:
        res_lines.append(lines[curr])
        curr+=1
        
    for funcname in funcs.keys():
        funcname = 'krum_'+funcname
        res_lines.append('\tset_to_cap_if_null(ops, '+funcname+');\n')
    res_lines.append('}\n')

    w = open(out, 'w')
    w.write(''.join(res_lines))
    w.close()

def write_security_c(funcs, inp, out):
    r = open(inp)
    lines = r.readlines()
    r.close()

    res_lines = lines
    arg_pat_comma = re.compile(' \**([^ ]+?),')
    arg_pat_paren = re.compile(' \**([^ ]+?)\)')
    
    for funcname, func_decl in funcs.items():
        '''
        type, decl = func_decl.split(funcname)
        args = arg_pat_comma.findall(decl)+arg_pat_paren.findall(decl)
        if args == []:
            args = 'void'
        else:
            args = ', '.join(args)

        decl = funcname + decl
        if 'int' in type:
            type = 'int'
        else:
            type = 'void'
        

        krum_hook = decl.replace(funcname, 'security_krum_'+funcname)
        krum_hook = type + ' ' + krum_hook
        '''
        krum_hook = 'void security_krum_' +funcname+'() \n{\n\tsecurity_ops->krum_'+funcname+'(); \n}\n\n'
        res_lines.append(krum_hook)
        
        
        '''
        if args == 'void':
            args = ''
        if type == 'int':
            res_lines.append('\treturn security_ops->krum_'+
                             funcname+'('+args+');\n}\n\n')
        else:
            res_lines.append('\tsecurity_ops->krum_'+
                             funcname+'('+args+');\n}\n\n')
        '''
            
    w = open(out, 'w')
    w.write(''.join(res_lines))
    w.close()

def write_security_h(funcs, inp, out):
    r = open(inp)
    lines = r.readlines()
    r.close()

    res_lines = []
    prots = []
    curr = 0
    
    while 'void (*audit_rule_free) (void *lsmrule);' not in lines[curr]:
        res_lines.append(lines[curr])
        curr+=1
    res_lines.append(lines[curr])
    curr+=1
    res_lines.append(lines[curr])
    curr+=1
    
    arg_pat = re.compile('(\(.+?\))\n(?s)')

    for funcname, func_decl in funcs.items():
        '''
        type, decl = func_decl.split(funcname)
        args = arg_pat.search(decl).group(1)

        decl = funcname + args
        if 'int' in type:
            type = 'int'
        else:
            type = 'void'
        

        krum_hook = decl.replace(funcname, '(*krum_'+funcname+') ')
        krum_hook = '\t'+type + ' ' + krum_hook +';\n'
        '''
        krum_hook = '\t void (*krum_'+funcname+') (void);\n'
        res_lines.append(krum_hook)

        '''
        krum_hook = decl.replace(funcname, 'security_krum_'+funcname)
        krum_prot = type + ' '+krum_hook
        '''
        prots.append('void security_krum_'+funcname+'(void);\n')

        '''krum_prot = 'static inline '+krum_prot+'\n{\n'
        prots.append(krum_prot)
        if type == 'int':
            prots.append('\treturn 0;\n')
        prots.append('}\n\n')'''
    
    res_lines.append('};\n\n')
    res_lines += prots
    curr+=1

    while curr < len(lines):
        res_lines.append(lines[curr])
        curr+=1
            
    w = open(out, 'w')
    #w.write('#include <linux/elf.h>\n')
    w.write(''.join(res_lines))
    w.close()

def write_krum_c(funcs, out):
    w = open(out, 'w')
    w.write('#include <linux/security.h>\n')
    w.write('#include <linux/module.h>\n')
    w.write('#include <linux/kernel.h>\n')
    w.write('#include <asm/current.h>\n#include "include/krum.h"\n\n\n')

    w.write('static struct security_operations krum_ops = {\n\t'+
            '.name = "krum",\n\t.krum_hook = test_krum_hook,\n\t')
    
    for funcname in funcs.keys():
        w.write('.krum_'+funcname+' = krum_impl_'+funcname+',\n\t')
    w.write('\n};\n\n')
    
    w.write('static int get_curr_pid(void) {\n  return current->pid;\n}\n\n')
    w.write('static void test_krum_hook(void) {\n  int pid;\n\n  '+
            'pid = get_curr_pid();\n'+'  if (pid > krum_pid_of_interest)\n'+
            '    printk(KERN_INFO "krum hook fired with pid %d\\n", pid);\n}\n\n')

    w.write('static int __init krum_init(void) {\n  int error;\n\n'+
            '  error = register_security(&krum_ops);\n  if (error) \n'+
            '    printk(KERN_INFO "could not load krum\\n");\n\n'+
            '  return error;\n}\n\n')
    w.write('void cleanup_module() { }\n\n')
    
    for funcname in funcs.keys():
        w.write('static void krum_impl_'+funcname+'(void) {\n  int pid;\n\n'+
                '  pid = get_curr_pid();\n  if (pid > krum_pid_of_interest)\n'+
                'printk(KERN_INFO "krum_'+funcname+ ' fired with pid %d\\n", pid);\n}\n\n')
        

    w.write('MODULE_LICENSE("GPL");\nsecurity_initcall(krum_init);\n\n')
    w.close()



def write_krum_h(funcs,  out):
    w = open(out, 'w')
    w.write('#ifndef _KRUM_SECURITY\n#define _KRUM_SECURITY\n\n'+
            '#include <linux/export.h>\n#include <linux/security.h>\n'+
            'int krum_pid_of_interest = 9999999;\n\n'+
            'EXPORT_SYMBOL(krum_pid_of_interest);\n\n'+
            'static void test_krum_hook(void);\n'+
            'static int get_curr_pid(void);\n\n')

    for funcname in funcs.keys():
        w.write('static void krum_impl_'+funcname+'(void);\n')

    w.write('#endif\n')
    w.close()

if __name__ == '__main__':
    in_path = 'linux-3.2.11-backup/'
    out_path = 'linux-3.2.11/'

    patch_parse = parse_patch('pax-linux-3.2.11-201203142315.patch')
    funcs = write_hooks(patch_parse, in_path, out_path)
    print len(funcs)
    write_capability_c(funcs, in_path+'security/capability.c', out_path+'security/capability.c')
    write_security_c(funcs, in_path+'security/security.c', out_path+'security/security.c')
    write_security_h(funcs, in_path+'include/linux/security.h', out_path+'include/linux/security.h')
    write_krum_c(funcs, out_path+'security/krum/krum.c')
    write_krum_h(funcs, out_path+'security/krum/include/krum.h')
                             
    
