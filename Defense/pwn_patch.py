#-*- coding:utf-8 -*-
from __future__ import print_function

import sys, re
#sys.path.append('C:\\Program Files\\IDA 7.0\\python')

import idc
import idaapi
import idautils


#
is_bit64 = idaapi.get_inf_structure().is_64bit()
if is_bit64:
    bits = 64
else:
    bits = 32

print('the bits is [%d]' %bits)

#if bits==32:
    #import wingdbstub
    #wingdbstub.Ensure()


#
def load_plugin_decompiler(is_bit64):
    # load decompiler plugins (32 and 64 bits, just let it fail)
    if is_bit64:
        # 64bit plugins
        idc.RunPlugin("hexx64", 0)
    else:
        # 32bit plugins
        idc.RunPlugin("hexrays", 0)
        idc.RunPlugin("hexarm", 0)

    return

#
def search_printf_instr(ea):
    func = idaapi.get_func(ea)    
    name = idc.GetFunctionName(ea)  
    
    end = func.endEA
    start = func.startEA

    printf_addr = []
    
    x = start    
    while x < end:
        asm = idc.GetDisasm(x)
        y = x + idc.ItemSize(x)
        
        if asm.startswith('call    _printf'):
            #print('%s(): %s => %s' %(name, hex(x), asm))
            printf_addr.append(x)
            
        x = y

    return printf_addr


#
def search_free_instr(ea):
    func = idaapi.get_func(ea)    
    name = idc.GetFunctionName(ea)  
    
    end = func.endEA
    start = func.startEA

    free_addr = []
    
    x = start    
    while x < end:
        asm = idc.GetDisasm(x)
        y = x + idc.ItemSize(x)
        
        if asm=='call    _free':
            #print('%s(): %s => %s' %(name, hex(x), asm))
            free_addr.append(x)
            
        x = y

    return free_addr


#
def search_sub_esp_instr(ea):
    func = idaapi.get_func(ea)
    
    name = idc.GetFunctionName(ea)  
    
    end = func.endEA
    start = func.startEA
    
    #print('%s - %s: %s()' %(hex(start), hex(end), name))
    
    #patten = '81 EC'
    #addr = idc.FindBinary(x, SEARCH_DOWN | SEARCH_NEXT, patten)
    
    bfind_sub_esp = False
    sub_esp_addr = None
    add_esp_addr = None
    
    x = start    
    while x < end:
        asm = idc.GetDisasm(x)
        y = x + idc.ItemSize(x)
        
        if bfind_sub_esp==False:
            if asm.startswith('sub     esp,') or asm.startswith('sub     rsp,'):
                #print('%s(): %s => %s' %(name, hex(x), asm))
                
                #sub     esp, 540h
                t = idc.GetOpType(x, 1)
                if t != idc.o_imm:
                    continue
                
                bfind_sub_esp = True
                sub_esp_addr = x
                add_esp_asm = asm.replace('sub', 'add')
        else:
            #搜索后续指令应该有leave指令 或   #add     esp, 540h
            if asm.startswith(add_esp_asm):
                add_esp_addr = x
                x = y
                break
            elif asm=='leave':
                break
                      
        x = y


    if add_esp_addr is not None:
        #搜索后续指令不再对esp操作
        while x < end:
            asm = idc.GetDisasm(x)
            y = x + idc.ItemSize(x)  
            
            if re.search('esp', asm):
                print('why to here')
                pass
            
            x = y
               
    return [sub_esp_addr, add_esp_addr]

def patch_32_sub_esp(addr, add_addr, sub_value):
    patch_32_esp(addr, sub_value, 1)
    
    if add_addr is not None:
        patch_32_esp(add_addr, sub_value, 0)
        print('')
        
    return

def patch_32_esp(addr, sub_value, is_sub_esp):
    count = idc.ItemSize(addr)
    
    #get value
    v = idc.GetOperandValue(addr, 1)
    #print(hex(v))
    
    if v==-1:
        print('get value error')
        return
    
    if count==3:
        #.text:0804867C 83 EC 18                                sub     esp, 18h
        off = 0xff - v
        if sub_value < off:
            idc.PatchByte(addr + 2, v + sub_value)
        else:
            idc.PatchByte(addr + 2, 0xff)
            
        idc.MakeCode(addr)                        
    else:
        #.text:0804875B 81 EC 30 02 00 00                       sub     esp, 230h
        idc.PatchDword(addr + 2, v + sub_value)
        idc.MakeCode(addr)
    
    if is_sub_esp != 0:
        print('patch [sub esp, %s] ok, addr: %s' %(hex(v), hex(addr)))
    else:
        print('patch [add esp, %s] ok, addr: %s' %(hex(v), hex(addr)))
    
    return


def patch_64_sub_rsp(addr, add_addr, sub_value):
    patch_64_rsp(addr, sub_value, 1)
    
    if add_addr is not None:
        patch_64_rsp(add_addr, sub_value, 0)
        print('')
        
    return
    
def patch_64_rsp(addr, sub_value, is_sub_rsp):
    count = idc.ItemSize(addr)
    
    #get value
    v = idc.GetOperandValue(addr, 1)
    #print(hex(v))
    
    if v==-1:
        print('get value error')
        return
    
    if count==4:
        #.text:000055BBF4127FD9 48 83 EC 10                             sub     rsp, 10h
        off = 0xff - v
        
        if sub_value < off:
            idc.PatchByte(addr + 3, v + sub_value)
        else:
            idc.PatchByte(addr + 3, 0xff)
            
        idc.MakeCode(addr)
    else:
        #.text:00007EFEA44A5310 48 81 EC 20 01 00 00                    sub     rsp, 120h
        idc.PatchDword(addr + 3, v + sub_value)
        idc.MakeCode(addr)
        
    if is_sub_rsp != 0:
        print('patch [sub rsp, %s] ok, addr: %s' %(hex(v), hex(addr)))
    else:
        print('patch [add rsp, %s] ok, addr: %s' %(hex(v), hex(addr)))

    return



#
def patch_call_free(addr):
    count = idc.ItemSize(addr)
    
    #.text:000011E1         E8 5A FE FF FF                  call    _free
    #.text:000055BBF4127EFF E8 5C F9 FF FF                  call    _free
    for i in range(count):
        idc.PatchByte(addr + i, 0x90)   #patch to NOP instr
        
    idc.MakeCode(addr)
    
    print('patch [call _free] ok, addr: %s' %hex(addr))
    
    return



#
def get_function_para(func_name):
    func_args = []
    code_buf = []
    
    ea = idc.LocByName(func_name)
    if ea != idc.BADADDR:
        f = idaapi.get_func(ea)
        if f is not None:
            try:
                cfunc = idaapi.decompile(f);
                if cfunc != None:
                    #
                    sv = cfunc.get_pseudocode();
                    for sline in sv:
                        code_line = idaapi.tag_remove(sline.line)
                        code_buf.append(code_line)
    
                    #print('find: %s(' %func_name, end='')
                    for arg in cfunc.arguments:
                        func_args.append(arg.name)
                        #print(arg.name+', ', end='')
                    #print(')') 
            except Exception as e:
                print(e)
                
    #code_str = '\n'.join(code_buf)
    return func_args, code_buf


#遍历反编译语法树
def search_ast_item(cfunc, addr):
    try:
        sv = cfunc.get_pseudocode();
    except Exception as e:
        print(e)
    
    #变量列表
    lvars = cfunc.get_lvars()
    func_vars = []
    for var in lvars:
        func_vars.append(var.name)
        
    for citem in cfunc.treeitems:
        citem = citem.to_specific_type        
        #print(type(citem), citem.opname)
        
        if citem.op==idaapi.cit_expr:
            expr = citem.cexpr
            opname = expr.opname
            
            if expr.op == idaapi.cot_call:
                if expr.x.obj_ea==idc.BADADDR:
                    #inline方式的函数
                    continue
        
                # look for calls to function
                func_name = idc.GetFunctionName(expr.x.obj_ea)
                #print('%s: ' %func_name)
                
                if func_name in printf_name_dict:
                    #参数个数
                    vars_count = expr.a.size()
                    if vars_count==1:
                        args = expr.a
            
                        for arg in args:
                            if arg.op==idaapi.cot_var:
                                #'{v}'
                                var_name = func_vars[arg.v.idx]
                                #print('%s: printf(%s)' %(hex(addr), var_name))
                                
                                #patch to call puts()
                                patch_to_call_puts(addr)
                            elif arg.op==idaapi.cot_obj:
                                var_ptr = arg.obj_ea
                        
                                #引用变量
                                try:
                                    var_name = idc.GetString(var_ptr)
                                except:
                                    pass
                        
                                if var_name is None:
                                    names = dict(idautils.Names())
                                    var_name = names.get(var_ptr)
                        
                                    if var_name is None:
                                        var_name = 'g_var_%x' %var_ptr
                                        idaapi.set_name(var_ptr, var_name)
                                        
                                #print('%s: printf(%s)' %(hex(addr), var_name))
                                
                                #patch to call puts()
                                #patch_to_call_puts(addr)                                
                            else:
                                print('does not handle [%s] opname' %arg.opname)
                                pass
    return


puts_name_dict = ['puts', '.puts']
printf_name_dict = ['printf', '.printf']

#
def patch_to_call_puts(addr):
    #.text:0000114D E8 DE FE FF FF                          call    _printf    
    count = idc.ItemSize(addr)
    
    #get value
    v = idc.GetOperandValue(addr, 0)
    
    #要CALL的地址 - 下一条指令地址 = E8 后面的硬编码
    
    plt_names = idautils.Names()
    for address, name in plt_names:
        if name=='.puts':
            puts_addr = address
        elif name=='.printf':
            printf_addr = address
            
    op = puts_addr - (addr + count)
    op = op & 0xffffffff
    
    #print('op: %s' %hex(op))
    
    idc.PatchDword(addr + 1, op)
    idc.MakeCode(addr)
    
    print('patch [call _printf] ok, addr: %s' %hex(addr))
    
    return


#
def patch_call_printf(addr):   
    #name = idc.GetFunctionName(addr)
    #get_function_para(name)
    
    f = idaapi.get_func(addr)
    try:
        cfunc = idaapi.decompile(f);
        if cfunc != None:
            search_ast_item(cfunc, addr)
    except Exception as e:
        print(e)
        
    return


#
def get_strings():
    for strinfo in idautils.Strings():
        strcont = GetString(strinfo.ea, strinfo.length, strinfo.strtype)
        straddr = hex(strinfo.ea)
        straddr = straddr[:-1]
    
        print('%s:\t%s' %(straddr, strcont))    
        
        
    #sc = idaapi.string_info_t()
    #count = idaapi.get_strlist_qty()
    #for i in range(count):
        #idaapi.get_strlist_item(i,sc)
        #print(idaapi.get_ascii_contents(sc.ea,sc.length,sc.type))
            
    return


#
def find_import_functions():
    def imports_names_cb(ea, name, ord):
        if name is not None:
            import_function_list.append([ea, name, ord])
                
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True

    import_function_list = []

    nimps = idaapi.get_import_module_qty()
    for i in xrange(nimps):
        name = idaapi.get_import_module_name(i)
        idaapi.enum_import_names(i, imports_names_cb)
    
    return import_function_list


#
def patch_vul_func(sub_value):
    bfind_puts = False
    addr = idc.LocByName('puts')
    if addr == idc.BADADDR:
        addr = idc.LocByName('.puts')
    
    if addr != idc.BADADDR:
        bfind_puts = True         
    
    func_list = idautils.Functions()
    
    for func in func_list:
        name = idc.GetFunctionName(func)
        if name.startswith('.') or name.startswith('__'):
            pass
        else:
            #patch stack vul
            sub_addr, add_addr = search_sub_esp_instr(func)
            if sub_addr is not None:
                if bits==32:
                    patch_32_sub_esp(sub_addr, add_addr, sub_value)
                else:
                    patch_64_sub_rsp(sub_addr, add_addr, sub_value)
                
        #patch heap vul
        free_addr = search_free_instr(func)
        if free_addr != []:
            for addr in free_addr:
                patch_call_free(addr)
                
        
        #patch format vul
        if bfind_puts==True:
            printf_addr = search_printf_instr(func)
            if printf_addr != []:
                for addr in printf_addr:
                    patch_call_printf(addr)
                
    return



if __name__=='__main__':
    #清空输出窗口
    form = idaapi.find_tform("Output window")
    idaapi.switchto_tform(form, True)
    idaapi.process_ui_action("msglist:Clear")

    #save to file
    path = os.path.abspath(__file__)
    path = os.path.realpath(__file__)
    path = os.path.dirname(path)

    #
    target_path = idc.GetInputFilePath()
    target_file = idc.GetInputFile()

    if idaapi.init_hexrays_plugin():
        #print("Hex-rays version %s has been detected" % idaapi.get_hexrays_version())
        pass
    else:
        load_plugin_decompiler(is_bit64)

    #
    #get_strings()
    sub_value = idaapi.ask_long(0x20, 'please input stack additional value')
    if sub_value is not None:
        #0x20 为在原来基础上再增加的空间大小
        patch_vul_func(sub_value)
    else:
        print('you select Cancel operate')
