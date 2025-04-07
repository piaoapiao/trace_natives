# -*- coding:utf-8 -*-
import os
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
import ida_nalt
import idaapi
import idautils
import idc
import time

# 全局变量定义
isAndroid = False
rangeStart = 0x100057508
rangeEnd = 0x10019ac84

# isAndroid = True
# rangeStart = 0x0
# rangeEnd = 0x20019ac84


# 获取SO文件名和路径
def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    filepath, filename = os.path.split(fullpath)
    return filepath, filename


# 获取代码段的范围
def getSegAddr():
    textStart = []
    textEnd = []

    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)).lower() == '.text' or (idc.get_segm_name(seg)).lower() == '__text':
            tempStart = idc.get_segm_start(seg)
            tempEnd = idc.get_segm_end(seg)

            textStart.append(tempStart)
            textEnd.append(tempEnd)
            break

    print(hex(min(textStart)))
    print(hex(max(textEnd)))  # 使用 max 替代原来的 min
    return min(textStart), max(textEnd)


# 插件类定义
class traceNatives(plugin_t):
    flags = PLUGIN_PROC
    comment = "traceNatives"
    help = ""
    wanted_name = "traceNatives"
    wanted_hotkey = ""

    def init(self):
        print("traceNatives(v0.3) plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):
        ea, ed = getSegAddr()
        search_result = []

        global rangeStart, rangeEnd, isAndroid

        for func in idautils.Functions(ea, ed):
            try:

                base = 0

                if not isAndroid:  # 如果非 Android
                    base = 0x100000000  # iOS 的基础地址
    
                func_data = idaapi.get_func(func)
                fun_start = func_data.start_ea
                fun_end = func_data.end_ea


                # check text range
                if fun_start >= rangeStart and fun_end <= rangeEnd:
                    pass
                else:
                    continue

                functionName = str(idaapi.ida_funcs.get_func_name(func))
                if len(list(idautils.FuncItems(func))) > 100:
                    # 检查是否 Thumb 指令集模式
                    arm_or_thumb = idc.get_sreg(func, "T")
                    if arm_or_thumb:
                        func += 1
                    search_result.append(hex(fun_start - base))  # iOS 基地址
                    print(hex(fun_start - base))
            except Exception as e:
                print(f"Error processing function {hex(func)}: {e}")
                pass

        so_path, so_name = getSoPathAndName()
        search_result = [f"-a '{so_name}!{offset}'" for offset in search_result]
        search_result = " ".join(search_result)

        script_name = so_name.split(".")[0] + "_" + str(int(time.time())) + ".txt"
        save_path = os.path.join(so_path, script_name)
        with open(save_path, "w", encoding="utf-8")as F:
            F.write(search_result)

        print("使用方法如下：")
        if not isAndroid:
            print(f"frida-trace -U -f bundleid -O {save_path}")
        else:
            print(f"frida-trace -UF -O {save_path}")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return traceNatives()
