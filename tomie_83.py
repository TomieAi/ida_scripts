import idc
import idaapi
import pyperclip
from os import name
from platform import version
from datetime import datetime



PLUGNAME = "TOMIE PLUGIN"
VERSION = "1.0"


class About_Form(idaapi.Form):
    def __init__(self, version):
        # create About form
        super(About_Form, self).__init__(
            r"""STARTITEM 0
TomieNW
        Some quality of life plugins and x64dbg goto address helper
        """, {})

        self.Compile()
 
class CE_GOTO(idaapi.Form):
    def __init__(self, version):
        # create About form
        super(CE_GOTO, self).__init__(
            r"""STARTITEM {id:c_address}
BUTTON YES* Search
Enter expression to follow...
        {FormChangeCb}
        <Address   :{c_address}>
        {c_label}
        """, {
                'c_address': self.StringInput(value=hex(idaapi.get_screen_ea())),
                'FormChangeCb': self.FormChangeCb(self.OnFormChange),
                'c_label': self.StringLabel(value="$:0x<offset>, 0x<address> + 0x<offset>, 0x<address>"),
            })
        self.Compile()

    def OnFormChange(self, fid):
        if fid == -2:
            c_input = self.GetControlValue(self.c_address)
            try:
                if(":" + "$" in c_input):
                    test = c_input.split("$")
                    OFFSET = 0
                    if("0x" in test[1]):
                        OFFSET = int(test[1], 0)
                    else:
                        OFFSET = int("0x"+test[1], 0)
                    final = idaapi.get_imagebase()+OFFSET
                    idaapi.jumpto(final)
                else:
                    if(idc.get_root_filename() + "$" in c_input):
                        test = c_input.split("$")
                        base = idaapi.get_imagebase()
                        OFFSET = 0
                        if("0x" in test[1]):
                            OFFSET = int(test[1], 0)
                        else:
                            OFFSET = int("0x"+test[1], 0)
                        final = base+OFFSET
                        idaapi.jumpto(final)
                    else:
                        if("0x" in c_input):
                            idaapi.jumpto(int(c_input, 0))
                        else:
                            idaapi.jumpto(int("0x"+c_input, 0))
            except:
                try:
                    last_try = eval(c_input)
                    idaapi.jumpto(last_try)
                except:
                    print("$:0x<offset>, 0x<address> + 0x<offset>, 0x<address> is the proper format.")
        else:
            return 1

class tomie:

    list = []
    name = PLUGNAME
    base = idaapi.get_imagebase()
    base_hex = hex(base)

    def about(self):
        f = About_Form(VERSION)
        f.Execute()
        f.Free()

    def copy_to_clip(self, data):
        pyperclip.copy(data)

    def do_OFFSET(self):
        OFFSET = hex(idaapi.get_screen_ea() - self.base)
        print("This value is now in your clipboard:", OFFSET)
        self.copy_to_clip(OFFSET)

    def do_OFFSET2(self):
        OFFSET = hex(idaapi.get_screen_ea() - self.base)
        value = idc.get_root_filename() + "+" + OFFSET
        print("This value is now in your clipboard:", value)
        self.copy_to_clip(value)

    def image_base(self):
        print("This value is now in your clipboard:", self.base_hex)
        self.copy_to_clip(self.base_hex)

    def ce_goto(self):
        f = CE_GOTO(VERSION)
        f.Execute()
        f.Free()
    def pause_analyze(self):
        idc.set_flag(idc.INF_GENFLAGS,idc.INFFL_AUTO, 0)
    def resume_analyze(self):
        idc.set_flag(idc.INF_GENFLAGS,idc.INFFL_AUTO, 1)
    def __init__(self):
        if len(self.list) == 0:
            # Delete Default Go To Address Hotkey
            idaapi.del_idc_hotkey("G")

            self.list.append({"fname": self.name + ":OFFSET",
                             "callback": self.do_OFFSET, "plugin": self.name, "desc": "Copy OFFSET", "hotkey": None})
            self.list.append({"fname": self.name + ":OFFSET2",
                             "callback": self.do_OFFSET2, "plugin": self.name, "desc": "Copy MODULE BASE + OFFSET", "hotkey": None})
            self.list.append({"fname": self.name + ":BASE",
                             "callback": self.image_base, "plugin": self.name, "desc": "Copy MODULE BASE", "hotkey": None})
            self.list.append({"fname": self.name + ":spacer",
                             "callback": None, "plugin": self.name, "desc": None, "hotkey": None})
            # 
            self.list.append({"fname": self.name + ":CEGOTO",
                             "callback": self.ce_goto, "plugin": self.name, "desc": "Go to Address", "hotkey": 'G'})
            # 
            self.list.append({"fname": self.name + ":PAUSE_ANALYZE",
                             "callback": self.pause_analyze, "plugin": self.name, "desc": "Pause Analysis", "hotkey": None})
            # 
            self.list.append({"fname": self.name + ":RESUME_ANALYZE",
                             "callback": self.resume_analyze, "plugin": self.name, "desc": "Resume Analysis", "hotkey": None})
            # 
            self.list.append({"fname": self.name + ":spacer2",
                             "callback": None, "plugin": self.name, "desc": None, "hotkey": None})
            # 
            self.list.append({"fname": self.name + ":ABOUT",
                             "callback": self.about, "plugin": self.name, "desc": "ABOUT", "hotkey": None})
        pass

    def all_functions(self):
        return self.list


class UIManager:
    def __init__(self, name):
        self.name = name
        self.hooks = UIManager.UIHooks()

    class UIHooks(idaapi.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup, ctx=None):
            if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
                for x in tomie().all_functions():
                    idaapi.attach_action_to_popup(
                        widget, popup, x["fname"], x["plugin"] + "/")

    class ActionHandler(idaapi.action_handler_t):
        def __init__(self, name, label, shortcut=None, tooltip=None, icon=-1, flags=0):
            idaapi.action_handler_t.__init__(self)
            self.name = name
            self.action_desc = idaapi.action_desc_t(
                name, label, self, shortcut, tooltip, icon, flags)

        def register_action(self, callback, toolbar_name=None, menupath=None):
            self.callback = callback
            if not idaapi.register_action(self.action_desc):
                return False
            if toolbar_name and not idaapi.attach_action_to_toolbar(toolbar_name, self.name):
                return False
            if menupath and not idaapi.attach_action_to_menu(menupath, self.name, idaapi.SETMENU_APP):
                return False
            return True

        def activate(self, ctx):
            self.callback(ctx)

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def register_actions(self):
        for x in tomie().all_functions():
            UIManager.ActionHandler(x["fname"], x["desc"], x["hotkey"], None, 4).register_action(
                self.selected_callback)
        self.hooks.hook()

    def selected_callback(self, ctx):
        funcs = map(idaapi.getn_func, ctx.chooser_selection)
        funcs = map(lambda func: func.start_ea, funcs)
        [i for i in tomie().all_functions() if i['fname']
         == ctx.action][0]["callback"]()


class TomieIDA(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Not much comment here. Its just some small commands I hope ida comes with it."
    help = "Right-Click in IDA-View and select my plugin."
    wanted_name = "TomieNW IDA Plugin"
    wanted_hotkey = "Ctrl-L-;"

    def init(self):
        print("=" * 80)
        print("TomieNW IDA Plugin is loaded.")
        print("=" * 80)
        self.hooks = UIManager.UIHooks()
        self.hooks.hook()
        UIManager(PLUGNAME).register_actions()
        return idaapi.PLUGIN_KEEP

    def show(self, something):
        print(something)

    def run(self, arg):
        pass

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None


def PLUGIN_ENTRY():
    return TomieIDA()
