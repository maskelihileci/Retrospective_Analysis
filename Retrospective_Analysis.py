import ida_hexrays
import ida_kernwin
import ida_funcs
import idautils
import idaapi
import idc
import ida_typeinf
import ida_bytes
import os
import ida_diskio
import json
import ida_xref
import re


# Debug Logger sınıfı
class DebugLogger:
  _instance = None
  
  def __init__(self):
      self.enabled = False
      
  @classmethod
  def get_instance(cls):
      if cls._instance is None:
          cls._instance = cls()
      return cls._instance
      
  def set_enabled(self, enabled):
      self.enabled = enabled
      
  def debug(self, message):
      if self.enabled:
          print(f"[DEBUG] {message}")

# Progress dialog context manager
# Progress dialog güncelleme
class ProgressDialog:
  def __init__(self, message="Please wait..."):
      self.message = message
      
  def __enter__(self):
      ida_kernwin.show_wait_box(self.message)
      return self
      
  def __exit__(self, exc_type, exc_val, exc_tb):
      ida_kernwin.hide_wait_box()
  
  def replace_message(self, new_message):
      ida_kernwin.replace_wait_box(new_message)
  
  def check_cancelled(self):
      return ida_kernwin.user_cancelled()

class ConfigDialog(ida_kernwin.Form):
  def __init__(self):
      try:
          self.config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
          self.config = self.load_config()
          
          Form = ida_kernwin.Form
          
          Form.__init__(
              self,
              r"""Retrospective Analysis

              Analysis Settings:
              <##Analysis depth (1-10):{max_layers}>
              
              Analysis Options:
              <##Search Engine:{cGroup0}>
              <##Enable parameter analysis:{param_analysis}>{cGroup1}>
              <##Enable function type analysis:{func_type_analysis}>{cGroup2}>
              <##Enable unused parameter analysis in call references:{unused_param_analysis}>{cGroup3}>
              <##Enable virtual call analysis:{virtual_call_analysis}>{cGroup6}>
              
              Debug Options:
              <##Show debug messages:{show_debug}>{cGroup4}>
              
              View Options:
              <##Auto refresh decompiler views:{auto_refresh_views}>{cGroup5}>
                """, {
                    'max_layers': Form.NumericInput(tp=Form.FT_DEC, value=self.config["max_layers"], swidth=5),
                    'cGroup0': Form.DropdownListControl(items=["IDA-API","Hex-Rays"],),
                    'cGroup1': Form.ChkGroupControl(("param_analysis",), value=1 if self.config["param_analysis"] else 0),
                    'cGroup2': Form.ChkGroupControl(("func_type_analysis",), value=1 if self.config["func_type_analysis"] else 0),
                    'cGroup3': Form.ChkGroupControl(("unused_param_analysis",), value=1 if self.config["unused_param_analysis"] else 0),
                    'cGroup6': Form.ChkGroupControl(("virtual_call_analysis",), value=1 if self.config["virtual_call_analysis"] else 0),
                    'cGroup4': Form.ChkGroupControl(("show_debug",), value=1 if self.config["show_debug"] else 0),
                    'cGroup5': Form.ChkGroupControl(("auto_refresh_views",), value=1 if self.config["auto_refresh_views"] else 0)
                })          
          Form.Compile(self)
          # Dropdown'ın başlangıç değerini ayarla
          self.cGroup0.items = ["IDA-API", "Hex-Rays"]
          # Dropdown'ın başlangıç değerini ayarla
          if self.config["search_engine"] == "IDA-API":
                self.cGroup0.value = 0
          elif self.config["search_engine"] == "Hex-Rays":
                self.cGroup0.value = 1
          
      except Exception as e:
          print(f"Error initializing ConfigDialog: {str(e)}")
          raise

  def OnFormChange(self, fid):
        if fid == -1:  # form initialized
            return 1
        
        if fid == self.max_layers.id:
            # Değeri 1-10 arasında tut
            if self.max_layers.value < 1:
                self.max_layers.value = 1
            elif self.max_layers.value > 10:
                self.max_layers.value = 10
        
        return 1

  def load_config(self):
      default_config = {
          "max_layers": 4,
          "auto_refresh_views": True,
          "show_debug": False,
          "param_analysis": True,
          "func_type_analysis": True,
          "unused_param_analysis": True,
          "virtual_call_analysis": True,
          "search_engine" : "IDA-API"
      }
      
      try:
          if os.path.exists(self.config_path):
              with open(self.config_path, 'r') as f:
                  config = json.load(f)
                  # Validate max_layers
                  if "max_layers" in config:
                      config["max_layers"] = max(1, min(10, int(config["max_layers"])))

                  if "search_engine" not in config:
                      config["search_engine"] = "IDA-API"
                  return config
      except Exception as e:
          print(f"Error loading config: {e}")
      
      return default_config
  #
  def save_config(self):
      logger = DebugLogger.get_instance()
      try:
          config = {
              "max_layers": self.max_layers.value,
              "auto_refresh_views": bool(self.cGroup5.value),
              "show_debug": bool(self.cGroup4.value),
              "param_analysis": bool(self.cGroup1.value),
              "func_type_analysis": bool(self.cGroup2.value),
              "unused_param_analysis": bool(self.cGroup3.value),
              "virtual_call_analysis": bool(self.cGroup6.value),
              "search_engine": self.cGroup0.items[self.cGroup0.value]
          }
          
          with open(self.config_path, 'w') as f:
              json.dump(config, f, indent=4)
              logger.debug(f"\nConfiguration saved successfully to: {self.config_path}")
              
      except Exception as e:
          logger.debug(f"Error saving config: {str(e)}")

  def OnFormChange(self, fid):
        return 1

# Add ConfigActionHandler class
class ConfigActionHandler(idaapi.action_handler_t):
  def activate(self, ctx):
      try:
          dialog = ConfigDialog()
          result = dialog.Execute()
          if result == 1:
              dialog.save_config()
          dialog.Free()
          return 1
      except Exception as e:
          print(f"Error in config dialog: {e}")
          return 0

  def update(self, ctx):
      return idaapi.AST_ENABLE_ALWAYS
    
def show_config_dialog():
  try:
      dialog = None
      dialog = ConfigDialog()
      if dialog.Execute() == 1:
          dialog.save_config()
  except Exception as e:
      print(f"Error showing config dialog: {str(e)}")
  finally:
      if dialog:
          try:
              dialog.Free()
          except:
              pass


def first_config(self):
    try:
        self.config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
        
        # Define default config
        self.default_config = {
            "max_layers": 4,
            "auto_refresh_views": True,
            "show_debug": False,
            "param_analysis": True,
            "func_type_analysis": True,
            "unused_param_analysis": True,
            "virtual_call_analysis": True,
            "search_engine" : "IDA-API"
        }
        
        # Check if config file exists
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    current_config = json.load(f)
                
                # Check for missing values and add them
                updated = False
                for key, value in self.default_config.items():
                    if key not in current_config:
                        current_config[key] = value
                        updated = True
                        print(f"Missing config value added: {key} = {value}")
                
                # If changes were made, update the file
                if updated:
                    with open(self.config_path, 'w') as f:
                        json.dump(current_config, f, indent=4)
                    print("Config file updated")
                        
            except Exception as e:
                print(f"Error reading/writing config file: {str(e)}")
        else:
            # Create config file if it doesn't exist
            try:
                with open(self.config_path, 'w') as f:
                    json.dump(self.default_config, f, indent=4)
                print(f"Default config file created: {self.config_path}")
            except Exception as e:
                print(f"Error creating default config file: {str(e)}")

    except Exception as e:
        print(f"Error in first_config: {str(e)}")



class CallingConventionFixer:
    def __init__(self):
        self.processed_funcs = set()

    @staticmethod
    def is_64bit():
        seg = idaapi.getseg(idaapi.inf_get_start_ea())
        is_64bit = seg and seg.bitness == 2
        return is_64bit

    def print_function_info(self, func_ea):
        """Print all available information about a function"""
        logger = DebugLogger.get_instance()
        logger.debug(f"\n=== Function Info for {hex(func_ea)} ===")

        # Basic function info
        logger.debug(f"Name: {idc.get_func_name(func_ea)}")

        # Get tinfo
        tinfo = ida_typeinf.tinfo_t()
        if ida_typeinf.guess_tinfo(tinfo, func_ea):
            logger.debug(f"Type info: {tinfo}")

            # Get function details
            func_details = ida_typeinf.func_type_data_t()
            if tinfo.get_func_details(func_details):
                logger.debug(f"Calling convention: {func_details.cc}")
                logger.debug("Arguments:")
                for i, arg in enumerate(func_details):
                    logger.debug(f"  Arg {i}: {arg.type} {arg.name}")
                    if hasattr(arg, 'argloc'):
                        logger.debug(f"    Location: {arg.argloc}")

        # Try decompilation
        try:
            ida_hexrays.mark_cfunc_dirty(func_ea,False)
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                logger.debug("\nDecompiled function type:")
                logger.debug(cfunc.type.dstr())
        except:
            logger.debug("Failed to decompile function")

        logger.debug("===========================\n")


    #
    def _getmt_cc_name(self,new_func_type_str):
        # Calling Convention isimlerini döndür
        logger = DebugLogger.get_instance()
        original_cc = ida_typeinf.CM_CC_UNKNOWN
        if "__thiscall" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_THISCALL
            logger.debug("[_getmt_cc_name] Calling convention: __thiscall")
        if "__fastcall" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_FASTCALL
            logger.debug("[_getmt_cc_name] Calling convention: __fastcall")
        if "__cdecl" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_CDECL
            logger.debug("[_getmt_cc_name] Calling convention: __cdecl")
        if "__stdcall" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_STDCALL
            logger.debug("[_getmt_cc_name] Calling convention: __stdcall")
        if "__usercall" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_SPECIAL
        if "__userpurge" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_SPECIAL
        if "__pascal" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_PASCAL
        if "__swiftcall" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_SWIFT
        if "__golang" in new_func_type_str:
            original_cc = ida_typeinf.CM_CC_GOLANG
        return original_cc
    
    def _getmt_rettype_name(self,new_func_type_str):
        logger = DebugLogger.get_instance()
        rettype = ida_typeinf.tinfo_t()
        return_type_str = new_func_type_str.split('(')[0].strip()
        return_type_str = re.sub(r'\bconst\b', '', return_type_str).strip() #Remove const keyword
        if return_type_str == "void":
            rettype.create_simple_type(ida_typeinf.BTF_VOID)
            logger.debug("[_getmt_rettype_name] Return type: void")
        elif return_type_str == "int" or return_type_str == "signed int":
            rettype.create_simple_type(ida_typeinf.BTF_INT)
            logger.debug("[_getmt_rettype_name] Return type: int")
        elif return_type_str == "char*":
            rettype.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BTF_CHAR))
            logger.debug("[_getmt_rettype_name] Return type: char*")
        elif return_type_str == "unsigned int" or return_type_str == "uint":
            rettype.create_simple_type(ida_typeinf.BTF_UINT)
            logger.debug("[_getmt_rettype_name] Return type: unsigned int")
        elif return_type_str == "long long" or return_type_str == "signed long long":
                rettype.create_simple_type(ida_typeinf.BTF_INT64)
                logger.debug("[_getmt_rettype_name] Return type: long long")
        elif return_type_str == "unsigned long long":
                rettype.create_simple_type(ida_typeinf.BTF_UINT64)
                logger.debug("[_getmt_rettype_name] Return type: unsigned long long")
        elif return_type_str == "float":
                rettype.create_simple_type(ida_typeinf.BTF_FLOAT)
                logger.debug("[_getmt_rettype_name] Return type: float")
        elif return_type_str == "double":
                rettype.create_simple_type(ida_typeinf.BTF_DOUBLE)
                logger.debug("[_getmt_rettype_name] Return type: double")
        elif return_type_str == "boolean":
                rettype.create_simple_type(ida_typeinf.BTF_BOOL)
                logger.debug("[_getmt_rettype_name] Return type: boolean")
        elif return_type_str.endswith('*'):
            rettype.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID))
            logger.debug(f"[_getmt_rettype_name] Return type: pointer (default void *)")
        else:
            rettype.create_simple_type(ida_typeinf.BTF_INT)  # Default return type
            logger.debug(f"[_getmt_rettype_name] Return type: Unknown, default int")
        return rettype
    
    def _analyze_virtual_calls_and_update_signature(self,func_ea):
        """Analyze virtual calls, find undefined variables, and update their types."""
        logger = DebugLogger.get_instance()
        logger.debug(f"[_analyze_virtual_calls_and_update_signature] Analyzing function at {hex(func_ea)}")
        config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except:
            return False

        if not config.get("virtual_call_analysis", True):
            return False

        try:
            ida_hexrays.mark_cfunc_dirty(func_ea, False)
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                logger.debug(f"[_analyze_virtual_calls_and_update_signature] Could not decompile function at {hex(func_ea)}")
                return False
            logger.debug(f"[_analyze_virtual_calls_and_update_signature] Function at {hex(func_ea)} decompiled successfully.")

            class UndefinedVarCollector(ida_hexrays.ctree_visitor_t):
                def __init__(self, cfunc):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.cfunc = cfunc
                    self.undefined_vars = set()
                    self.undefined_vars_propagated = set()
                    self.var_assignments = {}
                    self.virtual_calls = {}
                    self.undefined_vars_in_helpers = {}
                    self.helper_var_types = {} 
                    self.size_functions = {
                        "LOBYTE": ida_typeinf.BTF_UINT8,
                        "HIBYTE": ida_typeinf.BTF_UINT8,
                        "LOWORD": ida_typeinf.BTF_UINT16,
                        "HIWORD": ida_typeinf.BTF_UINT16,
                        "LODWORD": ida_typeinf.BTF_UINT32,
                        "HIDWORD": ida_typeinf.BTF_UINT32,
                        "BYTE": ida_typeinf.BTF_UINT8,
                        "WORD": ida_typeinf.BTF_UINT16,
                        "DWORD": ida_typeinf.BTF_UINT32,
                        "QWORD": ida_typeinf.BTF_UINT64
                    }
                    logger.debug(f"[UndefinedVarCollector] Initialized collector for function at {hex(cfunc.entry_ea)}")

                def _is_undefined(self, expr):
                    """Check if an expression is an undefined variable."""

                    if expr.op != ida_hexrays.cot_var:
                        return False

                    lvar = self.cfunc.get_lvars()[expr.v.idx]
                    if not lvar:
                        return False

                    if hasattr(lvar, 'has_user_info') and lvar.has_user_info and hasattr(lvar, 'user_info') and lvar.user_info is None:
                            return True

                    if expr.exflags & ida_hexrays.EXFL_UNDEF:
                            return True

                    if expr.v.idx in self.undefined_vars_propagated:
                            return True
                    return False


                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_helper:
                        helper_name = expr.x.helper
                        if helper_name in self.size_functions and expr.a and expr.a[0].op == ida_hexrays.cot_var:
                            var_idx = expr.a[0].v.idx
                            self.helper_var_types[var_idx] = self.size_functions[helper_name]

                    if expr.op == ida_hexrays.cot_var and hasattr(expr,'v') and hasattr(expr.v,'idx'):
                        lvar_index = expr.v.idx
                        if self._is_undefined(expr):
                            self.undefined_vars.add(lvar_index)
                            logger.debug(f"[UndefinedVarCollector] Added undefined variable index: {lvar_index}")
                    if expr.op == ida_hexrays.cot_asg and hasattr(expr, 'x') and hasattr(expr.x, 'v') and hasattr(expr.x.v,'idx'):
                        lvar_index = expr.x.v.idx
                        if self._is_undefined(expr.y):
                            if lvar_index not in self.undefined_vars_propagated:
                                self.undefined_vars_propagated.add(lvar_index)
                                self.undefined_vars.add(lvar_index)
                                logger.debug(f"[UndefinedVarCollector] Propagated Undefined var via assignment: {lvar_index}")
                        elif hasattr(expr.y, 'op') and expr.y.op == ida_hexrays.cot_var and hasattr(expr.y,'v') and hasattr(expr.y.v,'idx') and expr.y.v.idx in self.undefined_vars_propagated:
                            if lvar_index not in self.undefined_vars_propagated:
                                self.undefined_vars_propagated.add(lvar_index)
                                self.undefined_vars.add(lvar_index)
                                logger.debug(f"[UndefinedVarCollector] Propagated Undefined var via assignment from propagated: {lvar_index}")
                    return 0


                def traverse_tree_and_collect_vars(self, expr):
                    """
                    Traverse the given tree and collect variable names and
                    corresponding cexpr_t objects.

                    Args:
                        expr: The root node of the tree as a cexpr_t object.
                        cfunc: The function cfunc_t object.

                    Returns:
                        A list of tuples containing the variable names and
                        cexpr_t objects found in the tree. Each element is a
                        tuple of (var_name, cexpr_t).
                    """
                    var_info = []  # List to store (var_name, cexpr_t) tuples
                    added_vars = set() # Set to store added variable names

                    def _traverse(expr):
                        if expr is None:
                            return

                        if expr.op == ida_hexrays.cot_call:
                            # Traverse function call arguments
                            if expr.a:
                                for arg in expr.a:
                                    _traverse(arg)
                            # Skip function name (x)
                            return

                        if expr.op == ida_hexrays.cot_var:
                            lvar = self.cfunc.get_lvars()[expr.v.idx]
                            if lvar and lvar.name not in added_vars:
                                var_info.append((lvar.name, expr))
                                added_vars.add(lvar.name)

                        # Traverse the tree
                        if expr.a:
                            for arg in expr.a:
                                _traverse(arg)

                        if expr.x:
                            _traverse(expr.x)
                        if expr.y:
                            _traverse(expr.y)
                        if expr.z:
                            _traverse(expr.z)

                    _traverse(expr)
                    return var_info
                

            collector = UndefinedVarCollector(cfunc)
            collector.apply_to(cfunc.body, None)
            logger.debug(f"Undefined vars: {collector.undefined_vars}, Helper types: {collector.helper_var_types}")

            class UndefinedCallVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, cfunc, collector):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.cfunc = cfunc
                    self.collector = collector
                    self.virtual_calls = {}

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call:
                        indices = []
                        if expr.a:
                            for i, arg in enumerate(expr.a):
                                var_info = self.collector.traverse_tree_and_collect_vars(arg)
                                for var_name, var_expr in var_info:
                                    var_idx = var_expr.v.idx
                                    if var_idx in self.collector.undefined_vars or var_idx in self.collector.helper_var_types:
                                        if i not in indices:
                                            indices.append(i)
                        if indices:
                            self.virtual_calls[expr.ea] = indices
                    return 0

            callVisitor = UndefinedCallVisitor(cfunc, collector)
            callVisitor.apply_to(cfunc.body, None)
            logger.debug(f"Detected virtual calls: {callVisitor.virtual_calls}")

            # Update virtual call types
            for call_ea, undefined_args in callVisitor.virtual_calls.items():
                # Get cexpr from the address
                class ExprFinder(ida_hexrays.ctree_visitor_t):
                    def __init__(self, target_ea):
                        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                        self.target_ea = target_ea
                        self.found_expr = None
                        logger.debug(f"[ExprFinder] Initialized to find expression at {hex(target_ea)}")

                    def visit_expr(self, expr):
                        logger.debug(f"[ExprFinder.visit_expr] Visiting expression: {expr} at {hex(expr.ea)}")
                        logger.debug(f"[ExprFinder.visit_expr] Call expression: {expr} at {hex(call_ea)}")
                        if expr.ea == self.target_ea:
                            if expr.a is None:
                                return 0
                            self.found_expr = expr
                            logger.debug(f"[ExprFinder.visit_expr] Found target expression: {expr}")
                            return 1
                        return 0
                expr_finder = ExprFinder(call_ea)
                expr_finder.apply_to(cfunc.body, None)
                if expr_finder.found_expr:
                    func_ptr_ea = expr_finder.found_expr.x.ea if hasattr(expr_finder.found_expr, 'x') else idaapi.BADADDR
                    if func_ptr_ea == idaapi.BADADDR:
                        func_ptr_ea = expr_finder.found_expr.ea if hasattr(expr_finder.found_expr, 'ea') else idaapi.BADADDR
                    logger.debug(f"[_analyze_virtual_calls_and_update_signature] Found call expression at {hex(call_ea)} with function pointer at {hex(func_ptr_ea)}")
                    if func_ptr_ea and func_ptr_ea != idaapi.BADADDR:
                        self._update_virtual_call_type(expr_finder.found_expr, func_ptr_ea, cfunc, undefined_args, expr_finder,collector)
                    else:
                        logger.debug(f"[_analyze_virtual_calls_and_update_signature] Skip call type update {hex(call_ea)} because function address could not be found.")

            return True
        except Exception as e:
            logger.debug(f"[_analyze_virtual_calls_and_update_signature] Error analyzing virtual calls for {hex(func_ea)}: {str(e)}")
            return False
        
    def _update_virtual_call_type(self,call_expr, func_ptr_ea, cfunc, undefined_args, expr_finder,collector):
        logger = DebugLogger.get_instance()
        logger.debug(f"[_update_virtual_call_type] Updating virtual call type at {hex(call_expr.ea)}, func_ptr_ea: {hex(func_ptr_ea)}, undefined_args: {undefined_args}")
        try:
            if not call_expr or not func_ptr_ea or func_ptr_ea == idaapi.BADADDR:
                logger.debug("[_update_virtual_call_type] Invalid call expression or function pointer")
                return False

            current_ea = call_expr.ea if hasattr(call_expr, 'ea') else idaapi.BADADDR
            if current_ea == idaapi.BADADDR:
                logger.debug("[_update_virtual_call_type] Invalid EA value")
                return False

            # Log original information
            logger.debug("\n=== Original Call Information ===")
            logger.debug(f"Call Address: {hex(current_ea)}")
            logger.debug(f"Function Pointer: {hex(func_ptr_ea)}")
            if hasattr(call_expr, 'x') and hasattr(call_expr.x, 'type'):
                logger.debug(f"Return Type: {call_expr.x.type.get_rettype()}")
                logger.debug(f"Original Function Type: {call_expr.x.type}")
                original_func_type = call_expr.x.type
                logger.debug(f"Original_func_type : {original_func_type}")
                logger.debug(f"Original_func_type type : {type(original_func_type)}")
            else:
                logger.debug(f"Return Type: N/A")
                logger.debug("[_update_virtual_call_type] Original Function Type not found")
                original_func_type = None

            if expr_finder and expr_finder.found_expr:
                try:
                    # Get the virtual call expression
                    vcall_expr = expr_finder.found_expr
                    logger.debug(f"[_update_virtual_call_type] Found virtual call expression: {vcall_expr}")

                    # Create new type info for the virtual function call
                    new_func_type_str = ""

                    if original_func_type:
                        new_func_type_str = str(original_func_type)
                        logger.debug(f"[_update_virtual_call_type] Original function type string: {new_func_type_str}")

                    new_tinfo = ida_typeinf.tinfo_t()
                    ftd = ida_typeinf.func_type_data_t()
                    if hasattr(call_expr.x, 'type') and hasattr(call_expr.x.type,'get_rettype'):
                        ftd.rettype = call_expr.x.type.get_rettype()
                    else:
                        ftd.rettype = self._getmt_rettype_name(new_func_type_str)
                    ftd.cc = self._getmt_cc_name(new_func_type_str)  # Set the calling convention

                    # Corrected argument type handling
                    for i in range(len(call_expr.a) if call_expr.a else 0):
                        if i in undefined_args:  # Only process arguments that need to be corrected
                            arg = call_expr.a[i]
                            has_helper = False
                            
                            # Helper type check
                            if arg.op == ida_hexrays.cot_var:
                                var_idx = arg.v.idx
                                if var_idx in collector.helper_var_types:
                                    new_arg = ida_typeinf.funcarg_t()
                                    new_arg.type.create_simple_type(collector.helper_var_types[var_idx])
                                    ftd.push_back(new_arg)
                                    has_helper = True
                                    logger.debug(f"Argument {i} corrected with helper type")
                            
                            # Nested helper check
                            if not has_helper:
                                var_info = collector.traverse_tree_and_collect_vars(arg)
                                for var_name, var_expr in var_info:
                                    var_idx = var_expr.v.idx
                                    if var_idx in collector.helper_var_types:
                                        new_arg = ida_typeinf.funcarg_t()
                                        new_arg.type.create_simple_type(collector.helper_var_types[var_idx])
                                        ftd.push_back(new_arg)
                                        has_helper = True
                                        logger.debug(f"Argument {i} corrected with nested helper type")
                                        break
                            
                            if not has_helper:
                                logger.debug(f"Argument {i} is undefined and has no helper, SKIPPED")
                        else:
                            # Preserve original argument
                            original_arg = ida_typeinf.funcarg_t()
                            original_arg.type = call_expr.a[i].type
                            ftd.push_back(original_arg)
                            logger.debug(f"Argument {i} preserved as original")

                    if not new_tinfo.create_func(ftd):
                        logger.debug(f"[_update_virtual_call_type] Failed to create func type with func_type_data_t")
                        ida_typeinf.clear_tinfo_t(new_tinfo)
                        return False

                    new_ptr_tinfo = ida_typeinf.tinfo_t()
                    new_ptr_tinfo.create_ptr(new_tinfo)

                    logger.debug(f"\n=== New Type Information ===")
                    logger.debug(f"Function type: {new_tinfo}")
                    logger.debug(f"Pointer type: {new_ptr_tinfo}")

                    # Update the call expression type
                    if hasattr(vcall_expr, 'x') and vcall_expr.x:

                        # Update the function pointer type in expression
                        if idaapi.set_op_tinfo(vcall_expr.x.ea, 0, new_ptr_tinfo):
                            idaapi.set_op_tinfo(vcall_expr.ea, 0, new_tinfo)
                            pass
                        elif not idaapi.set_op_tinfo(vcall_expr.ea, 0, new_tinfo):
                            logger.debug(f"[_update_virtual_call_type] Failed to set new tinfo for call expression")
                            ida_typeinf.clear_tinfo_t(new_tinfo)
                            return False
                        logger.debug(f"[_update_virtual_call_type] Updated function pointer type: {new_ptr_tinfo}")

                    ida_hexrays.mark_cfunc_dirty(cfunc.entry_ea, False)
                    cfunc = ida_hexrays.decompile(cfunc.entry_ea)
                    if cfunc:
                        logger.debug("\n=== Call Update Status ===")
                        logger.debug(f"Successfully updated virtual call at {hex(current_ea)}")
                        logger.debug(f"New function type: {new_tinfo}")
                        ida_typeinf.clear_tinfo_t(new_tinfo)
                        return True
                    else:
                        logger.debug(" [_update_virtual_call_type] Failed to get function object after update.")
                        ida_typeinf.clear_tinfo_t(new_tinfo)
                        return False

                except Exception as e:
                    logger.debug(f"[_update_virtual_call_type] === Expression Update Error ===")
                    logger.debug(f"[_update_virtual_call_type] Error: {str(e)}")
                    logger.debug(f"[_update_virtual_call_type] Error type: {type(e)}")
                    raise
            else:
                logger.debug(" [_update_virtual_call_type] Could not find target expression")
                return False

        except Exception as e:
            logger.debug(f"[_update_virtual_call_type] === Error Information ===")
            logger.debug(f"[_update_virtual_call_type] Error in _update_virtual_call_type: {str(e)}")
            logger.debug(f"[_update_virtual_call_type] Error type: {type(e)}")
            return False
        
    def _is_virtual_call(self, expr):
            """Check if an expression is a virtual call."""
            if expr.op != ida_hexrays.cot_call:
                return False

            if hasattr(expr, 'x') and self._is_potential_vtable_access(expr.x):
                return True
            return False

    def _is_potential_vtable_access(self, expr):
            """Check various vtable access patterns"""
            logger = DebugLogger.get_instance()
            if not expr:
                return False

            try:
                # Pattern 1: Direct pointer dereference
                if expr.op == ida_hexrays.cot_ptr:
                    return True

                # Pattern 2: Member pointer access
                if expr.op == ida_hexrays.cot_memptr:
                    return True

                # Pattern 3: Addition operation (possible vtable offset)
                if expr.op == ida_hexrays.cot_add:
                    if hasattr(expr, 'x') and expr.x:
                        if expr.x.op == ida_hexrays.cot_ptr:
                            return True
                            #if self._check_expr_for_param(expr.x, "vtable base", True):
                            #   return True

                # Pattern 4: Cast operations
                if expr.op == ida_hexrays.cot_cast:
                    return self._is_potential_vtable_access(expr.x if hasattr(expr, 'x') else None)
                
            except Exception as ex:
                 logger.debug(f"Error in _is_potential_vtable_access: {str(ex)}")

            return False

    def _analyze_calls_and_update_signature(self, func_ea):
        """Analyze all calls to a function and determine if parameters are undefined"""
        logger = DebugLogger.get_instance()
        
        # Load config
        config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except:
            return False

        if not config.get("unused_param_analysis", True):
            return False

        try:
            # Get all references to this function
            xrefs = []
            for xref in idautils.XrefsTo(func_ea, 0):
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    xrefs.append(xref.frm)

            if not xrefs:
                logger.debug(f"No calls found for function at {hex(func_ea)}")
                return False

            # Get function type information
            tinfo = ida_typeinf.tinfo_t()
            func_details = ida_typeinf.func_type_data_t()

            # Track parameter usage across all calls
            param_count = func_details.size()
            param_usage = {i: {'undefined_count': 0, 'total_calls': 0} for i in range(param_count)}
            
            if config.get("show_debug", False):
                logger.debug(f"\nAnalyzing calls for function at {hex(func_ea)}")
                logger.debug(f"Number of parameters: {param_count}")
                logger.debug(f"Number of calls: {len(xrefs)}")

            #
            def types_compatible(actual_type, expected_type):
                """Check if two types are compatible"""
                try:
                    # Basic type compatibility checks
                    if actual_type.is_ptr() and not expected_type.is_ptr():
                        return False
                    if actual_type.is_int() and expected_type.is_float():
                        return False
                    if actual_type.is_float() and expected_type.is_int():
                        return False
                        # Null kontrolleri eksik
                    if actual_type is None or expected_type is None:
                        return False                       
                    # Tüm tip kombinasyonları kontrol edilmemiş
                    if actual_type.is_array() and not expected_type.is_array():
                        return False
                    return True
                except:
                    return True
            def check_function_parameter_mismatch(expr, cfunc):
                """Check for potential parameter count mismatches in function calls"""
                try:
                    if expr.op == ida_hexrays.cot_call:
                        # Get function type information
                        func_type = expr.x.type
                        if func_type.is_func():
                            expected_args = func_type.get_nargs()
                            actual_args = expr.a.size()
                            
                            # Check for significant parameter count mismatch
                            if actual_args < expected_args:
                                return True
                            
                            # Check argument types if available
                            for i in range(min(actual_args, expected_args)):
                                arg = expr.a[i]
                                expected_type = func_type.get_nth_arg(i)
                                
                                # Check for potential type mismatches
                                if not types_compatible(arg.type, expected_type):
                                    return True
                except:
                    return False
                return False
            def check_undefined_patterns(expr, cfunc):
                """Check various patterns that indicate undefined values using Hex-Rays API."""
                try:
                    # Check if the expression is a variable
                    if expr.op == ida_hexrays.cot_var:
                        lvar = cfunc.get_lvars()[expr.v.idx]
                        if not lvar:
                            return False

                    # Check if the expression is a function call
                    elif expr.op == ida_hexrays.cot_call:
                        if check_function_parameter_mismatch(expr, cfunc):
                            return True

                    # Check if the expression is undefined using exflags
                    if expr.exflags & ida_hexrays.EXFL_UNDEF:
                        return True

                    # Check for suspicious constant values
                    elif expr.op == ida_hexrays.cot_num:
                        suspicious_values = {
                            0xBADF00D, 0xDEADBEEF, 0xCCCCCCCC,
                            0xFEEEFEEE, 0xCDCDCDCD, 0xABABABAB,
                            0xFFFFFFFE, 0xFFFFFFFF, 0x0,
                            0xDEADC0DE, 0xDEADBEEF
                        }
                        if expr.numval() in suspicious_values:
                            return True

                    # Check for null or invalid pointers
                    elif expr.op == ida_hexrays.cot_ptr:
                        if expr.x.op == ida_hexrays.cot_num:
                            val = expr.x.numval()
                            if val < 0x1000:  # Likely null or invalid pointer
                                return True

                    # Check for memory accesses
                    elif expr.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
                        if expr.x.op == ida_hexrays.cot_var:
                            # Check if base pointer is undefined
                            if check_undefined_patterns(expr.x, cfunc):
                                return True

                except Exception as e:
                    logger.debug(f"Error in check_undefined_patterns: {str(e)}")
                    return False

                return False

            # Analyze each call
            for call_ea in xrefs:
                try:
                    caller_func = ida_funcs.get_func(call_ea)
                    if not caller_func:
                        continue
                    ida_hexrays.mark_cfunc_dirty(caller_func.start_ea,False)
                    cfunc = ida_hexrays.decompile(caller_func.start_ea)
                    if not cfunc:
                        continue

                    class CallArgVisitor(ida_hexrays.ctree_visitor_t):
                        def __init__(self, target_ea, param_count):
                            super().__init__(ida_hexrays.CV_FAST)
                            self.target_ea = target_ea
                            self.param_count = param_count
                            self.call_found = False
                            self.arg_status = []

                        def visit_expr(self, expr):
                            if expr.op == ida_hexrays.cot_call and expr.ea == self.target_ea:
                                self.call_found = True
                                
                                # Check actual arguments passed
                                for i in range(min(len(expr.a), self.param_count)):
                                    is_undefined = check_undefined_patterns(expr.a[i], cfunc)
                                    self.arg_status.append(is_undefined)
                                
                                # If fewer args than params, mark remaining as undefined
                                while len(self.arg_status) < self.param_count:
                                    self.arg_status.append(True)
                                
                                return 1
                            return 0

                    visitor = CallArgVisitor(call_ea, param_count)
                    visitor.apply_to(cfunc.body, None)

                    if visitor.call_found:
                        for i, is_undefined in enumerate(visitor.arg_status):
                            if i in param_usage:
                                param_usage[i]['total_calls'] += 1
                                if is_undefined:
                                    param_usage[i]['undefined_count'] += 1

                        if config.get("show_debug", False):
                            logger.debug(f"\nCall at {hex(call_ea)}:")
                            for i, status in enumerate(visitor.arg_status):
                                logger.debug(f"Param {i}: {'Undefined' if status else 'Defined'}")

                except Exception as e:
                    logger.debug(f"Error analyzing call at {hex(call_ea)}: {str(e)}")
                    continue

            # Calculate undefined ratio and track actually used parameters
            undefined_ratios = {}
            actually_used_params = []
            for param_idx, stats in param_usage.items():
                if stats['total_calls'] > 0:
                    ratio = stats['undefined_count'] / stats['total_calls']
                    undefined_ratios[param_idx] = ratio
                    if ratio < 0.8:  # Parameter is defined in >20% of calls
                        actually_used_params.append(param_idx)

            if config.get("show_debug", False):
                logger.debug("\nParameter undefined ratios:")
                for param_idx, ratio in undefined_ratios.items():
                    logger.debug(f"Param {param_idx}: {ratio:.2%} undefined ({param_usage[param_idx]['undefined_count']}/{param_usage[param_idx]['total_calls']} calls)")

            # Update function type if needed
            original_param_count = func_details.size()
            new_param_count = len(actually_used_params)

            if new_param_count < original_param_count:
                try:
                    ida_hexrays.mark_cfunc_dirty(func_ea, False)
                    cfunc = ida_hexrays.decompile(func_ea)
                    if not cfunc:
                        logger.debug("Failed to decompile function")
                        return False
                        
                    original_tinfo = cfunc.type
                    original_details = ida_typeinf.func_type_data_t()
                    
                    if not original_tinfo.get_func_details(original_details):
                        logger.debug("Failed to get original function details")
                        return False
                        
                    # Store original calling convention
                    original_cc = original_details.cc
                    logger.debug(f"Original calling convention (before): {original_cc}")
                    
                    # Create new function type with only actually used parameters
                    new_func_details = ida_typeinf.func_type_data_t()
                    new_func_details.rettype = original_details.rettype
                    
                    # Thiscall kontrolü
                    if original_cc == ida_typeinf.CM_CC_THISCALL and new_param_count == 0:
                        logger.debug("Thiscall detected with no parameters, converting to fastcall")
                        new_func_details.cc = ida_typeinf.CM_CC_FASTCALL
                    else:
                        new_func_details.cc = original_cc
                    
                    for idx in actually_used_params:
                        new_func_details.push_back(original_details[idx])
                    
                    new_tinfo = ida_typeinf.tinfo_t()
                    if new_tinfo.create_func(new_func_details):
                        logger.debug(f"New type info: {new_tinfo}")
                        
                        # Apply the new type
                        if ida_typeinf.apply_tinfo(func_ea, new_tinfo, ida_typeinf.TINFO_DEFINITE):
                            # Verify the final type
                            cfunc = ida_hexrays.decompile(func_ea)
                            final_tinfo = cfunc.type
                            
                            final_details = ida_typeinf.func_type_data_t()
                            final_tinfo.get_func_details(final_details)
                            
                            logger.debug(f"Final calling convention: {final_details.cc}")
                            
                            logger.debug(f"\nSuccessfully updated function type at {hex(func_ea)}")
                            logger.debug(f"Original parameter count: {original_param_count}")
                            logger.debug(f"New parameter count: {new_param_count}")
                            logger.debug(f"Actually used parameters: {actually_used_params}")
                            return True
                            
                except Exception as e:
                    logger.debug(f"Error updating function type: {str(e)}")
                    return False

                return False

        except Exception as e:
            logger.debug(f"Error analyzing calls for function at {hex(func_ea)}: {str(e)}")
            return False

    def _determine_new_calling_convention(self, original_cc, really_used_params, total_params):
        logger = DebugLogger.get_instance()

        # Calling convention specific register usage maps
        CC_REGISTER_MAPS = {
            ida_typeinf.CM_CC_FASTCALL: {
                "x64": ["rcx", "rdx", "r8", "r9"],
                "x86": ["ecx", "edx"]
            },
            ida_typeinf.CM_CC_THISCALL: {
                "x86": ["ecx"],
                "x64": ["rcx"]
            }
        }

        is_64bit = self.is_64bit()
        arch = 'x64' if is_64bit else 'x86'

        # Thiscall handling
        if original_cc == ida_typeinf.CM_CC_THISCALL:
            if 0 not in really_used_params:
                logger.debug("Thiscall with unused 'this' parameter - converting")
                if is_64bit:
                    return ida_typeinf.CM_CC_FASTCALL
                else:
                    return ida_typeinf.CM_CC_STDCALL
            return original_cc

        # Fastcall handling
        if original_cc == ida_typeinf.CM_CC_FASTCALL:
            register_count = len(CC_REGISTER_MAPS[ida_typeinf.CM_CC_FASTCALL][arch])
            unused_registers = [i for i in range(register_count) if i not in really_used_params]
            later_params_used = any(i in really_used_params for i in range(register_count, total_params))

            if unused_registers and later_params_used:
                if not is_64bit:  # x86 only
                    return ida_typeinf.CM_CC_CDECL

        return original_cc


    def _analyze_and_remove_unused_parameters(self, func_ea):
        """Analyze and remove unused parameters for all calling conventions"""
        logger = DebugLogger.get_instance()

        # Load config
        config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except:
            return False

        if not config.get("param_analysis", True):
            return False

        try:
            # Decompile the function
            ida_hexrays.mark_cfunc_dirty(func_ea, False)
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                return False

            # Get function type information
            tinfo = cfunc.type
            func_details = ida_typeinf.func_type_data_t()
            if not tinfo.get_func_details(func_details):
                return False

            class ParamVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, cfunc):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.cfunc = cfunc
                    self.used_params = set()
                    self.param_references = {}  # Track parameter references

                def _get_param_index(self, lvar):
                    if not lvar.is_arg_var:
                        return None

                    # Find position in arguments list
                    for i, arg in enumerate(self.cfunc.arguments):
                        if arg == lvar:
                            return i
                    return None

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_var:
                        lvar = self.cfunc.get_lvars()[expr.v.idx]
                        param_idx = self._get_param_index(lvar)
                        if param_idx is not None:
                            self.used_params.add(param_idx)
                            if param_idx not in self.param_references:
                                self.param_references[param_idx] = []
                            self.param_references[param_idx].append(expr.ea)
                    return 0

            # First pass - collect parameter references
            visitor = ParamVisitor(cfunc)
            visitor.apply_to(cfunc.body, None)
            initial_used_params = visitor.used_params

            # Second pass - check real usage
            really_used_params = set()
            for param_idx in initial_used_params:
                if self._is_parameter_really_used(cfunc, param_idx, visitor.param_references.get(param_idx, [])):
                    really_used_params.add(param_idx)

            # Debug info
            if config.get("show_param_analysis", False):
                logger.debug(f"\nParameter Usage Analysis for function at {hex(func_ea)}:")
                logger.debug(f"Total parameters: {len(func_details)}")
                for i in range(len(func_details)):
                    param_type = str(func_details[i].type)
                    param_name = func_details[i].name
                    is_referenced = i in initial_used_params
                    is_really_used = i in really_used_params
                    refs = visitor.param_references.get(i, [])
                    logger.debug(f"Parameter {i}: {param_type} {param_name}")
                    logger.debug(f"  Referenced: {is_referenced}")
                    logger.debug(f"  Actually Used: {is_really_used}")
                    logger.debug(f"  References: {[hex(ref) for ref in refs]}")

            # Determine new calling convention
            new_cc = self._determine_new_calling_convention(
                func_details.cc,
                really_used_params,
                len(func_details)
            )

            # Create new function details
            new_func_details = ida_typeinf.func_type_data_t()
            new_func_details.rettype = func_details.rettype
            new_func_details.cc = new_cc

            # Log calling convention change
            if new_cc != func_details.cc:
                logger.debug(f"Calling convention changed from {func_details.cc} to {new_cc}")

            # Handle parameters based on calling convention
            if new_cc == ida_typeinf.CM_CC_THISCALL:
                # Always include 'this' parameter for thiscall
                new_func_details.push_back(func_details[0])
                # Add other used parameters
                for i in range(1, len(func_details)):
                    if i in really_used_params:
                        new_func_details.push_back(func_details[i])
            else:
                # For other calling conventions, add only used parameters
                stack_args = [arg for arg in cfunc.arguments if arg.is_stk_var()]
                
                if stack_args:
                    first_param_idx = cfunc.arguments.index(stack_args[0])

                    if first_param_idx not in really_used_params and any(i in really_used_params for i in range(first_param_idx + 1, len(func_details))):
                        logger.debug(f"First stack parameter (index {first_param_idx}) is unused but later stack parameters are used. Keeping it.")
                        new_func_details.push_back(func_details[first_param_idx])

                for i in range(len(func_details)):
                    if i in really_used_params:
                        new_func_details.push_back(func_details[i])

            # Create and apply new type
            new_tinfo = ida_typeinf.tinfo_t()
            new_tinfo.create_func(new_func_details)

            if ida_typeinf.apply_tinfo(func_ea, new_tinfo, ida_typeinf.TINFO_DEFINITE):
                logger.debug(f"\nSuccessfully updated function type at {hex(func_ea)}")
                logger.debug(f"Original parameter count: {len(func_details)}")
                logger.debug(f"New parameter count: {len(new_func_details)}")
                logger.debug(f"Actually used parameters: {sorted(list(really_used_params))}")
                return True

            return False

        except Exception as e:
            logger.debug(f"Error analyzing parameters at {hex(func_ea)}: {str(e)}")
            return False

    def _is_parameter_really_used(self, cfunc, param_idx, param_refs):
        """Check if a parameter is really used"""
        if not param_refs:
            return False

        class UsageChecker(ida_hexrays.ctree_visitor_t):
            def __init__(self, cfunc):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.is_used = False
                self.cfunc = cfunc

            def visit_expr(self, expr):
                if expr.ea in param_refs:
                    # If this is a variable
                    if expr.op == ida_hexrays.cot_var:
                        # Check parent expressions
                        parent_expr = self.find_parent_expr(expr)
                        if parent_expr:
                            if parent_expr.op in [
                                # Assignment operations
                                ida_hexrays.cot_asg,      # Normal assignment
                                ida_hexrays.cot_asgadd,   # += assignment
                                ida_hexrays.cot_asgsub,   # -= assignment
                                ida_hexrays.cot_asgmul,   # *= assignment
                                ida_hexrays.cot_asgsdiv,   # /= s.assignment
                                ida_hexrays.cot_asgudiv,   # /= u.assignment
                                ida_hexrays.cot_asgsmod,   # %= s.assignment
                                ida_hexrays.cot_asgumod,   # %= u.assignment
                                ida_hexrays.cot_asgband,   # &= assignment
                                ida_hexrays.cot_asgbor,    # |= assignment
                                ida_hexrays.cot_asgxor,   # ^= assignment

                                # Function calls
                                ida_hexrays.cot_call,     # Function call

                                # Array and pointer operations
                                ida_hexrays.cot_idx,      # Array index
                                ida_hexrays.cot_ptr,      # Pointer dereferencing
                                ida_hexrays.cot_memref,   # Struct/Union member access
                                ida_hexrays.cot_memptr,   # Struct/Union pointer member access

                                # Arithmetic operations
                                ida_hexrays.cot_add,      # Addition
                                ida_hexrays.cot_sub,      # Subtraction
                                ida_hexrays.cot_mul,      # Multiplication
                                ida_hexrays.cot_sdiv,     # Signed division
                                ida_hexrays.cot_udiv,     # Unsigned division
                                ida_hexrays.cot_fdiv,     # Floating point division
                                ida_hexrays.cot_smod,     # Signed modulo
                                ida_hexrays.cot_umod,     # Unsigned modulo

                                # Comparison operations
                                ida_hexrays.cot_eq,       # Equality ==
                                ida_hexrays.cot_ne,       # Inequality !=
                                ida_hexrays.cot_slt,      # Signed less than <
                                ida_hexrays.cot_sle,      # Signed less than or equal <=
                                ida_hexrays.cot_sgt,      # Signed greater than >
                                ida_hexrays.cot_sge,      # Signed greater than or equal >=
                                ida_hexrays.cot_ult,      # Unsigned less than
                                ida_hexrays.cot_ule,      # Unsigned less than or equal
                                ida_hexrays.cot_ugt,      # Unsigned greater than
                                ida_hexrays.cot_uge,      # Unsigned greater than or equal

                                # Logical operations
                                ida_hexrays.cot_land,     # Logical AND &&
                                ida_hexrays.cot_lor,      # Logical OR ||
                                ida_hexrays.cot_band,     # Bitwise AND &
                                ida_hexrays.cot_bor,      # Bitwise OR |
                                ida_hexrays.cot_xor,      # Bitwise XOR ^

                                # Bit operations
                                ida_hexrays.cot_shl,      # Shift left <<
                                ida_hexrays.cot_sshr,      # s.Logical shift right >>
                                ida_hexrays.cot_ushr,      # u.Logical shift right >>

                                # Cast operations
                                ida_hexrays.cot_cast,     # Type casting

                                # Ternary operator
                                ida_hexrays.cot_tern,      # Ternary ? :

                                # Helper operations
                                ida_hexrays.cot_helper,   # Helper function call
                                ida_hexrays.cot_sizeof    # sizeof operator
                            ]:
                                self.is_used = True
                return 0

            def find_parent_expr(self, target_expr):
                """Find the parent expression that contains the given expression"""
                class ParentFinder(ida_hexrays.ctree_visitor_t):
                    def __init__(self, target_expr):
                        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                        self.target_expr = target_expr
                        self.parent = None

                    def compare_expr(self, e1, e2):
                        """Safely compare two expressions"""
                        if e1 is None or e2 is None:
                            return False
                        try:
                            # Compare basic properties
                            return (e1.op == e2.op and
                                    e1.ea == e2.ea and
                                    (hasattr(e1, 'v') and hasattr(e2, 'v') and
                                    e1.v.idx == e2.v.idx))
                        except:
                            return False

                    def visit_expr(self, e):
                        try:
                            # Check if any of the operands is our target
                            if hasattr(e, 'x') and self.compare_expr(e.x, self.target_expr):
                                self.parent = e
                                return 1
                            if hasattr(e, 'y') and self.compare_expr(e.y, self.target_expr):
                                self.parent = e
                                return 1
                            if hasattr(e, 'z') and self.compare_expr(e.z, self.target_expr):
                                self.parent = e
                                return 1
                            # For function calls, check arguments
                            if e.op == ida_hexrays.cot_call and hasattr(e, 'a'):
                                for arg in e.a:
                                    if self.compare_expr(arg, self.target_expr):
                                        self.parent = e
                                        return 1
                        except:
                            pass
                        return 0

                finder = ParentFinder(target_expr)
                finder.apply_to(self.cfunc.body, None)
                return finder.parent

        checker = UsageChecker(cfunc)
        checker.apply_to(cfunc.body, None)
        return checker.is_used

    def _is_register_used_in_virtual_call(self, cfunc, reg, param_names):
        """
        Checks if a register is used ONLY in virtual function calls.
        """
        logger = DebugLogger.get_instance()
        if not cfunc or not hasattr(cfunc, 'body'):
            logger.debug("No function body available")
            return False

        class VirtualCallChecker(ida_hexrays.ctree_visitor_t):
            def __init__(self, reg, cfunc, param_names):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.reg = reg
                self.cfunc = cfunc
                self.found_in_virtual_call = False
                self.found_in_normal_usage = False
                self.param_map = {}
                self.param_name = None


                if self.reg.lower() in param_names:
                    self.param_map[param_names[self.reg.lower()]] = self.reg.lower()
                    self.param_name = param_names[self.reg.lower()]

                logger.debug(f"Checking for parameter: {self.param_map},  target: {self.reg}")

            def _check_var_name(self, lvar):
                return hasattr(lvar, 'name') and lvar.name in self.param_map

            def _check_expr_for_param(self, expr, context="", in_virtual_call=False):
                """Recursively check expression for parameter usage"""
                if not expr:
                    return False

                try:
                    if expr.op == ida_hexrays.cot_var:
                        lvar = self.cfunc.get_lvars()[expr.v.idx]
                        if self._check_var_name(lvar):
                            reg_name = self.param_map[lvar.name]
                            if in_virtual_call:
                                logger.debug(
                                    f"Found parameter {lvar.name} ({reg_name}) in virtual call {context}"
                                )
                                self.found_in_virtual_call = True
                            else:
                                logger.debug(
                                    f"Found parameter {lvar.name} ({reg_name}) in normal usage {context}"
                                )
                                # Check if the normal usage is within a virtual call context
                                is_within = self.is_within_virtual_call_context(expr)
                                if not is_within:
                                    self.found_in_normal_usage = True
                                
                            return True

                    # Check sub-expressions
                    if hasattr(expr, "x") and expr.x:
                        if self._check_expr_for_param(expr.x, context, in_virtual_call):
                            return True
                    if hasattr(expr, "y") and expr.y:
                        if self._check_expr_for_param(expr.y, context, in_virtual_call):
                            return True
                    if hasattr(expr, "a") and expr.a:  # Check arguments of a call
                        for i, arg in enumerate(expr.a):
                            if arg:
                                if self._check_expr_for_param(
                                    arg, f"argument {i}", in_virtual_call
                                ):
                                    return True

                except Exception as ex:
                    logger.debug(f"Error in _check_expr_for_param: {str(ex)}")

                return False

            def is_within_virtual_call_context(self, expr):
                """
                Checks if the given expression is part of a virtual call context.
                """
                class ParentFinder(ida_hexrays.ctree_visitor_t):
                        def __init__(self, target_expr):
                            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                            self.target_expr = target_expr
                            self.parent = None

                        def compare_expr(self, e1, e2):
                            """Safely compare two expressions"""
                            if e1 is None or e2 is None:
                                return False
                            try:
                                # Compare basic properties
                                return (e1.op == e2.op and
                                        e1.ea == e2.ea and
                                        (hasattr(e1, 'v') and hasattr(e2, 'v') and
                                        e1.v.idx == e2.v.idx))
                            except:
                                return False
                            
                        def visit_expr(self, e):
                            try:
                                # Check if any of the operands is our target
                                if hasattr(e, 'x') and self.compare_expr(e.x, self.target_expr):
                                    self.parent = e
                                    return 1
                                if hasattr(e, 'y') and self.compare_expr(e.y, self.target_expr):
                                    self.parent = e
                                    return 1
                                if hasattr(e, 'z') and self.compare_expr(e.z, self.target_expr):
                                    self.parent = e
                                    return 1
                                # For function calls, check arguments
                                if e.op == ida_hexrays.cot_call and hasattr(e, 'a'):
                                    for arg in e.a:
                                        if self.compare_expr(arg, self.target_expr):
                                            self.parent = e
                                            return 1
                            except:
                                pass
                            return 0

                parent_finder = ParentFinder(expr)
                parent_finder.apply_to(self.cfunc.body, None)
                parent = parent_finder.parent
                
                while parent:
                    if parent.op == ida_hexrays.cot_call:
                        if self._is_potential_vtable_access(parent.x):
                            return True
                    elif parent.op == ida_hexrays.cot_asg:
                        # If it's an assignment, check the right-hand side
                        if parent.x == expr:  # Ensure we are on the left side of assignment
                            if hasattr(parent, 'y'):
                                if self._check_expr_for_param(parent.y, "assignment RHS", True):
                                    return True
                    elif parent.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
                        if self._is_potential_vtable_access(parent):
                            return True

                    parent_finder = ParentFinder(parent)
                    parent_finder.apply_to(self.cfunc.body, None)
                    parent = parent_finder.parent

                return False

            def _is_potential_vtable_access(self, expr):
                """Check various vtable access patterns"""
                if not expr:
                    return False

                try:
                    # Pattern 1: Direct pointer dereference
                    if expr.op == ida_hexrays.cot_ptr:
                        return True

                    # Pattern 2: Member pointer access
                    if expr.op == ida_hexrays.cot_memptr:
                        return True

                    # Pattern 3: Addition operation (possible vtable offset)
                    if expr.op == ida_hexrays.cot_add:
                        if hasattr(expr, 'x') and expr.x:
                            if expr.x.op == ida_hexrays.cot_ptr:
                                return True
                            if self._check_expr_for_param(expr.x, "vtable base", True):
                                return True

                    # Pattern 4: Cast operations
                    if expr.op == ida_hexrays.cot_cast:
                        return self._is_potential_vtable_access(expr.x if hasattr(expr, 'x') else None)

                except Exception as ex:
                    logger.debug(f"Error in _is_potential_vtable_access: {str(ex)}")

                return False

            def visit_expr(self, e):
                try:
                    if e.op == ida_hexrays.cot_call:
                        # Check if this is potentially a virtual call
                        is_virtual = False
                        if hasattr(e, 'x') and e.x:
                            is_virtual = self._is_potential_vtable_access(e.x)
                            if is_virtual:
                                logger.debug("Found potential virtual call pattern")
                                # Check the call expression itself
                                self._check_expr_for_param(e.x, "call expression", True)

                            # Check arguments
                            if hasattr(e, 'a') and e.a:
                                for i, arg in enumerate(e.a):
                                    if not arg:
                                        continue
                                    self._check_expr_for_param(arg, f"argument {i}", is_virtual)

                    # Check normal usage (non-call expressions)
                    elif e.op in [ida_hexrays.cot_asg, ida_hexrays.cot_idx,
                                ida_hexrays.cot_add, ida_hexrays.cot_sub,
                                ida_hexrays.cot_mul,
                                ida_hexrays.cot_sdiv, ida_hexrays.cot_udiv, # Possible division opcodes
                                ida_hexrays.cot_eq, ida_hexrays.cot_ne,
                                ida_hexrays.cot_slt, ida_hexrays.cot_ult, # Added cot_slt, cot_ult for signed/unsigned
                                ida_hexrays.cot_sle, ida_hexrays.cot_ule, # Added cot_sle, cot_ule for signed/unsigned
                                ida_hexrays.cot_sgt, ida_hexrays.cot_ugt, # Added cot_sgt, cot_ugt for signed/unsigned
                                ida_hexrays.cot_sge, ida_hexrays.cot_uge, # Added cot_sge, cot_uge for signed/unsigned
                                ida_hexrays.cot_land, ida_hexrays.cot_lor]:
                        self._check_expr_for_param(e, "normal operation", False)

                    # Also check member access expressions
                    elif e.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
                        if self._is_potential_vtable_access(e):
                            self._check_expr_for_param(e.x, "member access", True)
                        else:
                            self._check_expr_for_param(e.x, "normal member access", False)

                except Exception as ex:
                    logger.debug(f"Error in visit_expr: {str(ex)}")

                return 0

        checker = VirtualCallChecker(reg, cfunc, param_names)
        checker.apply_to(cfunc.body, None)

        logger.debug(f"Parameter: {reg}")
        logger.debug(f"Found in virtual calls: {checker.found_in_virtual_call}")
        logger.debug(f"Found in normal usage: {checker.found_in_normal_usage}")

        result = checker.found_in_virtual_call and not checker.found_in_normal_usage
        logger.debug(f"Final virtual call check result for {reg}: {result}")

        return result

    def _determine_calling_convention(self, func_ea, reg_specs,stack_specs, cfunc,param_names):
        """Determine the appropriate calling convention based on register specifications, stack specs and architecture"""
        logger = DebugLogger.get_instance()
        if not reg_specs:
            return ida_typeinf.CM_CC_CDECL

        # Debug for all register information
        logger.debug(f"Analyzing function at {hex(func_ea)}")
        logger.debug(f"Register specifications: {reg_specs}")
        logger.debug(f"Architecture: {'x64' if self.is_64bit() else 'x86'}")
        logger.debug(f"Stack specifications: {stack_specs}")
        
        # Analyze register usage
        param_regs = []
        return_reg = None
        register_usage = {
            'ecx_used': False,
            'rcx_used': False,
            'xmm0_used': False,
            'xmm1_used': False,
            'ebp_used' : False,
            'esp_used' : False,
        }
        
        # For first parameter tracking
        first_param = None
        param_count = 0
        
        virtual_call_registers = []

        for spec_type, reg in reg_specs:
            reg = reg.lower()
            logger.debug(f"Processing {spec_type}: {reg}")

            if spec_type == 'param':
                if param_count == 0:
                    first_param = reg
                param_count += 1
                
                param_regs.append(reg)
                
                # Save register usage status
                if reg == 'ecx':
                    register_usage['ecx_used'] = True
                    logger.debug("Found ecx parameter")
                elif reg == 'rcx':
                    register_usage['rcx_used'] = True
                    logger.debug("Found rcx parameter")
                elif reg in ['xmm0', 'xmm1']:
                    register_usage[f'{reg}_used'] = True
                    logger.debug(f"Found {reg} parameter")
                elif reg in ["ebp","esp"]:
                    register_usage[f'{reg}_used'] = True
                elif reg not in ['ecx','rcx','xmm0','xmm1','ebp','esp']:
                    virtual_call_registers.append(reg)
            elif spec_type == 'return':
                return_reg = reg

        # x64 architecture check
        if self.is_64bit():
            logger.debug("Processing x64 architecture rules")
            
            # Microsoft x64 calling convention (always fastcall)
            # RCX, RDX, R8, R9 or XMM0-XMM3 usage
            if (register_usage['rcx_used'] or 
                register_usage['xmm0_used'] or 
                first_param in ['rcx', 'xmm0']):
                logger.debug(f"Function at {hex(func_ea)} marked as x64 fastcall")
                return ida_typeinf.CM_CC_FASTCALL
                
        # x86 architecture check
        else:
            logger.debug("Processing x86 architecture rules")
            
            # Thiscall check (ECX parameter)
            if register_usage['ecx_used']:
                logger.debug(f"Function at {hex(func_ea)} marked as thiscall due to ecx parameter")
                return ida_typeinf.CM_CC_THISCALL
            if register_usage['ebp_used'] or register_usage['esp_used']:
                logger.debug(f"Function at {hex(func_ea)} marked as cdecl due to stack parameter")
                return ida_typeinf.CM_CC_CDECL
            
            # x86 fastcall check
            # First parameter ECX/XMM0 or certain register combinations
            if (first_param in ['ecx', 'xmm0'] or 
                register_usage['xmm0_used']):
                logger.debug(f"Function at {hex(func_ea)} marked as x86 fastcall")
                return ida_typeinf.CM_CC_FASTCALL
            
            # Virtual call check
            # If ebx, edi, etc. registers are used and followed by stack parameters

            if virtual_call_registers or stack_specs:
                                              
                for reg in virtual_call_registers:
                        if self._is_register_used_in_virtual_call(cfunc,reg,param_names):
                           logger.debug(f"Function at {hex(func_ea)} marked as cdecl due to register {reg} in virtual call and stack parameters.")
                           return ida_typeinf.CM_CC_CDECL
                        
                    
       
        logger.debug(f"Function at {hex(func_ea)} defaulting to usercall")
        return ida_typeinf.CM_CC_SPECIAL

    def get_function_type(self, func_ea):
        """Get function type from both decompiler and IDA database"""
        # First try to get type from decompiler
        try:
            ida_hexrays.mark_cfunc_dirty(func_ea, False)
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                func_type = str(cfunc.type.dstr())
                return func_type, cfunc  # Return both func_type and cfunc
        except:
            pass

        # If decompiler fails, try to get from IDA database
        func_type = idc.get_type(func_ea)
        return func_type, None  # Return func_type and None if decompiler fails

    #
    def parse_register_specs(self, func_type, cfunc):
        """Parse register specifications from function type string and cfunc arguments"""
        reg_specs = []
        stack_specs = []
        param_names = {}
        try:
            if not cfunc:  # If cfunc is None, we can't use cfunc.arguments
                if not func_type or '@<' not in func_type:
                    return None, None, None
            else:
                # Parse parameters from cfunc.arguments
                for j, arg in enumerate(cfunc.arguments):
                    if not arg.name:
                        continue
                    if arg.is_stk_var():
                        offset = cfunc.mba.stacksize - arg.location.stkoff()
                        stack_specs.append((arg.name, f"0x{abs(offset):x}"))
                    elif arg.is_reg_var():
                        regnum = arg.get_reg1()
                        register_name = idaapi.get_mreg_name(regnum, arg.width)
                        reg_specs.append(('param', register_name))
                        param_names[register_name.lower()] = arg.name

                if func_type and '@<' in func_type:
                    parts = func_type.split('@<')
                    # Check for return register in first part
                    return_reg = None
                    if len(parts) > 1:
                        return_part = parts[0]
                        if return_part.endswith('__userpurge') or return_part.endswith('__usercall'):
                            return_reg = parts[1].split('>')[0]
                            reg_specs.append(('return', return_reg))
                return reg_specs if reg_specs else None, stack_specs if stack_specs else None, param_names if param_names else None

        except Exception as e:
            print(f"Error parsing register specs: {str(e)}")
            return None, None, None

    def is_imported_function(self, func_ea):
        """Check if the function is imported/thunk"""

        # 1. Get flags
        flags = ida_bytes.get_flags(func_ea)

        # If it's not a function, return False
        if not ida_bytes.is_func(flags):
            return False

        func = ida_funcs.get_func(func_ea)
        if func:
            # 2. Check if it has FUNC_THUNK or FUNC_LIB flag
            if func.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
                return True

        # 5. Check if the function name starts with one of the import prefixes
        func_name = idc.get_func_name(func_ea)
        import_prefixes = ['__imp_', 'j_', 'imp_', '_imp']
        if any(func_name.startswith(prefix) for prefix in import_prefixes):
            return True

        # 6. Check if the demangled name starts with one of the import prefixes
        demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled_name and any(demangled_name.startswith(prefix) for prefix in import_prefixes):
            return True

        # If it's not an import, return False
        return False

    def has_usercall_convention(self, func_ea):
        """Enhanced check for __usercall/__userpurge convention"""
        logger = DebugLogger.get_instance()
        func_type, cfunc = self.get_function_type(func_ea)
        if func_type:
            # Check for __usercall or __userpurge keywords
            if ("__usercall" in func_type) or ("__userpurge" in func_type):
                reg_specs, stack_specs , param_names = self.parse_register_specs(func_type,cfunc)
                if reg_specs:
                    logger.debug(f"Found register specifications for {hex(func_ea)}: {reg_specs}")
                    self.print_function_info(func_ea)
                return True

            # Check for register specifications in function type
            if '@<' in func_type:
                reg_specs, stack_specs , param_names = self.parse_register_specs(func_type,cfunc)
                if reg_specs:
                    logger.debug(f"Found register specifications for {hex(func_ea)}: {reg_specs}")
                    return True

        return False

    def fix_calling_convention(self, func_ea):
        # Load config
        logger = DebugLogger.get_instance()
        config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except:
            return

        if not config.get("func_type_analysis", True):
            return

        if config.get("show_debug", False):
            logger.debug(f"\nAnalyzing function type at {hex(func_ea)}")

        def debug_print(msg):
            if config["show_debug"]:
                print(f"[DEBUG] {msg}")

        if func_ea in self.processed_funcs:
            debug_print(f"Function {hex(func_ea)} already processed")
            return

        if self.is_imported_function(func_ea):
            debug_print(f"Skipping imported function at {hex(func_ea)}")
            return

        self.processed_funcs.add(func_ea)

        try:
            # Get function type from decompiler first
            func_type, cfunc = self.get_function_type(func_ea)
            if not func_type:
                logger.debug(f"No type information available for function at {hex(func_ea)}")
                return

            logger.debug(f"\nProcessing function at {hex(func_ea)}")
            logger.debug(f"Original function type: {func_type}")

            if self.has_usercall_convention(func_ea):
                # Parse register specifications
                reg_specs, stack_specs, param_names = self.parse_register_specs(func_type, cfunc)

                if not reg_specs:
                    logger.debug(f"No register specifications found for function at {hex(func_ea)}")
                    return

                logger.debug(f"Found register specs: {reg_specs}")

                # Determine calling convention if direct conversion is not possible
                new_cc = self._determine_calling_convention(func_ea, reg_specs, stack_specs, cfunc, param_names)
                logger.debug(f"Determined calling convention: {new_cc}")

                # Try to decompile to get current function details
                ida_hexrays.mark_cfunc_dirty(func_ea, False)
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    logger.debug(f"Failed to decompile function at {hex(func_ea)}")
                    return

                # Get type info from decompiler
                tinfo = cfunc.type
                func_details = ida_typeinf.func_type_data_t()
                if tinfo.get_func_details(func_details):
                    # Set the determined calling convention
                    func_details.cc = new_cc

                    # Create and apply the new type
                    tinfo.create_func(func_details)
                    if ida_typeinf.apply_tinfo(func_ea, tinfo, ida_typeinf.TINFO_DEFINITE):
                        logger.debug(f"Successfully applied new calling convention at {hex(func_ea)}")

                        # Remove unused parameters
                        self._analyze_and_remove_unused_parameters(func_ea)
                        if config["unused_param_analysis"]:
                            self._analyze_calls_and_update_signature(func_ea)

                        # Refresh view if in pseudocode window
                        if config["auto_refresh_views"]:
                            widget_name = f"Pseudocode-{idc.get_func_name(func_ea)}"
                            vu = ida_hexrays.get_widget_vdui(ida_kernwin.find_widget(widget_name))
                            if vu:
                                vu.refresh_view(True)
                    else:
                        logger.debug(f"Failed to apply type at {hex(func_ea)}")
            else:
                logger.debug(f"Skipping function at {hex(func_ea)} as it does not use usercall convention")

        except Exception as e:
            logger.debug(f"Error processing function at {hex(func_ea)}: {str(e)}")

class BackwardsDecompilerHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-rays decompiler is not available!")
            return 0

        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if not vu:
            print("No pseudocode view available!")
            return 0

        current_function = vu.cfunc.entry_ea
        if not current_function:
            print("No function at current address!")
            return 0

        self.process_function_backwards(current_function)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def get_calls_in_function(self, func_ea):
        """
        Finds calls in a function using either the decompiler or IDA API.
        """
        logger = DebugLogger.get_instance()
        calls = []
        config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.debug(f"Config file not found {config_path}: {e}")
            return calls

        search_engine = config.get("search_engine", "IDA-API")

        try:
            if search_engine == "Hex-Rays":
                # Decompile the function
                ida_hexrays.mark_cfunc_dirty(func_ea, False)
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    logger.debug(f"Failed to decompile function at {hex(func_ea)}.")
                    return calls

                class CallVisitor(ida_hexrays.ctree_visitor_t):
                    def __init__(self, calls):
                        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                        self.calls = calls

                    def visit_expr(self, expr):
                        if expr.op == ida_hexrays.cot_call:
                            try:
                                if expr.x.op != ida_hexrays.cot_obj:
                                    return 0
                                if expr.x.obj_ea == idaapi.BADADDR:
                                    return 0
                                target_ea = expr.x.obj_ea
                                if target_ea not in self.calls and ida_funcs.get_func(target_ea):
                                    self.calls.append(target_ea)
                            except Exception as e:
                                logger.debug(f"Error during visit_expr: {str(e)}")
                        return 0

                visitor = CallVisitor(calls)
                visitor.apply_to(cfunc.body, None)
                return calls

            elif search_engine == "IDA-API":
                func = ida_funcs.get_func(func_ea)
                if not func:
                    return calls

                # Iterate over each instruction in the function
                func_items = list(idautils.FuncItems(func_ea))
                for ea in reversed(func_items):
                    if idaapi.is_call_insn(ea) or idc.print_insn_mnem(ea) == "jmp":
                        call_target = idc.get_operand_value(ea, 0)
                        # Add the call target if it has not been added before and is a valid function
                        if call_target not in calls and ida_funcs.get_func(call_target):
                            calls.append(call_target)
                return calls

            else:
                logger.debug(f"Invalid search engine selected: {search_engine}")
                return calls
        except Exception as e:
            logger.debug(f"Error getting calls in function at {hex(func_ea)}: {str(e)}")
            return calls

    
    def collect_layered_call_chain(self, func_ea, max_layers, current_layer=1, visited=None, call_chain=None):
        """Collects a layered call chain
        
        Args:
            func_ea: Starting function address
            max_layers: Maximum layer count (default: 2)
            current_layer: Current layer count
            visited: Set of visited functions
            call_chain: Collected call chain
        """
        logger = DebugLogger.get_instance()
        if visited is None:
            visited = set()
        if call_chain is None:
            call_chain = []
            
        # If the function has already been visited or the maximum layer count has been reached, stop
        if func_ea in visited or current_layer > max_layers:
            return call_chain

        visited.add(func_ea)
        
        # Collect calls in the current layer
        current_layer_calls = []
        func = ida_funcs.get_func(func_ea)
        if func:
                
                calls = self.get_calls_in_function(func_ea)
                for target in calls:
                    
                    current_layer_calls.append({
                                'caller_ea': func_ea,
                                'call_ea': target,
                                'target_ea': target,
                                'layer': current_layer,
                                'processed': False
                            })
        
        # Reverse the calls in the current layer
        current_layer_calls.reverse()
        
        # Add the calls in the current layer to the chain
        for call in current_layer_calls:
            call_chain.append(call)
            
            # Move to the next layer
            if current_layer < max_layers:
                self.collect_layered_call_chain(
                    call['target_ea'],
                    max_layers,
                    current_layer + 1,
                    visited,
                    call_chain
                )
        
        # Add the starting function to the chain (only for the first layer)
        if current_layer == 1:
            call_chain.append({
                'caller_ea': func_ea,
                'call_ea': func_ea,
                'target_ea': func_ea,
                'layer': 1,
                'processed': False,
                'is_start_function': True
            })
        
        return call_chain



    def process_function_backwards(self, start_ea):
        logger = DebugLogger.get_instance()
        
        with ProgressDialog("Initializing analysis... (Press Esc to cancel)") as progress:
            try:
                # Load config
                config_path = os.path.join(ida_diskio.get_user_idadir(), "retrospective_config.json")
                try:
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                        logger.set_enabled(config.get("show_debug", False))
                except:
                    config = {
                        "max_layers": 4,
                        "auto_refresh_views": True,
                        "show_debug": False,
                        "param_analysis": True,
                        "func_type_analysis": True,
                        "unused_param_analysis": True,
                        "virtual_call_analysis" : True,
                        "search_engine" : "IDA-API"
                    }

                logger.debug(f"Starting backwards analysis from {hex(start_ea)}")
                func = ida_funcs.get_func(start_ea)
                
                if config["auto_refresh_views"]:
                    ida_hexrays.mark_cfunc_dirty(func.start_ea)

                # Phase 1
                progress.replace_message("Phase 1: Collecting call chain... (Press Esc to cancel)")
                logger.debug("Phase 1: Collecting layered call chain...")
                
                if progress.check_cancelled():
                    print("\nOperation cancelled by user during call chain collection.")
                    return
                    
                call_chain = self.collect_layered_call_chain(start_ea, max_layers=config["max_layers"])
                
                # Phase 2
                progress.replace_message("Phase 2: Processing functions... (Press Esc to cancel)")
                logger.debug("\nPhase 2: Processing functions in reverse order...")
                fixer = CallingConventionFixer()
                
                max_layer = max(call['layer'] for call in call_chain)
                for current_layer in range(max_layer, 0, -1):
                    progress.replace_message(f"Processing Layer {current_layer} of {max_layer}... (Press Esc to cancel)")
                    logger.debug(f"\nProcessing Layer {current_layer}:")
                    
                    if progress.check_cancelled():
                        print(f"\nOperation cancelled by user at layer {current_layer}.")
                        return
                    
                    layer_calls = [call for call in call_chain if call['layer'] == current_layer]
                    for i, call in enumerate(layer_calls, 1):
                        try:
                            target_ea = call['target_ea']
                            caller_ea = call['caller_ea']
                            call_ea = call['call_ea']
                            
                            progress.replace_message(
                                f"Layer {current_layer}/{max_layer}: Processing function {i}/{len(layer_calls)} at {hex(target_ea)}... "
                                "(Press Esc to cancel)"
                            )
                            
                            if progress.check_cancelled():
                                print(f"\nOperation cancelled by user while processing function at {hex(target_ea)}.")
                                return
                            
                            logger.debug(f"\nProcessing call at {hex(call_ea)}:")
                            logger.debug(f"  From: {hex(caller_ea)}")
                            logger.debug(f"  To: {hex(target_ea)}")
                            
                            fixer.fix_calling_convention(target_ea)
                            if config["param_analysis"]:
                                fixer._analyze_and_remove_unused_parameters(target_ea)
                            else:
                                if config["func_type_analysis"]:
                                 fixer.fix_calling_convention(target_ea)
                                    
                            if config["auto_refresh_views"]:
                                func_name = idc.get_func_name(target_ea)
                                vu = ida_hexrays.get_widget_vdui(ida_kernwin.find_widget(f"Pseudocode-{func_name}"))
                                if vu:
                                    vu.refresh_view(True)
                                    
                        except Exception as e:
                            logger.debug(f"Error processing call: {str(e)}")
                            continue
                            
                        if progress.check_cancelled():
                            print(f"\nOperation cancelled by user during function processing.")
                            return
                
                # Phase 3: Virtual Call Type Analysis
                progress.replace_message("Phase 3: Analyzing virtual call types... (Press Esc to cancel)")
                logger.debug("\nPhase 3: Analyzing virtual call types...")
                
                if progress.check_cancelled():
                    print(f"\nOperation cancelled by user during virtual call analysis.")
                    return
                
                for current_layer in range(max_layer, 0, -1):
                    progress.replace_message(f"Processing Layer {current_layer} for virtual calls of {max_layer}... (Press Esc to cancel)")
                    logger.debug(f"\nProcessing Layer {current_layer}:")
                    
                    if progress.check_cancelled():
                        print(f"\nOperation cancelled by user at layer {current_layer}.")
                        return
                    
                    layer_calls = [call for call in call_chain if call['layer'] == current_layer]
                    for i, call in enumerate(layer_calls, 1):
                            try:
                                target_ea = call['target_ea']
                                caller_ea = call['caller_ea']
                                call_ea = call['call_ea']
                                
                                progress.replace_message(
                                    f"Layer {current_layer}/{max_layer}: Processing virtual calls for function {i}/{len(layer_calls)} at {hex(target_ea)}... "
                                    "(Press Esc to cancel)"
                                )
                            
                                if progress.check_cancelled():
                                    print(f"\nOperation cancelled by user while processing virtual call types at {hex(target_ea)}.")
                                    return
                                
                                logger.debug(f"\nAnalyzing virtual calls at {hex(call_ea)}:")
                                logger.debug(f"  From: {hex(caller_ea)}")
                                logger.debug(f"  To: {hex(target_ea)}")
                                
                                if config["virtual_call_analysis"]:
                                   fixer._analyze_virtual_calls_and_update_signature(target_ea)
                                else:
                                    logger.debug(f"Skipping virtual call analysis for {hex(target_ea)}")
                            
                                if config["auto_refresh_views"]:
                                   func_name = idc.get_func_name(target_ea)
                                   vu = ida_hexrays.get_widget_vdui(ida_kernwin.find_widget(f"Pseudocode-{func_name}"))
                                   if vu:
                                       vu.refresh_view(True)
                                       
                            except Exception as e:
                                logger.debug(f"Error processing virtual calls at {hex(target_ea)}: {str(e)}")
                                continue
                                
                            if progress.check_cancelled():
                                    print(f"\nOperation cancelled by user during virtual calls processing.")
                                    return
                
                progress.replace_message("Analysis completed successfully!")
                print("\nAnalysis completed successfully!")
                
            except Exception as e:
                print(f"\nError during analysis: {str(e)}")
            finally:
                if progress.check_cancelled():
                    print("\nOperation was cancelled by user.")

class BackwardsDecompilerHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        widget_type = idaapi.get_widget_type(form)

        if widget_type == idaapi.BWN_DISASM or widget_type == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, "Retrospective_analysis:run")

class BackwardsDecompilerPlugin(idaapi.plugin_t):
  flags = idaapi.PLUGIN_KEEP
  comment = "Retrospective Analysis Plugin"
  help = "Retrospective Analysis Plugin for IDA Pro"
  wanted_name = "Retrospective Analysis"
  wanted_hotkey = ""

  def __init__(self):
      super().__init__()
      self.action_name = "Retrospective_analysis:run"
      self.config_action_name = "Retrospective_analysis:config"
      self.hooks = None

  def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-rays decompiler is not available.")
            return idaapi.PLUGIN_SKIP

        # Register menu items
        menu_path = "Edit/Plugins/Retrospective Analysis/"
        
        # Register actions
        if not idaapi.register_action(idaapi.action_desc_t(
            self.action_name,
            "Retrospective analysis",
            BackwardsDecompilerHandler(),
            None,
            "Retrospective analysis",
            -1)):
            print("Failed to register run action")
            return idaapi.PLUGIN_SKIP

        if not idaapi.register_action(idaapi.action_desc_t(
            self.config_action_name,
            "Configure",
            ConfigActionHandler(),
            None,
            "Configure settings",
            -1)):
            print("Failed to register config action")
            return idaapi.PLUGIN_SKIP

        # Attach actions to menu
        if not idaapi.attach_action_to_menu(f"{menu_path}Retrospective analysis", self.action_name, idaapi.SETMENU_APP):
            print("Failed to attach run action")
            
        if not idaapi.attach_action_to_menu(f"{menu_path}Configure", self.config_action_name, idaapi.SETMENU_APP):
            print("Failed to attach config action")

        # Setup hooks
        self.hooks = BackwardsDecompilerHooks()
        self.hooks.hook()
        first_config(self)

        print("Retrospective analysis plugin initialized successfully")
        return idaapi.PLUGIN_KEEP

  def run(self, arg):
      show_config_dialog()

  def term(self):
      try:
          if self.hooks:
              self.hooks.unhook()
          idaapi.unregister_action(self.action_name)
          idaapi.unregister_action(self.config_action_name)
      except:
          pass

def PLUGIN_ENTRY():
    try:
        return BackwardsDecompilerPlugin()
    except Exception as e:
        print(f"Error loading Backwards Decompiler plugin: {str(e)}")
        return None