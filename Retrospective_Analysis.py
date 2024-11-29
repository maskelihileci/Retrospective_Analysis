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
              <##Enable parameter analysis:{param_analysis}>{cGroup1}>
              <##Enable function type analysis:{func_type_analysis}>{cGroup2}>
              <##Enable unused parameter analysis in call references:{unused_param_analysis}>{cGroup3}>
              
              Debug Options:
              <##Show debug messages:{show_debug}>{cGroup4}>
              
              View Options:
              <##Auto refresh decompiler views:{auto_refresh_views}>{cGroup5}>
              """, {
                  'max_layers': Form.NumericInput(tp=Form.FT_DEC, value=self.config["max_layers"], swidth=5),
                  'cGroup1': Form.ChkGroupControl(("param_analysis",), value=1 if self.config["param_analysis"] else 0),
                  'cGroup2': Form.ChkGroupControl(("func_type_analysis",), value=1 if self.config["func_type_analysis"] else 0),
                  'cGroup3': Form.ChkGroupControl(("unused_param_analysis",), value=1 if self.config["unused_param_analysis"] else 0),
                  'cGroup4': Form.ChkGroupControl(("show_debug",), value=1 if self.config["show_debug"] else 0),
                  'cGroup5': Form.ChkGroupControl(("auto_refresh_views",), value=1 if self.config["auto_refresh_views"] else 0)
              })
          
          Form.Compile(self)
          
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
          "unused_param_analysis": True
      }
      
      try:
          if os.path.exists(self.config_path):
              with open(self.config_path, 'r') as f:
                  config = json.load(f)
                  # Validate max_layers
                  if "max_layers" in config:
                      config["max_layers"] = max(1, min(10, int(config["max_layers"])))
                  return config
      except Exception as e:
          print(f"Error loading config: {e}")
      
      return default_config

  def save_config(self):
      logger = DebugLogger.get_instance()
      try:
          config = {
              "max_layers": self.max_layers.value,
              "auto_refresh_views": bool(self.cGroup5.value),
              "show_debug": bool(self.cGroup4.value),
              "param_analysis": bool(self.cGroup1.value),
              "func_type_analysis": bool(self.cGroup2.value),
              "unused_param_analysis": bool(self.cGroup3.value)
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
            "unused_param_analysis": True
        }
            
        # Mevcut config dosyasını kontrol et
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    current_config = json.load(f)
                
                # Eksik değerleri kontrol et ve ekle
                updated = False
                for key, value in self.default_config.items():
                    if key not in current_config:
                        current_config[key] = value
                        updated = True
                        print(f"Eksik config değeri eklendi: {key} = {value}")
                
                # Eğer değişiklik yapıldıysa dosyayı güncelle
                if updated:
                    with open(self.config_path, 'w') as f:
                        json.dump(current_config, f, indent=4)
                    print("Config dosyası güncellendi")
                        
            except Exception as e:
                print(f"Config dosyası okuma/yazma hatası: {str(e)}")
        else:
            # Config dosyası yoksa yeni oluştur
            try:
                with open(self.config_path, 'w') as f:
                    json.dump(self.default_config, f, indent=4)
                print(f"Varsayılan config dosyası oluşturuldu: {self.config_path}")
            except Exception as e:
                print(f"Default config dosyası oluşturma hatası: {str(e)}")

    except Exception as e:
        print(f"first_config'de hata: {str(e)}")



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

        if not config.get("call_analysis", True):
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
            if not ida_typeinf.guess_tinfo(tinfo, func_ea):
                logger.debug(f"Could not get type info for function at {hex(func_ea)}")
                return False

            func_details = ida_typeinf.func_type_data_t()
            if not tinfo.get_func_details(func_details):
                logger.debug(f"Could not get function details at {hex(func_ea)}")
                return False

            # Track parameter usage across all calls
            param_count = func_details.size()
            param_usage = {i: {'undefined_count': 0, 'total_calls': 0} for i in range(param_count)}
            
            if config.get("show_call_analysis", False):
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

                        if config.get("show_call_analysis", False):
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

            if config.get("show_call_analysis", False):
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
            ida_hexrays.mark_cfunc_dirty(func_ea,False)
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
                    if not lvar.is_arg_var:  # Sadece argüman olup olmadığını kontrol et
                        return None
                    
                    # Argümanlar listesindeki sırasını bul
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

            # Create new function details
            new_func_details = ida_typeinf.func_type_data_t()
            new_func_details.rettype = func_details.rettype

            # Calling convention kontrolü
            if func_details.cc == ida_typeinf.CM_CC_THISCALL and len(really_used_params) == 0:
                logger.debug(f"Converting thiscall to cdecl for function at {hex(func_ea)} due to no used parameters")
                new_func_details.cc = ida_typeinf.CM_CC_CDECL
            else:
                new_func_details.cc = func_details.cc

            # Orijinal parametreleri koru ve sadece kullanılanları ekle
            for i in range(len(func_details)):
                if i in really_used_params:
                    param = func_details[i]
                    #param.name = ""  # Parametre ismini boş bırak
                    new_func_details.push_back(param)  # Parametre ismini olduğu gibi koru

            # Thiscall için dummy parametre eklemesi
            if new_func_details.cc == ida_typeinf.CM_CC_THISCALL and len(new_func_details) == 0:
                logger.debug(f"Adding dummy 'this' parameter for thiscall function at {hex(func_ea)}")
                first_param = func_details[0]
                #first_param.name = ""  # Parametre ismini boş bırak
                new_func_details.push_back(first_param)  # İlk parametreyi olduğu gibi koru

            # Create and apply the new type
            new_tinfo = ida_typeinf.tinfo_t()
            new_tinfo.create_func(new_func_details)
            #ida_typeinf.apply_callee_tinfo(func_ea, new_tinfo)

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

    def _determine_calling_convention(self, func_ea, reg_specs):
        """Determine the appropriate calling convention based on register specifications and architecture"""
        logger = DebugLogger.get_instance()
        if not reg_specs:
            return ida_typeinf.CM_CC_CDECL

        # Debug için tüm register bilgilerini yazdır
        logger.debug(f"Analyzing function at {hex(func_ea)}")
        logger.debug(f"Register specifications: {reg_specs}")
        logger.debug(f"Architecture: {'x64' if self.is_64bit() else 'x86'}")

        # Register kullanımını analiz et
        param_regs = []
        return_reg = None
        register_usage = {
            'ecx_used': False,
            'rcx_used': False,
            'xmm0_used': False,
            'xmm1_used': False,
            'ebp_used' : False,
            'esp_used' : False
        }

        # İlk parametre takibi için
        first_param = None
        param_count = 0

        for spec_type, reg in reg_specs:
            reg = reg.lower()
            logger.debug(f"Processing {spec_type}: {reg}")

            if spec_type == 'param':
                if param_count == 0:
                    first_param = reg
                param_count += 1
                
                param_regs.append(reg)
                
                # Register kullanım durumlarını kaydet
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
                elif reg in ["eax","rax","edx","rdx","ebx","rbx"]:
                    break
                    
            elif spec_type == 'return':
                return_reg = reg

        # x64 mimarisi kontrolü
        if self.is_64bit():
            logger.debug("Processing x64 architecture rules")
            
            # Microsoft x64 calling convention (always fastcall)
            # RCX, RDX, R8, R9 veya XMM0-XMM3 kullanımı
            if (register_usage['rcx_used'] or 
                register_usage['xmm0_used'] or 
                first_param in ['rcx', 'xmm0']):
                logger.debug(f"Function at {hex(func_ea)} marked as x64 fastcall")
                return ida_typeinf.CM_CC_FASTCALL
                
        # x86 mimarisi kontrolü
        else:
            logger.debug("Processing x86 architecture rules")
            
            # Thiscall kontrolü (ECX parametresi)
            if register_usage['ecx_used']:
                logger.debug(f"Function at {hex(func_ea)} marked as thiscall due to ecx parameter")
                return ida_typeinf.CM_CC_THISCALL
            if register_usage['ebp_used'] or register_usage['esp_used']:
                logger.debug(f"Function at {hex(func_ea)} marked as cdecl due to stack parameter")
                return ida_typeinf.CM_CC_CDECL
                
            # x86 fastcall kontrolü
            # İlk parametre ECX/XMM0 ise veya belirli register kombinasyonları
            if (first_param in ['ecx', 'xmm0'] or 
                register_usage['xmm0_used']):
                logger.debug(f"Function at {hex(func_ea)} marked as x86 fastcall")
                return ida_typeinf.CM_CC_FASTCALL

        # Varsayılan olarak cdecl döndür
        logger.debug(f"Function at {hex(func_ea)} defaulting to usercall")
        return ida_typeinf.CM_CC_SPECIAL

    def get_function_type(self, func_ea):
        """Get function type from both decompiler and IDA database"""
        # First try to get type from decompiler
        try:
            ida_hexrays.mark_cfunc_dirty(func_ea,False)
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                return str(cfunc.type.dstr())
        except:
            pass

        # If decompiler fails, try to get from IDA database
        return idc.get_type(func_ea)

    def parse_register_specs(self, func_type):
        """Parse register specifications from function type string"""
        reg_specs = []
        try:
            if not func_type or '@<' not in func_type:
                return None

            # Split into parts
            parts = func_type.split('@<')

            # Parse parameter names and their registers
            param_names = {}
            if '(' in func_type and ')' in func_type:
                param_section = func_type.split('(')[1].split(')')[0]
                params = param_section.split(',')
                for param in params:
                    param = param.strip()
                    if '@<' in param:
                        name, reg = param.split('@<')
                        reg = reg.split('>')[0]
                        param_names[reg] = name

            # Check for return register in first part
            return_reg = None
            if len(parts) > 1:
                return_part = parts[0]
                if return_part.endswith('__userpurge') or return_part.endswith('__usercall'):
                    return_reg = parts[1].split('>')[0]
                    reg_specs.append(('return', return_reg))

            # Find all parameter registers
            for part in parts[1:]:
                if '>' in part:
                    reg = part.split('>')[0]
                    # Eğer bu register param_names içinde varsa, bir parametre olarak kullanılıyor demektir
                    if reg in param_names:
                        reg_specs.append(('param', reg))

            return reg_specs if reg_specs else None

        except Exception as e:
            print(f"Error parsing register specs: {str(e)}")
            return None

    def is_imported_function(self, func_ea):
        """Gelişmiş bir kontrolle, işlevin import edilmiş veya bir thunk/stub olup olmadığını belirler"""

        # 1. Bayrakları al
        flags = ida_bytes.get_flags(func_ea)

        # İşlev ise devam et, değilse doğrudan False döndür
        if not ida_bytes.is_func(flags):
            return False

        func = ida_funcs.get_func(func_ea)
        if func:
            # 2. FUNC_THUNK veya FUNC_LIB bayrağını kontrol et
            if func.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
                return True

        # 5. İşlev ismini kontrol et
        func_name = idc.get_func_name(func_ea)
        import_prefixes = ['__imp_', 'j_', 'imp_', '_imp']
        if any(func_name.startswith(prefix) for prefix in import_prefixes):
            return True

        # 6. Demangled isim kontrolü
        demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled_name and any(demangled_name.startswith(prefix) for prefix in import_prefixes):
            return True

        # Import değilse False döndür
        return False

    def has_usercall_convention(self, func_ea):
        """Enhanced check for __usercall/__userpurge convention"""
        logger = DebugLogger.get_instance()
        func_type = self.get_function_type(func_ea)
        if func_type:
            # Check for __usercall or __userpurge keywords
            if ("__usercall" in func_type) or ("__userpurge" in func_type):
                reg_specs = self.parse_register_specs(func_type)
                if reg_specs:
                    logger.debug(f"Found register specifications for {hex(func_ea)}: {reg_specs}")
                    self.print_function_info(func_ea)
                return True

            # Check for register specifications in function type
            if '@<' in func_type:
                reg_specs = self.parse_register_specs(func_type)
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
            func_type = self.get_function_type(func_ea)
            if not func_type:
                logger.debug(f"No type information available for function at {hex(func_ea)}")
                return

            logger.debug(f"\nProcessing function at {hex(func_ea)}")
            logger.debug(f"Original function type: {func_type}")

            if self.has_usercall_convention(func_ea):
                # Parse register specifications
                reg_specs = self.parse_register_specs(func_type)

                if not reg_specs:
                    logger.debug(f"No register specifications found for function at {hex(func_ea)}")
                    return

                logger.debug(f"Found register specs: {reg_specs}")

                # Eğer doğrudan dönüşüm yapılamadıysa calling convention belirle
                new_cc = self._determine_calling_convention(func_ea, reg_specs)
                logger.debug(f"Determined calling convention: {new_cc}")

                # Try to decompile to get current function details
                ida_hexrays.mark_cfunc_dirty(func_ea,False)
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
        calls = []
        func = ida_funcs.get_func(func_ea)
        if not func:
            return calls

        # Her fonksiyondaki çağrıları sıralı şekilde al
        func_items = list(idautils.FuncItems(func_ea))
        for ea in reversed(func_items):  # Tersten dolaş
            if idaapi.is_call_insn(ea):
                call_target = idc.get_operand_value(ea, 0)
                if ida_funcs.get_func(call_target):
                    calls.append(call_target)
        return calls
    
    def collect_layered_call_chain(self, func_ea, max_layers, current_layer=1, visited=None, call_chain=None):
        """Katmanlı çağrı zinciri toplama
        
        Args:
            func_ea: Başlangıç fonksiyonunun adresi
            max_layers: Maksimum katman sayısı (default: 2)
            current_layer: Mevcut katman sayısı
            visited: Ziyaret edilen fonksiyonların seti
            call_chain: Toplanan çağrı zinciri
        """
        if visited is None:
            visited = set()
        if call_chain is None:
            call_chain = []
            
        # Eğer fonksiyon zaten ziyaret edildiyse veya maksimum katmana ulaşıldıysa dur
        if func_ea in visited or current_layer > max_layers:
            return call_chain

        visited.add(func_ea)
        
        # Mevcut katmandaki çağrıları topla
        current_layer_calls = []
        func = ida_funcs.get_func(func_ea)
        if func:
            for ea in idautils.FuncItems(func_ea):
                if idaapi.is_call_insn(ea):
                    target = idc.get_operand_value(ea, 0)
                    if ida_funcs.get_func(target):
                        current_layer_calls.append({
                            'caller_ea': func_ea,
                            'call_ea': ea,
                            'target_ea': target,
                            'layer': current_layer,
                            'processed': False
                        })
        
        # Mevcut katmandaki çağrıları tersine çevir
        current_layer_calls.reverse()
        
        # Mevcut katmandaki çağrıları zincire ekle
        for call in current_layer_calls:
            call_chain.append(call)
            
            # Bir sonraki katmana geç
            if current_layer < max_layers:
                self.collect_layered_call_chain(
                    call['target_ea'],
                    max_layers,
                    current_layer + 1,
                    visited,
                    call_chain
                )
        
        # İlk fonksiyonu da zincire ekle (sadece ilk katman için)
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
                        "unused_param_analysis": True
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
                            
                            # Parameter analysis kontrolü
                            fixer.fix_calling_convention(target_ea)
                            if config["param_analysis"]:
                                fixer._analyze_and_remove_unused_parameters(target_ea)
                            else:
                                if config["func_type_analysis"]:
                                    fixer.fix_calling_convention(target_ea)
                            
                            # View refresh kontrolü
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
