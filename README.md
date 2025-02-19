

---

# Retrospective Analysis IDA Pro Plugin

**Retrospective Analysis** is a plugin for **IDA Pro** that accelerates and simplifies reverse engineering. It performs a comprehensive backward analysis of function calls using a layered system, predicts and modifies function types, and removes unused parameters. The analysis starts directly from the **context menu of the decompiled view**, ensuring a seamless integration into your workflow.

---

### Features

#### 🔍 Function Call Layer Analysis  
The analysis begins from the selected function and iteratively scans the call hierarchy up to a user-defined depth (1–10 layers). Each layer represents a group of function calls, enabling detailed examination of call relationships.

#### 🛠️ Parameter Optimization  
Analyzes function call types (e.g., `__thiscall`, `__stdcall`), modifies them, and removes unused parameters afterward.

#### ⚙️ Function Call Type Analysis  
Identifies inconsistencies and common patterns in function call types to improve function signatures.

#### 🚀 Unused Parameter Analysis in Call References  
Detects and removes redundant parameters from call references, ensuring cleaner and more optimized function signatures.

#### 🔄 Enhanced Backward Analysis Engines  
Choose the best approach for your analysis with two user-selectable engines:
- **Hex-Rays Compiler Based Engine:** Utilizes the Hex-Rays library to backward compile functions and analyze calls.
- **IDA API Based Engine:** Analyzes raw machine code to backward compile functions and inspect call relationships.

#### 🔧 Automated Virtual Call Corrections  
Automatically corrects virtual call types and parameters, deleting any unused parameters for a more accurate signature.

#### ⚡ Improved Call Type and Parameter Analysis  
Incorporates new methods for enhanced accuracy in determining call types and parameters. This update now supports the previously unsupported **usercall** and **userpurge** rules, allowing for more effective detection and correction of signature issues.

#### 🖥️ Easy Integration  
Start the analysis directly from the context menu in the decompiled view.

#### 🔄 Automatic Refresh  
The decompiled view is automatically refreshed after any modifications.

---

### How to Use

1. **Select a Function**  
   Open the **decompiled view** in IDA Pro and right-click the function you want to analyze.

2. **Start the Analysis**  
   Choose **Retrospective Analysis** from the context menu.

   ![Context Menu](https://github.com/user-attachments/assets/49540f7c-52ee-4db9-b63b-6fc6d7ed23e1)

3. **Configure Analysis Settings (Optional)**  
   Adjust the analysis depth (1–10 layers) and select your preferred analysis engine if needed.

   ![Settings Menu](https://github.com/user-attachments/assets/0f0fa637-9c9b-4255-b216-cbfec3adea5d)

4. **Review the Results**  
   The plugin automatically corrects call types, removes unused parameters, and updates the decompiled view with the changes.

---

### Installation

1. Download the latest release from [GitHub Releases](#).  
2. Place the plugin file in the `plugins` directory of your IDA Pro installation.  
3. Restart IDA Pro. The plugin will then appear in the context menu of the decompiled view.

---

### Future Improvements

- **Return Type Analysis:** Enhancing the analysis to automatically detect and adjust function return types.

---

Your new update lets you choose the best backward analysis engine for your scenario and delivers better accuracy when dealing with complex or unusual calling conventions. Contributions and feedback—especially regarding further automation and additional analysis capabilities—are highly welcome.

Feel free to fork the repository, submit pull requests, and help further improve the plugin!
