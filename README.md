---

# Retrospective Analysis IDA Pro Plugin  

**Retrospective Analysis** is a plugin compatible with **IDA Pro** that enhances the reverse engineering process. It performs backward analysis of function calls using a layered system, predicts and modifies function types, and removes unused parameters after these modifications. This process aims to accelerate and simplify the analysis workflow for reverse engineers.  

The analysis integrates seamlessly into your workflow, starting directly from the **context menu of the decompiled view**.  

---



![RA1](https://github.com/user-attachments/assets/49540f7c-52ee-4db9-b63b-6fc6d7ed23e1)


![RA2](https://github.com/user-attachments/assets/35d77173-c305-4adf-9f19-aa7cc99bd20b)






### Features  

#### 🔍 Function Call Layer Analysis  
The analysis begins from the selected function and iteratively scans the call hierarchy up to a user-defined depth (1-10 layers). Each layer represents a group of function calls, enabling a detailed examination of call relationships.  

#### 🛠️ Parameter Optimization  
Analyzes function call types (e.g., `__thiscall`, `__stdcall`), modifies them, and removes unused parameters afterward.  

#### ⚙️ Function Call Type Analysis  
Analyzes function call types, identifies inconsistencies or common patterns, and improves the function signature.  

#### 🖥️ Easy Integration  
Start the analysis directly from the context menu in the decompiled view (as shown in the image).  

#### 🔄 Automatic Refresh  
Automatically refreshes the decompiled view after making changes.  

---

### How to Use?  

1. **Select a Function**  
   Open the **decompiled view** in IDA Pro and right-click the function you want to analyze.  

   ![Context Menu]([image.png](https://github.com/user-attachments/assets/18ea7cc3-dcd6-44c6-8de3-3cdc97791879))  

2. **Start the Analysis**  
   Select **Retrospective Analysis** from the context menu.  

3. **Optionally Configure Analysis Settings**  
   Adjust the analysis depth (1-10 layers) and start the analysis.  

4. **Review the Results**  
   The plugin modifies call types and cleans up unused parameters. Review these changes in the **decompiled view**.  

---

### Known Limitations  

1. **Virtual Call Handling**  
   Virtual calls must currently be adjusted manually.  

2. **Return Type Analysis**  
   Planned for future releases.  

3. **Accuracy**  
   While the analysis achieves a high accuracy rate in identifying call types and unused parameters, incorrect results may still occur. Manual review is recommended.  

---

### Installation  

1. Download the latest release from [GitHub Releases](#).  
2. Place the plugin file in the `plugins` directory of your IDA Pro installation.  
3. Restart IDA Pro. The plugin will appear in the context menu of the decompiled view.  

---

### Future Improvements  

1. Automating virtual call type corrections *(For now, this must be done manually because I have yet to determine which library function to call to modify the types of these virtual calls).*  
2. Adding return type analysis functionality.  

---

### Contribute  

We welcome your contributions! Fork the repository, submit a pull request, and help improve the plugin. Feedback and suggestions, especially for automating virtual call handling and return type analysis, are highly valued.  

---  
