import os
import re

def fix_imports(root_dir, engine_name, modules):
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if not file.endswith('.py'): continue
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            modified = False
            for mod in modules:
                # Replace "from mod." with "from sentrix_core.engine_name.mod."
                pattern = rf"from {mod}\.([a-zA-Z0-9_]+) import"
                replacement = f"from sentrix_core.{engine_name}.{mod}.\\1 import"
                new_content = re.sub(pattern, replacement, content)
                
                # Replace "from mod import" with "from sentrix_core.engine_name.mod import"
                pattern2 = rf"from {mod} import"
                replacement2 = f"from sentrix_core.{engine_name}.{mod} import"
                new_content = re.sub(pattern2, replacement2, new_content)
                
                if new_content != content:
                    content = new_content
                    modified = True
            
            if modified:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Fixed {path}")

if __name__ == '__main__':
    base = os.path.join(os.path.dirname(__file__), "sentrix_core")
    
    pred_dir = os.path.join(base, "prediction_engine")
    pred_mods = ["models", "predictors", "scoring", "services", "storage"]
    fix_imports(pred_dir, "prediction_engine", pred_mods)
    
    inv_dir = os.path.join(base, "investigation_engine")
    inv_mods = ["analyzers", "case_management", "collectors", "evidence", "exporters", "queue", "reporting", "storage", "templates", "playbook_registry"]
    fix_imports(inv_dir, "investigation_engine", inv_mods)

    # Let's also do threat_engine just in case
    threat_dir = os.path.join(base, "threat_engine")
    threat_mods = ["campaign_memory", "context", "correlation", "crisis", "detection", "profiles", "rdf_runtime", "response", "schemas", "scoring", "storytelling"]
    fix_imports(threat_dir, "threat_engine", threat_mods)
    
    print("Done")
