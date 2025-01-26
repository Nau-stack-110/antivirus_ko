import yara
import os
def load_lalana(rule_files):
    try:
      rules = {}
      for file_type, rule_path in rule_files.items():
          rules[file_type] = yara.compile(filepath=rule_path)
          print("Toutes les Règles Yara chargé avec succès.")
      return rules
    except yara.SyntaxError as e:
      print(f"Erreur de syntaxe dans Yara: {e}")
      return None
    except Exception as e:
      print(f"Erreur lors du chargement de Yara: {e}")
      return None
  
def analyze_files(file_path, rules):
    file_extension = os.path.splitext(file_path)[1].lower()
    file_name = os.path.basename(file_path)
    print(f"Analyse de {file_name}...")
    if file_extension == ".exe":
        rule = rules.get("exe")
    elif file_extension == ".py":
        rule = rules.get("python")
    elif file_extension == ".txt":
        rule = rules.get("text")
    elif file_extension == ".sh":
        rule = rules.get("bash")
    else:
        print(f"Aucun règle trouvé pour le type: {file_extension}")
        return
    try:            
        matches = rule.match(file_path)
        if matches:
                print(f"Fichier suspect : {file_name} (correspondances: {matches})")
        else:
                print(f"Fichier sur: {file_name}")
    except Exception as e:  
                print(f"Erreur lors de l'analyse de {file_name}: {e}")

def main():
    rule_files = {
        "exe":"lalana_malware_exe.yar",
        "python":"lalana_malware_python.yar",
        "text":"lalana_malware_text.yar",
        "bash":"lalana_malware_bash.yar"
    }
    rules = load_lalana(rule_files)
    if not rules:
        return
    
    directory = "fichier_exe"
    
    if not os.path.isdir(directory):
        print("Le repertoire spécifié n'existe pas.")
        return
    
    print(f"Analyse des fichiers dans : {directory}") 
    for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):
                analyze_files(file_path, rules)
    
if __name__ == "__main__":
    main()