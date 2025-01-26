import yara
import os
def load_lalana(rule_path):
    try:
      rules = yara.compile(filepath=rule_path)
      print("Règles Yara chargé avec succès.")
      return rules
    except yara.SyntaxError as e:
      print(f"Erreur de syntaxe dans Yara: {e}")
      return None
    except Exception as e:
      print(f"Erreur lors du chargement de Yara: {e}")
      return None
  
def analyze_files(directory, rules):
    if not os.path.isdir(directory):
        print("Le repertoire spécifié n'existe pas.")
        return
    print(f"Analyse des fichiers dans : {directory}") 
    for file_name in os.listdir(directory):
        if file_name.endswith(".exe"):
            file_path = os.path.join(directory, file_name)
            print(f"Analyse {file_name}...")
            try:
                matches = rules.match(file_path)
                if matches:
                    print(f"Fichier suspect : {file_name} (correspondances: {matches})")
                else:
                    print(f"Fichier sur: {file_name}")
            except Exception as e:
                print(f"Erreur lors de l'analyse de {file_name}: {e}")

def main():
    rule_path = "lalana_malware.yar"
    directory = "fichier_exe"
    rules = load_lalana(rule_path)
    if not rules:
        return
    
    analyze_files(directory, rules)
    
if __name__ == "__main__":
    main()