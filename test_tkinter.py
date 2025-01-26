import os
import yara
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD

# Fonction pour charger les règles YARA
def load_rules(rule_path):
    try:
        rules = yara.compile(filepath=rule_path)
        print("✅ Règles YARA chargées avec succès.")
        return rules
    except yara.SyntaxError as e:
        print(f"❌ Erreur de syntaxe dans les règles YARA : {e}")
        return None
    except Exception as e:
        print(f"❌ Erreur lors du chargement des règles YARA : {e}")
        return None

# Fonction pour analyser un fichier avec les règles YARA
def analyze_file(file_path, rules):
    if not os.path.isfile(file_path):
        messagebox.showerror("Erreur", "Fichier invalide ou introuvable.")
        return

    print(f"🔍 Analyse de {file_path}...")
    try:
        matches = rules.match(file_path)
        if matches:
            result = f"⚠️ Fichier suspect détecté : {os.path.basename(file_path)}\nCorrespondances : {matches}"
            messagebox.showwarning("Résultat de l'analyse", result)
        else:
            result = f"✅ Fichier sûr : {os.path.basename(file_path)}"
            messagebox.showinfo("Résultat de l'analyse", result)
        print(result)
    except Exception as e:
        error = f"❌ Erreur lors de l'analyse : {e}"
        print(error)
        messagebox.showerror("Erreur", error)

# Fonction pour gérer le glisser-déposer
def handle_drop(event):
    file_path = event.data.strip()
    if file_path.startswith("{") and file_path.endswith("}"):
        file_path = file_path[1:-1] # Corrige les chemins entourés de { }
    analyze_file(file_path, rules)

# Fonction pour choisir un fichier via un sélecteur
def choose_file():
    file_path = filedialog.askopenfilename(title="Sélectionner un fichier")
    if file_path:
        analyze_file(file_path, rules)

# Configuration principale de l'interface Tkinter
def main():
    global rules
    # Charger les règles YARA
    rule_path = "lalana_malware.yar"
    rules = load_rules(rule_path)
    if not rules:
        return

    # Créer l'interface Tkinter avec support du glisser-déposer
    root = TkinterDnD.Tk()
    root.title("Analyseur de fichiers avec YARA")
    root.geometry("500x300")

    # Titre
    title = tk.Label(root, text="Analyseur de Fichiers avec YARA", font=("Helvetica", 16))
    title.pack(pady=10)

    # Instructions
    instructions = tk.Label(root, text="Glissez-déposez un fichier ici ou cliquez sur le bouton pour choisir un fichier.")
    instructions.pack(pady=5)

    # Zone de glisser-déposer
    drop_area = tk.Label(root, text="📂 Glissez votre fichier ici", bg="lightgray", width=40, height=5)
    drop_area.pack(pady=10)
    drop_area.drop_target_register(DND_FILES)
    drop_area.dnd_bind("<<Drop>>", handle_drop)

    # Bouton pour choisir un fichier
    browse_button = tk.Button(root, text="Choisir un fichier", command=choose_file)
    browse_button.pack(pady=5)

    # Lancer l'application Tkinter
    root.mainloop()

if __name__ == "__main__":
    main()