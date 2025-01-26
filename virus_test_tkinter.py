import yara
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD

def load_rules(rule_files):
    try:
        rules = {}
        for file_type, rule_path in rule_files.items():
            rules[file_type] = yara.compile(filepath=rule_path)
        print("✅ Toutes les règles YARA chargées avec succès.")
        return rules
    except yara.SyntaxError as e:
        messagebox.showerror("Erreur", f"Erreur de syntaxe dans les règles YARA : {e}")
    except Exception as e:
        messagebox.showerror("Erreur", f"Erreur lors du chargement des règles YARA : {e}")
    return None

def analyze_file(file_path, rules):
    file_extension = os.path.splitext(file_path)[1].lower()
    file_name = os.path.basename(file_path)

    print(f"🔍 Analyse de {file_name}...")

    # Sélectionner la règle appropriée
    if file_extension == ".exe":
        rule = rules.get("exe")
    elif file_extension == ".py":
        rule = rules.get("python")
    elif file_extension == ".txt":
        rule = rules.get("text")
    elif file_extension == ".sh":
        rule = rules.get("bash")
    else:
        print(f"⚠️ Aucun règle trouvée pour le type : {file_extension}")
        messagebox.showwarning("Alerte", f"Aucune règle disponible pour le fichier : {file_name}")
        return

    try:
        matches = rule.match(file_path)
        if matches:
            result = f"⚠️ Fichier suspect : {file_name}\nCorrespondances : {matches}"
            messagebox.showwarning("Résultat de l'analyse", result)
            print(result)
        else:
            result = f"✅ Fichier sûr : {file_name}"
            messagebox.showinfo("Résultat de l'analyse", result)
            print(result)
    except Exception as e:
        error = f"❌ Erreur lors de l'analyse de {file_name} : {e}"
        messagebox.showerror("Erreur", error)
        print(error)

def analyze_directory(directory, rules):
    if not os.path.isdir(directory):
        messagebox.showerror("Erreur", "Le dossier spécifié n'existe pas.")
        return

    print(f"📂 Analyse des fichiers dans : {directory}")
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        if os.path.isfile(file_path):
            analyze_file(file_path, rules)

def choose_file():
    file_path = filedialog.askopenfilename(title="Sélectionner un fichier")
    if file_path:
        analyze_file(file_path, rules)

def choose_directory():
    directory = filedialog.askdirectory(title="Sélectionner un dossier")
    if directory:
        analyze_directory(directory, rules)

def handle_drop(event):
    """Gérer le glisser-déposer."""
    file_path = event.data.strip()
    if file_path.startswith("{") and file_path.endswith("}"):
        file_path = file_path[1:-1] 
    if os.path.isfile(file_path):
        analyze_file(file_path, rules)
    elif os.path.isdir(file_path):
        analyze_directory(file_path, rules)

def main():
    global rules
    rule_files = {
        "exe": "lalana_malware_exe.yar",
        "python": "lalana_malware_python.yar",
        "text": "lalana_malware_text.yar",
        "bash": "lalana_malware_bash.yar"
    }

    rules = load_rules(rule_files)
    if not rules:
        return

    root = TkinterDnD.Tk()
    root.title("Analyseur de fichiers avec YARA")
    root.geometry("500x400")

    title = tk.Label(root, text="Analyseur de Fichiers avec YARA", font=("Helvetica", 16))
    title.pack(pady=10)

    # Instructions
    instructions = tk.Label(root, text="Glissez-déposez un fichier ou un dossier ici,\nou utilisez les boutons ci-dessous pour analyser.")
    instructions.pack(pady=5)

    # Zone de glisser-déposer
    drop_area = tk.Label(root, text="📂 Glissez un fichier ou dossier ici", bg="lightgray", width=40, height=5)
    drop_area.pack(pady=10)
    drop_area.drop_target_register(DND_FILES)
    drop_area.dnd_bind("<<Drop>>", handle_drop)

    # Boutons
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    file_button = tk.Button(button_frame, text="Analyser un fichier", command=choose_file)
    file_button.grid(row=0, column=0, padx=10)

    directory_button = tk.Button(button_frame, text="Analyser un dossier", command=choose_directory)
    directory_button.grid(row=0, column=1, padx=10)

    root.mainloop()

if __name__ == "__main__":
    main()