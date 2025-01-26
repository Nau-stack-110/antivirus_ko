from gtts import gTTS

texts = {
    "10":"Dix",
    "9" :"Neuf",
    "8": "Huit",
    "7":"Sept",
    "6":"six",
    "5":"Cinq",
    "4":"Quatre",
    "3":"Trois",
    "2":"Deux",
    "1":"Un",
    "0":"Zéro",
    "bonne_année":"Bonne année 2025 !"
}
for filename, text in texts.items():
    tts= gTTS(text, lang="fr")
    tts.save(f"{filename}.mp3")
    
print("Fichiers audio génerés avec succès !")