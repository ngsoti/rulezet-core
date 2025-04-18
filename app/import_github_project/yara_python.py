import plyara
import os

def extraire_regles_yara(fichier_yara):
    if not os.path.exists(fichier_yara):
        print(f"Le fichier YARA {fichier_yara} n'existe pas.")
        return
    # Initialiser le parseur Plyara
    parser = plyara.Plyara()

   

    with open(fichier_yara, 'r') as file:
        yara_rules = file.read()

    # Parser le contenu du fichier
    parsed_rules = parser.parse_string(yara_rules)

    # Vérification de la structure et affichage des règles
    for rule_info in parsed_rules:
        print(f"Nom de la règle : {rule_info['rule_name']}")
        
        # Vérification et affichage des métadonnées
        if 'metadata' in rule_info:
            print(f"Métadonnées : {rule_info['metadata']}")
        else:
            print("Pas de métadonnées")

        # Affichage des chaînes
        if 'strings' in rule_info:
            print(f"Chaînes : {rule_info['strings']}")
        else:
            print("Pas de chaînes définies")
        
        # Affichage des conditions
        if 'condition_terms' in rule_info:
            print(f"Conditions : {rule_info['condition_terms']}")
        else:
            print("Pas de conditions")


