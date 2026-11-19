# ARKS — AURUM Research Knowledge System

ARKS est un outil documentaire local : conservation des sources admises, recherche
et vérification des passages exacts avec empreintes et provenance. L'interface
est en français, avec catalogue, filtres, thèmes et consultation des sources.
Il ne génère pas de réponses par IA.

Cette préparation publique contient le code, les schémas, l'interface et des tests
synthétiques. Elle ne contient aucun corpus de travail, base, index, modèle ni
rapport interne. Le démarrage proposé utilise un petit texte entièrement fictif.

## Pourquoi ARKS existe

ARKS est né d’une réflexion sur la place de l’intelligence artificielle dans une
chaîne de recherche en trading systématique. Si une IA aide à formuler des
hypothèses, comment revenir au document qui les a inspirées et vérifier ce qu’il
dit exactement ?

Dans AURUM, ARKS tient ce rôle documentaire. Il retrouve des passages et permet
de les vérifier dans leur source. ADAM s’appuie sur ce travail pour formuler des
hypothèses de recherche. Les backtests servent ensuite à éprouver ces hypothèses
sur des données de marché.

## Installation sous Windows

Prérequis : Windows et Python **3.14, 64 bits**, installés sur la machine.
Les commandes suivantes s'exécutent dans PowerShell, à la racine du dépôt.
Aucun lecteur ou dossier d'installation particulier n'est requis.

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-public.lock.txt
```

La première installation télécharge les dépendances depuis PyPI. Le lancement
et la recherche de démonstration fonctionnent ensuite localement, sans accès réseau
externe et sans compte ni clé API. Il n'est pas nécessaire d'activer le venv.

## Lancer l'exemple fictif

```powershell
.\.venv\Scripts\python.exe -I -B tools\public_demo.py serve
```

Ou double-cliquez sur `LANCER_DOCUMENTAIRE.cmd` après l'installation.
Ouvrez l'adresse `http://127.0.0.1:...` affichée, puis saisissez le code de session
du terminal. Recherchez **luminosité** : le passage fictif du capteur Azur contient
« 42 unités ». Arrêt : **Ctrl+C** dans le terminal.

Autres commandes :

```powershell
.\.venv\Scripts\python.exe -I -B tools\public_demo.py search luminosité
.\.venv\Scripts\python.exe -I -B tools\public_demo.py status
.\.venv\Scripts\python.exe -I -B tools\run_public_checks.py
```

Le fichier `examples/observatoire.txt` est l'unique source de cette démonstration.
La politique d'admission et la base sont créées localement dans `data/public_demo/`.
Les rapports et rendus sont générés sous `reports/`. Ces dossiers sont ignorés par
Git. Les relancements réutilisent la base et vérifient la source ; le code de session
change à chaque démarrage. Ne partagez pas ce code. Le serveur écoute uniquement
sur la boucle locale et est destiné à un opérateur local.

## Périmètre des fonctions

Le démarrage public utilise la **recherche lexicale** sur le texte fictif.
Il permet de vérifier l'interface, l'authentification, la conservation des octets
et les passages sourcés sans utiliser de données privées.

Le code des fonctions hybrides ONNX, de traduction locale FR→EN, d'ingestion PDF,
de versions et de provenance est conservé dans `src/aurum_arks/`. Ces fonctions
nécessitent une configuration explicite, des modèles et un index construits sur
des documents dont vous possédez les droits. Elles ne sont pas activées dans la
démonstration, et leur fonctionnement complet n'est pas validé par les tests publics.
Les scripts de campagnes et de qualification du corpus privé ne sont pas fournis.

`tools/documentary.py` est l'entrée opérateur pour une politique et une base locales :

```powershell
.\.venv\Scripts\python.exe -I -B tools\documentary.py --data data\public_demo\vault --config data\public_demo\POLICY.json search luminosité
```

La commande `serve` de cet outil est lexicale par défaut ; `serve --hybrid` exige
les dépendances RAG, les modèles, un index actif et une politique correctement préparés.
Les fichiers `requirements-rag*.lock.txt` conservent les dépendances de la source
pour référence ; ils ne sont ni nécessaires ni validés pour le parcours de démonstration.
Le groupe optionnel `rag` du `pyproject.toml` décrit les dépendances directes ONNX.

Les lecteurs PDF sont optionnels et isolés. Les chemins par défaut se situent dans
`.venv_pdf`, `.venv_pdf_passive` et `.venv_pdf_native` à la racine du dépôt. Les variables
`ARKS_PDF_PYTHON`, `ARKS_PASSIVE_PYTHON`, `ARKS_NATIVE_PYTHON` peuvent les remplacer par
des chemins absolus d'interpréteurs locaux. Les profils du code exigent notamment
pypdf 6.19.0 et, selon le profil, pypdfium2 et pdfminer.six 20260107. Leur installation
et leur qualification PDF ne sont pas couvertes par cette préparation. L'absence
de ces environnements n'empêche pas de lancer la démonstration TXT.

## Confidentialité du dépôt

Ne versionnez jamais les corpus personnels, données, index, modèles, politiques
locales, rapports de travail, bases, journaux, sauvegardes ni secrets.
`.gitignore` exclut les emplacements standards et plusieurs formats sensibles.
Avant tout ajout Git, contrôlez aussi les fichiers placés dans d'autres dossiers :
une règle d'exclusion ne remplace pas une revue du contenu.

## Licence

Le code d’ARKS est accessible au public. Son installation et son utilisation
sont gratuites pour un usage strictement personnel, privé et non commercial,
selon les conditions de [LICENSE.txt](LICENSE.txt).

Toute exploitation commerciale, y compris la revente, l’intégration dans une
offre payante ou l’utilisation dans une activité professionnelle à but lucratif,
nécessite un accord écrit préalable avec le titulaire des droits. Les conditions
de rémunération sont définies dans cet accord. Les dépendances tierces restent
soumises à leurs propres licences.
