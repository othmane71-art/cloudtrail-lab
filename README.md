# TP CloudTrail — suivi, collecte et analyse de journaux (100 % local, gratuit)

Projet Docker pour un TP de 3 h (cybersécurité, M2/5e année). Aucun compte AWS, aucune carte bancaire.

## ⚠️ Ce qui est réel, ce qui est simulé

| Élément | Statut |
|---|---|
| Docker, AWS CLI, Python, fichiers JSON | Réels |
| S3 et IAM de base dans LocalStack (buckets, utilisateurs, clés, politiques) | **Réels** (émulés par LocalStack) |
| Lignes `AWS s3.CreateBucket => 200` dans `docker logs lab-localstack` | **Réelles**, mais **ce n'est pas CloudTrail** (pas d'identité, pas d'IP, pas de paramètres) |
| Service **CloudTrail** | **Absent** de la version gratuite de LocalStack |
| Application des politiques IAM (vrais `AccessDenied`) | **Non** dans la version gratuite |
| Journaux `data/**` (S3 layout, `dataset_*.json`, `scenarios/`) | **SYNTHÉTIQUES** : fabriqués par `generate_events.py` pour imiter le format CloudTrail |

Les événements synthétiques portent la mention `_lab_notice` et vivent dans un bucket nommé `corp-cloudtrail-logs-synthetic`.
**Ne jamais les présenter comme de vrais journaux CloudTrail.**

## Prérequis
- Docker Desktop (ou Docker Engine) + Docker Compose v2 — `docker compose version`
- ~2 Go de RAM libres, accès Internet **une seule fois** pour télécharger les images
- Windows : lancer les scripts avec `bash scripts/xx.sh` (dans le conteneur, pas besoin de WSL)

## Démarrage rapide (≈ 5 min)
```bash
cp .env.example .env                 # (Windows PowerShell : Copy-Item .env.example .env)
docker compose up -d --build         # démarre LocalStack + conteneur "lab"
docker compose ps                    # localstack doit être "healthy"
docker compose exec lab bash         # shell avec aws + python (tout ce qui suit s'exécute ICI)

bash scripts/00_check_env.sh         # vérifie S3/IAM, constate l'absence de CloudTrail
bash scripts/01_init_aws_local.sh    # buckets, utilisateurs, politiques
python src/generate_events.py        # génère les événements SYNTHÉTIQUES
bash scripts/03_upload_logs.sh       # dépose les .json.gz dans S3 (disposition CloudTrail)
bash scripts/04_collect_and_analyze.sh   # collecte depuis S3 + analyse
```
Résultats : `reports/analysis_report.md`, `reports/findings.json`, `reports/findings.csv`.

Mode sans Docker (seulement Python 3.9+) : `python src/generate_events.py && python src/analyze_logs.py data/s3_layout`

## Contenu
| Chemin | Rôle |
|---|---|
| `docker-compose.yml`, `Dockerfile`, `.env.example`, `requirements.txt` | Environnement |
| `scripts/00…04, 99` | Vérification, initialisation, activité réelle LocalStack, upload, collecte+analyse, reset |
| `src/generate_events.py` | Générateur d'événements **synthétiques** (déterministe, `--seed`) |
| `src/analyze_logs.py` | Analyseur : 9 règles (R01–R09), rapport Markdown/JSON/CSV |
| `src/parse_localstack_logs.py` | Convertit les logs de requêtes LocalStack (réels, mais non-CloudTrail) |
| `data/` | Jeux de test générés (seed 42) ; `data/scenarios/S1…S6` = événements isolés |
| `reports/` | Rapport d'analyse généré (exemple, seed 42) |
| `config/dev-policy.json` | Politique IAM volontairement fautive de `bob` |
| `tests/test_pipeline.py` | Tests de cohérence génération → analyse |
| `teacher/` | **Corrigé : `answer_key.json`, `evaluate.py`, `CORRIGE.md` — retirer avant distribution** |
| `student_templates/rapport_investigation.md` | Gabarit du rapport |

## Les 6 scénarios (tous dans la même chaîne d'attaque, 29/10/2026 UTC)
| Id | Scénario | Événement(s) clé(s) | Règle |
|---|---|---|---|
| S5 | Connexion console sans MFA | `ConsoleLogin` (MFAUsed=No), 3 échecs avant | R01, R07 |
| S6 | Accès refusés | `AccessDenied` ×4 (IAM, S3) | R06 |
| S2 | Privilèges administrateur | `AttachUserPolicy` AdministratorAccess | R02 |
| S1 | Clé d'accès non autorisée | `CreateAccessKey` pour un autre utilisateur + 1er usage | R03 |
| S3 | Suppression de bucket | `DeleteBucket corp-backups-prod` | R04 |
| S4 | Désactivation de la journalisation | `DeleteTrail` refusé, `StopLogging` réussi → trou de 71 min | R05, R08 |

Leurres bénins (à ne pas sur-alerter) : 1 échec de login isolé, rotation de clé par son propriétaire, `ReadOnlyAccess`, suppression d'un bucket de test, 1 accès refusé isolé.

## Plans de secours
1. **L'image LocalStack ne démarre pas / demande un token.** Depuis mars 2026, `localstack/localstack:latest` exige un compte (plan gratuit *Hobby*, usage non commercial) et un `LOCALSTACK_AUTH_TOKEN`. Ce projet épingle `localstack/localstack:4.14` (indiqué comme dernière version sans token : **vérifiez `docker pull localstack/localstack:4.14` avant le cours**). Sinon : créez un compte Hobby, mettez le token et `LOCALSTACK_IMAGE=localstack/localstack:latest` dans `.env`.
2. **LocalStack indisponible → moto.** `docker compose --profile backup up -d moto lab`, puis `LAB_ENDPOINT=http://moto:4566` dans `.env` et `docker compose up -d lab`. (S3/IAM suffisent ; `moto` télécharge son paquet au 1er lancement.)
3. **Aucun conteneur possible → Python seul.** Le générateur et l'analyseur n'ont aucune dépendance. Les parties S3 sont remplacées par la lecture directe de `data/s3_layout`.
4. **`AdministratorAccess` refusé (politique gérée absente).** Créer une politique équivalente : `aws iam create-policy --policy-name AdministratorAccess --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'` puis l'attacher via son ARN `arn:aws:iam::000000000000:policy/AdministratorAccess`.
5. **Ports** : 4566 déjà utilisé → modifier le mapping dans `docker-compose.yml`.

## Tests effectués par l'auteur du projet
- ✅ `python -m unittest discover -s tests -v` (6 tests : déterminisme, 6/6 scénarios ≥ HIGH, pas de leurre ≥ HIGH, trou de journal, cohérence des champs)
- ✅ Syntaxe `bash -n` de tous les scripts ; validation YAML de `docker-compose.yml` ; validation JSON des données
- ✅ Chaîne upload S3 → collecte → analyse validée avec un **faux** AWS CLI local
- ⚠️ **Non testé** (pas de Docker dans l'environnement de rédaction) : démarrage réel de LocalStack, `docker compose build`, commandes AWS CLI contre LocalStack réel (comportement de `aws iam attach-user-policy …AdministratorAccess`, format exact des logs `localstack.request.aws`). **Faites un essai complet avant le cours.**

## Réinitialiser
`bash scripts/99_reset.sh` (sorties locales) ; hôte : `docker compose down -v` (état LocalStack) ; `python src/generate_events.py` régénère les données.
