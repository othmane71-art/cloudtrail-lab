# Rapport d'analyse automatique de journaux de type CloudTrail

> **Avertissement** : si l'entrée est `data/s3_layout` ou `data/dataset_*.json`, ces événements sont **synthétiques** (générés par `generate_events.py`). Ils ne proviennent pas d'un vrai CloudTrail.

## 1. Périmètre

- Fichiers lus : 1 (illisibles : 0)
- Événements uniques analysés : **4**
- Période couverte : 2026-11-16T17:48:23Z -> 2026-11-16T17:48:24Z
- Plages IP de confiance : `198.51.100.0/24,10.0.0.0/8,172.20.0.0/16` | seuil de silence : 30 min

## 2. Synthèse des alertes

| Sévérité | Nombre |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

| Règle | Titre | Alertes | MITRE ATT&CK |
|---|---|---|---|
| R01 | Connexion console sans MFA | 0 | T1078.004 Valid Accounts: Cloud Accounts |
| R02 | Attribution de privilèges administrateur | 0 | T1098.003 Account Manipulation: Additional Cloud Roles |
| R03 | Clé d'accès non autorisée / usage suspect | 0 | T1098.001 Account Manipulation: Additional Cloud Credentials |
| R04 | Suppression de bucket S3 | 0 | T1485 Data Destruction |
| R05 | Altération de la journalisation CloudTrail | 0 | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| R06 | Accès refusé(s) à des ressources | 0 | T1580 Cloud Infrastructure Discovery / T1087.004 Cloud Account Discovery |
| R07 | Échecs de connexion console répétés | 0 | T1110 Brute Force |
| R08 | Trou de journalisation | 0 | T1562.008 Impair Defenses: Disable or Modify Cloud Logs |
| R09 | Activité depuis une IP hors périmètre | 0 | T1078.004 Valid Accounts: Cloud Accounts |

## 3. Alertes de sévérité MEDIUM ou plus

## 4. Alertes LOW / INFO (à trier - candidats faux positifs)

Aucune.

## 5. Chronologie de l'incident (activité des IP externes suspectes)

Aucune IP externe associée à une alerte HIGH/CRITICAL.

## 6. Fenêtres de journalisation interrompue

Aucun trou détecté.

## 7. Mesures correctives recommandées (par règle déclenchée)


## 8. Limites de l'analyse

- Règles à seuils fixes : elles n'identifient pas tout et génèrent des faux positifs (cf. section 4).
- Un attaquant qui coupe la journalisation rend ses actions invisibles : croiser avec d'autres sources.
- Les événements de données S3 n'existent que si les *data events* sont activés sur la trail.
- Les verdicts sont des **hypothèses d'investigation**, à confirmer auprès des personnes concernées.
