# Investigation d’un incident de sécurité AWS — Environnement local avec Floci

Auteur : ABIDI Othmane
Date de l’analyse : 17 novembre 2026
Jeu de données : événements synthétiques, seed 42

## 1. Résumé exécutif

L’analyse d’un jeu de 265 événements synthétiques met en évidence une chaîne de compromission simulée visant une infrastructure AWS.
Le 29 octobre 2026, l’identité bob est utilisée depuis une IP extérieure au périmètre défini, après trois échecs de connexion puis un succès sans MFA.
La séquence comprend une élévation de privilèges, la création d’une clé pour svc-backup, la suppression d’un bucket de sauvegardes et l’arrêt de la journalisation.
Une interruption de visibilité de 71 minutes et 7 secondes empêche de déterminer les actions réalisées pendant cette période.
Les événements de réponse montrent la reprise de la journalisation et la désactivation de la clé créée ; ils ne démontrent pas une remédiation complète.

## 2. Périmètre et sources

### Objectif du projet

Pratiquer l’utilisation des API AWS en environnement local et la démarche d’investigation de journaux au format CloudTrail : collecte, détection, corrélation, chronologie et proposition de mesures correctives.

### Environnement technique

- Hôte Windows avec Docker Desktop et Docker Compose.
- Floci comme émulateur local de services AWS.
- Conteneur lab-shell pour l’utilisation de l’AWS CLI, de Python et de jq.
- Point d’accès de Floci publié uniquement sur 127.0.0.1:4566 côté hôte.
- Aucun compte AWS réel utilisé.

### Sources de l’investigation

- Jeu synthétique principal : data/dataset_full.json.
- Extraits des six scénarios : data/scenarios/.
- Fichiers compressés organisés selon une arborescence de livraison CloudTrail : data/s3_layout/.
- Bucket de dépôt et de collecte : corp-cloudtrail-logs-synthetic.
- Copie collectée depuis S3 : collected/.
- Analyseur : src/analyze_logs.py.
- Résultats : reports/analysis_report.md, reports/findings.json et reports/findings.csv.
- Configuration IAM étudiée : config/dev-policy.json.

### Volume analysé et paramètres

Le jeu contient 265 événements : 247 événements normaux ou leurres et 18 événements d’attaque et de réponse. Les événements sont répartis dans 114 fichiers compressés.

L’analyse de référence utilise un seuil de détection des interruptions de 15 minutes. Elle produit 20 alertes : 9 CRITICAL, 2 HIGH, 2 MEDIUM, 6 LOW et 1 INFO. Ces alertes ne correspondent pas à 20 incidents distincts : plusieurs règles peuvent signaler une même séquence.

La chronologie de l’incident étudié se déroule le 29 octobre 2026, de 02:11:07 à 03:58:30 UTC. Des événements du 28 octobre servent de contexte pour comparer les activités habituelles et les cas bénins.

### Nature des données

Les événements de cette investigation sont fabriqués par src/generate_events.py et portent la mention _lab_notice. Ils imitent le format CloudTrail mais ne proviennent pas du service AWS CloudTrail.

Les journaux natifs produits séparément par Floci et leurs analyses dans reports/native/ et reports/native-tuned/ ne sont pas utilisés pour prouver la chaîne d’incident décrite dans ce rapport.

Les identités, clés et adresses IP du scénario sont des données de démonstration. Les plages considérées comme internes ou externes sont celles définies pour ce projet.

## 3. Chronologie (UTC)

Tous les événements ci-dessous sont synthétiques et datent du 29 octobre 2026. Les résultats sont interprétés à partir des champs ConsoleLogin, errorCode et requestParameters.

| Heure UTC | Acteur | IP | Action | Résultat et interprétation | Preuve (eventID) | Scénario |
|---|---|---|---|---|---|---|
| 02:11:07 | bob | 203.0.113.66 | ConsoleLogin | Premier échec de connexion | 4970ed9a-09ce-4cfb-a339-ba1925637cc3 | S5 |
| 02:11:31 | bob | 203.0.113.66 | ConsoleLogin | Deuxième échec de connexion | b49e04cc-c243-49e7-a387-eaf6d4c3a832 | S5 |
| 02:11:52 | bob | 203.0.113.66 | ConsoleLogin | Troisième échec de connexion | 41843b03-04dd-4054-9448-23f7e7e646c7 | S5 |
| 02:14:30 | bob | 203.0.113.66 | ConsoleLogin | Connexion réussie sans MFA | 871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1 | S5 |
| 02:16:02 | bob | 203.0.113.66 | ListUsers | Refus : AccessDenied | b7f28572-3def-4849-9336-4f7e83efa9f3 | S6 |
| 02:16:40 | bob | 203.0.113.66 | ListRoles | Refus : AccessDenied | 40ef3935-5f90-4ed6-bb25-664d630aa767 | S6 |
| 02:17:25 | bob | 203.0.113.66 | GetBucketPolicy | Refus sur corp-finance-secrets : AccessDenied | 10275b53-2285-42ef-8fbe-4fe92ea9c542 | S6 |
| 02:18:03 | bob | 203.0.113.66 | GetObject | Refus sur corp-finance-secrets/2026/payroll.xlsx : AccessDenied | 0c3ce284-c7e5-4bbb-9cb5-1c535b62a8df | S6 |
| 02:21:40 | bob | 203.0.113.66 | AttachUserPolicy | Attribution d’AdministratorAccess à bob, sans erreur déclarée | 6cac028c-ba22-4065-9526-0718cd180a82 | S2 |
| 02:23:15 | bob | 203.0.113.66 | CreateAccessKey | Création de la clé AKIALABROGUE00000001 pour svc-backup, sans erreur déclarée | e95f176c-deba-4186-ba10-82170ad7c9a2 | S1 |
| 02:26:48 | svc-backup | 203.0.113.66 | GetCallerIdentity | Utilisation de la clé AKIALABROGUE00000001, sans erreur déclarée | ca9e4a62-fae3-414b-a3b4-42bd46494296 | S1 |
| 02:31:12 | bob | 203.0.113.66 | ListBuckets | Inventaire des buckets, sans erreur déclarée | add702c9-2747-493c-9ae7-7eab084a6780 | Préparation S3 |
| 02:33:05 | bob | 203.0.113.66 | DeleteBucket | Suppression de corp-backups-prod, sans erreur déclarée | 1e2595b8-8fc9-486b-a9dd-ebf563119aca | S3 |
| 02:39:20 | bob | 203.0.113.66 | DeleteTrail | Suppression de corp-trail refusée par un refus explicite dans une SCP | 51d08109-fc90-4838-9874-1408f7b217c7 | S4 |
| 02:41:03 | bob | 203.0.113.66 | StopLogging | Arrêt de la journalisation de corp-trail, sans erreur déclarée | fba6abf7-cdbc-4653-b7a7-e8b75e70f65f | S4 |
| 03:52:10 | alice | 198.51.100.10 | StartLogging | Reprise de la journalisation de corp-trail, sans erreur déclarée | c7bf4fbc-d43c-4d6d-a0c1-ff1e20da8972 | Réponse |
| 03:58:30 | alice | 198.51.100.10 | UpdateAccessKey | Passage de la clé AKIALABROGUE00000001 de svc-backup au statut Inactive, sans erreur déclarée | 46426c45-8d03-417a-b4d3-75c1a29319fa | Réponse |

### Interruption de visibilité

Aucun événement n’est présent dans le jeu entre StopLogging à 02:41:03 et StartLogging à 03:52:10, soit un intervalle de 71 minutes et 7 secondes.

Cette absence de journaux ne démontre pas une absence d’activité. Les actions éventuellement réalisées pendant cette période restent inconnues à partir des seules données analysées.

### Contexte de supervision

Les appels GetTrailStatus du rôle MonitoringRole, depuis 10.0.12.5, sont des événements de supervision. Ils ne sont pas inclus dans le tableau des actions de l’incident.

Un GetTrailStatus est notamment présent à 03:52:21, après StartLogging :
eventID 6070b6a1-98e5-4499-a18c-6e1c9e374f7a.
Cet événement montre la reprise des appels de supervision visibles dans le jeu, sans prouver à lui seul une remédiation complète.

## 4. Analyse par scénario (S1 à S6)

Les niveaux de confiance ci-dessous concernent l’interprétation des événements synthétiques disponibles, et non la constatation d’un incident sur un compte AWS réel.

### S1 — Création d’une clé d’accès non autorisée

Faits observés :
À 02:23:15 UTC, bob crée une clé pour un autre utilisateur, svc-backup. La réponse contient l’identifiant AKIALABROGUE00000001. À 02:26:48, cette même clé est utilisée sous l’identité svc-backup pour appeler GetCallerIdentity depuis 203.0.113.66.

Indices et preuves :
- Création : e95f176c-deba-4186-ba10-82170ad7c9a2.
- Utilisation : ca9e4a62-fae3-414b-a3b4-42bd46494296.
- L’acteur de la création, bob, est différent de la cible, svc-backup.
- La création et l’utilisation proviennent de la même IP extérieure au périmètre défini.
- Le client déclaré lors de l’utilisation est AWS CLI 2.15.30 sous Windows 10.

Impact :
La clé fournit un moyen d’accès supplémentaire sous une autre identité. Le jeu démontre son utilisation pour GetCallerIdentity, mais pas une exfiltration ou d’autres opérations avec cette clé.

Réponse observée :
À 03:58:30, Alice place cette clé au statut Inactive.
Preuve : 46426c45-8d03-417a-b4d3-75c1a29319fa.

Détection : R03.
Confiance : élevée pour la création et l’utilisation corrélées ; portée des autres usages inconnue.

### S2 — Auto-attribution de privilèges administrateur

Faits observés :
À 02:21:40 UTC, bob appelle AttachUserPolicy pour attacher la policy arn:aws:iam::aws:policy/AdministratorAccess à son propre utilisateur. L’événement ne comporte pas de code d’erreur.

Indices et preuves :
- Événement : 6cac028c-ba22-4065-9526-0718cd180a82.
- Acteur et utilisateur cible identiques : bob.
- Policy cible : AdministratorAccess.
- Action précédée de quatre appels refusés depuis la même IP.
- La configuration initiale DevPolicy autorise iam:AttachUserPolicy sur toutes les ressources.

Impact :
L’attribution représente une élévation majeure des privilèges dans le scénario. Les événements synthétiques ne constituent toutefois pas une vérification exhaustive de toutes les autorisations ainsi obtenues.

Détection : R02.
Confiance : élevée pour l’auto-attribution décrite dans le jeu.

### S3 — Suppression du bucket de sauvegardes

Faits observés :
À 02:31:12 UTC, bob appelle ListBuckets. À 02:33:05, il appelle DeleteBucket sur corp-backups-prod, sans erreur déclarée, depuis 203.0.113.66.

Indices et preuves :
- Inventaire : add702c9-2747-493c-9ae7-7eab084a6780.
- Suppression : 1e2595b8-8fc9-486b-a9dd-ebf563119aca.
- La cible désigne le bucket de sauvegardes de production du scénario.
- La suppression intervient dans la continuité des actions suspectes de bob.

Impact :
La suppression compromet la disponibilité du bucket de sauvegardes. Le volume de données perdues et les possibilités de restauration ne sont pas établis par ces événements.

Limite :
Aucune séquence de suppression des objets n’est démontrée par les extractions présentées. Il ne faut pas inventer cette séquence ni déduire l’absence de pertes à partir de journaux manquants.

Détection : R04.
Confiance : élevée pour la suppression du bucket dans le scénario ; impact exact sur les données inconnu.

### S4 — Altération de la journalisation

Faits observés :
À 02:39:20 UTC, bob tente de supprimer corp-trail avec DeleteTrail. L’appel est refusé. À 02:41:03, StopLogging sur le même trail ne présente pas d’erreur. Aucun événement n’est ensuite présent avant StartLogging par Alice à 03:52:10.

Indices et preuves :
- DeleteTrail refusé : 51d08109-fc90-4838-9874-1408f7b217c7.
- StopLogging : fba6abf7-cdbc-4653-b7a7-e8b75e70f65f.
- StartLogging : c7bf4fbc-d43c-4d6d-a0c1-ff1e20da8972.
- Le message de refus cite explicitement une service control policy, ou SCP.
- L’intervalle entre l’arrêt et la reprise est de 71 minutes et 7 secondes.

Impact :
Une interruption de visibilité empêche de reconstituer les actions éventuellement réalisées pendant cet intervalle.

Analyse :
La protection observée bloque DeleteTrail, mais n’empêche pas StopLogging. Le document complet de la SCP n’est pas disponible ; toutes ses règles ne peuvent donc pas être décrites.

Détection : R05 et R08.
Confiance : élevée pour la séquence arrêt/reprise ; activité pendant l’interruption inconnue.

### S5 — Connexion suspecte sans MFA

Faits observés :
Trois connexions de bob échouent à 02:11:07, 02:11:31 et 02:11:52 UTC. Une connexion réussit à 02:14:30 depuis la même IP, 203.0.113.66, avec MFAUsed égal à No.

Indices et preuves :
- Échecs : 4970ed9a-09ce-4cfb-a339-ba1925637cc3,
  b49e04cc-c243-49e7-a387-eaf6d4c3a832,
  41843b03-04dd-4054-9448-23f7e7e646c7.
- Succès : 871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1.
- IP extérieure au périmètre défini.
- Client déclaré : Firefox 131 sous Linux.
- Une connexion habituelle de bob observée la veille utilisait le MFA depuis 198.51.100.23.

Impact :
Le succès sans MFA ouvre la séquence d’actions suspectes sous l’identité bob.

Limite :
Les événements ne permettent pas de déterminer comment les identifiants ont été obtenus. Les trois échecs ne prouvent pas à eux seuls une technique précise de vol ou de devinette du mot de passe.

Détection : R01 et R07.
Confiance : élevée pour la connexion sans MFA ; compromission fortement étayée par les actions suivantes.

### S6 — Reconnaissance par appels refusés

Faits observés :
Entre 02:16:02 et 02:18:03 UTC, bob reçoit quatre refus : ListUsers, ListRoles, GetBucketPolicy et GetObject.

Indices et preuves :
- ListUsers : b7f28572-3def-4849-9336-4f7e83efa9f3.
- ListRoles : 40ef3935-5f90-4ed6-bb25-664d630aa767.
- GetBucketPolicy : 10275b53-2285-42ef-8fbe-4fe92ea9c542.
- GetObject : 0c3ce284-c7e5-4bbb-9cb5-1c535b62a8df.
- Même identité et même IP extérieure au périmètre défini.
- Plusieurs services et ressources sont sondés en 2 minutes et 1 seconde.
- La cible S3 comprend corp-finance-secrets/2026/payroll.xlsx.
- La séquence précède l’auto-attribution d’AdministratorAccess.

Impact :
Les événements indiquent des tentatives de découverte des ressources et de sondage des autorisations. Ils ne démontrent pas une lecture réussie du fichier ciblé.

Détection : R06.
Confiance : élevée pour les refus ; interprétation en reconnaissance fortement étayée par leur enchaînement et le contexte.

### Analyse des cas bénins et réduction des faux positifs

Les événements suivants sont distingués de la chaîne suspecte grâce à leur contexte. Leur classement ne repose pas uniquement sur une IP interne, la présence de MFA ou le nom d’une ressource.


| Cas | Indices observés | Conclusion |
|---|---|---|
| Échec isolé de connexion d’Alice | Échec à 08:04:40 le 28 octobre, puis succès avec MFA 26 secondes plus tard depuis la même IP 198.51.100.10 | Compatible avec une erreur de saisie ; ne présente pas la même séquence que les connexions suspectes de bob |
| Création de clé par Alice | Alice crée une clé pour elle-même à 09:32:10, depuis 198.51.100.10, avec une session MFA | Compatible avec une opération légitime de gestion de clé ; la suppression d’une ancienne clé n’est pas démontrée par cet événement seul |
| Attribution de ReadOnlyAccess à Carol | Action réalisée par Alice à 10:15:41, depuis son IP habituelle et avec une session MFA | Compatible avec une administration attendue ; ne correspond pas à l’auto-attribution d’AdministratorAccess de S2 |
| Suppression du bucket de test | Alice supprime tmp-test-bucket-7f3a à 11:50:27, depuis son IP habituelle, avec MFA | Compatible avec un nettoyage de ressources de test ; le nom seul ne prouve pas l’innocuité |
| Refus isolé de Carol | ListUsers refusé à 14:20:09 depuis 198.51.100.31, sans rafale observée | Insuffisant pour déclarer un incident ; deviendrait plus préoccupant avec des refus répétés, de nouvelles cibles ou des actions sensibles corrélées |

Preuves, toutes datées du 28 octobre 2026 :

- Échec d’Alice : bc8960a9-23b8-41e9-b924-56de3eb13b90.
- Succès d’Alice avec MFA : 0822e8f3-6c03-4199-972a-846916419f82.
- Création de clé par Alice : 26d794d3-0db9-4301-afbb-411aa1235a8c.
- Attribution de ReadOnlyAccess : dc0f2fcf-b3f6-4e0d-8860-3b32b4fb0eb9.
- Suppression du bucket de test : d6016237-ac9e-4156-b63f-ce413a9aca5e.
- Refus de Carol : ac1aa554-c3c7-4611-bfe3-fa49054f92ff.

## 5. Indicateurs de compromission (IoC)

Les valeurs ci-dessous sont issues du jeu synthétique. Elles servent à illustrer les pivots d’investigation et les cibles de confinement dans le scénario ; elles ne constituent pas une liste de menaces réelles à bloquer.

### Indicateurs et éléments de contexte

| Type | Valeur | Observation | Utilisation |
|---|---|---|---|
| IP suspecte | 203.0.113.66 | Source commune des connexions suspectes, des refus, des actions sensibles et de l’utilisation de la clé créée | Rechercher tous les événements associés et corréler les identités utilisées |
| Identité principale | arn:aws:iam::000000000000:user/bob | Identité utilisée pour la connexion sans MFA, l’élévation de privilèges et les actions sensibles | Examiner les activités, les autorisations et les moyens d’accès de bob |
| Identité de persistance | arn:aws:iam::000000000000:user/svc-backup | Utilisateur ciblé par la création de clé, puis identité utilisée avec cette clé | Rechercher les usages de la clé et examiner les autres moyens d’accès du compte |
| Clé non autorisée | AKIALABROGUE00000001 | Créée par bob, utilisée sous svc-backup, puis désactivée par Alice | Pivot précis entre les événements de création, d’utilisation et de réponse |
| Agent utilisateur | Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0 | Client déclaré dans les événements suspects de bob | Élément de corrélation ; insuffisant seul pour conclure à une activité malveillante |
| Agent utilisateur | aws-cli/2.15.30 Python/3.11.8 Windows/10 exe/AMD64 prompt/off command/sts.get-caller-identity | Client déclaré lors de l’utilisation de la clé de svc-backup | Rechercher des usages similaires en les corrélant à l’identité, à la clé et à l’IP |
| Policy attribuée | arn:aws:iam::aws:policy/AdministratorAccess | Policy attachée par bob à son propre utilisateur | Rechercher d’autres attributions de privilèges et identifier l’attachement à retirer |
| Ressource sondée | corp-finance-secrets/2026/payroll.xlsx | Cible du GetObject refusé | Rechercher d’éventuels accès réussis à cette ressource dans les sources disponibles |
| Ressource supprimée | corp-backups-prod | Cible du DeleteBucket sans erreur déclarée | Évaluer les conséquences sur les sauvegardes et les possibilités de restauration |
| Journalisation ciblée | arn:aws:cloudtrail:eu-west-3:000000000000:trail/corp-trail | Cible de DeleteTrail, StopLogging et StartLogging | Vérifier la continuité de la journalisation et les protections contre son altération |

### Corrélation de la clé non autorisée

| Étape | Heure UTC du 29 octobre 2026 | Preuve (eventID) |
|---|---|---|
| Création par bob pour svc-backup | 02:23:15 | e95f176c-deba-4186-ba10-82170ad7c9a2 |
| Utilisation sous svc-backup depuis 203.0.113.66 | 02:26:48 | ca9e4a62-fae3-414b-a3b4-42bd46494296 |
| Désactivation par Alice, statut Inactive | 03:58:30 | 46426c45-8d03-417a-b4d3-75c1a29319fa |

### Distinguer recherche et confinement

- Pour la recherche : utiliser l’IP, les ARN, l’identifiant de clé, les ressources et les agents utilisateurs comme pivots de corrélation.
- Pour le confinement proposé dans le scénario : cibler les moyens d’accès compromis et l’attribution de privilèges non autorisée. La désactivation de la clé AKIALABROGUE00000001 est déjà visible dans les événements.
- L’IP suspecte constitue un indicateur complémentaire : elle ne doit pas être l’unique pivot, puisque le jeu ne démontre pas que toute activité malveillante utiliserait nécessairement cette adresse.
- Les noms des ressources ciblées et AdministratorAccess ne sont pas malveillants en eux-mêmes : leur intérêt vient des actions et du contexte observés.

### Limites des identifiants et agents utilisateurs

Les identifiants ASIALAB… de bob varient entre les événements synthétiques. Ils ne permettent donc pas de présenter toute la séquence comme l’utilisation d’une clé unique.

Le champ userAgent décrit le client déclaré dans l’événement ; il ne suffit pas à attribuer l’activité à une personne ou à prouver le système réellement utilisé.

Les adresses 198.51.100.10, 198.51.100.23, 198.51.100.31 et 10.0.12.5 apparaissent dans le contexte habituel ou la réponse à l’incident. Elles ne sont pas classées comme suspectes sur la seule base des observations présentées.

## 6. Cause racine et facteurs aggravants

### Cause racine retenue

La séquence démarre par l'authentification de bob avec un mot de passe seul : après trois échecs, la connexion réussit à 02:14:30 UTC sans MFA (eventID 871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1). L'attaque progresse ensuite grâce à la policy DevPolicy, trop permissive : elle autorise iam:AttachUserPolicy et iam:CreateAccessKey sur toutes les ressources (config/dev-policy.json).

Ces deux faiblesses se combinent dans le scénario. La connexion suspecte réussit sans MFA, puis les permissions IAM excessives permettent l’auto-attribution d’AdministratorAccess (S2) et la création d’un accès supplémentaire sous une autre identité (S1). Les événements ne permettent pas de déterminer comment les identifiants de bob ont été obtenus.

### Facteurs aggravants

1. **Permissions IAM trop larges.** DevPolicy accorde iam:AttachUserPolicy sur Resource "*". Bob a pu s'attacher AdministratorAccess (eventID 6cac028c-ba22-4065-9526-0718cd180a82).
2. **Création de clés pour d'autres utilisateurs.** iam:CreateAccessKey sur Resource "*" permet de créer une clé pour svc-backup (eventID e95f176c-deba-4186-ba10-82170ad7c9a2). La clé a ensuite été utilisée depuis l'IP extérieure (eventID ca9e4a62-fae3-414b-a3b4-42bd46494296).
3. **Droits S3 étendus.** DevPolicy contient s3:* sur Resource "*". Le rôle de développeur n'exige pas nécessairement des droits d'administration sur tous les buckets. Les événements ne permettent pas d'établir si la suppression de corp-backups-prod dépendait de cette permission ou de l'élévation de privilèges, car les deux sont présentes avant l'événement.
4. **Protection incomplète de la journalisation.** Une SCP bloque DeleteTrail (eventID 51d08109-fc90-4838-9874-1408f7b217c7), mais StopLogging aboutit sans erreur (eventID fba6abf7-cdbc-4653-b7a7-e8b75e70f65f). La suppression est donc protégée, pas l'arrêt de la collecte. Nous n'avons pas le texte de la SCP, donc cette conclusion se limite aux deux appels observés.
5. **Visibilité limitée sur la détection et la réaction.** Les événements montrent une reprise de la journalisation 71 minutes et 7 secondes après l’arrêt. Les sources analysées ne contiennent pas de traces d’alertes ou de réaction automatique ; leur absence dans ce jeu ne permet pas d’affirmer qu’aucun mécanisme de détection n’existait.

### Éléments non établis par les données

- Les journaux ne montrent pas comment le mot de passe de bob a été obtenu.
- Aucun événement ne prouve que le MFA n'a jamais été enrôlé pour bob. Il montre seulement que cette connexion n'a pas utilisé de MFA.
- Les journaux ne permettent pas de savoir si des sauvegardes existaient ailleurs, si le versioning ou une réplication était activé, ni quelles données ont été perdues avec corp-backups-prod.
- Les actions éventuelles pendant la période sans journaux ne sont pas connues.

## 7. Mesures correctives

Les mesures suivantes constituent un plan de réponse proposé pour le scénario. Les responsables sont des rôles fonctionnels, et les délais sont relatifs à la détection de l’incident.

Seules deux actions de réponse sont explicitement visibles dans les données : la reprise de la journalisation et la désactivation de la clé non autorisée. Les autres mesures ne doivent pas être considérées comme réalisées.

### Actions de réponse observées

| Heure UTC du 29 octobre 2026 | Action | Acteur | Preuve (eventID) |
|---|---|---|---|
| 03:52:10 | Reprise de la journalisation de corp-trail avec StartLogging | alice | c7bf4fbc-d43c-4d6d-a0c1-ff1e20da8972 |
| 03:58:30 | Désactivation de la clé AKIALABROGUE00000001 de svc-backup | alice | 46426c45-8d03-417a-b4d3-75c1a29319fa |

La suppression de la clé, le retrait d’AdministratorAccess, la révocation des sessions et la restauration des sauvegardes ne sont pas démontrés par les événements analysés.

### Plan de remédiation proposé

| Priorité | Action | Responsable proposé | Délai cible | Scénarios |
|---|---|---|---|---|
| Immédiate | Restreindre l’identité bob avec un accès d’administration de confiance, puis neutraliser ses moyens d’accès compromis et ses sessions actives | Administrateur IAM / équipe de réponse | Dès la détection | S2, S5, S6 |
| Immédiate | Désactiver la clé AKIALABROGUE00000001 et inventorier les autres clés de bob et svc-backup | Administrateur IAM | Dès la détection ; désactivation observée à 03:58:30 | S1 |
| Immédiate | Retirer l’attachement non autorisé d’AdministratorAccess à bob et empêcher sa réattribution | Administrateur IAM | 0–4 h | S2 |
| Immédiate | Rétablir la journalisation et protéger sa configuration contre une nouvelle altération | Administrateur sécurité cloud | Dès la détection ; reprise observée à 03:52:10 | S4 |
| Immédiate | Préserver les journaux disponibles, les configurations IAM et les paramètres du trail avant les modifications, dans la mesure compatible avec l’urgence du confinement | Équipe de réponse | En parallèle du confinement | S1–S6 |
| Immédiate | Rechercher les actions des identités compromises, les nouvelles clés, les changements de policies et les autres mécanismes de persistance | Analyste sécurité / administrateur IAM | 0–4 h, puis approfondissement | S1, S2, S6 |
| Immédiate | Évaluer l’état des sauvegardes, suspendre les suppressions non indispensables et identifier les sources de restauration | Responsable sauvegardes / administrateur S3 | 0–4 h | S3 |
| Court terme | Retirer de DevPolicy les permissions IAM injustifiées et limiter les ressources accessibles au besoin réel du développeur | Administrateur IAM / responsable applicatif | ≤ 7 jours | S1, S2 |
| Court terme | Remplacer s3:* sur toutes les ressources par des permissions et des cibles explicitement justifiées | Administrateur S3 / responsable applicatif | ≤ 7 jours | S3, S6 |
| Court terme | Réinitialiser les identifiants concernés dans le cadre du confinement, imposer le MFA et vérifier la révocation des accès antérieurs | Administrateur IAM | Confinement immédiat ; vérification ≤ 7 jours | S5 |
| Court terme | Étendre la protection de la journalisation à StopLogging et aux autres opérations sensibles de configuration, avec exceptions administratives contrôlées | Administrateur sécurité cloud | ≤ 7 jours | S4 |
| Court terme | Rechercher des traces complémentaires pour la période sans journaux et documenter les sources effectivement disponibles | Analyste sécurité | ≤ 7 jours | S4 |
| Court terme | Restaurer les sauvegardes depuis une source vérifiée et tester la restauration avant de déclarer le service rétabli | Responsable sauvegardes | Selon l’impact et les objectifs de reprise | S3 |
| Durable | Réduire l’usage des clés permanentes et privilégier des accès temporaires adaptés aux applications et aux utilisateurs | Architecte cloud / administrateur IAM | Planification ≤ 30 jours | S1, S5 |
| Durable | Séparer les droits d’administration, de développement, de sauvegarde et de gestion des journaux | Architecte sécurité | Planification ≤ 30 jours | S1–S4 |
| Durable | Renforcer la protection des sauvegardes et des journaux, puis tester régulièrement leur récupération | Responsable sauvegardes / sécurité cloud | Planification ≤ 30 jours | S3, S4 |
| Durable | Mettre en place des détections sur les changements IAM sensibles, les connexions sans MFA, les rafales de refus et l’altération de la journalisation | Équipe détection | Planification ≤ 30 jours | S1–S6 |

### Ordre de confinement proposé

1. Utiliser une identité d’administration de confiance et restreindre bob afin d’empêcher de nouvelles actions sensibles.
2. Neutraliser les accès persistants identifiés, notamment la clé créée pour svc-backup, ainsi que les autres moyens d’accès compromis.
3. Retirer les privilèges non autorisés et corriger les permissions permettant de les rétablir.
4. Réinitialiser le mot de passe concerné, traiter les sessions actives et imposer le MFA avant de rétablir l’accès légitime.
5. Rétablir et protéger la journalisation sans attendre la fin de l’investigation, en parallèle du confinement dès que possible.
6. Rechercher les autres modifications, évaluer les pertes et restaurer les services depuis des sources vérifiées.

Cet ordre est une proposition, pas la description de la réponse effectivement observée. La préservation des preuves et le rétablissement de la visibilité doivent être menés en parallèle lorsque cela est possible.

### Critères de clôture

La remédiation ne sera considérée comme terminée qu’après vérification des points suivants :

- Les moyens d’accès non autorisés sont neutralisés.
- Les privilèges excessifs et les possibilités de réattribution sont corrigés.
- Les accès légitimes sont rétablis avec des contrôles adaptés.
- La journalisation fonctionne et sa protection est vérifiée.
- L’étendue des modifications et les limites de l’investigation sont documentées.
- Les sauvegardes nécessaires sont disponibles et leur restauration a été testée.

Les événements du jeu ne suffisent pas à confirmer l’ensemble de ces critères.

## 8. Détection : amélioration proposée

### Objectif

Adapter le seuil de la règle R08, qui détecte les interruptions de visibilité, afin de réduire le bruit tout en conservant la détection de l’interruption présente dans le scénario.

Cette amélioration porte sur le paramétrage de l’analyseur existant. Aucune nouvelle règle et aucune modification du code de src/analyze_logs.py ne sont revendiquées.

### Tests réalisés

Les trois exécutions portent sur les mêmes 265 événements, collectés depuis S3 dans 114 fichiers.

| Seuil --gap-minutes | CRITICAL | HIGH | MEDIUM | LOW | INFO | Observation sur R08 |
|---|---|---|---|---|---|---|
| 5 | 9 | 2 | 126 | 6 | 1 | Interruption de 71 minutes détectée, mais nombreuses alertes sur les intervalles habituels |
| 15 | 9 | 2 | 2 | 6 | 1 | Interruption de 71 minutes détectée, sans les nombreuses alertes MEDIUM observées à 5 minutes |
| 120 | 8 | 2 | 2 | 6 | 1 | Interruption de 71 minutes non détectée par R08 |

Commandes utilisées :

    python src/analyze_logs.py collected --gap-minutes 5
    python src/analyze_logs.py collected --gap-minutes 120
    python src/analyze_logs.py collected --gap-minutes 15

La dernière commande rétablit l’analyse de référence à 15 minutes dans reports/.

### Analyse du compromis

Avec un seuil de 5 minutes, les intervalles habituels de supervision, proches de 10 minutes, déclenchent de nombreuses alertes. Le total MEDIUM passe de 2 à 126, soit 124 alertes supplémentaires. Cette sensibilité excessive augmente la charge d’analyse et risque de masquer les événements importants.

Avec un seuil de 120 minutes, l’interruption de 71 minutes n’atteint pas le seuil : R08 ne la signale plus. Il s’agit d’un faux négatif pour cette règle sur le scénario étudié. Les alertes R05 sur DeleteTrail et StopLogging restent toutefois présentes : la séquence n’est donc pas entièrement invisible pour l’analyseur.

### Paramétrage retenu

Le seuil de 15 minutes est conservé comme réglage de référence pour ce jeu de données. Il détecte l’interruption liée à StopLogging tout en évitant le bruit massif observé avec un seuil de 5 minutes.

Ce résultat ne démontre pas que 15 minutes est un seuil universellement optimal. Un autre environnement peut présenter des volumes d’activité, des périodes creuses et des rythmes de supervision différents.

### Faux positifs et limites attendus

- Une faible activité légitime peut produire un intervalle sans événement.
- Une interruption de collecte ou de livraison peut créer un manque de visibilité sans arrêt malveillant du trail.
- Un seuil trop élevé peut manquer une interruption plus courte.
- La présence d’un événement StopLogging à proximité renforce l’interprétation, mais l’absence d’un tel événement ne suffit pas à exclure un problème de journalisation.

### Vérification de l’amélioration

Le réglage retenu est justifié par une comparaison reproductible sur un même jeu de données. L’évaluation porte ici sur le nombre d’alertes et la détection de l’interruption connue ; elle ne constitue pas une mesure générale des performances de R08 sur des incidents réels.

## 9. Limites et zones d’ombre

### Données synthétiques et émulation locale

L’investigation porte sur un jeu d’événements fabriqué par src/generate_events.py. Ces événements permettent de pratiquer la lecture du format CloudTrail et la corrélation, mais ne prouvent pas qu’un incident s’est produit sur un compte AWS réel.

Floci est utilisé pour les manipulations locales de services AWS. Les capacités et les résultats de cet émulateur ne doivent pas être assimilés à une reproduction exhaustive du comportement d’AWS.

Les événements synthétiques analysés et les journaux natifs de Floci sont deux sources distinctes. Les constats de ce rapport sur la chaîne d’incident reposent sur les premiers.

### Interruption de visibilité

Aucun événement n’est présent dans le jeu entre StopLogging à 02:41:03 et StartLogging à 03:52:10 UTC le 29 octobre 2026, soit 71 minutes et 7 secondes.

L’acteur a pu réaliser d’autres actions pendant cet intervalle, mais les données analysées ne permettent ni de les démontrer ni de les exclure. L’absence de journaux ne constitue pas une preuve d’absence d’activité.

Pour approfondir une investigation dans un environnement AWS réel, les sources complémentaires à examiner, si elles existent et ont été conservées, comprendraient notamment :

- les journaux d’accès S3 et les journaux applicatifs ;
- les VPC Flow Logs pour rechercher des communications réseau ;
- les journaux centralisés dans CloudWatch ;
- les résultats de détection disponibles dans GuardDuty ;
- les inventaires, historiques de configuration et traces des systèmes de sauvegarde.

Ces sources n’ont pas été collectées dans ce projet. Aucune conclusion ne repose sur leur contenu supposé.

### Accès initial et attribution

Les événements montrent trois échecs de connexion suivis d’un succès sans MFA sous l’identité bob. Ils ne permettent pas de déterminer comment le mot de passe a été obtenu.

Une identité IAM, une adresse IP et un userAgent ne suffisent pas à identifier une personne physique. Le champ userAgent décrit le client déclaré dans l’événement, pas une attribution certaine du poste utilisé.

Les identifiants ASIALAB… varient entre les appels synthétiques de bob. Ils ne sont donc pas utilisés pour affirmer que tous ces appels proviennent d’une session technique unique.

### Étendue des accès et impact sur les données

Le GetObject visant corp-finance-secrets/2026/payroll.xlsx est refusé. Aucun accès réussi à ce fichier n’est démontré dans les extractions présentées.

La suppression de corp-backups-prod est représentée par un DeleteBucket sans erreur déclarée. Les données ne précisent pas le contenu antérieur du bucket, le volume perdu ni la disponibilité de copies de secours.

Les extractions ne démontrent pas la séquence de suppression des objets précédant celle du bucket. Il ne faut pas inventer cette séquence ni interpréter son absence comme une preuve d’absence de destruction.

L’utilisation démontrée de la clé AKIALABROGUE00000001 est un appel GetCallerIdentity. Aucune exfiltration avec cette clé n’est établie.

### Configuration et réponse incomplètement observées

Le refus de DeleteTrail mentionne une SCP, mais son document complet n’est pas disponible. La conclusion se limite au contraste observé entre DeleteTrail refusé et StopLogging sans erreur déclarée.

La réponse visible comprend StartLogging et la désactivation de la clé non autorisée. Le retrait d’AdministratorAccess, la révocation des sessions, la correction effective de DevPolicy et la restauration des sauvegardes ne sont pas démontrés par les événements du scénario.

Les mesures présentées dans la section 7 sont donc distinguées des actions effectivement observées.

### Limites de la détection

Les alertes constituent des pistes d’investigation, pas des incidents distincts ni des preuves suffisantes à elles seules.

Les essais sur R08 montrent qu’un seuil trop bas génère du bruit et qu’un seuil trop haut manque l’interruption étudiée. Le réglage de 15 minutes est adapté aux résultats de ce jeu, sans garantie de performance générale.

### Synthèse du niveau de certitude

| Niveau | Conclusions |
|---|---|
| Établi dans les données synthétiques | Connexion réussie sans MFA, quatre refus rapprochés, auto-attribution d’AdministratorAccess, création et utilisation de la clé de svc-backup, suppression du bucket, tentative de suppression du trail refusée, arrêt puis reprise de la journalisation et désactivation de la clé |
| Fortement étayé par la corrélation | Utilisation compromise de l’identité bob, reconnaissance des autorisations et création d’un accès persistant sous svc-backup |
| Inconnu | Origine des identifiants compromis, actions pendant l’interruption, étendue exacte des pertes, éventuelle exfiltration et caractère complet de la remédiation |


## 10. Validation complémentaire — Test IAM local S2

### Périmètre

Ce test a été réalisé séparément contre Floci. Il ne fait pas partie de la chronologie synthétique du 29 octobre 2026 et ne constitue pas une preuve supplémentaire des événements de cette chronologie.

### Résultats observés

| Contrôle | Résultat |
|---|---|
| Policies attachées à bob avant le test | DevPolicy uniquement |
| ListUsers sous bob avant attribution | AccessDenied, code 255 |
| Attribution d’AdministratorAccess sous bob | Code 0, aucune erreur |
| ListUsers sous bob après attribution | Code 0, liste des quatre utilisateurs |
| Retrait d’AdministratorAccess par l’opérateur | Code 0 |
| Policies attachées après nettoyage | DevPolicy uniquement |
| Nouveau contrôle ListUsers sous bob après retrait | Non effectué : fonction aws_bob absente de la session |

Le test démontre une augmentation effective des permissions dans Floci, vérifiée sur iam:ListUsers. Il ne valide pas exhaustivement toutes les permissions administrateur.

### Journalisation et limites

Les recherches AttachUserPolicy enregistrées dans eu-west-3 et us-east-1 retournent une liste vide. L’état enregistré du trail indique IsLogging: true, mais l’unique objet natif listé est antérieur au début du test.

La présence de l’événement d’attribution dans les journaux natifs n’est donc pas confirmée par les preuves examinées.

Le retrait d’AdministratorAccess est confirmé par l’appel de détachement et par la liste des policies attachées après nettoyage. Le retour effectif au refus de ListUsers n’a pas été vérifié.

DevPolicy reste volontairement permissive pour les besoins du laboratoire : le retrait de la policy administrateur ne corrige pas la configuration initiale.

### Preuves

Les sorties, erreurs et codes retour disponibles sont conservés dans evidence/scenarios/S2/.