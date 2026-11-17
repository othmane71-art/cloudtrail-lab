# Notes techniques — Projet de sécurité AWS en environnement local



Auteur : ABIDI Othmane

Date : 17 novembre 2026



Les numéros Q1 à Q31 correspondent aux questions du support de référence. Les réponses distinguent le fonctionnement décrit dans ce support de l’adaptation réalisée avec Floci.



## Q1 — Pourquoi publier le port sur 127.0.0.1 ?



La configuration utilise :



&#x20;   127.0.0.1:4566:4566



Le port est lié à l’interface de boucle locale de l’hôte plutôt qu’à toutes ses interfaces réseau. Cela limite l’exposition du point d’accès de l’émulateur et évite de le rendre directement accessible aux autres machines du réseau par cette publication.



Cette précaution est importante : les services contiennent des identités de démonstration et des configurations volontairement trop permissives.



Les communications entre lab-shell et Floci utilisent séparément le réseau Docker et l’adresse http://floci:4566.



## Q2 — Pourquoi utiliser les identifiants test/test ?



Les variables AWS\_ACCESS\_KEY\_ID=test et AWS\_SECRET\_ACCESS\_KEY=test sont des identifiants factices configurés pour les appels locaux de l’AWS CLI vers Floci. Leur fonctionnement a été constaté avec l’identité opérateur de démonstration :



&#x20;   arn:aws:iam::000000000000:root



Ils ne correspondent pas aux identifiants d’un compte AWS réel.



Il faut distinguer cette identité opérateur des identifiants locaux créés pour bob. Avec l’application des autorisations IAM activée dans Floci, un appel ListUsers sous bob a été refusé avant l’attribution d’AdministratorAccess, puis accepté après cette attribution.



L’utilisation d’un émulateur ne signifie donc pas que tous les identifiants disposent nécessairement des mêmes autorisations.



## Q3 — Pourquoi figer la version d’une image ?



Une version identifiée facilite la reproductibilité et l’analyse des changements. En contrepartie, sa mise à jour doit être organisée pour bénéficier des corrections.



Dans l’état actuel du projet, FLOCI\_IMAGE vaut floci/floci:latest. La configuration ne garantit donc pas de récupérer la même image lors d’un téléchargement ultérieur.



Floci 2.5.0 a été observé pendant les manipulations. Cette observation ne remplace pas un verrouillage de l’image. Pour une reproductibilité stricte, une référence par digest peut être utilisée après vérification de l’image retenue.



## Q4 — Quels services sont vérifiés et quelle est la nature des journaux ?



Le script scripts/00\_check\_env.sh vérifie :



\- STS, avec get-caller-identity ;

\- S3, avec list-buckets ;

\- IAM, avec list-users ;

\- CloudTrail, avec describe-trails ;

\- l’état de Floci, via /\_floci/health.



Dans cette adaptation, CloudTrail est émulé par Floci. Un trail corp-trail a été configuré et un fichier natif a été observé dans corp-cloudtrail-logs-native. Cela ne correspond pas au service AWS réel.



Les 265 événements étudiés dans le rapport d’investigation sont une autre source : ils sont générés par src/generate\_events.py, portent \_lab\_notice et sont déposés dans corp-cloudtrail-logs-synthetic.



Les recherches natives effectuées sur l’attachement d’AdministratorAccess à bob n’ont pas retourné l’événement recherché. La journalisation native de cette opération n’est donc pas établie par les preuves disponibles.



## Q5 — Quelles permissions de DevPolicy sont dangereuses ?



La policy initiale contient notamment :



&#x20;   iam:AttachUserPolicy

&#x20;   iam:CreateAccessKey

&#x20;   Resource: "\*"



iam:AttachUserPolicy permet une attribution dangereuse de privilèges lorsqu’aucune restriction applicable ne l’empêche. Dans le scénario synthétique, bob s’attache AdministratorAccess.



iam:CreateAccessKey sur toutes les ressources autorise une portée excessive : le scénario montre bob créant une clé pour svc-backup, donc pour un autre utilisateur.



DevPolicy contient également s3:\* sur Resource "\*", ce qui accorde des permissions S3 très larges au lieu de les limiter aux opérations et ressources nécessaires au développeur.



Les risques illustrés sont l’élévation de privilèges, la création d’un accès supplémentaire et les actions destructrices sur S3.



La correction proposée consiste à retirer les permissions IAM injustifiées et à limiter les actions et ressources S3 aux besoins réels. Cette correction n’est pas présentée comme déjà appliquée.



## Q6 — Quelles opérations relèvent des management events ou des data events ?



Les opérations de gestion concernent la configuration et l’administration des ressources. Parmi les commandes du projet, cela comprend notamment :



\- S3 : CreateBucket, DeleteBucket, ListBuckets et GetBucketLocation.

\- IAM : ListUsers, ListAttachedUserPolicies, ListAccessKeys, AttachUserPolicy et CreateAccessKey.

\- CloudTrail : DescribeTrails, GetTrailStatus, StopLogging et StartLogging.



Les opérations sur le contenu des objets S3, comme GetObject, PutObject et DeleteObject, relèvent des data events. Leur journalisation doit être activée explicitement pour les ressources concernées ; elle n’est pas activée par défaut dans un trail.



Il faut donc examiner l’opération API réellement appelée : une commande de haut niveau comme aws s3 cp peut produire plusieurs appels.



Cette classification décrit AWS. Elle ne prouve pas que chaque appel exécuté dans Floci a effectivement été enregistré par son émulation CloudTrail.



## Q7 — Qu’apporte un événement CloudTrail par rapport à une simple ligne de requête ?



Une ligne de requête indiquant uniquement un service, une opération et un statut HTTP ne fournit pas le même contexte d’investigation qu’un événement CloudTrail structuré.



Les champs étudiés dans le projet apportent notamment :



1\. userIdentity : identité de l’appelant, ARN et éventuellement identifiant de clé.

2\. sourceIPAddress : origine déclarée de l’appel.

3\. requestParameters : utilisateur, bucket, policy ou autre ressource ciblée.

4\. userAgent : client déclaré.

5\. eventID : identifiant permettant de citer et de dédupliquer l’événement.

6\. errorCode et errorMessage : résultat en erreur et contexte du refus.

7\. additionalEventData ou sessionContext : informations de contexte, notamment sur le MFA selon le type d’événement.



La comparaison exacte dépend du format du journal de requêtes utilisé. Un champ ne doit pas être déclaré absent sans avoir examiné la source.



Dans ce projet, les événements synthétiques structurés ont permis de relier la création d’une clé, son utilisation et sa désactivation grâce à l’identifiant AKIALABROGUE00000001.



## Q8 — Quelle différence entre NoSuchKey et AccessDenied ?



NoSuchKey correspond à une clé d’objet inexistante et est associé au statut HTTP 404.



AccessDenied est associé au statut HTTP 403 et signale un refus d’accès. Ce n’est pas la même erreur et il ne faut pas classer automatiquement un objet introuvable comme une tentative d’accès interdite.



Une nuance existe pour GetObject sur AWS : si l’objet n’existe pas, la réponse peut être 404 lorsque l’appelant possède s3:ListBucket, ou 403 lorsqu’il ne possède pas cette permission. Un 403 ne prouve donc pas à lui seul que l’objet existe.



Pour l’investigation, il faut corréler le code, le message, la ressource, l’identité et les permissions applicables.



Aucune nouvelle exécution sur une clé inexistante n’est revendiquée dans cette réponse. Elle explique la distinction ; le GetObject suspect extrait du jeu synthétique porte, lui, le code AccessDenied.



## Q9 — Pourquoi les refus dépendent-ils de l’émulateur et de sa configuration ?



Le support initial décrit un environnement dans lequel les autorisations IAM ne sont pas appliquées comme sur AWS. Cette limite ne doit pas être reprise telle quelle pour l’adaptation Floci sans tenir compte des contrôles réalisés.



Au début des essais, bob pouvait appeler ListUsers alors que sa policy ne lui accordait pas cette action. Après activation de :



&#x20;   FLOCI\_SERVICES\_IAM\_ENFORCEMENT\_ENABLED=true



et recréation de Floci, les résultats observés ont été :



\- identité opérateur : ListUsers autorisé ;

\- identité bob avant élévation : AccessDenied, code de sortie 255 ;

\- attachement d’AdministratorAccess par bob : code de sortie 0 ;

\- identité bob après élévation : ListUsers autorisé, code de sortie 0.



Ces résultats démontrent l’application d’un contrôle IAM pour l’action testée et une augmentation effective des permissions dans l’émulateur. Ils ne démontrent pas une reproduction exhaustive du moteur d’autorisation AWS.



Les refus présents dans data/dataset\_full.json restent des événements synthétiques, indépendants de ces essais locaux.



## Q10 — Quel champ indique l’utilisation du MFA lors d’une connexion console ?



Dans les événements ConsoleLogin étudiés, le champ est :



&#x20;   additionalEventData.MFAUsed



Il vaut Yes ou No. Il doit être lu avec :



&#x20;   responseElements.ConsoleLogin



Ce second champ indique Success ou Failure. MFAUsed: No sur un échec de connexion ne démontre donc pas une connexion réussie sans MFA.



Exemple du scénario : la connexion de bob à 02:14:30 UTC le 29 octobre présente ConsoleLogin: Success et MFAUsed: No.



Preuve : 871c0884-9bdf-40f2-ba2c-0f19f0b2a5d1.



Pour les appels API du jeu, un autre champ de contexte peut être présent :



&#x20;   userIdentity.sessionContext.attributes.mfaAuthenticated



Ces champs ne doivent pas être confondus ni considérés comme toujours renseignés.



## Q11 — Pourquoi GetTrailStatus domine-t-il les événements ?



Le jeu contient 138 événements GetTrailStatus. Les extractions montrent notamment des appels du rôle MonitoringRole depuis 10.0.12.5, correspondant à la supervision du scénario.



Cette activité régulière explique la forte présence de GetTrailStatus dans le décompte. Elle sert également de contexte pour examiner les interruptions de visibilité.



Un analyste peut distinguer cette supervision des actions suspectes dans ses vues de travail, sans supprimer les événements sources. Toute exception doit rester limitée à l’identité, à l’origine et au comportement attendus, plutôt qu’exclure tous les GetTrailStatus.



## Q12 — Quels événements en erreur paraissent bénins ?



Parmi les six événements portant un errorCode, le ListUsers refusé de Carol le 28 octobre à 14:20:09 UTC paraît bénin dans le contexte disponible :



\- identité : carol ;

\- IP : 198.51.100.31, considérée comme interne dans le scénario ;

\- refus isolé, sans rafale comparable à celle de bob ;

\- aucune chaîne d’actions suspectes corrélée dans les extractions présentées.



Preuve : ac1aa554-c3c7-4611-bfe3-fa49054f92ff.



L’IP et l’heure ne suffisent pas à elles seules à conclure. Ce classement repose aussi sur le caractère isolé et le contexte.



Les quatre AccessDenied de bob, entre 02:16:02 et 02:18:03 le 29 octobre depuis 203.0.113.66, sont plus préoccupants : ils concernent plusieurs opérations IAM et S3 et précèdent l’élévation de privilèges.



Le DeleteTrail refusé à 02:39:20 depuis cette même IP appartient également à la chaîne suspecte.



L’échec de connexion d’Alice n’appartient pas à ces six événements filtrés sur errorCode : son résultat Failure se trouve dans responseElements.ConsoleLogin.



## Q13 — Pourquoi les événements IAM et ConsoleLogin sont-ils placés dans us-east-1 ?



Dans ce jeu synthétique, le générateur place les événements IAM et ConsoleLogin dans us-east-1. La région du dossier correspond à la région attribuée à l’événement, pas nécessairement à la région d’origine du trail étudié.



Sur AWS, les événements des services globaux tels qu’IAM sont associés à us-east-1 dans la partition commerciale standard. La région des événements ConsoleLogin peut toutefois varier selon le type d’utilisateur et le point de connexion utilisé : leur classement systématique dans us-east-1 est ici une simplification du jeu.



Il faut aussi distinguer l’organisation du jeu synthétique de la configuration native de Floci. Le trail natif observé est mono-région en eu-west-3 avec IncludeGlobalServiceEvents: true. Cela ne suffit pas à démontrer une collecte exhaustive des événements globaux.



Sur AWS, pour un trail mono-région situé hors de us-east-1, le seul paramètre IncludeGlobalServiceEvents: true ne garantit pas la livraison des événements globaux IAM ; une configuration adaptée est nécessaire.



## Q14 — Pourquoi le fichier contient-il \_lab\_notice ?



Le champ exact observé à la racine du fichier est :



&#x20;   \_lab\_notice



Sa valeur indique que les données sont synthétiques, générées par generate\_events.py et non produites par AWS CloudTrail.



Ce marqueur est ajouté par le générateur du projet ; ce n’est pas un champ standard de livraison CloudTrail.



Il évite de confondre :



\- un fichier synthétique qui reproduit le format CloudTrail ;

\- un journal natif produit par Floci ;

\- un journal provenant réellement d’AWS.



Cette distinction est conservée dans le rapport et dans la documentation du projet.



## Q15 — Comparaison avec une autre graine de génération (option)



La génération avec une autre graine, par exemple --seed 7, n’a pas été réalisée dans ce projet.



Les résultats documentés correspondent uniquement à la graine 42. Aucune comparaison expérimentale entre deux graines n’est donc revendiquée.



## Q16 — Quelle fonction applique les règles et comment une alerte est-elle représentée ?



La fonction qui applique les règles est :



&#x20;   run\_detections(records, corp\_cidrs, gap\_minutes)



Elle est définie dans src/analyze\_logs.py et retourne une liste de dictionnaires Python.



Chaque alerte est construite par la fonction :



&#x20;   finding(rule, sev, r, details, \*, events=None, ext=False)



Il n’existe pas de classe Finding dans le fichier examiné. Une alerte est un dictionnaire contenant les champs suivants :



\- rule : identifiant de règle ;

\- title : titre de la règle ;

\- severity : sévérité ;

\- eventID : identifiant de l’événement principal ;

\- eventTime : date et heure ;

\- eventName : opération ;

\- principal : identité normalisée ;

\- sourceIP : IP source ;

\- region : région ;

\- details : explication de l’alerte ;

\- mitre : correspondance MITRE ATT\&CK définie dans RULES ;

\- external\_ip : indicateur d’IP extérieure aux plages configurées ;

\- related\_eventIDs : événements associés ;

\- recommendation : mesure corrective associée à la règle.



La fonction main() charge les événements avec load\_records(), appelle run\_detections(), puis écrit les résultats avec write\_outputs().



## Q17 — Pourquoi distinguer un refus isolé d’une rafale ?



Un refus isolé peut correspondre à une erreur de manipulation ou à un besoin légitime non autorisé. Plusieurs refus rapprochés sur différentes opérations peuvent indiquer un sondage des permissions.



Dans le code examiné :



\- chaque événement dont le code appartient à ACCESS\_DENIED\_CODES produit une alerte R06 LOW ;

\- les événements refusés sont regroupés par principal ;

\- au moins trois refus dans une fenêtre de dix minutes produisent une alerte de rafale HIGH ;

\- la rafale devient CRITICAL si elle contient au moins quatre refus et qu’au moins une IP associée est extérieure aux plages configurées.



L’alerte de rafale s’ajoute aux alertes individuelles ; elle ne les remplace pas.



Avec un seuil de rafale de 1, chaque refus pourrait également générer une alerte de niveau supérieur, ce qui augmenterait fortement le bruit.



Avec un seuil de 20, la rafale de quatre refus du scénario ne déclencherait plus l’alerte agrégée. Les alertes individuelles LOW resteraient présentes.



Le texte de l’alerte indique « <10 min », mais la comparaison du code utilise <= timedelta(minutes=10) : la fenêtre inclut donc exactement dix minutes.



## Q18 — Quel effet a le seuil des interruptions sur R08 ?



Trois réglages ont été comparés sur les mêmes 265 événements :



| Seuil en minutes | CRITICAL | HIGH | MEDIUM | LOW | INFO |

|---|---|---|---|---|---|

| 5 | 9 | 2 | 126 | 6 | 1 |

| 15 | 9 | 2 | 2 | 6 | 1 |

| 120 | 8 | 2 | 2 | 6 | 1 |



Avec 5 minutes, les nombreux intervalles habituels entre événements produisent 124 alertes MEDIUM supplémentaires par rapport au réglage de 15 minutes.



Avec 120 minutes, l’interruption de 71 minutes et 7 secondes ne déclenche plus R08. Les alertes R05 sur l’altération de la journalisation restent néanmoins présentes.



Le code compare les événements consécutifs, après tri chronologique, et déclenche R08 lorsque leur intervalle est strictement supérieur au seuil.



Il attribue une sévérité CRITICAL lorsqu’un StopLogging est trouvé entre le début de l’intervalle et les deux minutes suivantes ; sinon, l’alerte de silence est MEDIUM.



Cette corrélation est une heuristique. Le code ne vérifie pas explicitement que l’événement terminant l’intervalle est StartLogging. Dans le scénario étudié, il s’agit bien de StartLogging, ce qui a été vérifié dans les événements.



Le seuil par défaut du programme est de 30 minutes. L’analyse finale du projet utilise explicitement :



&#x20;   python src/analyze\_logs.py collected --gap-minutes 15



Le compromis recherché est de limiter les alertes sur les périodes normales de faible activité sans manquer les interruptions significatives.



## Q19 — Pourquoi dédupliquer les événements sur eventID ?



Un même événement peut être présent dans plusieurs copies d’un fichier, dans une collecte S3 et dans un export manuel. Le compter plusieurs fois fausserait les statistiques et pourrait déclencher artificiellement des règles de seuil.



La fonction load\_records() utilise un ensemble seen :



1\. elle récupère l’eventID ;

2\. elle ignore l’événement si cet identifiant a déjà été rencontré ;

3\. sinon, elle ajoute l’identifiant à seen et conserve l’événement ;

4\. elle trie ensuite les événements par eventTime.



La déduplication est fondée sur l’identifiant, pas sur une comparaison complète du contenu. Si deux enregistrements portent le même eventID, le premier rencontré est conservé.



Lorsqu’un eventID est absent ou vide, le code utilise une valeur de remplacement construite à partir du chemin du fichier et du nombre d’événements déjà chargés. Cela permet de charger l’enregistrement, mais ne garantit pas de reconnaître ses copies dans plusieurs fichiers.



## Q20 — Quelle est la chronologie de l’incident ?



La chronologie complète figure dans la section 3 de rapport\_investigation.md. Elle comprend les heures UTC, les acteurs, les IP, les actions, les résultats, les eventID et les scénarios associés.



Synthèse du 29 octobre 2026 :



\- 02:11:07–02:11:52 : trois échecs de connexion de bob.

\- 02:14:30 : connexion réussie sans MFA.

\- 02:16:02–02:18:03 : quatre refus sur des opérations IAM et S3.

\- 02:21:40 : auto-attribution d’AdministratorAccess.

\- 02:23:15 : création d’une clé pour svc-backup.

\- 02:26:48 : utilisation de cette clé pour GetCallerIdentity.

\- 02:31:12 : inventaire des buckets.

\- 02:33:05 : suppression de corp-backups-prod.

\- 02:39:20 : tentative de suppression du trail refusée.

\- 02:41:03 : arrêt de la journalisation.

\- 03:52:10 : reprise de la journalisation par Alice.

\- 03:58:30 : désactivation de la clé non autorisée par Alice.



Les actions suspectes proviennent de 203.0.113.66. Les deux actions de réponse d’Alice proviennent de 198.51.100.10.



## Q21 — Quelle est la cause racine et quels facteurs aggravent l’incident ?



L’accès suspect sous bob est suivi d’un abus de permissions IAM trop larges. Les événements démontrent une connexion réussie sans MFA, mais pas la façon dont les identifiants ont été obtenus.



Les principaux facteurs sont :



1\. Connexion suspecte réussie sans MFA.

2\. iam:AttachUserPolicy sur Resource "\*", permettant l’auto-attribution d’AdministratorAccess.

3\. iam:CreateAccessKey sur Resource "\*", permettant la création d’une clé pour svc-backup.

4\. s3:\* sur Resource "\*", donnant des permissions S3 excessivement larges.

5\. Protection de la journalisation incomplète au regard des résultats observés : DeleteTrail est refusé, mais StopLogging ne présente pas d’erreur.



La section 6 du rapport distingue ces constats des éléments inconnus. Elle ne prétend pas que l’élévation était indispensable à la suppression du bucket, puisque DevPolicy accordait déjà s3:\*.



## Q22 — Pourquoi DeleteTrail échoue-t-il alors que StopLogging réussit ?



L’événement DeleteTrail contient AccessDeniedException et un message mentionnant un refus explicite dans une service control policy.



Preuve : 51d08109-fc90-4838-9874-1408f7b217c7.



L’événement StopLogging suivant ne contient pas de code d’erreur et précède l’interruption des journaux.



Preuve : fba6abf7-cdbc-4653-b7a7-e8b75e70f65f.



La protection observée empêche donc la suppression du trail, mais pas l’arrêt de sa journalisation. Le document complet de la SCP n’est pas disponible : ses autres règles restent inconnues.



## Q23 — L’acteur a-t-il pu agir pendant la période sans journaux ?



Oui, d’autres actions sont possibles pendant cet intervalle, mais elles ne sont ni démontrées ni exclues par les données disponibles.



La période entre StopLogging et StartLogging dure 71 minutes et 7 secondes. Aucun événement intermédiaire n’est présent dans le jeu.



L’absence d’événements ne prouve pas l’absence d’activité. Pour approfondir l’investigation, il faudrait examiner les autres sources effectivement disponibles : journaux d’accès S3, journaux applicatifs, VPC Flow Logs, CloudWatch, résultats GuardDuty et historiques des sauvegardes ou des configurations.



Ces sources complémentaires n’ont pas été collectées dans ce projet. Leur disponibilité et leur contenu ne sont donc pas présumés.



Voir la section 9 du rapport.



## Q24 — Quels indicateurs servent au confinement et lesquels servent à la recherche ?



Les indicateurs détaillés figurent dans la section 5 du rapport.



Cibles de confinement proposées dans le scénario :



\- les moyens d’accès compromis de bob ;

\- la clé AKIALABROGUE00000001 de svc-backup ;

\- l’attachement non autorisé d’AdministratorAccess ;

\- les permissions permettant de rétablir ces accès.



La désactivation de la clé est effectivement visible dans les événements. Les autres mesures ne sont pas présentées comme réalisées.



Pivots de recherche :



\- IP : 203.0.113.66 ;

\- identités : bob et svc-backup ;

\- clé : AKIALABROGUE00000001 ;

\- agents utilisateurs : Firefox 131 sous Linux et AWS CLI 2.15.30 sous Windows 10 ;

\- ressources : corp-finance-secrets/2026/payroll.xlsx, corp-backups-prod et corp-trail ;

\- policy : arn:aws:iam::aws:policy/AdministratorAccess.



L’IP est un indicateur complémentaire, pas une cible de confinement suffisante à elle seule. Les agents utilisateurs, noms de ressources et noms de policies ne sont pas malveillants en eux-mêmes.



Toutes ces valeurs appartiennent au scénario synthétique : elles ne constituent pas une liste réelle d’indicateurs à bloquer.



## Q25 — Dans quel ordre proposer les mesures de confinement ?



L’ordre proposé est :



1\. Utiliser une identité d’administration de confiance pour restreindre bob et empêcher de nouvelles actions sensibles.

2\. Neutraliser les moyens d’accès compromis, notamment la clé créée pour svc-backup, et traiter les sessions actives.

3\. Retirer AdministratorAccess et corriger les permissions permettant sa réattribution.

4\. Réinitialiser les identifiants concernés et imposer le MFA avant le rétablissement de l’accès légitime.

5\. Rétablir et protéger la journalisation dès que possible, en parallèle des premières actions.

6\. Rechercher les autres mécanismes de persistance, évaluer l’impact et restaurer les services depuis des sources vérifiées.



La préservation des preuves doit accompagner le confinement sans retarder indûment l’arrêt des actions dangereuses.



L’objectif est d’éviter qu’une identité encore active recrée une clé ou réattribue des privilèges pendant la remédiation. Un simple changement de mot de passe ne traite pas, à lui seul, la clé créée pour une autre identité.



Cet ordre est une proposition de réponse. Les événements montrent uniquement la reprise du trail par Alice, puis la désactivation de la clé. Ils ne démontrent pas l’exécution de l’ensemble du plan.



Voir la section 7 du rapport.



## Q26 — Quand une création de clé peut-elle être légitime ?



Une création de clé peut correspondre à une opération autorisée, par exemple une rotation. Elle doit être interprétée dans son contexte.



Trois indices rendent la création de clé d’Alice compatible avec une activité bénigne :



1\. Alice crée une clé pour elle-même : acteur et cible sont identiques.

2\. L’appel provient de son IP habituelle dans le scénario, 198.51.100.10.

3\. Le contexte de session indique mfaAuthenticated: "true".



Preuve : 26d794d3-0db9-4301-afbb-411aa1235a8c.



Le code R03 classe cette création en INFO parce que l’acteur est identique à la cible et que l’IP est interne. Il ne vérifie pas le MFA pour cette classification.



La création seule ne prouve pas une rotation complète : il faudrait également vérifier le remplacement de l’ancienne clé et sa désactivation ou sa suppression.



À l’inverse, bob crée une clé pour un autre utilisateur, svc-backup, depuis l’IP extérieure 203.0.113.66. Cette différence de cible déclenche R03 avec une gravité élevée.



## Q27 — Pourquoi ReadOnlyAccess ne déclenche-t-elle pas R02 et quelle est la couverture réelle ?



L’événement d’Alice attache ReadOnlyAccess à Carol :



&#x20;   arn:aws:iam::aws:policy/ReadOnlyAccess



Preuve : dc0f2fcf-b3f6-4e0d-8860-3b32b4fb0eb9.



Pour AttachUserPolicy, AttachRolePolicy et AttachGroupPolicy, R02 recherche un ARN se terminant par AdministratorAccess. L’ARN ReadOnlyAccess ne satisfait pas cette condition.



L’absence d’alerte R02 dépend donc du nom de la policy ciblée, et non d’une validation générale de la légitimité de l’action d’Alice. La présence de MFA et l’IP habituelle sont des indices examinés pendant l’investigation, pas des conditions de cette branche de R02.



Le code surveille également :



\- PutUserPolicy ;

\- PutRolePolicy ;

\- PutGroupPolicy ;

\- CreatePolicy ;

\- CreatePolicyVersion.



Pour ces opérations, il recherche dans policyDocument, uniquement lorsque ce champ est une chaîne, les motifs textuels "Action": "\*" et "Resource": "\*".



Limites de cette détection :



\- elle ne réalise pas une évaluation complète des permissions IAM ;

\- elle ne vérifie pas que les deux motifs appartiennent au même Statement ;

\- elle ne vérifie pas Effect: Allow ;

\- elle ne couvre pas toutes les représentations équivalentes, notamment les tableaux ou documents encodés ;

\- cette branche ne filtre pas les événements en erreur avant de produire une alerte ;

\- le passage examiné ne traite pas explicitement SetDefaultPolicyVersion.



Une amélioration possible serait d’analyser la structure de la policy et le résultat de l’appel, puis de corréler les changements de version et leurs attributions. Cette amélioration n’a pas été implémentée dans le projet.



## Q28 — Quel est l’impact de la perte du bucket de sauvegardes et que signifie l’absence de DeleteObject ?



La perte d’un bucket applicatif peut affecter directement les données utilisées par l’application et son fonctionnement.



La perte du bucket de sauvegardes affecte la capacité à restaurer les données après un incident. Son impact dépend notamment de l’existence de copies indépendantes et de leur état, ce que le jeu ne permet pas d’établir.



L’événement observé cible corp-backups-prod :



&#x20;   1e2595b8-8fc9-486b-a9dd-ebf563119aca



L’absence de DeleteObject dans les journaux analysés ne démontre ni que des objets n’ont jamais été supprimés ni qu’ils ont effectivement été supprimés pendant la période étudiée. Elle ne permet pas de reconstituer le contenu antérieur du bucket.



Il faut distinguer la suppression du bucket, représentée dans le jeu, de la séquence de suppression de ses objets, qui n’est pas démontrée par les extractions.



## Q29 — Pourquoi tenter DeleteTrail avant StopLogging et que révèle le résultat ?



La tentative de DeleteTrail est cohérente avec une volonté de supprimer la configuration du trail. Après le refus, StopLogging représente une autre manière d’interrompre la journalisation.



Cette lecture est une interprétation de la séquence ; les événements ne prouvent pas le raisonnement exact de l’acteur.



Les résultats montrent une protection incomplète au regard des deux opérations :



\- DeleteTrail est refusé par une SCP ;

\- StopLogging ne présente pas d’erreur et précède l’interruption de visibilité.



La suppression du trail est donc empêchée, mais pas l’arrêt observé de sa journalisation.



Les seules données analysées ne permettent pas de prouver l’absence d’activité pendant les 71 minutes et 7 secondes. Des sources complémentaires pourraient réduire cette incertitude, sans être présumées disponibles ni exhaustives.



## Q30 — Pourquoi l’échec isolé d’Alice diffère-t-il de la séquence de bob ?



Pour Alice, le 28 octobre :



\- un échec à 08:04:40 ;

\- une IP habituelle dans le scénario : 198.51.100.10 ;

\- un succès 26 secondes plus tard depuis la même IP ;

\- MFAUsed: Yes lors du succès.



Preuves :



\- échec : bc8960a9-23b8-41e9-b924-56de3eb13b90 ;

\- succès : 0822e8f3-6c03-4199-972a-846916419f82.



Pour bob, le 29 octobre :



\- trois échecs rapprochés ;

\- une IP extérieure au périmètre défini : 203.0.113.66 ;

\- un succès ultérieur sans MFA ;

\- des appels refusés et des actions sensibles dans la continuité.



L’échec d’Alice est compatible avec une erreur de saisie. Ce n’est pas une certitude fondée uniquement sur l’IP, mais une interprétation étayée par l’ensemble de la séquence.



## Q31 — Pourquoi le refus de Carol ne suffit-il pas à déclarer un incident ?



Carol reçoit un refus isolé sur ListUsers le 28 octobre à 14:20:09 depuis 198.51.100.31.



Preuve : ac1aa554-c3c7-4611-bfe3-fa49054f92ff.



Dans les extractions examinées, ce refus n’est pas suivi d’une rafale ou d’une chaîne d’actions sensibles. Il peut correspondre à une tentative légitime dépassant les permissions de l’utilisatrice.



Le code produit une alerte R06 LOW sur cet événement. Le niveau LOW n’est pas une preuve d’innocuité : il indique qu’une contextualisation est nécessaire.



Le même refus deviendrait plus préoccupant s’il était associé à :



\- plusieurs autres refus rapprochés ;

\- de nouvelles ressources sensibles ciblées ;

\- une origine inhabituelle ;

\- une connexion suspecte ;

\- une modification des permissions ou un accès sensible réussi.



L’appréciation doit donc porter sur la séquence et le contexte, pas uniquement sur un événement isolé.
