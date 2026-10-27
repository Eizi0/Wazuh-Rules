# Wazuh-Rules

Règles personnalisées pour Wazuh, chacune accompagnée de la source de données qu'elle exploite, de son intégration (décodeur, wodle, script de collecte) et de sa correspondance MITRE ATT&CK quand elle s'applique.

## Distinction importante : visibilité vs détection

Toutes les règles de ce dépôt ne sont pas des détecteurs d'anomalie. Certaines créent de la **visibilité** (elles journalisent un état, utile pour l'investigation et le threat hunting manuel) ; d'autres font de la **détection** à proprement parler (elles ne se déclenchent que sur un comportement anormal). Chaque dossier précise explicitement de quel type il s'agit, pour éviter de présenter une règle de collecte comme une alerte de sécurité.

## Statut de test

Chaque dossier indique si sa règle a été validée contre une instance Wazuh réelle ou seulement écrite/revue. Une règle « non testée » est un point de départ documenté, pas une détection prête à déployer sans vérification — voir la section « À venir » plus bas.

## Règles disponibles

| Dossier | Type | Statut | Source | MITRE ATT&CK |
|---|---|---|---|---|
| [`Windows Logon Session/`](./Windows%20Logon%20Session/) | Visibilité | Déployée | Sysinternals `logonsessions` via wodle Wazuh | T1078 (Valid Accounts) |
| [`Kerberoasting Detection/`](./Kerberoasting%20Detection/) | Détection | Écrite, non testée | Journal Security Windows, événement 4769 | T1558.003 (Kerberoasting) |
| [`DNS Tunneling Exfiltration/`](./DNS%20Tunneling%20Exfiltration/) | Détection | Écrite, non testée | Sysmon, événement 22 (DNS query) | T1048.003 (Exfiltration over DNS) |

### Windows Logon Session

Collecte périodique (toutes les heures) des sessions Windows actives via l'utilitaire Sysinternals `logonsessions`, convertie en JSON et ingérée par Wazuh. La règle associée (id `100070`, niveau 3) journalise chaque relevé — **elle ne détecte pas une anomalie en elle-même**, elle construit l'historique sur lequel une règle de corrélation ou une recherche manuelle peut s'appuyer. Voir le [README du dossier](./Windows%20Logon%20Session/README.md).

### Kerberoasting Detection

Détecte une demande anormalement fréquente de tickets de service Kerberos en chiffrement RC4 par un même compte — signal classique de Kerberoasting (Rubeus, GetUserSPNs.py). Logique de détection adaptée d'une requête KQL de [SlimKQL/Hunting-Queries-Detection-Rules](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules), réécrite pour les journaux Windows plutôt que pour Microsoft Defender for Identity. Voir le [README du dossier](./Kerberoasting%20Detection/README.md) pour la règle complète, ses limites assumées et les faux positifs à surveiller.

### DNS Tunneling Exfiltration

Détecte un volume anormal de requêtes DNS vers des noms d'hôte anormalement longs depuis un même poste — signal classique de tunneling DNS (exfiltration, C2 déguisé en trafic DNS). Logique de détection adaptée d'une requête KQL de [SlimKQL/Hunting-Queries-Detection-Rules](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules), réécrite pour Sysmon plutôt que pour Microsoft Defender for Endpoint. Voir le [README du dossier](./DNS%20Tunneling%20Exfiltration/README.md).

## À venir

Un lab Wazuh réel est en préparation pour valider ces deux dernières règles avec de vrais scénarios d'attaque simulés (Kerberoasting, exfiltration), et en ajouter d'autres au fur et à mesure — pas de calendrier annoncé pour éviter de promettre un contenu qui n'existe pas encore.
