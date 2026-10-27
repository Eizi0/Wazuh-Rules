# Wazuh-Rules

Règles personnalisées pour Wazuh, chacune accompagnée de la source de données qu'elle exploite, de son intégration (décodeur, wodle, script de collecte) et de sa correspondance MITRE ATT&CK quand elle s'applique.

## Distinction importante : visibilité vs détection

Toutes les règles de ce dépôt ne sont pas des détecteurs d'anomalie. Certaines créent de la **visibilité** (elles journalisent un état, utile pour l'investigation et le threat hunting manuel) ; d'autres font de la **détection** à proprement parler (elles ne se déclenchent que sur un comportement anormal). Chaque dossier précise explicitement de quel type il s'agit, pour éviter de présenter une règle de collecte comme une alerte de sécurité.

## Règles disponibles

| Dossier | Type | Source | MITRE ATT&CK |
|---|---|---|---|
| [`Windows Logon Session/`](./Windows%20Logon%20Session/) | Visibilité | Sysinternals `logonsessions` via wodle Wazuh | T1078 (Valid Accounts) |

### Windows Logon Session

Collecte périodique (toutes les heures) des sessions Windows actives via l'utilitaire Sysinternals `logonsessions`, convertie en JSON et ingérée par Wazuh. La règle associée (id `100070`, niveau 3) journalise chaque relevé — **elle ne détecte pas une anomalie en elle-même**, elle construit l'historique sur lequel une règle de corrélation ou une recherche manuelle peut s'appuyer (ex. une session inhabituelle sur un compte à privilèges, un nombre de sessions concurrentes anormal pour un même compte). Voir le [README du dossier](./Windows%20Logon%20Session/README.md) pour l'intégration complète (configuration du wodle, script PowerShell, règle XML).

## À venir

Rien d'engagé pour l'instant — ce dépôt grandit au fil des règles réellement testées, pas par lot. Pas de calendrier annoncé pour éviter de promettre un contenu qui n'existe pas encore.
