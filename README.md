# Wazuh-Rules

Règles personnalisées pour Wazuh. Chaque dossier contient sa règle, sa source de données, son intégration et, le cas échéant, son attribution — ce README racine n'est qu'un index, le détail vit dans chaque dossier pour rester gérable à mesure que la liste grandit.

## Distinction importante : visibilité vs détection

Toutes les règles de ce dépôt ne sont pas des détecteurs d'anomalie. Certaines créent de la **visibilité** (elles journalisent un état, utile pour l'investigation et le threat hunting manuel) ; d'autres font de la **détection** à proprement parler (elles ne se déclenchent que sur un comportement anormal). Le README de chaque dossier précise de quel type il s'agit.

## Statut de test

Une règle « non testée » est un point de départ documenté, pas une détection prête à déployer sans vérification contre une instance Wazuh réelle.

## Index

| Dossier | Type | Statut | MITRE ATT&CK |
|---|---|---|---|
| [`Windows Logon Session/`](./Windows%20Logon%20Session/) | Visibilité | Déployée | T1078 |
| [`Kerberoasting Detection/`](./Kerberoasting%20Detection/) | Détection | Écrite, non testée | T1558.003 |
| [`DNS Tunneling Exfiltration/`](./DNS%20Tunneling%20Exfiltration/) | Détection | Écrite, non testée | T1048.003 |
