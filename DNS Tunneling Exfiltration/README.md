# Détection d'exfiltration par tunneling DNS (T1048.003)

**Statut : écrite, non testée contre une instance Wazuh réelle.** À valider lors de la mise en place du lab Wazuh, avec un outil de tunneling DNS réel en environnement isolé (ex. `dnscat2`, `iodine`) avant toute mise en production.

## Logique de détection

Le tunneling DNS encode des données dans des sous-domaines interrogés auprès d'un serveur DNS contrôlé par l'attaquant, pour exfiltrer des données ou maintenir un canal C2 en contournant les contrôles réseau classiques (le DNS sortant est rarement bloqué). Signal retenu : un volume anormal de requêtes DNS vers des **noms d'hôte inhabituellement longs**, provenant d'un même poste, sur une fenêtre de temps courte — le trafic DNS légitime ne génère pas ce schéma.

## Source de données

**Sysmon Event ID 22** (DNS query), qui expose le nom interrogé (`QueryName`). Nécessite Sysmon installé sur l'hôte Windows et la configuration Sysmon à journaliser les requêtes DNS (`DnsQuery` activé), remonté à Wazuh via l'agent.

## Règle Wazuh

```xml
<group name="windows,sysmon,dns_tunneling,">

<rule id="100090" level="3">
  <if_group>sysmon_event22</if_group>
  <field name="win.eventdata.QueryName" type="pcre2">^.{40,}$</field>
  <description>Sysmon : requête DNS vers un nom d'hôte anormalement long (&gt;= 40 caractères)</description>
  <mitre>
    <id>T1048.003</id>
  </mitre>
  <group>dns_tunneling,</group>
</rule>

<rule id="100091" level="10" frequency="8" timeframe="300">
  <if_matched_sid>100090</if_matched_sid>
  <same_field>win.system.computer</same_field>
  <description>Possible tunneling DNS / exfiltration : volume anormal de requêtes DNS à noms longs depuis le même poste en moins de 5 minutes</description>
  <mitre>
    <id>T1048.003</id>
  </mitre>
  <group>dns_tunneling,</group>
</rule>

</group>
```

## Limite assumée par rapport à la requête d'origine

La requête source compte le nombre de **noms de domaine distincts** longs interrogés par poste sur 30 jours (`dcount`), une fenêtre large adaptée à la chasse (threat hunting) manuelle. La règle Wazuh ci-dessus utilise une **fréquence sur une fenêtre courte** (8 requêtes en 5 minutes) pour produire une alerte en quasi temps réel plutôt qu'un rapport périodique — un compromis différent, pas une reproduction à l'identique. Le seuil de longueur (40 caractères) et de fréquence sont des points de départ à calibrer avec du trafic réel de l'environnement de test.

## Faux positifs à surveiller

- CDN et services cloud légitimes utilisant des sous-domaines générés dynamiquement longs (tokens de session, identifiants de requête).
- Résolveurs DNS internes qui génèrent du trafic groupé pour plusieurs clients derrière une même IP.

## Attribution

Logique de détection adaptée de la requête KQL [« DefenderXDR - Threat Hunting DNS Tunneling »](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules/blob/main/DefenderXDR/DefenderXDR%20-%20Threat%20Hunting%20DNS%20Tunneling.kql) du dépôt [SlimKQL/Hunting-Queries-Detection-Rules](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules) (Steven Lim, [@SlimKQL](https://github.com/SlimKQL)), sous licence BSD-3-Clause. La requête source interroge la télémétrie cloud `DeviceEvents` (Microsoft Defender for Endpoint) ; cette version a été réécrite pour une source de données différente (Sysmon via agent Wazuh), pas traduite littéralement.
