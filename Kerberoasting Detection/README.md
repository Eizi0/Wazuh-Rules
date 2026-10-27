# Détection de Kerberoasting (T1558.003)

**Statut : écrite, non testée contre une instance Wazuh réelle.** À valider dès la mise en place du lab Wazuh, idéalement avec une simulation réelle de Kerberoasting (ex. Rubeus, Atomic Red Team T1558.003) avant toute mise en production.

## Logique de détection

Le Kerberoasting consiste à demander des tickets de service Kerberos (TGS) pour des comptes de service, en forçant un chiffrement faible (RC4), puis à tenter de casser le hash hors ligne. Deux signaux combinés :

1. Un ticket de service est demandé avec un chiffrement `RC4-HMAC` (`0x17`) — significatif mais pas suffisant seul, certains environnements legacy en génèrent légitimement.
2. Le **même compte** déclenche ce signal plusieurs fois en peu de temps — une demande de ticket RC4 isolée arrive ; plusieurs en quelques minutes pour des services différents est le schéma d'un outil d'énumération (Rubeus, GetUserSPNs.py).

## Source de données

Journal **Security** de Windows, événement **4769** (« A Kerberos service ticket was requested »), avec l'audit de la création de processus/accès aux services activé. Remonté à Wazuh via la surveillance `eventchannel` de l'agent Windows.

## Règle Wazuh

```xml
<group name="windows,kerberoasting,">

<rule id="100080" level="3">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.TicketEncryptionType">^0x17$</field>
  <description>Windows : demande de ticket de service Kerberos en chiffrement RC4 (faible)</description>
  <mitre>
    <id>T1558.003</id>
  </mitre>
  <group>kerberoasting,</group>
</rule>

<rule id="100081" level="10" frequency="4" timeframe="3600">
  <if_matched_sid>100080</if_matched_sid>
  <same_field>win.eventdata.TargetUserName</same_field>
  <description>Possible Kerberoasting : un même compte a demandé plusieurs tickets de service en RC4 en moins d'une heure</description>
  <mitre>
    <id>T1558.003</id>
  </mitre>
  <group>kerberoasting,</group>
</rule>

</group>
```

## Limite assumée par rapport à la requête d'origine

La requête source compte le nombre de **SPN distincts** demandés par un même compte (`dcount`). La règle Wazuh ci-dessus compte la **fréquence** des demandes RC4 pour un même compte — une approximation plus simple, faisable nativement avec le moteur de corrélation de Wazuh (`frequency`/`timeframe`/`same_field`), sans décodeur personnalisé. Elle peut donc se déclencher sur un compte qui redemande plusieurs fois le même SPN plutôt que des SPN différents — à affiner après les premiers tests réels, potentiellement en ajoutant un champ `ServiceName` distinct si le décodeur Wazuh l'expose de façon fiable.

## Faux positifs à surveiller

- Comptes de service legacy dans un environnement où RC4 est encore activé par politique (à exclure explicitement par compte plutôt que de relever le seuil).
- Outils d'administration légitimes qui énumèrent des SPN (scanners d'inventaire AD).

## Attribution

Logique de détection adaptée de la requête KQL [« Kerberos Roasting Detection »](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules/blob/main/DefenderXDR/Kerberos%20Roasting%20Detection.kql) du dépôt [SlimKQL/Hunting-Queries-Detection-Rules](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules) (Steven Lim, [@SlimKQL](https://github.com/SlimKQL)), sous licence BSD-3-Clause. La requête source interroge `IdentityLogonEvents` (Microsoft Defender for Identity) ; cette version a été réécrite pour une source de données différente (journal Security Windows via agent Wazuh), pas traduite littéralement.
