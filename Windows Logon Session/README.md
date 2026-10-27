

# Sysinternals - Logonsessions 
## 🔐 Intégration de Sysinternals Logonsessions avec Wazuh

Si vous pensez qu’une seule session est active lorsque vous vous connectez à Windows, cet utilitaire risque de vous surprendre.
Logonsessions (de Sysinternals) permet de lister toutes les sessions en cours et, avec l’option -p, d’afficher les processus associés.

## Description

[Sysinternals Logonsessions - Official documentation.](https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions)

## 🎯 Objectif du projet

L’idée est d’intégrer Logonsessions dans Wazuh afin de :

Collecter automatiquement les informations de sessions Windows.

Convertir ces données en JSON pour une exploitation directe par Wazuh.

Déclencher des alertes personnalisées pour améliorer la détection des menaces liées aux compromissions de comptes (MITRE ATT&CK T1078 – Valid Accounts).

## ⚙️ Intégration avec Wazuh

Capacité Wazuh utilisée : wodles-command
Type de sortie : active-responses.log
MITRE ATT&CK : T1078

Configuration à ajouter côté Wazuh Manager dans :
/var/ossec/etc/shared/your_windows_agents_group/agent.conf


 ```<wodle name="command">
  <disabled>no</disabled>
  <tag>logonsessions</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\logonsessions.ps1"</command>
  <interval>1h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```
## 📜 Script PowerShell : logonsessions.ps1

Ce script est déclenché automatiquement par Wazuh.

Exécute logonsessions.exe en mode CSV.

Nettoie et formate les données.

Convertit chaque entrée en JSON.

Envoie le résultat dans active-responses.log de l’agent Wazuh.


```################################

# Exécution de Logonsessions et export CSV
$Sessions_Output_CSV = c:\"Program Files"\Sysinternals\logonsessions.exe -nobanner -c -p

# Nettoyage et conversion en tableau
$Sessions_Output_Array = $Sessions_Output_CSV.PSObject.BaseObject.Trim(' ') -Replace '\s','' | ConvertFrom-Csv

# Conversion JSON et envoi vers active-responses.log
Foreach ($item in $Sessions_Output_Array) {
  echo $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
}

```

## 🛡️ Règle Wazuh personnalisée

Pour exploiter les données JSON générées, une règle personnalisée a été créée :

```
<rule id="100070" level="3">
  <decoded_as>json</decoded_as>
  <field name="LogonSession">\.+</field>
  <field name="UserName">\.+</field>
  <description>Windows Logon Sessions - Snapshot</description>
  <mitre>
   <id>T1078</id>
  </mitre>
  <options>no_full_log</options>
  <group>windows_logonsessions,</group>
</rule>
```

## ✅ Résultats obtenus

Centralisation des sessions Windows actives dans Wazuh.

Détection facilitée d’anomalies liées aux connexions suspectes.

Réduction du bruit grâce à une règle custom adaptée.

✍️ Auteur : Eizi0

🎓 Étudiant en Mastère Cybersécurité – ESGI Paris

📌 Projet orienté Blue Team / SOC
