# Script de Post-Installation Windows 11 🚀

## 📋 Description

Ce script PowerShell automatise entièrement la configuration post-déploiement de postes de travail Windows 11 en entreprise. Il permet de standardiser et d'accélérer la mise en service des nouveaux ordinateurs avec une configuration cohérente et sécurisée.

**Version :** 2.0  
**Compatibilité :** Windows 11 (PowerShell 5.1+)  
**Prérequis :** Droits administrateur obligatoires

---

## ✨ Fonctionnalités Principales

### 🔧 Configuration Système
- **Vérification des privilèges administrateur** - Contrôle automatique avant exécution
- **Configuration linguistique** - Passage automatique en français (France)
- **Plan d'alimentation** - Basculement vers "Hautes performances"
- **Synchronisation horaire** - Mise à jour via les serveurs de temps Windows
- **Nettoyage des bloatwares** - Suppression des applications préinstallées inutiles

### 💻 Gestion des Ordinateurs
- **Renommage intelligent** - Attribution de noms standardisés aux postes
- **Jonction au domaine** - Intégration automatique à l'Active Directory
- **Comptes utilisateurs** - Création d'administrateurs locaux personnalisés
- **Bureau à distance** - Activation et sécurisation du RDP

### 📦 Installation de Logiciels
- **Gestionnaire Winget** - Installation automatisée d'applications métier
- **Microsoft 365** - Déploiement via Office Deployment Tool (ODT)
- **Mises à jour système** - Installation automatique des correctifs Windows
- **Applications personnalisables** - Liste configurable selon les besoins

### 🛡️ Sécurité et Fiabilité
- **Logging complet** - Traçabilité de toutes les opérations
- **Gestion d'erreurs avancée** - Continuité du script même en cas de problème
- **Système de reprise** - Mécanisme de checkpoint après redémarrage
- **Validation de configuration** - Vérification de cohérence des paramètres

---

## 📁 Structure du Projet

```
📦 Post-Installation-Windows11/
├── 📄 Deploiement-Script-Post-Installation.ps1  # Script principal
├── 📄 PostInstallConfig.json                     # Fichier de configuration
├── 📄 README.md                                  # Cette documentation
└── 📁 Logs/                                      # Répertoire des journaux (auto-créé)
    ├── Post-Install-Log-YYYY-MM-DD.txt
    └── Post-Install-Transcript-YYYY-MM-DD-HH-mm-ss.txt
```

---

## 🚀 Installation et Utilisation

### Prérequis Système
- Windows 11 (toutes éditions)
- PowerShell 5.1 ou supérieur
- Connexion Internet (recommandée)
- Compte administrateur local ou de domaine

### Installation Rapide

1. **Télécharger les fichiers**
   ```cmd
   # Placer les fichiers dans C:\ ou sur un support amovible
   ```

2. **Configurer les paramètres** (optionnel)
   ```json
   # Éditer PostInstallConfig.json selon vos besoins
   ```

3. **Exécuter le script**
   ```powershell
   # Clic-droit sur le fichier .ps1 → "Exécuter avec PowerShell"
   # OU depuis PowerShell Admin :
   .\Deploiement-Script-Post-Installation.ps1
   ```

### Modes d'Exécution

#### 🤖 Mode Automatique (Recommandé)
Utilise le fichier `PostInstallConfig.json` pour une exécution sans intervention.

#### 👤 Mode Interactif  
Le script demande les informations nécessaires via des prompts utilisateur.

---

## ⚙️ Configuration Avancée

### Fichier de Configuration JSON

Le fichier `PostInstallConfig.json` permet de personnaliser entièrement le comportement du script :

```json
{
  "PCName": "WS-CORP-001",
  "DomainJoin": true,
  "DomainName": "contoso.local",
  "LocalUserName": "AdminLocal",
  "LocalUserPassword": "P@ssw0rd123!Secure",
  "Applications": [
    "Google.Chrome",
    "Microsoft.VisualStudioCode",
    "Adobe.Acrobat.Reader.64-bit"
  ]
}
```

#### Paramètres Disponibles

| Paramètre | Type | Description | Valeur par défaut |
|-----------|------|-------------|-------------------|
| `PCName` | String | Nouveau nom du poste | *Demande interactive* |
| `DomainJoin` | Boolean | Active la jonction au domaine | `false` |
| `DomainName` | String | Nom du domaine AD | *Requis si DomainJoin=true* |
| `LocalUserName` | String | Nom de l'utilisateur local | *Demande interactive* |
| `LocalUserPassword` | String | Mot de passe (⚠️ sécuriser) | *Demande interactive* |
| `Applications` | Array | Liste des apps Winget | *Liste par défaut* |

### Applications Par Défaut

Le script installe automatiquement ces applications via Winget :

- **🌐 Google Chrome** - Navigateur web
- **🦊 Mozilla Firefox** - Navigateur alternatif  
- **📦 7-Zip** - Gestionnaire d'archives
- **📄 Adobe Acrobat Reader** - Lecteur PDF
- **⚡ Microsoft PowerToys** - Outils système
- **📝 Notepad++** - Éditeur de texte avancé
- **💻 Visual Studio Code** - Éditeur de code
- **🎬 VLC Media Player** - Lecteur multimédia

---

## 📊 Étapes d'Exécution Détaillées

### 🔄 Étape 0 : Configuration Initiale
- ✅ Vérification des privilèges administrateur
- ✅ Configuration de la politique d'exécution PowerShell
- ✅ Initialisation du système de logging
- ✅ Test de connectivité Internet
- ✅ Configuration langue française (avec redémarrage si nécessaire)
- ✅ Activation du plan d'alimentation "Hautes performances"
- ✅ Nettoyage des applications préinstallées (bloatware)

### 💻 Étape 1 : Renommage du Poste
- ✅ Lecture du nom actuel de l'ordinateur
- ✅ Application du nouveau nom (configuration ou saisie)
- ✅ Préparation du redémarrage pour appliquer les changements

### 🏢 Étape 2 : Jonction au Domaine
- ✅ Détection du mode domaine/groupe de travail
- ✅ Demande des identifiants de domaine si nécessaire
- ✅ Jonction automatique au domaine Active Directory
- ✅ Mise à jour forcée des stratégies de groupe

### 👥 Étape 3 : Gestion des Utilisateurs
- ✅ Création d'un compte administrateur local personnalisé
- ✅ Attribution des droits administrateur
- ✅ Configuration de la politique de mot de passe

### ⏰ Étape 4 : Synchronisation Horaire
- ✅ Démarrage du service de temps Windows (W32Time)
- ✅ Synchronisation avec les serveurs de temps Microsoft
- ✅ Vérification de la précision temporelle

### 📦 Étape 5 : Installation de Logiciels
- ✅ Vérification de la disponibilité de Winget
- ✅ Installation silencieuse des applications définies
- ✅ Gestion des erreurs et des dépendances
- ✅ Rapport détaillé des installations réussies/échouées

### 🖥️ Étape 6 : Bureau à Distance
- ✅ Activation des règles de pare-feu pour RDP
- ✅ Configuration du service Terminal Services
- ✅ Activation de l'authentification au niveau réseau (sécurité)

### 📄 Étape 7 : Microsoft 365
- ✅ Téléchargement de l'Office Deployment Tool officiel
- ✅ Génération du fichier de configuration XML personnalisé
- ✅ Installation silencieuse d'Office 365 en français
- ✅ Configuration de l'activation automatique

### 🔄 Étape 8 : Mises à Jour Windows
- ✅ Installation du module PSWindowsUpdate
- ✅ Recherche des mises à jour disponibles
- ✅ Installation automatique des correctifs système
- ✅ Gestion du redémarrage différé

### 🧹 Étape 9 : Nettoyage
- ✅ Suppression des raccourcis inutiles du bureau
- ✅ Nettoyage des fichiers temporaires d'installation
- ✅ Suppression des fichiers de checkpoint
- ✅ Optimisation de l'espace disque

---

## 📋 Journalisation et Traçabilité

### Types de Logs Générés

#### 📊 Journal Principal
- **Fichier :** `C:\Logs\Post-Install-Log-YYYY-MM-DD.txt`
- **Contenu :** Messages formatés avec horodatage et niveau de criticité
- **Format :** `[YYYY-MM-DD HH:MM:SS] [LEVEL] Message`

#### 📝 Transcription Complète
- **Fichier :** `C:\Logs\Post-Install-Transcript-YYYY-MM-DD-HH-mm-ss.txt`
- **Contenu :** Sortie complète de la session PowerShell
- **Usage :** Débogage approfondi et audit complet

#### ⚡ Fichier de Checkpoint
- **Fichier :** `C:\PostInstall_Checkpoint.txt`
- **Contenu :** Numéro de la dernière étape complétée
- **Usage :** Reprise automatique après redémarrage

### Niveaux de Criticité

| Niveau | Couleur | Description |
|--------|---------|-------------|
| **Info** | ⚪ Blanc | Informations générales d'avancement |
| **Success** | 🟢 Vert | Operations réussies avec succès |
| **Warning** | 🟡 Jaune | Problèmes non-critiques, script continue |
| **Error** | 🔴 Rouge | Erreurs graves, étape échoue |

---

## 🛡️ Sécurité et Bonnes Pratiques

### ⚠️ Avertissements Sécurité

- **Mots de passe** : Ne jamais stocker des mots de passe en clair en production
- **Droits administrateur** : Le script nécessite des privilèges élevés
- **Connexion réseau** : Certaines fonctionnalités nécessitent Internet
- **Validation** : Toujours tester sur un environnement non-productif d'abord

### 🔒 Recommandations

1. **Chiffrement des mots de passe**
   ```powershell
   # Utiliser des SecureStrings ou des solutions de coffre-fort
   ConvertTo-SecureString "Password" -AsPlainText -Force
   ```

2. **Sécurisation des fichiers de configuration**
   ```cmd
   # Limiter l'accès au fichier JSON
   icacls PostInstallConfig.json /grant Administrators:F /remove Users
   ```

3. **Politique d'exécution**
   ```powershell
   # Configurer une politique restrictive après déploiement
   Set-ExecutionPolicy Restricted -Scope LocalMachine
   ```

---

## 🔧 Dépannage et FAQ

### ❓ Questions Fréquentes

**Q : Le script s'arrête avec "Execution Policy" ?**  
R : Exécuter `Set-ExecutionPolicy Bypass -Scope Process` depuis PowerShell Admin.

**Q : L'installation d'Office 365 échoue ?**  
R : Vérifier la connectivité Internet et les permissions sur le dossier C:\ODT.

**Q : Winget n'est pas reconnu ?**  
R : Installer "App Installer" depuis le Microsoft Store ou Windows Package Manager.

**Q : Le script redémarre en boucle ?**  
R : Supprimer le fichier C:\PostInstall_Checkpoint.txt et relancer.

### 🐛 Résolution de Problèmes

#### Erreur de Privilèges
```powershell
# Solution : Lancer PowerShell en tant qu'Administrateur
Right-click PowerShell → "Run as Administrator"
```

#### Problème de Domaine
```powershell
# Vérifier la connectivité au contrôleur de domaine
Test-NetConnection "domaine.local" -Port 389
```

#### Installation Winget Échoue
```powershell
# Mettre à jour Winget manuellement
winget upgrade --id Microsoft.Winget.Source
```

---

## 🚀 Personnalisation Avancée

### Ajouter de Nouvelles Applications

1. **Rechercher l'ID Winget**
   ```powershell
   winget search "nom_application"
   ```

2. **Ajouter au fichier JSON**
   ```json
   "Applications": [
     "Existing.App",
     "New.Application.ID"
   ]
   ```

### Modifier les Étapes d'Installation

Le script est modulaire, chaque étape peut être désactivée en commentant l'appel dans la fonction `Main()`.

### Ajouter des Configurations Personnalisées

Exemple d'ajout d'une nouvelle section :

```powershell
function Step-CustomConfiguration {
    Write-LogMessage "=== ÉTAPE PERSONNALISÉE ===" -Level "Info"
    # Votre code personnalisé ici
    return $true
}
```

---

## 📞 Support et Contribution

### 🐛 Signaler un Bug
- Vérifier les logs dans `C:\Logs\`
- Créer un rapport détaillé avec les messages d'erreur
- Inclure la version du script et de Windows

### 💡 Demander une Fonctionnalité
- Décrire le besoin métier
- Fournir des exemples d'usage
- Expliquer la valeur ajoutée

### 🤝 Contribuer au Code
- Respecter le style de code PowerShell existant
- Ajouter des commentaires pour les nouvelles fonctions
- Tester sur différentes configurations Windows 11

---

## 📝 Historique des Versions

### Version 2.0 (Actuelle)
- ✅ Correction de l'URL ODT Microsoft
- ✅ Système de checkpoint et reprise après redémarrage  
- ✅ Gestion d'erreurs robuste avec niveaux de log
- ✅ Sécurisation des mots de passe
- ✅ Validation de configuration avancée
- ✅ Support des applications personnalisables
- ✅ Authentification réseau pour RDP

### Version 1.0 (Originale)
- ✅ Configuration de base Windows 11
- ✅ Installation Office et applications
- ✅ Jonction domaine et utilisateurs locaux
- ❌ Problèmes d'URL et de sécurité (corrigés en v2.0)

---

## 📄 Licence et Avertissements

⚠️ **AVERTISSEMENT IMPORTANT**

Ce script modifie des paramètres système critiques et installe des logiciels. Il est fortement recommandé de :

1. **Tester en environnement de développement** avant utilisation en production
2. **Sauvegarder le système** avant exécution
3. **Valider la compatibilité** avec votre infrastructure
4. **Former les équipes** à l'utilisation et au dépannage

**Utilisation à vos risques et périls**. Les auteurs ne peuvent être tenus responsables des dommages causés par une utilisation inappropriée.

---

## 🔗 Ressources Utiles

- [Documentation PowerShell Microsoft](https://docs.microsoft.com/powershell/)
- [Winget Package Manager](https://docs.microsoft.com/windows/package-manager/)
- [Office Deployment Tool](https://docs.microsoft.com/deployoffice/overview-office-deployment-tool)
- [Windows 11 Deployment](https://docs.microsoft.com/windows/deployment/)

---

*Dernière mise à jour : 26 septembre 2025*  
*Version du README : 2.0*
