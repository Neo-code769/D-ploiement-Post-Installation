## Script PowerShell de post-installation Windows 11 
## Objectif : Configurer le poste automatiquement après déploiement
## Version : 2.0
## Auteur : Pierre Trublereau

#Requires -RunAsAdministrator
#Requires -Version 5.1

# Configuration globale
$script:LogPath = "C:\Logs"
$script:CheckpointFile = "C:\PostInstall_Checkpoint.txt"
$script:ConfigPath = "C:\PostInstallConfig.json"
$script:CurrentStep = 0

# Fonction de logging améliorée
function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "Info" = "White"
        "Warning" = "Yellow" 
        "Error" = "Red"
        "Success" = "Green"
    }
    
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $colors[$Level]
    
    # Écrire aussi dans le fichier de log
    if ($script:LogPath -and (Test-Path $script:LogPath)) {
        Add-Content -Path "$script:LogPath\Post-Install-Log-$(Get-Date -f yyyy-MM-dd).txt" -Value $logEntry
    }
}

# Fonction de validation de la configuration
function Test-Configuration {
    param($Config)
    
    Write-LogMessage "Validation de la configuration..." -Level "Info"
    
    if (-not $Config) {
        Write-LogMessage "Aucune configuration fournie" -Level "Warning"
        return $false
    }
    
    # Validation des champs critiques
    if ($Config.DomainJoin -and (-not $Config.DomainName)) {
        Write-LogMessage "DomainName requis si DomainJoin est activé" -Level "Error"
        return $false
    }
    
    if ($Config.LocalUserName -and (-not $Config.LocalUserPassword)) {
        Write-LogMessage "LocalUserPassword requis si LocalUserName est spécifié" -Level "Error"
        return $false
    }
    
    return $true
}

# Fonction de sauvegarde du checkpoint
function Save-Checkpoint {
    param([int]$Step)
    Set-Content -Path $script:CheckpointFile -Value $Step
}

# Fonction de récupération du checkpoint
function Get-Checkpoint {
    if (Test-Path $script:CheckpointFile) {
        return [int](Get-Content $script:CheckpointFile)
    }
    return 0
}

# Fonction de nettoyage sécurisé du mot de passe
function ConvertTo-SecurePassword {
    param([string]$PlainPassword)
    return ConvertTo-SecureString $PlainPassword -AsPlainText -Force
}

# Fonction de test de connectivité Internet
function Test-InternetConnection {
    try {
        $null = Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 10
        return $true
    } catch {
        return $false
    }
}

# ÉTAPE 0: VÉRIFICATION ET CONFIGURATION INITIALE
function Step-InitialConfiguration {
    Write-LogMessage "=== ÉTAPE 0: VÉRIFICATION ET CONFIGURATION INITIALE ===" -Level "Info"
    
    # Création du dossier de logs
    if (-not (Test-Path $script:LogPath)) { 
        New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
    }
    
    # Démarrer la transcription
    Start-Transcript -Path "$script:LogPath\Post-Install-Transcript-$(Get-Date -f yyyy-MM-dd-HH-mm-ss).txt" -Append
    Write-LogMessage "Transcription démarrée" -Level "Success"
    
    # Configurer la politique d'exécution
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Write-LogMessage "Politique d'exécution configurée" -Level "Success"
    
    # Vérifier la connectivité Internet
    if (-not (Test-InternetConnection)) {
        Write-LogMessage "Aucune connectivité Internet détectée. Certaines fonctionnalités seront limitées." -Level "Warning"
    }
    
    # Configurer la langue et la région en français (France)
    $locale = (Get-WinSystemLocale).Name
    if ($locale -ne "fr-FR") {
        Write-LogMessage "Configuration de la langue en français..." -Level "Info"
        try {
            Set-WinUILanguageOverride -Language fr-FR
            Set-WinUserLanguageList -LanguageList fr-FR -Force
            Set-WinSystemLocale fr-FR
            Set-WinHomeLocation -GeoId 84   # 84 = France
            Set-WinCultureFromLanguageListOptOut -OptOut $false
            Write-LogMessage "Langue configurée en français. Redémarrage nécessaire." -Level "Success"
            
            # Sauvegarder le checkpoint avant redémarrage
            Save-Checkpoint 1
            Write-LogMessage "Redémarrage dans 10 secondes pour appliquer les changements de langue..." -Level "Info"
            Start-Sleep -Seconds 10
            Restart-Computer -Force
        } catch {
            Write-LogMessage "Impossible de changer la langue du système: $($_.Exception.Message)" -Level "Error"
            return $false
        }
    } else {
        Write-LogMessage "Langue déjà configurée en français" -Level "Success"
    }
    
    # Configurer le plan d'alimentation sur Hautes performances (utilisation du GUID)
    try {
        $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        powercfg -s $highPerfGuid
        Write-LogMessage "Plan d'alimentation configuré sur Hautes performances" -Level "Success"
    } catch {
        Write-LogMessage "Impossible de configurer le plan d'alimentation" -Level "Warning"
    }
    
    # Nettoyage des applications préinstallées
    $bloatware = @("*CandyCrush*", "*BubbleWitch*", "*Xbox*", "*Solitaire*", "*MarchofEmpires*")
    foreach ($app in $bloatware) {
        try {
            Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Write-LogMessage "Application supprimée: $app" -Level "Success"
        } catch {
            Write-LogMessage "Impossible de supprimer: $app" -Level "Warning"
        }
    }
    
    return $true
}

# ÉTAPE 1: RENOMMER LE PC
function Step-RenameComputer {
    param($Config)
    
    Write-LogMessage "=== ÉTAPE 1: RENOMMAGE DU PC ===" -Level "Info"
    
    $computerName = $env:COMPUTERNAME
    $newName = $null
    
    if ($Config -and $Config.PCName) {
        $newName = $Config.PCName
        Write-LogMessage "Nom du PC défini par la configuration: $newName" -Level "Info"
    } else {
        $newName = Read-Host "Entrez le nouveau nom du PC (actuel: $computerName)"
    }
    
    if ($newName -and $newName -ne $computerName) {
        try {
            Rename-Computer -NewName $newName -Force
            Write-LogMessage "PC renommé de '$computerName' vers '$newName'" -Level "Success"
            return $true
        } catch {
            Write-LogMessage "Échec du renommage: $($_.Exception.Message)" -Level "Error"
            return $false
        }
    } else {
        Write-LogMessage "Aucun changement de nom nécessaire" -Level "Info"
        return $true
    }
}

# ÉTAPE 2: JOINDRE LE DOMAINE
function Step-JoinDomain {
    param($Config)
    
    Write-LogMessage "=== ÉTAPE 2: JONCTION AU DOMAINE ===" -Level "Info"
    
    $shouldJoin = $false
    $domainName = $null
    
    if ($Config -and $Config.DomainJoin -eq $true) {
        $shouldJoin = $true
        $domainName = $Config.DomainName
        Write-LogMessage "Jonction au domaine activée par configuration: $domainName" -Level "Info"
    } else {
        $response = Read-Host "Voulez-vous joindre ce PC à un domaine? (oui/non)"
        if ($response.ToLower() -in @("oui", "o", "yes", "y")) {
            $shouldJoin = $true
            $domainName = Read-Host "Entrez le nom du domaine"
        }
    }
    
    if ($shouldJoin -and $domainName) {
        try {
            Write-LogMessage "Jonction au domaine $domainName en cours..." -Level "Info"
            Add-Computer -DomainName $domainName -Credential (Get-Credential -Message "Identifiants pour joindre le domaine") -Force
            Write-LogMessage "PC joint au domaine $domainName avec succès" -Level "Success"
            
            # Mise à jour des stratégies de groupe
            gpupdate /force
            Write-LogMessage "Stratégies de groupe mises à jour" -Level "Success"
            return $true
        } catch {
            Write-LogMessage "Échec de la jonction au domaine: $($_.Exception.Message)" -Level "Error"
            return $false
        }
    } else {
        Write-LogMessage "Le PC restera dans un groupe de travail" -Level "Info"
        return $true
    }
}

# ÉTAPE 3: CRÉER UN COMPTE UTILISATEUR LOCAL
function Step-CreateLocalUser {
    param($Config)
    
    Write-LogMessage "=== ÉTAPE 3: CRÉATION D'UN COMPTE UTILISATEUR LOCAL ===" -Level "Info"
    
    $userName = $null
    $password = $null
    
    if ($Config -and $Config.LocalUserName) {
        $userName = $Config.LocalUserName
        # Sécurisation du mot de passe depuis la configuration
        $password = ConvertTo-SecurePassword $Config.LocalUserPassword
        Write-LogMessage "Utilisateur local défini par configuration: $userName" -Level "Info"
    } else {
        $userName = Read-Host "Entrez le nom du nouvel utilisateur local"
        $password = Read-Host "Entrez le mot de passe pour $userName" -AsSecureString
    }
    
    if ($userName) {
        try {
            # Vérifier si l'utilisateur existe déjà
            if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
                Write-LogMessage "L'utilisateur $userName existe déjà" -Level "Warning"
                return $true
            }
            
            New-LocalUser -Name $userName -Password $password -FullName $userName -Description "Compte administrateur local créé par script d'automatisation" -PasswordNeverExpires
            Add-LocalGroupMember -Group "Administrateurs" -Member $userName
            Write-LogMessage "Utilisateur '$userName' créé avec droits administrateur" -Level "Success"
            return $true
        } catch {
            Write-LogMessage "Échec de la création de l'utilisateur: $($_.Exception.Message)" -Level "Error"
            return $false
        }
    } else {
        Write-LogMessage "Création d'utilisateur annulée" -Level "Info"
        return $true
    }
}

# ÉTAPE 4: SYNCHRONISATION HORAIRE
function Step-TimeSynchronization {
    Write-LogMessage "=== ÉTAPE 4: SYNCHRONISATION HORAIRE ===" -Level "Info"
    
    try {
        # Démarrer le service de temps Windows
        Start-Service w32time -ErrorAction SilentlyContinue
        Write-LogMessage "Service de temps Windows démarré" -Level "Info"
        
        # Synchroniser l'heure
        w32tm /resync
        Write-LogMessage "Synchronisation horaire effectuée" -Level "Success"
        return $true
    } catch {
        Write-LogMessage "Échec de la synchronisation horaire: $($_.Exception.Message)" -Level "Warning"
        return $true # Non critique
    }
}

# ÉTAPE 5: INSTALLATION DE LOGICIELS VIA WINGET
function Step-InstallSoftware {
    param($Config)
    
    Write-LogMessage "=== ÉTAPE 5: INSTALLATION DE LOGICIELS ===" -Level "Info"
    
    # Vérifier si Winget est disponible
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-LogMessage "Winget n'est pas disponible. Installation manuelle requise." -Level "Warning"
        return $false
    }
    
    # Déterminer la liste des applications à installer
    $applications = @()
    if ($Config -and $Config.Applications) {
        $applications = $Config.Applications
    } else {
        # Liste par défaut corrigée
        $applications = @(
            "Google.Chrome",
            "Mozilla.Firefox", 
            "7zip.7zip",
            "Adobe.Acrobat.Reader.64-bit",
            "Microsoft.PowerToys",
            "Notepad++.Notepad++"
        )
    }
    
    Write-LogMessage "Installation de $(($applications).Count) applications via Winget..." -Level "Info"
    
    $successCount = 0
    foreach ($app in $applications) {
        try {
            Write-LogMessage "Installation de $app..." -Level "Info"
            $process = Start-Process -FilePath "winget" -ArgumentList "install", "--id=$app", "--silent", "--accept-package-agreements", "--accept-source-agreements" -Wait -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-LogMessage "$app installé avec succès" -Level "Success"
                $successCount++
            } else {
                Write-LogMessage "Échec de l'installation de $app (Code: $($process.ExitCode))" -Level "Warning"
            }
        } catch {
            Write-LogMessage "Erreur lors de l'installation de $app : $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    Write-LogMessage "$successCount/$($applications.Count) applications installées avec succès" -Level "Info"
    return $true
}

# ÉTAPE 6: ACTIVER REMOTE DESKTOP
function Step-EnableRemoteDesktop {
    Write-LogMessage "=== ÉTAPE 6: ACTIVATION DU BUREAU À DISTANCE ===" -Level "Info"
    
    try {
        # Activer les règles de pare-feu
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
        Write-LogMessage "Règles de pare-feu activées pour Remote Desktop" -Level "Success"
        
        # Activer les connexions Remote Desktop
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        Write-LogMessage "Connexions Remote Desktop activées" -Level "Success"
        
        # Activer l'authentification au niveau réseau (recommandé pour la sécurité)
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
        Write-LogMessage "Authentification réseau activée pour RDP" -Level "Success"
        
        return $true
    } catch {
        Write-LogMessage "Échec de l'activation du Remote Desktop: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# ÉTAPE 7: INSTALLER MICROSOFT 365 VIA ODT
function Step-InstallOffice365 {
    Write-LogMessage "=== ÉTAPE 7: INSTALLATION DE MICROSOFT 365 ===" -Level "Info"
    
    if (-not (Test-InternetConnection)) {
        Write-LogMessage "Pas de connexion Internet - Installation d'Office annulée" -Level "Warning"
        return $false
    }
    
    try {
        # Chemins de travail
        $odtFolder = "C:\ODT"
        $setupExe = "$odtFolder\setup.exe"
        $configXmlPath = "$odtFolder\config.xml"
        
        # Créer le dossier ODT
        if (-not (Test-Path $odtFolder)) {
            New-Item -ItemType Directory -Path $odtFolder -Force | Out-Null
        }
        
        # URL officielle Microsoft pour ODT (vérifiée)
        $odtUrl = "https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16328-20210.exe"
        $odtExe = "$odtFolder\officedeploymenttool.exe"
        
        Write-LogMessage "Téléchargement de l'Office Deployment Tool..." -Level "Info"
        Invoke-WebRequest -Uri $odtUrl -OutFile $odtExe -UseBasicParsing
        
        # Extraire l'ODT
        Write-LogMessage "Extraction de l'Office Deployment Tool..." -Level "Info"
        Start-Process -FilePath $odtExe -ArgumentList "/quiet", "/extract:$odtFolder" -Wait
        
        # Créer le fichier de configuration XML
        $configXml = @"
<Configuration>
    <Add OfficeClientEdition="64" Channel="MonthlyEnterprise">
        <Product ID="O365ProPlusRetail">
            <Language ID="fr-fr" />
            <ExcludeApp ID="Groove" />
            <ExcludeApp ID="Lync" />
            <ExcludeApp ID="Teams" />
        </Product>
    </Add>
    <Display Level="None" AcceptEULA="TRUE" />
    <Property Name="AUTOACTIVATE" Value="1" />
    <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
    <Property Name="SharedComputerLicensing" Value="0" />
</Configuration>
"@
        $configXml | Out-File -FilePath $configXmlPath -Encoding UTF8
        Write-LogMessage "Fichier de configuration ODT créé" -Level "Success"
        
        # Lancer l'installation
        Write-LogMessage "Lancement de l'installation de Microsoft 365..." -Level "Info"
        $installProcess = Start-Process -FilePath $setupExe -ArgumentList "/configure", $configXmlPath -Wait -PassThru
        
        if ($installProcess.ExitCode -eq 0) {
            Write-LogMessage "Microsoft 365 installé avec succès" -Level "Success"
            return $true
        } else {
            Write-LogMessage "Échec de l'installation de Microsoft 365 (Code: $($installProcess.ExitCode))" -Level "Error"
            return $false
        }
    } catch {
        Write-LogMessage "Erreur lors de l'installation de Microsoft 365: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

# ÉTAPE 8: MISES À JOUR WINDOWS UPDATE
function Step-WindowsUpdates {
    Write-LogMessage "=== ÉTAPE 8: INSTALLATION DES MISES À JOUR WINDOWS ===" -Level "Info"
    
    try {
        # Installer le module PSWindowsUpdate si nécessaire
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-LogMessage "Installation du module PSWindowsUpdate..." -Level "Info"
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
        }
        
        Import-Module PSWindowsUpdate
        Write-LogMessage "Module PSWindowsUpdate chargé" -Level "Success"
        
        # Rechercher et installer les mises à jour
        Write-LogMessage "Recherche des mises à jour disponibles..." -Level "Info"
        $updates = Get-WindowsUpdate
        
        if ($updates.Count -eq 0) {
            Write-LogMessage "Aucune mise à jour disponible" -Level "Info"
            return $true
        }
        
        Write-LogMessage "$($updates.Count) mise(s) à jour trouvée(s)" -Level "Info"
        Install-WindowsUpdate -AcceptAll -IgnoreReboot -Confirm:$false
        Write-LogMessage "Mises à jour installées avec succès" -Level "Success"
        
        return $true
    } catch {
        Write-LogMessage "Échec de l'installation des mises à jour: $($_.Exception.Message)" -Level "Warning"
        return $true # Non critique
    }
}

# ÉTAPE 9: NETTOYAGE
function Step-Cleanup {
    Write-LogMessage "=== ÉTAPE 9: NETTOYAGE DU SYSTÈME ===" -Level "Info"
    
    try {
        # Supprimer les raccourcis inutiles du bureau public
        $publicDesktop = "C:\Users\Public\Desktop"
        if (Test-Path $publicDesktop) {
            Get-ChildItem -Path $publicDesktop -Filter "*.lnk" | Remove-Item -Force -ErrorAction SilentlyContinue
            Write-LogMessage "Raccourcis du bureau public supprimés" -Level "Success"
        }
        
        # Nettoyer le dossier ODT
        if (Test-Path "C:\ODT") {
            Remove-Item -Path "C:\ODT" -Recurse -Force -ErrorAction SilentlyContinue
            Write-LogMessage "Dossier ODT nettoyé" -Level "Success"
        }
        
        # Nettoyer le fichier de checkpoint
        if (Test-Path $script:CheckpointFile) {
            Remove-Item -Path $script:CheckpointFile -Force -ErrorAction SilentlyContinue
            Write-LogMessage "Fichier de checkpoint supprimé" -Level "Success"
        }
        
        # Nettoyer les fichiers temporaires
        Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-LogMessage "Fichiers temporaires nettoyés" -Level "Success"
        
        return $true
    } catch {
        Write-LogMessage "Erreur lors du nettoyage: $($_.Exception.Message)" -Level "Warning"
        return $true
    }
}

# FONCTION PRINCIPALE
function Main {
    Write-LogMessage "=== DÉBUT DU SCRIPT DE POST-INSTALLATION WINDOWS 11 ===" -Level "Info"
    Write-LogMessage "Version du script: 2.0" -Level "Info"
    Write-LogMessage "Date d'exécution: $(Get-Date)" -Level "Info"
    
    # Chargement de la configuration
    $config = $null
    if (Test-Path $script:ConfigPath) {
        try {
            $config = Get-Content $script:ConfigPath | ConvertFrom-Json
            Write-LogMessage "Configuration chargée depuis $script:ConfigPath" -Level "Success"
            
            if (-not (Test-Configuration $config)) {
                Write-LogMessage "Configuration invalide. Passage en mode interactif." -Level "Warning"
                $config = $null
            }
        } catch {
            Write-LogMessage "Erreur lors du chargement de la configuration: $($_.Exception.Message)" -Level "Warning"
            $config = $null
        }
    } else {
        Write-LogMessage "Aucun fichier de configuration trouvé. Mode interactif activé." -Level "Info"
    }
    
    # Récupérer le checkpoint pour reprendre après redémarrage
    $startStep = Get-Checkpoint
    if ($startStep -gt 0) {
        Write-LogMessage "Reprise du script à l'étape $startStep" -Level "Info"
    }
    
    # Exécution des étapes
    $steps = @(
        @{ Name = "Configuration initiale"; Function = { Step-InitialConfiguration } },
        @{ Name = "Renommage du PC"; Function = { Step-RenameComputer $config } },
        @{ Name = "Jonction au domaine"; Function = { Step-JoinDomain $config } },
        @{ Name = "Création utilisateur local"; Function = { Step-CreateLocalUser $config } },
        @{ Name = "Synchronisation horaire"; Function = { Step-TimeSynchronization } },
        @{ Name = "Installation de logiciels"; Function = { Step-InstallSoftware $config } },
        @{ Name = "Activation Remote Desktop"; Function = { Step-EnableRemoteDesktop } },
        @{ Name = "Installation Microsoft 365"; Function = { Step-InstallOffice365 } },
        @{ Name = "Mises à jour Windows"; Function = { Step-WindowsUpdates } },
        @{ Name = "Nettoyage"; Function = { Step-Cleanup } }
    )
    
    $totalSteps = $steps.Count
    $completedSteps = 0
    
    for ($i = $startStep; $i -lt $totalSteps; $i++) {
        $step = $steps[$i]
        Write-LogMessage "Progression: $($i + 1)/$totalSteps - $($step.Name)" -Level "Info"
        
        try {
            $result = & $step.Function
            if ($result) {
                Save-Checkpoint ($i + 1)
                $completedSteps++
                Write-LogMessage "Étape '$($step.Name)' terminée avec succès" -Level "Success"
            } else {
                Write-LogMessage "Étape '$($step.Name)' a échoué mais le script continue" -Level "Warning"
            }
        } catch {
            Write-LogMessage "Erreur lors de l'étape '$($step.Name)': $($_.Exception.Message)" -Level "Error"
        }
    }
    
    # Résumé final
    Write-LogMessage "=== RÉSUMÉ DE L'EXÉCUTION ===" -Level "Info"
    Write-LogMessage "$completedSteps/$totalSteps étapes complétées avec succès" -Level "Info"
    
    # Arrêter la transcription
    Stop-Transcript
    
    # Redémarrage final
    Write-LogMessage "Configuration terminée. Redémarrage dans 30 secondes..." -Level "Success"
    Write-LogMessage "Vous pouvez annuler le redémarrage avec Ctrl+C" -Level "Info"
    
    Start-Sleep -Seconds 30
    Restart-Computer -Force
}

# POINT D'ENTRÉE DU SCRIPT
try {
    Main
} catch {
    Write-LogMessage "Erreur fatale du script: $($_.Exception.Message)" -Level "Error"
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
        Stop-Transcript
    }
    exit 1
}