## Script PowerShell de post-installation Windows 11
## Objectif : Configurer le poste automatiquement après déploiement
## Liste des fonctionnalités :
    # 0. Vérification et configuration initiale (langue, plan d'alimentation, nettoyage bloatware, privilèges admin, logging, politique d'exécution)
    # 1. Renommer le PC
    # 2. Joindre le domaine (optionnel)
    # 3. Créer un compte utilisateur local avec droits administrateur
    # 4. Synchronisation horaire
    # 5. Installer des logiciels via Winget
    # 6. Activer Remote Desktop
    # 7. Installer Microsoft 365 via ODT (Office Deployment Tool)
    # 8. Mises à jour Windows Update
    # 9. Nettoyage
    # 10. Redémarrage

# 0. VERIFICATION ET CONFIGURATION INITIALE
    # Vérifier si le script est exécuté avec des privilèges administratifs
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Host "Ce script doit être exécuté en tant qu'administrateur." -ForegroundColor Red
            exit
        }
        Write-Host "✅ Exécution avec des privilèges administratifs confirmée."
    # Configurer la politique d'exécution pour permettre l'exécution de scripts
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Write-Host "✅ Politique d'exécution configurée sur Bypass pour ce processus."
    # Démarrer la transcription pour le logging
        $LogPath = "C:\Logs"
        if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force }
        Start-Transcript -Path "$LogPath\Post-Install-Log-$(Get-Date -f yyyy-MM-dd-HH-mm-ss).txt"
        Write-Host "✅ Transcription démarrée. Les logs seront enregistrés dans $LogPath."
    # Configurer la langue et la région en français (France)
        $locale = (Get-WinSystemLocale).Name
        if ($locale -ne "fr-FR") {
            Write-Host "Windows n'est pas configuré en français. Modification en cours..." -ForegroundColor Yellow
            try {
                Set-WinUILanguageOverride -Language fr-FR
                Set-WinUserLanguageList -LanguageList fr-FR -Force
                Set-WinSystemLocale fr-FR
                Set-WinHomeLocation -GeoId 84   # 84 = France
                Set-WinCultureFromLanguageListOptOut -OptOut $false
                Write-Host "✅ La langue du système a été changée en français. Redémarrage requis." -ForegroundColor Green
                Write-Host "Après le redémarrage, relancez ce script pour poursuivre la configuration." -ForegroundColor Cyan
                Start-Sleep -Seconds 10
                Restart-Computer
            } catch {
                Write-Host "❌ Impossible de changer la langue du système." -ForegroundColor Red
                exit
            }
        } else {
            Write-Host "✅ Windows est déjà configuré en français." -ForegroundColor Green
        }
    # Regler le plan d'alimentation sur Performances élevées
    $HighPerf = powercfg -l | ForEach-Object { if ($_ -match "Performances élevées") { $_.Split()[3] } }
    if ($HighPerf) {
        powercfg -s $HighPerf
        Write-Host "✅ Plan d'alimentation réglé sur Performances élevées."
    } else {
        Write-Warning "⚠️ Plan d'alimentation 'Performances élevées' non trouvé."
    }
    # Liste des applications à supprimer (noms partiels)
    $bloatware = @("*CandyCrush*", "*BubbleWitch*", "*Xbox*")
    foreach ($app in $bloatware) {
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers
    }
    Write-Host "✅ Nettoyage des applications préinstallées terminé."

# Chargement des paramètres depuis un fichier de configuration JSON
$ConfigPath = "C:\PostInstallConfig.json"
if (Test-Path $ConfigPath) {
    try {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        Write-Host "Configuration chargée depuis $ConfigPath."
    } catch {
        Write-Host "❌ Erreur lors du chargement du fichier de configuration. Arrêt du script." -ForegroundColor Red
        exit
    }
} else {
    Write-Host "⚠️ Fichier de configuration non trouvé. Passage en mode interactif."
}

# 1. RENOMMER LE PC
if ($config.PCName) {
    $nouveauNom = $config.PCName
    Write-Host "Nom du PC défini par la configuration : $nouveauNom"
} else {
    $nouveauNom = Read-Host "Entrez le nouveau nom du PC"
}
try {
    Rename-Computer -NewName $nouveauNom -Force
    Write-Host "✅ PC renommé avec succès."
} catch {
    Write-Host "❌ Échec du renommage du PC. Arrêt du script." -ForegroundColor Red
    exit
}

# 2. JOINDRE LE DOMAINE (OPTIONNEL)
if ($config.DomainJoin -and $config.DomainJoin -eq $true) {
    $domainName = $config.DomainName
    Write-Host "Nom du domaine défini par la configuration : $domainName"
    try {
        Add-Computer -DomainName $domainName -Credential (Get-Credential) -Force
        Write-Host "✅ Le PC a été joint au domaine $domainName."
        Write-Host "Mise à jour des stratégies de groupe..."
        gpupdate /force
    } catch {
        Write-Host "❌ Échec de la jonction au domaine. Arrêt du script." -ForegroundColor Red
        exit
    }
} else {
    $joinDomain = Read-Host "Voulez-vous joindre ce PC à un domaine d'entreprise ? (oui/non)"
    if ($joinDomain.ToLower() -eq "oui") {
        $domainName = Read-Host "Entrez le nom du domaine"
        try {
            Add-Computer -DomainName $domainName -Credential (Get-Credential) -Force
            Write-Host "✅ Le PC a été joint au domaine $domainName."
            Write-Host "Mise à jour des stratégies de groupe..."
            gpupdate /force
        } catch {
            Write-Host "❌ Échec de la jonction au domaine. Arrêt du script." -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Le PC ne sera pas joint à un domaine."
    }
}

# 3. CREER UN COMPTE UTILISATEUR LOCAL AVEC DROITS ADMINISTRATEUR
if ($config.LocalUserName) {
    $userName = $config.LocalUserName
    Write-Host "Nom d'utilisateur local défini par la configuration : $userName"
    $password = ConvertTo-SecureString $config.LocalUserPassword -AsPlainText -Force
} else {
    $userName = Read-Host "Entrez le nom du nouvel utilisateur"
    $password = Read-Host "Entrez le mot de passe pour $userName" -AsSecureString
}
try {
    New-LocalUser -Name $userName -Password $password -FullName $userName -Description "Compte administrateur local personnalisé"
    Add-LocalGroupMember -Group "Administrateurs" -Member $userName
    Write-Host "L'utilisateur '$userName' a été créé avec les droits administrateur."
} catch {
    Write-Host "❌ Échec de la création de l'utilisateur. Arrêt du script." -ForegroundColor Red
    exit
}

# 4. SYNCHRONISATION HORAIRE
    # Assurer que le service de temps Windows est en cours d'exécution
    try {
        net start w32time
        Write-Host "Synchronisation de l'heure système..."
        w32tm /resync
        Write-Host "✅ Synchronisation horaire réussie."
    } catch {
        Write-Warning "⚠️ Échec de la synchronisation horaire. Le script continue."
    }

# 5. INSTALLATION DE LOGICIELS VIA WINGET
    # Vérifier si Winget est installé
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Winget n'est pas installé. Veuillez installer l'App Installer depuis le Microsoft Store."
        exit
    }
    # Installer les applications
    Write-Host "Installation des applications via Winget..."
    $apps = @("Google.Chrome", "Mozilla.Firefox", "7zip.7zip", "AdobeAcrobatReaderDC")
    foreach ($app in $apps) {
        try {
            winget install --id=$app --silent --accept-package-agreements --accept-source-agreements
            Write-Host "✅ $app installé avec succès."
        } catch {
            Write-Warning "⚠️ Échec de l'installation de $app. Continuation du script..."
        }
    }
    Write-Host "✅ Installation des applications terminée."

# 6. ACTIVER REMOTE DESKTOP
    # Active la règle de pare-feu pour le Bureau à distance
    # Active la connexion (identique à votre commande)
    try {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
        Write-Host "✅ Remote Desktop activé."
    } catch {
        Write-Host "❌ Échec de l'activation du Remote Desktop. Arrêt du script." -ForegroundColor Red
        exit
    }

# 7. INSTALLER MICROSOFT 365 VIA ODT (OFFICE DEPLOYMENT TOOL)
try {
    Write-Host "Installation de Microsoft 365 en cours..."
    # Définir les chemins
    $odtFolder = "C:\\ODT"
    $odtExe = "$odtFolder\\OfficeDeploymentTool.exe"
    $setupExe = "$odtFolder\\setup.exe"
    $configXmlPath = "$odtFolder\\config.xml"
    # Créer le dossier ODT
    New-Item -ItemType Directory -Path $odtFolder -Force
    # Télécharger l'outil de déploiement Office
    $odtUrl = "https://download.microsoft.com/download/2/9/0/290F3A3E-3B3B-4E8B-9F3F-6C6F6F6F6F6F/OfficeDeploymentTool.exe"
    Invoke-WebRequest -Uri $odtUrl -OutFile $odtExe
    # Exécuter l'ODT pour extraire les fichiers
    Start-Process -FilePath $odtExe -ArgumentList "/extract:$odtFolder /quiet" -Wait
    # Créer le fichier de configuration XML
    $configXml = @"
<Configuration>
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise">
    <Product ID="O365ProPlusRetail">
      <Language ID="fr-fr" />
    </Product>
  </Add>
  <Display Level="None" AcceptEULA="TRUE" />
  <Property Name="AUTOACTIVATE" Value="1" />
</Configuration>
"@
    $configXml | Out-File -FilePath $configXmlPath -Encoding UTF8
    # Lancer l'installation silencieuse
    Start-Process -FilePath $setupExe -ArgumentList "/configure $configXmlPath" -Wait
    Write-Host "✅ Installation de Microsoft 365 terminée."
} catch {
    Write-Host "❌ Échec de l'installation de Microsoft 365. Arrêt du script." -ForegroundColor Red
    exit
}

# 8. MISES À JOUR WINDOWS UPDATE
    # Installer le module PSWindowsUpdate si nécessaire
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-PackageProvider -Name NuGet -Force
            Install-Module -Name PSWindowsUpdate -Force
        }
        Import-Module PSWindowsUpdate
        Write-Host "Recherche et installation des mises à jour Windows..."
        Install-WindowsUpdate -AcceptAll -SuppressReboot -Confirm:$false
        Write-Host "✅ Mises à jour installées avec succès."
    } catch {
        Write-Host "❌ Échec de l'installation des mises à jour. Arrêt du script." -ForegroundColor Red
        exit
    }

# 9. NETTOYAGE
# Supprime les raccourcis inutiles du bureau public
    Remove-Item -Path "C:\Users\Public\Desktop\*.lnk" -Force -ErrorAction SilentlyContinue

# 10. REDEMARRAGE
# Arrêter la transcription avant le redémarrage
    Stop-Transcript
    Write-Host "Le système va redémarrer dans 10 secondes..."
    Restart-Computer -Delay 10

# NOTES: Bypass Log Windows
# Maj+F10 -> cmd -> oobe\BypassNRO.cmd