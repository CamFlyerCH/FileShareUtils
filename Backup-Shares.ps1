Import-Module FileShareUtils
$FileServer = 'netappsvm.gugus.ch'
$OutputFileName = 'Backup-Shares_' + $FileServer + '_' + $(get-date -format yyyyMMdd_HHmmss) + '.ps1.txt'

"Import-Module FileShareUtils" | Out-File -FilePath $OutputFileName -Encoding default -Append

$AllShares = Get-NetFileShares -Server $FileServer
ForEach ($Share in $AllShares){
    Write-Host $Share.Name
    ("Redo-NetShare -Server '" + $Share.Server + "' -Name '" + $Share.Name + "' -Path '" + $Share.Path + "' -Description '" + $Share.Description + "' -Permissions '" + $Share.ShareACLText + "' -ABE " + $Share.ABE + " -CachingMode " + $Share.CachingMode) | Out-File -FilePath $OutputFileName -Encoding default -Append
}
