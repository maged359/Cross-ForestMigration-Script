# Target folder
$TargetFolder = "C:\Program Files (x86)\Quest\On Demand Migration Active Directory Agent\Files"

# Verify the folder exists
if (Test-Path -Path $TargetFolder) {
    Write-Host "`nListing files in: $TargetFolder`n"

    # Get list of files
    $Files = Get-ChildItem -Path $TargetFolder -File

    if ($Files.Count -eq 0) {
        Write-Host "No files found in the folder."
    } else {
        foreach ($File in $Files) {
            Write-Host "`n==============================="
            Write-Host "File: $($File.Name)"
            Write-Host "==============================="

            # Read and display file content (safe for small files)
            try {
                $Content = Get-Content -Path $File.FullName -ErrorAction Stop
                if ($Content) {
                    Write-Output $Content
                } else {
                    Write-Host "File is empty."
                }
            } catch {
                Write-Host "Failed to read file: $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Host "Folder not found: $TargetFolder"
}
