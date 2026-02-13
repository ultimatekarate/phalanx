function Get-FileTree {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,

        [Parameter()]
        [string]$Indent = ""
    )

    process {
        try {
            $resolvedPath = Resolve-Path -Path $Path -ErrorAction Stop
            if (-not (Test-Path -Path $resolvedPath -PathType Container)) {
                throw "The path '$resolvedPath' is not a directory."
            }

            $items = Get-ChildItem -Path $resolvedPath -ErrorAction Stop
            $itemCount = $items.Count

            for ($i = 0; $i -lt $itemCount; $i++) {
                $item = $items[$i]
                $isLast = $i -eq ($itemCount - 1)
                
                # Using standard ASCII to avoid encoding errors
                if ($isLast) {
                    $junction = "\-- "
                    $extension = "    "
                } else {
                    $junction = "|-- "
                    $extension = "|   "
                }

                Write-Host "$Indent$junction$($item.Name)"

                if ($item.PSIsContainer) {
                    Get-FileTree -Path $item.FullName -Indent "$Indent$extension"
                }
            }
        }
        catch [System.IO.IOException], [System.UnauthorizedAccessException] {
            Write-Error "Access denied or I/O error at '$Path': $($_.Exception.Message)"
        }
        catch {
            Write-Error "An unexpected error occurred: $($_.Exception.Message)"
        }
    }
}