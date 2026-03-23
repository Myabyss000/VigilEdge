param(
    [string]$MainTex = "MANUSCRIPT_IEEE_SUBMISSION.tex",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path $MainTex)) {
    Write-Error "Main tex file not found: $MainTex"
}

$baseName = [System.IO.Path]::GetFileNameWithoutExtension($MainTex)

if ($Clean) {
    $exts = @("aux","bbl","bcf","blg","fdb_latexmk","fls","log","out","toc","run.xml")
    foreach ($ext in $exts) {
        $target = "$baseName.$ext"
        if (Test-Path $target) {
            Remove-Item -Force $target
        }
    }
}

$latexmk = Get-Command latexmk -ErrorAction SilentlyContinue
function Invoke-PdfLatexPipeline {
    $pdflatex = Get-Command pdflatex -ErrorAction SilentlyContinue
    $bibtex = Get-Command bibtex -ErrorAction SilentlyContinue

    if ($null -eq $pdflatex -or $null -eq $bibtex) {
        Write-Error "Missing build tools. Install TeX with pdflatex and bibtex, or install latexmk."
    }

    Write-Host "Using fallback pipeline: pdflatex -> bibtex -> pdflatex -> pdflatex"
    & pdflatex -interaction=nonstopmode -halt-on-error $MainTex
    if ($LASTEXITCODE -ne 0) { Write-Error "pdflatex failed on first pass." }
    & bibtex $baseName
    if ($LASTEXITCODE -ne 0) { Write-Error "bibtex failed." }
    & pdflatex -interaction=nonstopmode -halt-on-error $MainTex
    if ($LASTEXITCODE -ne 0) { Write-Error "pdflatex failed on second pass." }
    & pdflatex -interaction=nonstopmode -halt-on-error $MainTex
    if ($LASTEXITCODE -ne 0) { Write-Error "pdflatex failed on third pass." }
}

if ($null -ne $latexmk) {
    Write-Host "Trying latexmk build pipeline..."
    & latexmk -pdf -interaction=nonstopmode -halt-on-error $MainTex
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "latexmk failed. Falling back to pdflatex/bibtex pipeline."
        Invoke-PdfLatexPipeline
    }
} else {
    Invoke-PdfLatexPipeline
}

$pdfPath = Join-Path $PSScriptRoot "$baseName.pdf"
if (Test-Path $pdfPath) {
    Write-Host "Build complete: $pdfPath"
} else {
    Write-Error "Build finished without PDF output. Check LaTeX logs."
}
