<#
Build, publish and deploy the verifiable agent to Phala Cloud.

  .\deploy.ps1 build   -Image docker.io/<user>/verifiable-agent   # build + push, pin digest in compose
  .\deploy.ps1 plan                                                # terraform plan
  .\deploy.ps1 apply                                               # create / update the CVM(s)
  .\deploy.ps1 stop                                                # power off (compute billing stops, disk kept)
  .\deploy.ps1 start                                               # power on again
  .\deploy.ps1 output                                              # app id + public URL
  .\deploy.ps1 link                                                # shareable demo page link (includes access code)
  .\deploy.ps1 destroy                                             # delete the CVM(s), stops all billing

Secrets come from agent-poc\.env (never printed, never put on a command line):
  PHALA_CLOUD_API_KEY  Phala Cloud API key (phak_...), used by Terraform
  PHALA_API_KEY        Private AI key the agent uses for LLM calls
  ADMIN_TOKEN, CHAT_TOKEN   generated and appended to .env on first run if missing

Terraform runs in the hashicorp/terraform container, because Windows Application Control
blocks the unsigned Phala provider binary on this machine (and a container is reproducible anyway).
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet("build", "plan", "apply", "start", "stop", "output", "link", "destroy")] [string]$Action,
    [string]$Image
)
# "Continue": docker/terraform write progress to stderr; failures are caught via $LASTEXITCODE below.
$ErrorActionPreference = "Continue"
$Deploy = $PSScriptRoot
$Root = Split-Path $Deploy -Parent
$EnvFile = Join-Path $Root ".env"
$Compose = Join-Path $Deploy "docker-compose.cvm.yml"

function Read-DotEnv {
    $vals = @{}
    if (Test-Path $EnvFile) {
        foreach ($line in Get-Content $EnvFile) {
            if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') { $vals[$Matches[1]] = $Matches[2].Trim() }
        }
    }
    return $vals
}

function New-Token { -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) }) }

if ($Action -eq "build") {
    if (-not $Image) { throw "Pass -Image, e.g. docker.io/<user>/verifiable-agent" }
    $stamp = Get-Date -Format yyyyMMdd-HHmmss
    $text = Get-Content $Compose -Raw
    # Two images: the agent, and the demo page + verifier service. Each line is found by its "# ...-image" marker.
    foreach ($img in @(@{ marker = "agent-image"; repo = $Image; args = @((Join-Path $Root "agent")) },
                       @{ marker = "demo-image"; repo = "$Image-demo"; args = @("-f", (Join-Path $Root "demo\Dockerfile"), $Root) })) {
        $tag = "$($img.repo):$stamp"
        docker build --platform linux/amd64 -t $tag @($img.args)
        if ($LASTEXITCODE) { throw "docker build failed for $($img.marker)" }
        docker push $tag
        if ($LASTEXITCODE) { throw "docker push failed (run 'docker login' first)" }
        $digestRef = docker inspect --format '{{index .RepoDigests 0}}' $tag
        $text = $text -replace "(?m)^(\s*image:\s*)\S+(\s*#\s*$($img.marker))\s*$", "`${1}$digestRef`${2}"
        Write-Host "Pinned $digestRef ($($img.marker))"
    }
    [IO.File]::WriteAllText($Compose, $text, (New-Object Text.UTF8Encoding($false)))  # UTF-8 without BOM
    return
}

if ($Action -eq "link") {
    # Shareable demo link: the access code rides in the #fragment, which browsers never send to the server.
    $vals = Read-DotEnv
    $code = $vals["DEMO_TOKEN"]
    if (-not $code) { throw "DEMO_TOKEN missing in agent-poc\.env - run '.\deploy.ps1 apply' first" }
    $docker = @("run", "--rm", "-v", "${Deploy}:/deploy", "-w", "/deploy/terraform", "hashicorp/terraform:1.15")
    $demoUrl = (docker @docker output -raw demo_url)
    Write-Host "$demoUrl#code=$code"
    return
}

# --- terraform actions ---------------------------------------------------------------
if ((Get-Content $Compose -Raw) -match 'IMAGE_PLACEHOLDER') { throw "Run '.\deploy.ps1 build -Image ...' first" }
$vals = Read-DotEnv
foreach ($t in "ADMIN_TOKEN", "CHAT_TOKEN", "DEMO_TOKEN") {
    if (-not $vals[$t]) {
        $vals[$t] = New-Token
        Add-Content $EnvFile "`n$t=$($vals[$t])"
        Write-Host "Generated $t and saved it to agent-poc\.env"
    }
}
foreach ($k in "PHALA_CLOUD_API_KEY", "PHALA_API_KEY") { if (-not $vals[$k]) { throw "$k is missing in agent-poc\.env" } }

# Pass secrets through the process environment, not the command line.
$env:PHALA_CLOUD_API_KEY = $vals["PHALA_CLOUD_API_KEY"]
$env:TF_VAR_phala_api_key = $vals["PHALA_API_KEY"]
$env:TF_VAR_admin_token = $vals["ADMIN_TOKEN"]
$env:TF_VAR_chat_token = $vals["CHAT_TOKEN"]
$env:TF_VAR_demo_token = $vals["DEMO_TOKEN"]
$env:TF_VAR_openai_api_key = if ($vals["OPEN_AI_API_KEY"]) { $vals["OPEN_AI_API_KEY"] } else { "" }
$tfArgs = switch ($Action) {
    "plan" { @("plan", "-input=false") }
    "apply" { @("apply", "-input=false", "-auto-approve") }
    "start" { @("apply", "-input=false", "-auto-approve", "-var", "power_state=running") }
    "stop" { @("apply", "-input=false", "-auto-approve", "-var", "power_state=stopped") }
    "output" { @("output") }
    "destroy" { @("destroy", "-input=false", "-auto-approve") }
}
$docker = @("run", "--rm", "-v", "${Deploy}:/deploy", "-w", "/deploy/terraform",
    "-e", "PHALA_CLOUD_API_KEY", "-e", "TF_VAR_phala_api_key", "-e", "TF_VAR_admin_token", "-e", "TF_VAR_chat_token", "-e", "TF_VAR_demo_token", "-e", "TF_VAR_openai_api_key",
    "hashicorp/terraform:1.15")
if (-not (Test-Path (Join-Path $Deploy "terraform\.terraform"))) { docker @docker init -input=false }
# Phala answers 409 while a previous update is still being applied to the CVM: wait and retry.
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $out = docker @docker @tfArgs 2>&1 | ForEach-Object { "$_" }
    $out | Write-Output
    if (-not (($out -join "`n") -match "status 409")) { break }
    Write-Host "Phala reports another operation in progress; retrying in 30 s ($attempt/6)..."
    Start-Sleep 30
}
