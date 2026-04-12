# Builds the canonical student record blob (same layout as `StudentDump::write_blob` / `StudentInfo::record_blob`),
# signs it with RSA PKCS#1 v1.5 + SHA-256, and writes base64 sig into `student_card.json`.
#
# Default key: demo issuer private key in `credentials/passport/`.
#   .\sign_student_record.ps1 -PrivateKeyPath ..\passport\issuer_demo_priv.pem
#
param(
    [string]$JsonPath = (Join-Path $PSScriptRoot "student_card.json"),
    [string]$PrivateKeyPath = (Join-Path $PSScriptRoot "..\passport\issuer_demo_priv.pem")
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $JsonPath)) { Write-Error "Missing $JsonPath" }
if (-not (Test-Path $PrivateKeyPath)) { Write-Error "Missing private key: $PrivateKeyPath" }

$nameLen = 32
$schoolLen = 32
$collegeLen = 32
$studentIdLen = 16

$j = (Get-Content -LiteralPath $JsonPath -Raw -Encoding UTF8) | ConvertFrom-Json

function Pad-Utf8([string]$s, [int]$max) {
    $raw = [System.Text.Encoding]::UTF8.GetBytes($s)
    $buf = New-Object byte[] $max
    [Array]::Clear($buf, 0, $max)
    $n = [Math]::Min($raw.Length, $max)
    if ($n -gt 0) { [Array]::Copy($raw, $buf, $n) }
    return $buf
}

$blob = New-Object byte[] ($nameLen + $schoolLen + $collegeLen + $studentIdLen + 4 + 4)
$o = 0
[Array]::Copy((Pad-Utf8 $j.name $nameLen), 0, $blob, $o, $nameLen); $o += $nameLen
[Array]::Copy((Pad-Utf8 $j.school $schoolLen), 0, $blob, $o, $schoolLen); $o += $schoolLen
[Array]::Copy((Pad-Utf8 $j.college $collegeLen), 0, $blob, $o, $collegeLen); $o += $collegeLen
[Array]::Copy((Pad-Utf8 $j.student_id $studentIdLen), 0, $blob, $o, $studentIdLen); $o += $studentIdLen
function To-BE4([uint32]$v) {
    $b = New-Object byte[] 4
    $b[0] = [byte](($v -shr 24) -band 255)
    $b[1] = [byte](($v -shr 16) -band 255)
    $b[2] = [byte](($v -shr 8) -band 255)
    $b[3] = [byte]($v -band 255)
    return $b
}
$ey = To-BE4([uint32]$j.enrollment_year)
[Array]::Copy($ey, 0, $blob, $o, 4); $o += 4
$ex = To-BE4([uint32]$j.card_expiry)
[Array]::Copy($ex, 0, $blob, $o, 4)

$tmp = [System.IO.Path]::GetTempFileName()
$tmpSig = [System.IO.Path]::GetTempFileName()
try {
    [System.IO.File]::WriteAllBytes($tmp, $blob)
    & openssl dgst -sha256 -sign $PrivateKeyPath -out $tmpSig $tmp
    if ($LASTEXITCODE -ne 0) { Write-Error "openssl sign failed: $LASTEXITCODE" }
    $sigB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($tmpSig))
    $j.sig = $sigB64
    # 无 BOM 的 UTF-8，避免 Rust serde_json 在首字节解析失败
    $jsonText = ($j | ConvertTo-Json)
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($JsonPath, $jsonText, $utf8NoBom)
    Write-Host "Updated sig in $JsonPath"
}
finally {
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpSig -ErrorAction SilentlyContinue
}
