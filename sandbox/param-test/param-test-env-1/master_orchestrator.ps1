# master_orchestrator.ps1

$CRYPTO_CONFIGS = @(
    "mlkem768:mldsa65"
    # "p256_mlkem768:mldsa65",
    # "p256_mlkem768:ecdsa_p256",
    # "ecdsa_p256:ecdsa_p256"
)

$LATENCIES = @(
    "10ms"
    # "100ms"
)
$LOSS_RATES = @(
    "0%"
    # "2%"
)

# Fix path formatting for Docker volume stability
$DockerContextPath = $PSScriptRoot.Replace('\', '/')

foreach ($config in $CRYPTO_CONFIGS) {
    $parts = $config.Split(":")
    $KEM = $parts[0]
    $SIG = $parts[1]

    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "CONFIGURING SERVER: KEM=$KEM | Signature=$SIG"
    Write-Host "=============================================" -ForegroundColor Cyan

    # 1. GENERATE DYNAMIC NGINX CONFIG
    $nginxTemplate = @"
server {
    listen 80;
    server_name localhost;
    return 301 https://`$host:8443`$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate /etc/nginx/ssl/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx.key;

    ssl_protocols TLSv1.3;
    ssl_ecdh_curve $KEM; 
    
    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}
"@ 
    [System.IO.File]::WriteAllText("$PSScriptRoot/nginx.conf", $nginxTemplate)
    
    if (Test-Path "$PSScriptRoot/ssl") { Remove-Item "$PSScriptRoot/ssl" -Recurse -Force }
    New-Item -ItemType Directory -Force -Path "$PSScriptRoot/ssl" | Out-Null

    # 2. GENERATE PQC CERTIFICATE
    Write-Host "Generating PQC Certificate..." -ForegroundColor Gray
    
    docker run --rm -v "${DockerContextPath}/ssl:/ssl" openquantumsafe/curl:latest `
        openssl req -x509 -nodes -days 1 -newkey $SIG `
        -keyout /ssl/nginx.key -out /ssl/nginx.crt `
        -subj "/CN=web-server"

    Write-Host "Booting web-server environment..." -ForegroundColor Gray
    docker compose up -d web-server
    Start-Sleep -Seconds 2

    Write-Host "Verifying Nginx status..." -ForegroundColor Gray
    docker exec web-server nginx -t
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Nginx config test failed! Checking logs:" -ForegroundColor Red
        docker logs web-server
        break # Stop the script to debug
    }
    
    docker exec -u 0 web-server apk add --no-cache iproute2-tc *>$null

    foreach ($latency in $LATENCIES) {
        foreach ($loss in $LOSS_RATES) {
            
            Write-Host "Applying Network Impairments -> Latency: $latency | Loss: $loss..." -ForegroundColor Yellow
            
            # Inject network impairment inside the Linux container network interface
            docker exec web-server tc qdisc add dev eth0 root netem delay $latency loss $loss

            # Run the load tester container
            docker compose run --rm --entrypoint sh load-tester ./run-load.sh $KEM $SIG $latency $loss

            # OPTIMIZATION: Clean up just the network impairment, don't destroy the container yet
            docker exec web-server tc qdisc del dev eth0 root 2>$null
        }
    }

    # Teardown to clean state only after ALL network tests for this crypto config are done
    Write-Host "Tearing down environment for next configuration..." -ForegroundColor Gray
    docker compose down
    Start-Sleep -Seconds 2
}

Write-Host "=============================================" -ForegroundColor Green
Write-Host "ALL TESTS COMPLETED!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green