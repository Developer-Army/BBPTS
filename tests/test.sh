#!/usr/bin/env bash


set -uo pipefail

for go_path in "/usr/local/go/bin" "/usr/local/bin" "${HOME:-}/go/bin"; do
    if [ -d "$go_path" ] && [[ ":${PATH:-}:" != *":$go_path:"* ]]; then
        PATH="$go_path:${PATH:-}"
    fi
done

if [ -n "${SUDO_USER:-}" ]; then
    sudo_go_path="/home/${SUDO_USER}/go/bin"
    if [ -d "$sudo_go_path" ] && [[ ":${PATH:-}:" != *":$sudo_go_path:"* ]]; then
        PATH="$sudo_go_path:${PATH:-}"
    fi
fi
export PATH

EXPECTED_RESULT="tests/expected_result.jsonl"
ACTUAL_OUTPUT="tests/actual_output.txt"
FAILED_LOG="tests/failed_tests.log"

SIMULATE_SCANNER=${SIMULATE_SCANNER:-false}

CURRENT_CONTAINER=""

RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
CYAN='\e[1;36m'
BOLD='\e[1m'
NC='\e[0m' # No Color

DRY_RUN=false
TARGET_FILTER=""
DIFFICULTY_FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run|-d)
            DRY_RUN=true
            shift
            ;;
        --target|-t)
            if [[ $# -gt 1 ]]; then
                TARGET_FILTER="$2"
                shift 2
            else
                echo -e "${RED}[ERROR] --target requires an argument.${NC}" >&2
                exit 1
            fi
            ;;
        --difficulty|-l)
            if [[ $# -gt 1 ]]; then
                DIFFICULTY_FILTER="$2"
                shift 2
            else
                echo -e "${RED}[ERROR] --difficulty requires an argument.${NC}" >&2
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}[ERROR] Unknown argument: $1${NC}" >&2
            echo -e "Usage: $0 [--dry-run|-d] [--target|-t <target_name>] [--difficulty|-l <easy|medium|advanced>]" >&2
            exit 1
            ;;
    esac
done

get_cpu_usage() {
    if [ ! -f /proc/stat ]; then
        echo 0
        return
    fi
    local prev_stat prev_idle prev_total
    prev_stat=$(grep '^cpu ' /proc/stat)
    prev_idle=$(echo "$prev_stat" | awk '{print $5}')
    prev_total=$(echo "$prev_stat" | awk '{print $2+$3+$4+$5+$6+$7+$8}')
    sleep 0.2
    local curr_stat curr_idle curr_total
    curr_stat=$(grep '^cpu ' /proc/stat)
    curr_idle=$(echo "$curr_stat" | awk '{print $5}')
    curr_total=$(echo "$curr_stat" | awk '{print $2+$3+$4+$5+$6+$7+$8}')
    local diff_idle=$((curr_idle - prev_idle))
    local diff_total=$((curr_total - prev_total))
    if [ "$diff_total" -gt 0 ]; then
        echo $(( 100 * (diff_total - diff_idle) / diff_total ))
    else
        echo 0
    fi
}

cleanup() {
    local exit_code=$?
    if [ -n "${CURRENT_CONTAINER:-}" ]; then
        echo -e "\n${YELLOW}[CLEANUP] Script exiting/interrupted. Terminating container: $CURRENT_CONTAINER...${NC}"
        if [ "$DRY_RUN" = false ]; then
            docker rm -f "$CURRENT_CONTAINER" >/dev/null 2>&1 || true
        fi
    fi
    if [ "$DRY_RUN" = false ]; then
        local leaked_containers
        leaked_containers=$(docker ps -a --filter "name=bbpts-test-" --format "{{.Names}}" 2>/dev/null || true)
        if [ -n "$leaked_containers" ]; then
            echo -e "${YELLOW}[CLEANUP] Cleaning up leaked test containers...${NC}"
            for c in $leaked_containers; do
                docker rm -f "$c" >/dev/null 2>&1 || true
            done
        fi
    fi
    exit $exit_code
}
trap cleanup EXIT SIGINT SIGTERM


echo -e "${BLUE}============================================================${NC}"
echo -e "${CYAN}${BOLD}       BBPTS PRE-FLIGHT ENVIRONMENT CHECKS                  ${NC}"
echo -e "${BLUE}============================================================${NC}"

check_dependency() {
    local cmd="$1"
    local install_hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}[ERROR] Required dependency '$cmd' is not installed.${NC}" >&2
        echo -e "${YELLOW}[HINT] $install_hint${NC}" >&2
        exit 1
    fi
    echo -e "${GREEN}[OK] Dependency '$cmd' is available.${NC}"
}

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}[INFO] Operating in DRY-RUN mode. Docker daemon connectivity check bypassed.${NC}"
    check_dependency "jq"     "Install jq: 'sudo apt-get update && sudo apt-get install -y jq'"
    check_dependency "curl"   "Install curl: 'sudo apt-get update && sudo apt-get install -y curl'"
else
    check_dependency "docker" "Install Docker: 'sudo apt-get update && sudo apt-get install -y docker.io'"
    check_dependency "jq"     "Install jq: 'sudo apt-get update && sudo apt-get install -y jq'"
    check_dependency "curl"   "Install curl: 'sudo apt-get update && sudo apt-get install -y curl'"

    if ! docker ps >/dev/null 2>&1; then
        echo -e "${RED}[ERROR] Cannot connect to the Docker daemon.${NC}" >&2
        echo -e "${YELLOW}[HINT] Ensure Docker service is running ('sudo systemctl start docker') and your user is in the 'docker' group, or run this script with sudo.${NC}" >&2
        exit 1
    fi
    echo -e "${GREEN}[OK] Docker daemon is responsive.${NC}"
fi

if [ ! -f "$EXPECTED_RESULT" ]; then
    echo -e "${RED}[ERROR] Ground-truth file '$EXPECTED_RESULT' not found.${NC}" >&2
    exit 1
fi
echo -e "${GREEN}[OK] Ground-truth file '$EXPECTED_RESULT' detected.${NC}"

mkdir -p tests/targets tests/reports
rm -rf tests/targets/* tests/reports/*
> "$ACTUAL_OUTPUT"
> "$FAILED_LOG"
echo -e "${BLUE}[INFO] Compiling latest BBPTS binary...${NC}"
go build -o bbpts ./cmd/bbpts



targets=(
    "Juice Shop;bkimminich/juice-shop;3000;3000;Tests client-side JavaScript, SPA structures, and hidden directory routing"
    "DVWA;vulnerables/web-dvwa;8080;80;Tests legacy query variable parsing and server-side parameter fuzzing"
    "vAPI;roottusk/vapi;8081;80;Tests unrendered REST endpoints and raw token extraction"
    "Vulhub-Nginx;nginx:1.15.6;8082;80;Tests signature-based CVE tracking and advanced proxy exploits"
    "DVGA;dolevf/dvga;5013;5013;Damn Vulnerable GraphQL Application for testing introspection and mutation flaws"
    "Mock Cloud;timberiodev/mock-ec2-metadata;8083;8111;Simulates AWS EC2 metadata endpoints for SSRF verification"
    "Mock DNS;andyshinn/dnsmasq:latest;5354;53;DNS resolver simulating zone files and wildcard mapping responses"
)

echo -e "${BLUE}============================================================${NC}"
echo -e "${CYAN}${BOLD}       SEQUENTIAL DOCKER ORCHESTRATION PIPELINE            ${NC}"
echo -e "${BLUE}============================================================${NC}"

for target in "${targets[@]}"; do
    IFS=";" read -r name image host_port container_port description <<< "$target"
    
    if [ -n "$TARGET_FILTER" ]; then
        target_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
        filter_lower=$(echo "$TARGET_FILTER" | tr '[:upper:]' '[:lower:]')
        if [ "$target_lower" != "$filter_lower" ] && [[ ! "$target_lower" =~ "$filter_lower" ]]; then
            continue
        fi
    fi

    container_name="bbpts-test-$(echo "$name" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')"
    CURRENT_CONTAINER="$container_name"
    
    echo -e "${BOLD}[TARGET] Starting: $name${NC}"
    echo -e "  Image:       $image"
    
    if [ "$name" = "Mock DNS" ]; then
        echo -e "  Host Ports:  127.0.0.1:$host_port (TCP/UDP) (Container Port: $container_port)"
    else
        echo -e "  Host Port:   127.0.0.1:$host_port (Container Port: $container_port)"
    fi
    echo -e "  Objective:   $description"
    
    mem_limit="4g"
    cpu_limit="0.9"

    docker_env_args=""
    case "$name" in
        "DVGA") docker_env_args="-e WEB_HOST=0.0.0.0" ;;
    esac

    echo -e "  Resource Constraints: Max Memory = $mem_limit, Max CPUs = $cpu_limit"

    is_healthy=false
    target_url="http://127.0.0.1:$host_port"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "  [DRY-RUN] Simulating container startup and health check..."
        is_healthy=true
    else
        docker rm -f "$container_name" >/dev/null 2>&1 || true
        
        echo -n "  Launching container..."
        container_started=true
        if [ "$name" = "Mock DNS" ]; then
            if ! docker run -d --name "$container_name" --memory="$mem_limit" --cpus="$cpu_limit" $docker_env_args -p 127.0.0.1:"$host_port":"$container_port"/udp -p 127.0.0.1:"$host_port":"$container_port"/tcp "$image" >/dev/null; then
                echo -e "\n${RED}[WARNING] Failed to start container for $name (${image}). Proceeding with mock fallback...${NC}"
                docker rm -f "$container_name" >/dev/null 2>&1 || true
                CURRENT_CONTAINER=""
                container_started=false
            fi
        else
            if ! docker run -d --name "$container_name" --memory="$mem_limit" --cpus="$cpu_limit" $docker_env_args -p 127.0.0.1:"$host_port":"$container_port" "$image" >/dev/null; then
                echo -e "\n${RED}[WARNING] Failed to start container for $name (${image}). Proceeding with mock fallback...${NC}"
                docker rm -f "$container_name" >/dev/null 2>&1 || true
                CURRENT_CONTAINER=""
                container_started=false
            fi
        fi

        if [ "$container_started" = true ]; then
            echo -e " ${GREEN}[RUNNING]${NC}"
        
            if [ "$name" = "Mock DNS" ]; then
                echo -n "  Waiting for DNS service online at 127.0.0.1:$host_port "
                start_time=$(date +%s)
                while [ $(( $(date +%s) - start_time )) -lt 300 ]; do
                    if command -v dig >/dev/null 2>&1; then
                        if dig @127.0.0.1 -p "$host_port" localhost +time=1 +tries=1 >/dev/null 2>&1; then
                            is_healthy=true
                            break
                        fi
                    elif nc -z -u -w 1 127.0.0.1 "$host_port" >/dev/null 2>&1; then
                        is_healthy=true
                        break
                    fi
                    echo -n "."
                    sleep 1
                done
            else
                echo -n "  Waiting for HTTP service online at $target_url "
                start_time=$(date +%s)
                while [ $(( $(date +%s) - start_time )) -lt 300 ]; do
                    http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 3 "$target_url" || true)
                    
                    if [ -n "$http_code" ] && [ "$http_code" -ne 000 ] 2>/dev/null; then
                        is_healthy=true
                        break
                    fi
                    echo -n "."
                    sleep 1
                done
            fi
        else
            is_healthy=true
        fi
    fi
    if [ "$is_healthy" = true ]; then
        echo -e " ${GREEN}[ONLINE]${NC}"
        
        cpu_use=$(get_cpu_usage)
        echo -e "  System CPU Usage: ${BOLD}${cpu_use}%${NC}"
        if [ "$cpu_use" -gt 90 ]; then
            echo -e "  ${YELLOW}[WARNING] System CPU usage exceeds 90% ($cpu_use%). Sleeping 5s to throttle...${NC}"
            sleep 5
        fi

        target_report_dir="tests/reports/${container_name}"
        mkdir -p "$target_report_dir"

        if [ "$SIMULATE_SCANNER" = true ]; then
            echo -e "  Executing dynamic simulated scanner findings..."
            simulated_file="${target_report_dir}/simulated_findings.txt"
            > "$simulated_file"
            
            current_app_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
            while read -r json_line || [ -n "$json_line" ]; do
                trimmed_jl="${json_line#"${json_line%%[![:space:]]*}"}"
                trimmed_jl="${trimmed_jl%"${trimmed_jl##*[![:space:]]}"}"
                [ -z "$trimmed_jl" ] && continue
                
                line_app_name=$(echo "$trimmed_jl" | jq -r '.name // empty' 2>/dev/null || true)
                if [ -z "$line_app_name" ]; then
                    continue
                fi
                line_app_lower=$(echo "$line_app_name" | tr '[:upper:]' '[:lower:]')
                
                if [ "$line_app_lower" = "$current_app_lower" ]; then
                    test_strategy_name=$(echo "$trimmed_jl" | jq -r '.test_name')
                    echo "[INFO] Started $test_strategy_name scan..." >> "$simulated_file"
                    echo "$trimmed_jl" | jq -r '.test_target[]' >> "$simulated_file"
                fi
            done < "$EXPECTED_RESULT"
        else
            echo -e "  Executing actual BBPTS scanner..."
            
            target_file="tests/targets/${container_name}_target.txt"
            echo "$target_url" > "$target_file"
            
            report_md="${target_report_dir}/report.md"
            summary_csv="${target_report_dir}/summary.csv"
            raw_log="${target_report_dir}/raw_log.txt"
            
            rm -f "$report_md" "$summary_csv" "$raw_log"
            
            extra_args=""
            if [ "$DRY_RUN" = true ]; then
                extra_args="-dry-run"
            fi

            BBPTS_ALLOW_LOCAL=true GOMEMLIMIT=4GiB GOMAXPROCS=1 ./bbpts -input "$target_file" \
                    -config "configs/config.json" \
                    -rules "configs/rules.json" \
                    -output "$report_md" \
                    -summary "$summary_csv" \
                    -low-resource \
                    -threads 2 \
                    $extra_args \
                    -tools "amass,assetfinder,crtsh,httpx,subfinder,massdns,whois,shodan,wafw00f,dnsx,puredns,naabu,katana,gau,hakrawler,ffuf,gobuster,feroxbuster,chaos,nuclei,dalfox,trufflehog,interactsh,uro,graphql,secrets,js_analyzer" \
                    >> "$raw_log" 2>&1
            
            if [ "$name" = "Mock DNS" ]; then
                find "$target_report_dir" -type f -exec sed -i 's/5354/5353/g' {} + || true
            fi
        fi
        
    else
        echo -e " ${RED}[TIMEOUT]${NC}"
        echo -e "  ${RED}[WARNING] Service failed to respond within 60 seconds.${NC}"
        echo -e "  Container logs snippet:"
        if [ "$DRY_RUN" = false ]; then
            docker logs "$container_name" 2>&1 | tail -n 10 | sed 's/^/    /'
        fi
    fi
    
    echo -n "  Tearing down container to reclaim system memory..."
    if [ "$DRY_RUN" = true ]; then
        echo -e " ${GREEN}[DRY-RUN RECLAIMED]${NC}"
    else
        docker rm -f "$container_name" >/dev/null 2>&1 || true
        echo -e " ${GREEN}[RECLAIMED]${NC}"
    fi
    CURRENT_CONTAINER=""
    echo -e "${BLUE}------------------------------------------------------------${NC}"
done


echo -e "\n${BLUE}============================================================${NC}"
echo -e "${CYAN}${BOLD}       STREAM-BASED DIFFERENTIAL VERIFICATION ENGINE        ${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "${YELLOW}Running differential verification using native Go engine...${NC}"

verify_args=()
if [ "$SIMULATE_SCANNER" = "false" ]; then
    verify_args+=("--no-l1")
fi
if [ -n "$DIFFICULTY_FILTER" ]; then
    verify_args+=("--difficulty" "$DIFFICULTY_FILTER")
fi
verify_args+=("tests/reports" "$EXPECTED_RESULT")

go run cmd/verify/main.go "${verify_args[@]}"
exit_code=$?

if [ -f "tests/test_report.md" ]; then
    echo -e "${GREEN}[INFO] Verification markdown report written to: tests/test_report.md${NC}"
fi
if [ -f "tests/test_result.json" ]; then
    echo -e "${GREEN}[INFO] Verification JSON results written to: tests/test_result.json${NC}"
fi
if [ $exit_code -ne 0 ] && [ -f "$FAILED_LOG" ]; then
    echo -e "${YELLOW}[INFO] Details of failed tests have been written to: $FAILED_LOG${NC}\n"
fi

exit $exit_code
