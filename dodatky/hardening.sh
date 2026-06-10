#!/usr/bin/env bash
# =============================================================================
# hardening.sh — Автоматизований hardening веб-сервера (Ubuntu 24.04 LTS)
# =============================================================================
# Версія        : 1.9
# Цільова ОС    : Ubuntu 24.04 LTS
# Стек          : SSH + Nginx/Apache + MySQL/MariaDB + vsftpd + UFW + Fail2Ban
# Формат роботи : один самодостатній shell-скрипт без зовнішніх залежностей,
#                 окрім стандартних системних пакетів Ubuntu.
#
# ЩО РОБИТЬ ЦЕЙ СКРИПТ
# ---------------------
# 1. Перевіряє root-права та аргументи запуску.
# 2. Перевіряє наявність необхідних пакетів і, за потреби, встановлює їх.
# 3. Визначає середовище: який веб-сервер активний, чи присутні MySQL/vsftpd.
# 4. Визначає адміністративного non-root користувача, створює його за потреби.
# 5. Готує безпечний SSH-доступ для admin-користувача:
#    - використовує наявні authorized_keys, або
#    - копіює root authorized_keys, або
#    - входить у bootstrap-режим і генерує тимчасову пару ключів.
# 6. Виконує hardening SSH:
#    - PermitRootLogin no
#    - нестандартний порт
#    - AllowUsers
#    - вимкнення паролів (через drop-in override, сумісний з cloud-init)
#    - коректна підтримка socket-activation в Ubuntu 24.04+
# 7. Виконує hardening веб-сервера (Nginx або Apache):
#    - приховування версії
#    - security headers
#    - вимкнення directory listing
# 8. Виконує hardening MySQL/MariaDB:
#    - bind-address = 127.0.0.1
#    - видалення anonymous users
#    - заборона remote root
#    - видалення test DB
# 9. Виконує hardening FTP (vsftpd):
#    - TLS/FTPS
#    - chroot
#    - обмежений PASV range
#    - генерація self-signed сертифіката, якщо немає Let's Encrypt
# 10. Налаштовує UFW і Fail2Ban.
# 11. Генерує фінальний звіт.
#
# ОСОБЛИВО ВАЖЛИВІ ОСОБЛИВОСТІ
# ----------------------------
# - Скрипт працює в режимі strict bash: set -Eeuo pipefail.
# - Перед зміною критичних конфігів створюються резервні копії.
# - Для SSH використовується Dead Man's Switch watchdog, який може повернути
#   конфіг назад, якщо зміни призводять до втрати доступу.
# - Для Ubuntu 24.04 враховано нову модель ssh.socket / socket activation.
# - Для Ubuntu/cloud-init враховано проблему, коли PasswordAuthentication yes
#   повертається через /etc/ssh/sshd_config.d/50-cloud-init.conf.
#   Тому скрипт створює власний override-файл 99-local-auth.conf.
#
# ВИКОРИСТАННЯ
# ------------
# sudo bash hardening.sh [--ssh-port PORT] [--admin-user USER] [--dry-run]
#
# ПРИКЛАДИ
# --------
# sudo bash hardening.sh
# sudo bash hardening.sh --ssh-port 2222
# sudo bash hardening.sh --admin-user vitalii
# sudo bash hardening.sh --dry-run
# =============================================================================

# -----------------------------------------------------------------------------
# РОЗДІЛ 1. РЕЖИМ СУВОРОГО ВИКОНАННЯ
# -----------------------------------------------------------------------------
# set -E        : trap ERR успадковується функціями.
# set -e        : перша ж помилка команди завершує скрипт.
# set -u        : звернення до неоголошеної змінної вважається помилкою.
# pipefail      : помилка будь-якої команди в пайпі вважається помилкою всього пайпу.
set -Eeuo pipefail

# -----------------------------------------------------------------------------
# РОЗДІЛ 2. ГЛОБАЛЬНІ КОНСТАНТИ ТА РОБОЧІ ЗМІННІ
# -----------------------------------------------------------------------------
# SCRIPT_VERSION  : версія поточного скрипта.
# SCRIPT_NAME     : ім'я файла скрипта без шляху.
# RUN_TIMESTAMP   : мітка часу запуску — використовується в логах і backup names.
# LOG_FILE        : єдиний лог-файл на один запуск.
# BACKUP_DIR      : директорія всіх бекапів поточного запуску.
# SSH_PORT        : новий порт SSH; може бути перевизначений параметром --ssh-port.
# DRY_RUN         : режим попереднього перегляду без застосування змін.
# WEB_SERVER      : визначений активний веб-сервер (nginx/apache2/none).
# HAS_VSFTPD      : прапор наявності vsftpd.
# HAS_MYSQL       : прапор наявності MySQL/MariaDB.
# ADMIN_USER      : non-root користувач, якому буде дозволено SSH-вхід.
# BOOTSTRAP_CONFIRMED : чи підтверджено успішний bootstrap-доступ по ключу.
readonly SCRIPT_VERSION="1.9"
readonly SCRIPT_NAME="$(basename "$0")"
readonly RUN_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/var/log/hardening_${RUN_TIMESTAMP}.log"
readonly BACKUP_DIR="/var/backups/hardening_${RUN_TIMESTAMP}"

SSH_PORT="${SSH_PORT:-2222}"
DRY_RUN=false
ASSUME_YES=false
RESET_UFW=true
RUN_UPGRADE=true
STRICT_SSH=true
INSTALL_MALWARE_SCANNER=true
WEB_SERVER="none"
HAS_VSFTPD=false
HAS_MYSQL=false
ADMIN_USER="${ADMIN_USER:-}"
BOOTSTRAP_CONFIRMED=false

declare -a BACKUP_FILES=()
declare -a BACKUP_ORIGINALS=()

# -----------------------------------------------------------------------------
# РОЗДІЛ 3. ЖУРНАЛЮВАННЯ
# -----------------------------------------------------------------------------
# log() — базова функція журналювання.
# Виводить повідомлення одночасно:
# 1) у stderr/термінал,
# 2) у лог-файл,
# 3) у syslog через logger.
#
# Аргументи:
#   $1 — текст повідомлення
#   $2 — рівень (INFO/WARN/ERROR), за замовчуванням INFO
log() {
  local message="$1"
  local level="${2:-INFO}"
  local timestamp color="" reset="\033[0m"
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  if [[ -t 1 ]]; then
    case "$level" in
      INFO) color="\033[0;32m" ;;
      WARN) color="\033[0;33m" ;;
      ERROR) color="\033[0;31m" ;;
    esac
  fi
  printf "%b[%s] [%-5s] %s%b\n" "$color" "$timestamp" "$level" "$message" "$reset" >&2
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  { printf "[%s] [%-5s] %s\n" "$timestamp" "$level" "$message" >> "$LOG_FILE"; } 2>/dev/null || true
  logger -t "$SCRIPT_NAME" "[${level}] ${message}" 2>/dev/null || true
}
log_info(){ log "$1" INFO; }
log_warn(){ log "$1" WARN; }
log_error(){ log "$1" ERROR; }

# -----------------------------------------------------------------------------
# РОЗДІЛ 4. ВІДКАТ І ОБРОБКА ПОМИЛОК
# -----------------------------------------------------------------------------
# restore_all_backups() — відновлює всі конфігурації з масиву BACKUP_FILES.
# Використовується у випадку помилки або ручного rollback.
restore_all_backups() {
  if [[ ${#BACKUP_FILES[@]} -eq 0 ]]; then
    log_warn "No backups to restore."
    return 0
  fi
  log_warn "Restoring all backed-up configurations..."
  local i backup original
  for i in "${!BACKUP_FILES[@]}"; do
    backup="${BACKUP_FILES[$i]}"
    original="${BACKUP_ORIGINALS[$i]}"
    if [[ -f "$backup" ]]; then
      cp -a "$backup" "$original"
      log_warn "Restored: $original (from $backup)"
    fi
  done
}

cleanup_on_error() {
  local exit_code=$?
  local line_number="${1:-unknown}"
  log_error "Script failed at line ${line_number} with exit code ${exit_code}"
  log_error "Attempting to restore all backups..."
  restore_all_backups
  log_error "Hardening aborted. Review ${LOG_FILE} for details."
  exit "$exit_code"
}
trap 'cleanup_on_error $LINENO' ERR

trap_exit() {
  local code=$?
  if [[ $code -eq 0 ]]; then
    log_info "hardening.sh completed successfully. Log: ${LOG_FILE}"
  fi
}
trap 'trap_exit' EXIT

# -----------------------------------------------------------------------------
# РОЗДІЛ 5. ПЕРЕВІРКИ ЗАПУСКУ ТА РОЗБІР АРГУМЕНТІВ
# -----------------------------------------------------------------------------
# check_root() — гарантує, що скрипт запущений від root.
# Більшість операцій hardening потребують повного доступу до системи.
check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root. Use: sudo bash ${SCRIPT_NAME}"
    exit 1
  fi
}

usage() {
  cat <<EOF
Usage: sudo bash ${SCRIPT_NAME} [options]

Options:
  --ssh-port PORT      SSH port to configure (1-65535, default: 2222)
  --admin-user USER    Non-root admin user to create/use
  --dry-run            Show planned actions without changing files or services
  --yes                Non-interactive first-run confirmation
  --no-ufw-reset       Preserve existing UFW rules instead of resetting them
  --no-upgrade         Skip apt-get upgrade
  --no-strict-ssh      Skip extra strict SSH options for Lynis recommendations
  --no-malware-scanner Skip rkhunter installation and initialization
  -h, --help           Show this help
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ssh-port)
        [[ $# -ge 2 && ! "$2" =~ ^-- ]] || { log_error "--ssh-port requires a value"; usage; exit 1; }
        SSH_PORT="$2"; shift 2 ;;
      --admin-user)
        [[ $# -ge 2 && ! "$2" =~ ^-- ]] || { log_error "--admin-user requires a value"; usage; exit 1; }
        ADMIN_USER="$2"; shift 2 ;;
      --dry-run) DRY_RUN=true; shift ;;
      --yes) ASSUME_YES=true; shift ;;
      --no-ufw-reset) RESET_UFW=false; shift ;;
      --no-upgrade) RUN_UPGRADE=false; shift ;;
      --no-strict-ssh) STRICT_SSH=false; shift ;;
      --no-malware-scanner) INSTALL_MALWARE_SCANNER=false; shift ;;
      -h|--help) trap - EXIT; usage; exit 0 ;;
      *) log_error "Unknown argument: $1"; usage; exit 1 ;;
    esac
  done
}

validate_args() {
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
    log_error "Invalid SSH port: ${SSH_PORT}. Use a number from 1 to 65535."
    exit 1
  fi
  if [[ -n "${ADMIN_USER:-}" ]]; then
    if [[ "$ADMIN_USER" == "root" || ! "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
      log_error "Invalid admin username: ${ADMIN_USER}"
      exit 1
    fi
  fi
}

show_first_run_notice() {
  log_warn "This script is designed for a fresh Ubuntu 24.04 web server first run."
  log_warn "It may change SSH, firewall, web, database and FTP service configuration."
  if [[ "$RESET_UFW" == "true" ]]; then
    log_warn "UFW rules will be reset to a clean default-deny baseline."
  else
    log_warn "Existing UFW rules will be preserved."
  fi
  if [[ "$DRY_RUN" == "true" || "$ASSUME_YES" == "true" || ! -t 0 ]]; then
    return 0
  fi
  read -r -p "Continue with first-run hardening? Type YES to continue: " answer
  if [[ "${answer,,}" != "yes" && "${answer,,}" != "y" ]]; then
    log_error "Aborted by user."
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 6. ДОПОМІЖНІ УТИЛІТАРНІ ФУНКЦІЇ
# -----------------------------------------------------------------------------
# run_cmd() — обгортка над виконанням команд.
# У dry-run режимі не виконує команду, а лише логує її.
run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would execute: $*"
    return 0
  fi
  "$@"
}

backup_config() {
  local file="$1"
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would backup: ${file}"
    return 0
  fi
  if [[ ! -f "$file" ]]; then
    log_warn "Backup skipped, file not found: ${file}"
    return 0
  fi
  mkdir -p "$BACKUP_DIR"
  local safe_name backup_path
  safe_name="$(echo "$file" | tr '/' '_')"
  backup_path="${BACKUP_DIR}/${safe_name}.bak.${RUN_TIMESTAMP}"
  cp -a "$file" "$backup_path"
  BACKUP_FILES+=("$backup_path")
  BACKUP_ORIGINALS+=("$file")
  log_info "Backup created: ${backup_path}"
}

check_and_install_package() {
  local pkg="$1" bin="${2:-}"
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
    log_info "Package already installed: ${pkg}"
    return 0
  fi
  if [[ -n "$bin" ]] && command -v "$bin" >/dev/null 2>&1; then
    log_info "Binary '${bin}' found, skipping package install: ${pkg}"
    return 0
  fi
  log_info "Package not found: ${pkg}. Installing..."
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would run: apt-get install -y ${pkg}"
    return 0
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
  log_info "Package installed successfully: ${pkg}"
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 7. ПЕРЕВІРКА І ВСТАНОВЛЕННЯ ПАКЕТІВ
# -----------------------------------------------------------------------------
# check_and_install_all_packages() — централізовано перевіряє всі пакети,
# які потрібні для подальших модулів hardening.
check_and_install_all_packages() {
  log_info "========================================"
  log_info "MODULE: Package verification & install"
  log_info "========================================"
  log_info "Refreshing apt package cache..."
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would run: apt-get update -qq"
    [[ "$RUN_UPGRADE" == "true" ]] && log_info "[DRY-RUN] Would run: apt-get upgrade -y"
  else
    apt-get update -qq || log_warn "apt-get update returned non-zero; continuing anyway."
    if [[ "$RUN_UPGRADE" == "true" ]]; then
      log_info "Applying available package upgrades..."
      DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
      log_info "Package upgrade complete."
    else
      log_warn "Package upgrade skipped by --no-upgrade."
    fi
  fi
  log_info "--- Checking SSH ---"
  check_and_install_package "openssh-server" "sshd"
  log_info "--- Checking web server ---"
  local apache_installed=false nginx_installed=false
  dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -q 'install ok installed' && apache_installed=true || true
  dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -q 'install ok installed' && nginx_installed=true || true
  if [[ "$apache_installed" == "true" && "$nginx_installed" == "true" ]]; then
    log_warn "Both nginx and apache2 are installed. Will use whichever is active."
  elif [[ "$apache_installed" == "true" ]]; then
    log_info "apache2 is already installed."
  elif [[ "$nginx_installed" == "true" ]]; then
    log_info "nginx is already installed."
  else
    log_info "No web server found. Installing nginx..."
    check_and_install_package "nginx" "nginx"
  fi
  log_info "--- Checking MySQL/MariaDB ---"
  if dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -q 'install ok installed'; then
    log_info "mysql-server is already installed."
  elif dpkg-query -W -f='${Status}' mariadb-server 2>/dev/null | grep -q 'install ok installed'; then
    log_info "mariadb-server is already installed."
  else
    log_info "No MySQL/MariaDB found. Installing mariadb-server..."
    check_and_install_package "mariadb-server" "mysql"
  fi
  log_info "--- Checking FTP (vsftpd) ---"
  if dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q 'install ok installed'; then
    log_info "vsftpd is already installed."
  else
    log_warn "vsftpd is not installed."
    if [[ -t 0 && "$DRY_RUN" != "true" ]]; then
      read -rp "Install vsftpd (FTP server)? [y/N]: " answer
      if [[ "${answer,,}" == "y" ]]; then
        check_and_install_package "vsftpd" "vsftpd"
      else
        log_info "vsftpd installation skipped. FTP module will be disabled."
      fi
    else
      log_info "Non-interactive mode: vsftpd installation skipped."
    fi
  fi
  log_info "--- Checking perimeter tools (ufw, fail2ban) ---"
  check_and_install_package "ufw" "ufw"
  check_and_install_package "fail2ban" "fail2ban-server"
  log_info "--- Checking auxiliary tools ---"
  check_and_install_package "openssl" "openssl"
  check_and_install_package "debsums" "debsums"
  check_and_install_package "apt-show-versions" "apt-show-versions"
  if [[ "$INSTALL_MALWARE_SCANNER" == "true" ]]; then
    check_and_install_package "rkhunter" "rkhunter"
  fi
  log_info "Package verification complete."
  log_info ""
}

detect_webserver() {
  if systemctl -q is-active nginx 2>/dev/null; then
    echo nginx
  elif systemctl -q is-active apache2 2>/dev/null; then
    echo apache2
  elif dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -q 'install ok installed'; then
    systemctl start nginx 2>/dev/null && echo nginx || echo none
  elif dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -q 'install ok installed'; then
    systemctl start apache2 2>/dev/null && echo apache2 || echo none
  else
    echo none
  fi
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 8. ВИЗНАЧЕННЯ СЕРЕДОВИЩА
# -----------------------------------------------------------------------------
# detect_environment() — визначає активний веб-сервер, наявність MySQL та vsftpd.
detect_environment() {
  log_info "========================================"
  log_info "MODULE: Environment detection"
  log_info "========================================"
  WEB_SERVER="$(detect_webserver)"
  log_info "Active web server: ${WEB_SERVER}"
  if systemctl -q is-active vsftpd 2>/dev/null || dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q 'install ok installed'; then
    HAS_VSFTPD=true
    log_info "vsftpd: present"
  else
    log_info "vsftpd: not found (FTP module will be skipped)"
  fi
  if systemctl -q is-active mysql 2>/dev/null || systemctl -q is-active mariadb 2>/dev/null || command -v mysql >/dev/null 2>&1; then
    HAS_MYSQL=true
    log_info "MySQL/MariaDB: present"
  else
    log_info "MySQL/MariaDB: not found (MySQL module will be skipped)"
  fi
  log_info ""
}

user_exists() { id "$1" >/dev/null 2>&1; }

user_has_authorized_keys() {
  local user="$1" home_dir
  home_dir="$(getent passwd "$user" | cut -d: -f6 || true)"
  [[ -n "$home_dir" && -s "${home_dir}/.ssh/authorized_keys" ]]
}

ensure_user_ssh_dir() {
  local user="$1" home_dir group_name
  home_dir="$(getent passwd "$user" | cut -d: -f6 || true)"
  group_name="$(id -gn "$user" 2>/dev/null || echo "$user")"
  mkdir -p "${home_dir}/.ssh"
  chmod 700 "${home_dir}/.ssh"
  touch "${home_dir}/.ssh/authorized_keys"
  chmod 600 "${home_dir}/.ssh/authorized_keys"
  chown -R "${user}:${group_name}" "${home_dir}/.ssh"
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 9. NON-ROOT ADMIN USER І SSH BOOTSTRAP
# -----------------------------------------------------------------------------
# resolve_admin_user() — визначає адміністративного non-root користувача.
# Пріоритет:
# 1) --admin-user / ADMIN_USER
# 2) SUDO_USER
# 3) локальний користувач із групою sudo
# 4) інтерактивний запит імені
resolve_admin_user() {
  if [[ -n "${ADMIN_USER:-}" && "$ADMIN_USER" != "root" ]]; then
    log_info "Admin user provided via arg/env: ${ADMIN_USER}"
    return 0
  fi
  if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    ADMIN_USER="$SUDO_USER"
    log_info "Admin user inferred from SUDO_USER: ${ADMIN_USER}"
    return 0
  fi
  local candidate
  while IFS=: read -r name _ uid _ _ _ _; do
    if [[ "$name" != "root" && "$uid" -ge 1000 ]] && id -nG "$name" 2>/dev/null | grep -qw sudo; then
      ADMIN_USER="$name"
      log_info "Admin user inferred from local sudo user: ${ADMIN_USER}"
      return 0
    fi
  done < /etc/passwd
  if [[ -t 0 ]]; then
    while true; do
      read -r -p "Enter non-root admin username to create/use [webmaster]: " candidate
      candidate="${candidate:-webmaster}"
      if [[ "$candidate" == "root" ]]; then
        echo "Username must not be root." >&2
        continue
      fi
      if [[ "$candidate" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        ADMIN_USER="$candidate"
        log_info "Admin user selected interactively: ${ADMIN_USER}"
        return 0
      fi
      echo "Invalid username format." >&2
    done
  fi
  log_error "Cannot determine a non-root admin user automatically. Re-run with sudo or pass --admin-user."
  exit 1
}

# ensure_admin_user() — перевіряє існування admin-користувача і створює його за потреби.
# Також гарантує членство в групі sudo.
ensure_admin_user() {
  resolve_admin_user
  if [[ "$ADMIN_USER" == "root" || -z "$ADMIN_USER" ]]; then
    log_error "Admin user must be a non-root user"
    exit 1
  fi
  if user_exists "$ADMIN_USER"; then
    log_info "Admin user already exists: ${ADMIN_USER}"
  else
    log_warn "Admin user does not exist yet: ${ADMIN_USER}"
    log_info "Creating admin user: ${ADMIN_USER}"
    if [[ "$DRY_RUN" == "true" ]]; then
      log_info "[DRY-RUN] useradd -m -s /bin/bash ${ADMIN_USER}"
      log_info "[DRY-RUN] usermod -aG sudo ${ADMIN_USER}"
    else
      useradd -m -s /bin/bash "$ADMIN_USER"
      usermod -aG sudo "$ADMIN_USER"
      log_info "Created user and added to sudo group: ${ADMIN_USER}"
    fi
  fi
  if [[ "$DRY_RUN" != "true" ]]; then
    usermod -aG sudo "$ADMIN_USER"
  fi
  log_info "Admin user (for AllowUsers SSH): ${ADMIN_USER}"
}

copy_root_authorized_keys_to_admin() {
  local root_keys="/root/.ssh/authorized_keys"
  local admin_home admin_group
  [[ -s "$root_keys" ]] || return 1
  admin_home="$(getent passwd "$ADMIN_USER" | cut -d: -f6 || true)"
  admin_group="$(id -gn "$ADMIN_USER" 2>/dev/null || echo "$ADMIN_USER")"
  ensure_user_ssh_dir "$ADMIN_USER"
  cat "$root_keys" >> "${admin_home}/.ssh/authorized_keys"
  sort -u "${admin_home}/.ssh/authorized_keys" -o "${admin_home}/.ssh/authorized_keys"
  chmod 600 "${admin_home}/.ssh/authorized_keys"
  chown "$ADMIN_USER:${admin_group}" "${admin_home}/.ssh/authorized_keys"
  log_info "Copied /root/.ssh/authorized_keys to ${ADMIN_USER}"
}

show_private_key_to_tty() {
  local key_file="$1"
  [[ -t 0 && -t 2 ]] || { log_warn "Non-interactive session detected; private key will not be shown."; return 1; }
  echo >&2
  echo "========================================================" >&2
  echo " TEMPORARY SSH PRIVATE KEY — COPY IT NOW " >&2
  echo "========================================================" >&2
  echo "Save locally as: ~/.ssh/id_ed25519_${ADMIN_USER}" >&2
  echo "Then: chmod 600 ~/.ssh/id_ed25519_${ADMIN_USER}" >&2
  echo >&2
  echo "How to copy from terminal safely:" >&2
  echo "  1) Select the whole key with the mouse (from BEGIN to END)." >&2
  echo "  2) Press Ctrl+Shift+C to copy (do NOT use Ctrl+C — it stops the script)." >&2
  echo "  3) On your LOCAL computer run:" >&2
  echo "       mkdir -p ~/.ssh" >&2
  echo "       nano ~/.ssh/id_ed25519_${ADMIN_USER}" >&2
  echo "  4) Paste with Ctrl+Shift+V, save the file, then run:" >&2
  echo "       chmod 600 ~/.ssh/id_ed25519_${ADMIN_USER}" >&2
  echo "  5) Test login from your LOCAL computer:" >&2
  echo "       ssh -i ~/.ssh/id_ed25519_${ADMIN_USER} -p ${SSH_PORT} ${ADMIN_USER}@<server-ip>" >&2
  echo >&2
  echo "-----BEGIN COPY BELOW THIS LINE-----" >&2
  cat "$key_file" >&2
  echo "-----END COPY ABOVE THIS LINE-----" >&2
  echo >&2
}

bootstrap_ssh_key_for_admin() {
  local admin_home ssh_dir key_file pub_file admin_group answer pub_key_line tmp_keys
  admin_home="$(getent passwd "$ADMIN_USER" | cut -d: -f6 || true)"
  ssh_dir="${admin_home}/.ssh"
  key_file="${ssh_dir}/id_ed25519_hardening_bootstrap"
  pub_file="${key_file}.pub"
  tmp_keys="${ssh_dir}/authorized_keys.tmp"
  admin_group="$(id -gn "$ADMIN_USER" 2>/dev/null || echo "$ADMIN_USER")"
  ensure_user_ssh_dir "$ADMIN_USER"
  ssh-keygen -t ed25519 -f "$key_file" -N "" -C "bootstrap-${ADMIN_USER}-$(date +%Y%m%d_%H%M%S)" >/dev/null 2>&1
  pub_key_line="$(cat "$pub_file")"
  printf "%s\n" "$pub_key_line" >> "${ssh_dir}/authorized_keys"
  sort -u "${ssh_dir}/authorized_keys" -o "${ssh_dir}/authorized_keys"
  chmod 600 "$key_file" "$pub_file" "${ssh_dir}/authorized_keys"
  chown -R "$ADMIN_USER:${admin_group}" "$ssh_dir"
  if ! show_private_key_to_tty "$key_file"; then
    grep -vxF "$pub_key_line" "${ssh_dir}/authorized_keys" > "$tmp_keys" || true
    mv "$tmp_keys" "${ssh_dir}/authorized_keys"
    shred -u "$key_file" 2>/dev/null || rm -f "$key_file"
    rm -f "$pub_file"
    chmod 600 "${ssh_dir}/authorized_keys"
    chown "$ADMIN_USER:${admin_group}" "${ssh_dir}/authorized_keys"
    return 1
  fi
  if [[ -t 0 ]]; then
    while true; do
      # Приймаємо відповіді без залежності від регістру, щоб уникнути ситуації,
      # коли користувач вводить yes замість YES і потрапляє в нескінченний цикл.
      read -r -p "Type YES after successful test login, or SKIP to keep PasswordAuthentication enabled: " answer
      case "${answer,,}" in
        yes|y)
          shred -u "$key_file" 2>/dev/null || rm -f "$key_file"
          rm -f "$pub_file"
          BOOTSTRAP_CONFIRMED=true
          log_info "Bootstrap confirmed by user. Private key deleted from server."
          return 0 ;;
        skip|s)
          grep -vxF "$pub_key_line" "${ssh_dir}/authorized_keys" > "$tmp_keys" || true
          mv "$tmp_keys" "${ssh_dir}/authorized_keys"
          shred -u "$key_file" 2>/dev/null || rm -f "$key_file"
          rm -f "$pub_file"
          chmod 600 "${ssh_dir}/authorized_keys"
          chown "$ADMIN_USER:${admin_group}" "${ssh_dir}/authorized_keys"
          BOOTSTRAP_CONFIRMED=false
          log_warn "Bootstrap skipped by user. PasswordAuthentication will remain enabled."
          return 2 ;;
        *) echo "Type YES/Y or SKIP/S." >&2 ;;
      esac
    done
  fi
  return 1
}

# prepare_admin_ssh_access() — готує SSH-доступ для ADMIN_USER.
# Якщо є authorized_keys — використовує їх.
# Якщо є root authorized_keys — копіює їх.
# Якщо ключів немає — запускає bootstrap-режим.
prepare_admin_ssh_access() {
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would prepare SSH access for ${ADMIN_USER}"
    log_info "[DRY-RUN] Would use existing keys, copy root keys, or bootstrap a temporary key if needed."
    return 0
  fi
  ensure_user_ssh_dir "$ADMIN_USER"
  if user_has_authorized_keys "$ADMIN_USER"; then
    log_info "Admin user already has SSH authorized_keys: ${ADMIN_USER}"
    return 0
  fi
  if copy_root_authorized_keys_to_admin; then
    log_info "Admin SSH access prepared from root authorized_keys."
    return 0
  fi
  log_warn "No existing SSH keys found for ${ADMIN_USER}. Starting bootstrap mode..."
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would bootstrap SSH key for ${ADMIN_USER}"
    return 0
  fi
  bootstrap_ssh_key_for_admin || true
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 10. SSH HARDENING
# -----------------------------------------------------------------------------
# configure_ssh_socket_port() — критично важлива функція для Ubuntu 24.04+,
# де OpenSSH часто запускається через systemd socket activation (ssh.socket).
# Простого Port у sshd_config недостатньо — треба ще оновити ListenStream.
configure_ssh_socket_port() {
  local socket_dir="/etc/systemd/system/ssh.socket.d"
  local socket_override="${socket_dir}/listen.conf"
  mkdir -p "$socket_dir"
  cat > "$socket_override" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${SSH_PORT}
ListenStream=[::]:${SSH_PORT}
EOF
  systemctl daemon-reload
  systemctl restart ssh.socket
  log_info "SSH: ssh.socket override applied for port ${SSH_PORT}"
}

disable_password_auth() {
  # ---------------------------------------------------------------------------
  # МЕТА:
  # На Ubuntu 24.04 парольна автентифікація часто повертається через
  # /etc/ssh/sshd_config.d/50-cloud-init.conf, де cloud-init може залишити:
  #   PasswordAuthentication yes
  # Тому недостатньо змінити лише /etc/ssh/sshd_config.
  # Надійніший підхід — створити власний drop-in файл з вищим пріоритетом,
  # наприклад 99-local-auth.conf, який остаточно перевизначить політику SSH.
  # ---------------------------------------------------------------------------
  local cfg="/etc/ssh/sshd_config"
  local dropin_dir="/etc/ssh/sshd_config.d"
  local dropin_file="${dropin_dir}/99-local-auth.conf"

  # Якщо bootstrap-режим не був підтверджений і в admin-користувача немає
  # authorized_keys, не вимикаємо пароль, щоб не заблокувати доступ.
  if [[ "$BOOTSTRAP_CONFIRMED" != "true" ]] && ! user_has_authorized_keys "$ADMIN_USER"; then
    log_warn "SSH bootstrap key not confirmed; PasswordAuthentication will remain enabled."
    return 0
  fi

  mkdir -p "$dropin_dir"

  # Бекапимо існуючий drop-in, якщо він уже є.
  [[ -f "$dropin_file" ]] && backup_config "$dropin_file"

  # Додатково логічно зберегти для журналу факт, що cloud-init файл існує.
  if [[ -f "/etc/ssh/sshd_config.d/50-cloud-init.conf" ]]; then
    log_warn "SSH: Detected /etc/ssh/sshd_config.d/50-cloud-init.conf — local override will take precedence"
  fi

  # Записуємо локальну політику SSH у файл з вищим пріоритетом.
  # Саме цей файл повинен остаточно вимкнути парольну автентифікацію.
  cat > "$dropin_file" <<EOF
# Managed by hardening.sh v${SCRIPT_VERSION}
# This file overrides cloud-init SSH auth defaults on Ubuntu 24.04+
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
EOF

  # Для сумісності все одно прописуємо те саме і в основний sshd_config,
  # щоб конфіг був логічно узгодженим навіть без drop-in механізму.
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$cfg"
  grep -q '^PasswordAuthentication ' "$cfg" || echo 'PasswordAuthentication no' >> "$cfg"

  sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$cfg"
  grep -q '^KbdInteractiveAuthentication ' "$cfg" || echo 'KbdInteractiveAuthentication no' >> "$cfg"

  sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "$cfg"
  grep -q '^PubkeyAuthentication ' "$cfg" || echo 'PubkeyAuthentication yes' >> "$cfg"

  log_info "SSH: PasswordAuthentication disabled via local drop-in override"
}


# apply_ssh_hardening() — застосовує базові директиви безпеки до sshd_config.
# Сюди входять PermitRootLogin, Port, AllowUsers, ClientAlive*, X11Forwarding тощо.
apply_ssh_hardening() {
  local cfg="/etc/ssh/sshd_config"
  log_info "Applying SSH hardening directives..."
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would set PermitRootLogin no, Port ${SSH_PORT}, AllowUsers ${ADMIN_USER}"
    log_info "[DRY-RUN] Would set MaxAuthTries 3, LoginGraceTime 20, MaxStartups 10:30:100"
    log_info "[DRY-RUN] Would disable X11/agent forwarding, DebianBanner and password auth when safe"
    return 0
  fi
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$cfg"; grep -q '^PermitRootLogin ' "$cfg" || echo 'PermitRootLogin no' >> "$cfg"; log_info "SSH: PermitRootLogin -> no"
  sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$cfg"; grep -q '^MaxAuthTries ' "$cfg" || echo 'MaxAuthTries 3' >> "$cfg"; log_info "SSH: MaxAuthTries -> 3"
  sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 20/' "$cfg"; grep -q '^LoginGraceTime ' "$cfg" || echo 'LoginGraceTime 20' >> "$cfg"; log_info "SSH: LoginGraceTime -> 20"
  sed -i 's/^#*MaxStartups.*/MaxStartups 10:30:100/' "$cfg"; grep -q '^MaxStartups ' "$cfg" || echo 'MaxStartups 10:30:100' >> "$cfg"; log_info "SSH: MaxStartups -> 10:30:100"
  sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$cfg"; grep -q '^X11Forwarding ' "$cfg" || echo 'X11Forwarding no' >> "$cfg"; log_info "SSH: X11Forwarding -> no"
  sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/' "$cfg"; grep -q '^AllowAgentForwarding ' "$cfg" || echo 'AllowAgentForwarding no' >> "$cfg"; log_info "SSH: AllowAgentForwarding -> no"
  sed -i 's/^#*DebianBanner.*/DebianBanner no/' "$cfg"; grep -q '^DebianBanner ' "$cfg" || echo 'DebianBanner no' >> "$cfg"; log_info "SSH: DebianBanner -> no"
  sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$cfg"; grep -q '^ClientAliveInterval ' "$cfg" || echo 'ClientAliveInterval 300' >> "$cfg"
  sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' "$cfg"; grep -q '^ClientAliveCountMax ' "$cfg" || echo 'ClientAliveCountMax 2' >> "$cfg"; log_info "SSH: ClientAlive -> 300s interval, 2 max count"
  sed -i "s/^#*Port.*/Port ${SSH_PORT}/" "$cfg"; grep -q '^Port ' "$cfg" || sed -i "1s/^/Port ${SSH_PORT}\n/" "$cfg"; log_info "SSH: Port -> ${SSH_PORT}"
  if grep -q '^AllowUsers' "$cfg"; then
    if ! grep -q "^AllowUsers.*\b${ADMIN_USER}\b" "$cfg"; then
      sed -i "s/^AllowUsers.*/& ${ADMIN_USER}/" "$cfg"
      log_info "SSH: Added '${ADMIN_USER}' to existing AllowUsers"
    fi
  else
    echo "AllowUsers ${ADMIN_USER}" >> "$cfg"
    log_info "SSH: AllowUsers set to '${ADMIN_USER}'"
  fi
  disable_password_auth
}

# hardening_ssh() — головна функція SSH-модуля.
# Виконує backup sshd_config, запускає watchdog, застосовує hardening,
# перевіряє синтаксис через sshd -t і лише після цього перезапускає SSH.
hardening_ssh() {
  log_info "========================================"
  log_info "MODULE: SSH Hardening"
  log_info "========================================"
  local cfg="/etc/ssh/sshd_config"
  backup_config "$cfg"
  local backup_cfg=""
  [[ ${#BACKUP_FILES[@]} -gt 0 ]] && backup_cfg="${BACKUP_FILES[-1]}"
  local watchdog_pid=""
  if [[ "$DRY_RUN" != "true" ]]; then
    (
      sleep 60
      if cp -a "$backup_cfg" "$cfg"; then
        systemctl restart ssh || true
        logger -t "$SCRIPT_NAME" "[WARN] SSH config auto-reverted by Dead Man's Switch"
      fi
    ) &
    watchdog_pid=$!
    log_info "SSH: Dead Man's Switch watchdog started (PID ${watchdog_pid}, timeout 60s)"
  fi
  apply_ssh_hardening
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would run sshd -t and restart/reconfigure SSH socket if valid."
    log_info ""
    return 0
  fi
  if sshd -t >/dev/null 2>&1; then
    log_info "SSH: sshd -t syntax check PASSED"
    if [[ "$DRY_RUN" != "true" ]]; then
      if systemctl list-unit-files ssh.socket >/dev/null 2>&1; then
        configure_ssh_socket_port
      else
        systemctl restart ssh
      fi
      sleep 3
      if systemctl -q is-active ssh 2>/dev/null; then
        if [[ -n "$watchdog_pid" ]]; then
          kill "$watchdog_pid" 2>/dev/null || true
          log_info "SSH: Dead Man's Switch cancelled (PID ${watchdog_pid})"
        fi
        if ss -ltnp 2>/dev/null | grep -q ":${SSH_PORT} "; then
          log_info "SSH: ssh restarted and active on port ${SSH_PORT}"
        else
          log_error "SSH: expected listener on port ${SSH_PORT} was not found"
          return 1
        fi
      else
        log_error "SSH: ssh failed to stay active after restart"
        log_warn "SSH: watchdog will auto-revert config in remaining time"
        return 1
      fi
    fi
  else
    log_error "SSH: sshd -t syntax check FAILED — reverting immediately"
    [[ -n "$watchdog_pid" ]] && kill "$watchdog_pid" 2>/dev/null || true
    cp -a "$backup_cfg" "$cfg"
    systemctl restart ssh || true
    log_error "SSH: original config restored"
    return 1
  fi
  log_info "SSH hardening completed."
  log_info ""
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 11. HARDENING ВЕБ-СЕРВЕРА
# -----------------------------------------------------------------------------
# hardening_nginx() — вмикає базові безпечні налаштування Nginx.
hardening_nginx() {
  local cfg="/etc/nginx/nginx.conf" default_site="/etc/nginx/sites-available/default" snippets_dir="/etc/nginx/snippets"
  backup_config "$cfg"
  [[ -f "$default_site" ]] && backup_config "$default_site"
  if grep -q 'server_tokens' "$cfg"; then sed -i 's/.*server_tokens.*/\tserver_tokens off;/' "$cfg"; else sed -i '/http\s*{/a\\tserver_tokens off;' "$cfg"; fi
  log_info "Nginx: server_tokens off"
  mkdir -p "$snippets_dir"
  local has_tls=false
  if [[ -f "/etc/ssl/certs/ssl-cert-snakeoil.pem" || -d "/etc/letsencrypt/live" || -f "/etc/nginx/ssl/server.crt" ]]; then has_tls=true; log_info "Nginx: TLS certificate detected — HSTS will be enabled"; else log_warn "Nginx: No TLS certificate detected — HSTS will be DISABLED"; fi
  {
    echo 'add_header X-Frame-Options "SAMEORIGIN" always;'
    echo 'add_header X-Content-Type-Options "nosniff" always;'
    echo 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
    echo 'add_header Content-Security-Policy-Report-Only "default-src '\''self'\''" always;'
    echo 'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;'
    [[ "$has_tls" == "true" ]] && echo 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
  } > "${snippets_dir}/security-headers.conf"
  log_info "Nginx: security headers snippet created: ${snippets_dir}/security-headers.conf"
  if [[ -f "$default_site" ]]; then
    if ! grep -q 'security-headers' "$default_site"; then
      sed -i '/listen 80/a\\tinclude snippets/security-headers.conf;' "$default_site"
      log_info "Nginx: security-headers.conf included in default site"
    fi
    sed -i 's/autoindex on/autoindex off/g' "$default_site"
    log_info "Nginx: autoindex disabled"
  fi
  if nginx -t >/dev/null 2>&1; then
    log_info "Nginx: nginx -t syntax check PASSED"
    run_cmd systemctl reload nginx
    log_info "Nginx: reloaded successfully"
  else
    log_error "Nginx: syntax check FAILED — reverting"
    restore_all_backups
    return 1
  fi
}

# hardening_apache() — аналогічний модуль hardening для Apache2.
hardening_apache() {
  local security_cfg="/etc/apache2/conf-available/security.conf" apache_cfg="/etc/apache2/apache2.conf" headers_cfg="/etc/apache2/conf-available/security-headers.conf"
  [[ -f "$security_cfg" ]] && backup_config "$security_cfg"
  [[ -f "$apache_cfg" ]] && backup_config "$apache_cfg"
  if [[ -f "$security_cfg" ]]; then
    sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$security_cfg"
    sed -i 's/^ServerSignature.*/ServerSignature Off/' "$security_cfg"
    log_info "Apache: ServerTokens -> Prod, ServerSignature -> Off"
  fi
  cat > "$headers_cfg" <<'EOF'
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy-Report-Only "default-src 'self'"
Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
EOF
  log_info "Apache: security headers config created"
  run_cmd a2enmod headers
  run_cmd a2enconf security-headers
  if [[ -f "$apache_cfg" ]]; then
    sed -i 's/Options Indexes/Options -Indexes/g' "$apache_cfg"
    log_info "Apache: directory listing disabled (Options -Indexes)"
  fi
  if apache2ctl -t >/dev/null 2>&1; then
    log_info "Apache: syntax check PASSED"
    run_cmd systemctl reload apache2
    log_info "Apache: reloaded successfully"
  else
    log_error "Apache: syntax check FAILED — reverting"
    restore_all_backups
    return 1
  fi
}

hardening_webserver() {
  log_info "========================================"
  log_info "MODULE: Web Server Hardening (${WEB_SERVER})"
  log_info "========================================"
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would harden web server: ${WEB_SERVER}"
    return 0
  fi
  case "$WEB_SERVER" in
    nginx) hardening_nginx ;;
    apache2) hardening_apache ;;
    none) log_warn "No active web server detected. Skipping web server module." ;;
  esac
  log_info ""
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 12. HARDENING MySQL/MariaDB
# -----------------------------------------------------------------------------
# hardening_mysql() — обмежує мережеву доступність СУБД і прибирає небезпечні
# дефолтні елементи інсталяції.
hardening_mysql() {
  log_info "========================================"
  log_info "MODULE: MySQL/MariaDB Hardening"
  log_info "========================================"
  if [[ "$HAS_MYSQL" == "false" ]]; then log_info "MySQL/MariaDB not found. Skipping."; log_info ""; return 0; fi
  if [[ "$DRY_RUN" == "true" ]]; then log_info "[DRY-RUN] Would set bind-address = 127.0.0.1"; log_info "[DRY-RUN] Would remove anonymous users, test DB, remote root"; return 0; fi
  local mysql_cfg=""
  for candidate in /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/my.cnf; do [[ -f "$candidate" ]] && mysql_cfg="$candidate" && break; done
  if [[ -z "$mysql_cfg" ]]; then
    log_warn "MySQL config file not found. Skipping network hardening."
  else
    backup_config "$mysql_cfg"
    if grep -q '^bind-address' "$mysql_cfg"; then sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$mysql_cfg"; elif grep -q '^\[mysqld\]' "$mysql_cfg"; then sed -i '/^\[mysqld\]/a bind-address = 127.0.0.1' "$mysql_cfg"; else echo -e '\n[mysqld]\nbind-address = 127.0.0.1' >> "$mysql_cfg"; fi
    log_info "MySQL: bind-address set to 127.0.0.1"
    mysqld --validate-config >/dev/null 2>&1 && log_info "MySQL: config validation PASSED" || log_warn "MySQL: mysqld --validate-config returned non-zero (may be non-fatal)"
    run_cmd systemctl restart mysql || run_cmd systemctl restart mariadb || log_warn "Could not restart MySQL/MariaDB service"
  fi
  log_info "MySQL: running security initialization (mysql_secure_installation equivalent)..."
  if ! mysql -u root -e 'SELECT 1;' >/dev/null 2>&1; then
    log_warn "Cannot connect to MySQL as root without password."
    log_warn "Skipping SQL security init. Run mysql_secure_installation manually."
    log_info ""
    return 0
  fi
  mysql -u root <<'SQL'
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;
SQL
  log_info "MySQL: anonymous users removed"
  log_info "MySQL: remote root login blocked"
  log_info "MySQL: test database dropped"
  log_info "MySQL: privileges flushed"
  log_info "MySQL hardening completed."
  log_info ""
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 13. HARDENING FTP (vsftpd)
# -----------------------------------------------------------------------------
# provision_ftp_certificate() — забезпечує TLS-сертифікат для vsftpd.
# Якщо доступний Let's Encrypt — використовує його.
# Інакше створює self-signed для тестового середовища.
provision_ftp_certificate() {
  local cfg="$1" le_cert="" le_key=""
  if [[ -d /etc/letsencrypt/live ]]; then
    local domain
    domain="$(ls /etc/letsencrypt/live/ | head -1 || true)"
    if [[ -n "$domain" ]]; then
      le_cert="/etc/letsencrypt/live/${domain}/fullchain.pem"
      le_key="/etc/letsencrypt/live/${domain}/privkey.pem"
    fi
  fi
  if [[ -f "${le_cert:-}" && -f "${le_key:-}" ]]; then
    grep -q '^rsa_cert_file' "$cfg" && sed -i "s|^rsa_cert_file.*|rsa_cert_file=${le_cert}|" "$cfg" || echo "rsa_cert_file=${le_cert}" >> "$cfg"
    grep -q '^rsa_private_key_file' "$cfg" && sed -i "s|^rsa_private_key_file.*|rsa_private_key_file=${le_key}|" "$cfg" || echo "rsa_private_key_file=${le_key}" >> "$cfg"
    log_info "FTP: Using Let's Encrypt certificate: ${le_cert}"
  else
    local ssl_dir="/etc/ssl/vsftpd"
    mkdir -p "$ssl_dir"
    openssl req -new -x509 -days 365 -nodes -out "${ssl_dir}/vsftpd.pem" -keyout "${ssl_dir}/vsftpd.key" -subj "/CN=$(hostname -f)/O=Hardening/C=UA" >/dev/null 2>&1
    chmod 600 "${ssl_dir}/vsftpd.pem" "${ssl_dir}/vsftpd.key"
    grep -q '^rsa_cert_file' "$cfg" && sed -i "s|^rsa_cert_file.*|rsa_cert_file=${ssl_dir}/vsftpd.pem|" "$cfg" || echo "rsa_cert_file=${ssl_dir}/vsftpd.pem" >> "$cfg"
    grep -q '^rsa_private_key_file' "$cfg" && sed -i "s|^rsa_private_key_file.*|rsa_private_key_file=${ssl_dir}/vsftpd.key|" "$cfg" || echo "rsa_private_key_file=${ssl_dir}/vsftpd.key" >> "$cfg"
    log_warn "FTP: Self-signed certificate generated: ${ssl_dir}/vsftpd.pem"
    log_warn "FTP: Replace with a valid certificate for production!"
  fi
}

set_or_append_cfg() {
  local key="$1" value="$2" cfg="$3"
  if grep -q "^${key}=" "$cfg"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$cfg"
  else
    echo "${key}=${value}" >> "$cfg"
  fi
}

hardening_ftp() {
  log_info "========================================"
  log_info "MODULE: FTP (vsftpd) Hardening"
  log_info "========================================"
  if [[ "$HAS_VSFTPD" == "false" ]]; then log_info "vsftpd not found. Skipping FTP module."; log_info ""; return 0; fi
  if [[ "$DRY_RUN" == "true" ]]; then log_info "[DRY-RUN] Would enable FTPS, chroot, restrict PASV to 40000-40099"; return 0; fi
  local cfg="/etc/vsftpd.conf"
  backup_config "$cfg"
  set_or_append_cfg ssl_enable YES "$cfg"; log_info "FTP: ssl_enable=YES"
  set_or_append_cfg force_local_logins_ssl YES "$cfg"; set_or_append_cfg force_local_data_ssl YES "$cfg"; log_info "FTP: force_local_logins_ssl=YES, force_local_data_ssl=YES"
  set_or_append_cfg ssl_sslv2 NO "$cfg"; set_or_append_cfg ssl_sslv3 NO "$cfg"; set_or_append_cfg ssl_tlsv1 NO "$cfg"; set_or_append_cfg ssl_tlsv1_1 NO "$cfg"; set_or_append_cfg ssl_tlsv1_2 YES "$cfg"; log_info "FTP: SSLv2/v3 disabled, TLSv1.2 enabled"
  set_or_append_cfg chroot_local_user YES "$cfg"; log_info "FTP: chroot_local_user=YES"
  set_or_append_cfg allow_writeable_chroot YES "$cfg"; log_info "FTP: allow_writeable_chroot=YES"
  set_or_append_cfg xferlog_enable YES "$cfg"; set_or_append_cfg log_ftp_protocol YES "$cfg"; log_info "FTP: xferlog_enable=YES, log_ftp_protocol=YES (Repudiation countermeasure)"
  set_or_append_cfg pasv_min_port 40000 "$cfg"; set_or_append_cfg pasv_max_port 40099 "$cfg"; log_info "FTP: PASV range restricted to 40000-40099"
  provision_ftp_certificate "$cfg"
  run_cmd systemctl restart vsftpd
  if systemctl -q is-active vsftpd; then log_info "FTP: vsftpd restarted and active"; else log_error "FTP: vsftpd failed to start after configuration change"; return 1; fi
  log_info "FTP hardening completed."
  log_info ""
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 14. ПЕРИМЕТР: UFW + FAIL2BAN
# -----------------------------------------------------------------------------
# hardening_perimeter() — налаштовує firewall і базовий brute-force захист.
hardening_perimeter() {
  log_info "========================================"
  log_info "MODULE: Perimeter (UFW + Fail2Ban)"
  log_info "========================================"
  log_info "--- UFW Firewall ---"
  if [[ "$DRY_RUN" == "true" ]]; then
    if [[ "$RESET_UFW" == "true" ]]; then
      log_info "[DRY-RUN] Would reset UFW and allow SSH:${SSH_PORT}, HTTP, HTTPS, FTP as needed"
    else
      log_info "[DRY-RUN] Would preserve existing UFW rules and add SSH:${SSH_PORT}, HTTP, HTTPS, FTP as needed"
    fi
  else
    if [[ "$RESET_UFW" == "true" ]]; then
      ufw --force reset
      log_info "UFW: reset to clean state"
    else
      log_warn "UFW: preserving existing rules (--no-ufw-reset)"
    fi
    ufw default deny incoming
    ufw default allow outgoing
    log_info "UFW: default deny incoming, allow outgoing"
    ufw allow "${SSH_PORT}/tcp" comment 'SSH hardened'
    log_info "UFW: allowed SSH on port ${SSH_PORT}/tcp"
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    log_info "UFW: allowed HTTP (80/tcp) and HTTPS (443/tcp)"
    if [[ "$HAS_VSFTPD" == "true" ]]; then
      ufw allow 21/tcp comment 'FTP control'
      ufw allow 40000:40099/tcp comment 'FTP PASV range'
      log_info "UFW: allowed FTP (21/tcp) and PASV range (40000-40099/tcp)"
    fi
    ufw --force enable
    log_info "UFW: enabled and active"
    ufw status verbose | tee -a "$LOG_FILE" >/dev/null || true
  fi
  log_info "--- Fail2Ban ---"
  if [[ "$DRY_RUN" != "true" ]]; then
    local jail_dir="/etc/fail2ban/jail.d"
    local jail_file="${jail_dir}/hardening.local"
    mkdir -p "$jail_dir"
    [[ -f "$jail_file" ]] && backup_config "$jail_file"
    cat > "$jail_file" <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s

[vsftpd]
enabled = ${HAS_VSFTPD}
logpath = /var/log/vsftpd.log
EOF
    case "$WEB_SERVER" in
      nginx)
        cat >> "$jail_file" <<'EOF'
[nginx-http-auth]
enabled = true
EOF
        ;;
      apache2)
        cat >> "$jail_file" <<'EOF'
[apache-auth]
enabled = true
EOF
        ;;
      *)
        log_info "Fail2Ban: no web auth jail enabled because active web server is ${WEB_SERVER}"
        ;;
    esac
    log_info "Fail2Ban: ${jail_file} written"
    run_cmd systemctl enable fail2ban
    run_cmd systemctl restart fail2ban
    sleep 2
    if systemctl -q is-active fail2ban; then log_info "Fail2Ban: active and running"; else log_warn "Fail2Ban: service may not have started properly"; fi
  fi
  log_info "Perimeter hardening completed."
  log_info ""
}

apply_sshd_option() {
  local key="$1" value="$2" cfg="/etc/ssh/sshd_config"
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would set SSH option: ${key} ${value}"
    return 0
  fi
  if grep -Eq "^[#[:space:]]*${key}[[:space:]]+" "$cfg"; then
    sed -ri "s|^[#[:space:]]*(${key})[[:space:]]+.*|\\1 ${value}|" "$cfg"
  else
    printf "\n%s %s\n" "$key" "$value" >> "$cfg"
  fi
  log_info "SSH: ${key} -> ${value}"
}

apply_extra_ssh_policies() {
  log_info "========================================"
  log_info "MODULE: Extra SSH policies for Lynis"
  log_info "========================================"
  if [[ "$STRICT_SSH" != "true" ]]; then
    log_warn "Strict SSH extras disabled by --no-strict-ssh"
    log_info ""
    return 0
  fi
  apply_sshd_option "AllowTcpForwarding" "no"
  apply_sshd_option "LogLevel" "VERBOSE"
  apply_sshd_option "MaxSessions" "2"
  apply_sshd_option "TCPKeepAlive" "no"
  if [[ "$DRY_RUN" != "true" ]]; then
    if sshd -t >/dev/null 2>&1; then
      run_cmd systemctl restart ssh
      log_info "SSH: extra Lynis-oriented policies applied successfully"
    else
      log_error "SSH: syntax check failed after extra policies"
      return 1
    fi
  fi
  log_info ""
}

configure_login_defs_hardening() {
  log_info "========================================"
  log_info "MODULE: login.defs hardening"
  log_info "========================================"
  local cfg="/etc/login.defs"
  [[ -f "$cfg" ]] || { log_warn "${cfg} not found. Skipping."; log_info ""; return 0; }
  backup_config "$cfg"
  if [[ "$DRY_RUN" != "true" ]]; then
    if grep -Eq '^[#[:space:]]*UMASK[[:space:]]+' "$cfg"; then
      sed -ri 's|^[#[:space:]]*UMASK[[:space:]]+.*|UMASK 027|' "$cfg"
    else
      printf '\nUMASK 027\n' >> "$cfg"
    fi
    if grep -Eq '^[#[:space:]]*SHA_CRYPT_MIN_ROUNDS[[:space:]]+' "$cfg"; then
      sed -ri 's|^[#[:space:]]*SHA_CRYPT_MIN_ROUNDS[[:space:]]+.*|SHA_CRYPT_MIN_ROUNDS 10000|' "$cfg"
    else
      printf 'SHA_CRYPT_MIN_ROUNDS 10000\n' >> "$cfg"
    fi
    if grep -Eq '^[#[:space:]]*SHA_CRYPT_MAX_ROUNDS[[:space:]]+' "$cfg"; then
      sed -ri 's|^[#[:space:]]*SHA_CRYPT_MAX_ROUNDS[[:space:]]+.*|SHA_CRYPT_MAX_ROUNDS 100000|' "$cfg"
    else
      printf 'SHA_CRYPT_MAX_ROUNDS 100000\n' >> "$cfg"
    fi
  else
    log_info "[DRY-RUN] Would set UMASK 027 and SHA_CRYPT_* rounds in ${cfg}"
  fi
  log_info "login.defs hardening complete"
  log_info ""
}

configure_shell_timeout() {
  log_info "========================================"
  log_info "MODULE: Shell timeout policy"
  log_info "========================================"
  local cfg="/etc/profile.d/hardening-timeout.sh"
  if [[ "$DRY_RUN" == "true" ]]; then
    log_info "[DRY-RUN] Would create ${cfg} with TMOUT=900"
    log_info ""
    return 0
  fi
  cat > "$cfg" <<'EOF'
TMOUT=900
readonly TMOUT
export TMOUT
EOF
  chmod 644 "$cfg"
  log_info "Shell timeout policy created: ${cfg}"
  log_info ""
}

configure_malware_scanner() {
  log_info "========================================"
  log_info "MODULE: Malware scanner (rkhunter)"
  log_info "========================================"
  if [[ "$INSTALL_MALWARE_SCANNER" != "true" ]]; then
    log_warn "Malware scanner disabled by --no-malware-scanner"
    log_info ""
    return 0
  fi
  local cfg="/etc/rkhunter.conf"
  if [[ ! -f "$cfg" ]]; then
    log_warn "rkhunter config not found. Skipping initialization."
    log_info ""
    return 0
  fi
  backup_config "$cfg"
  if [[ "$DRY_RUN" != "true" ]]; then
    if grep -Eq '^[#[:space:]]*WEB_CMD=' "$cfg"; then
      sed -ri 's|^[#[:space:]]*WEB_CMD=.*|WEB_CMD=""|' "$cfg"
    else
      printf '\nWEB_CMD=""\n' >> "$cfg"
    fi
    rkhunter --update || log_warn "rkhunter update returned non-zero"
    rkhunter --propupd || log_warn "rkhunter property update returned non-zero"
  else
    log_info "[DRY-RUN] Would initialize rkhunter and update properties"
  fi
  log_info "Malware scanner module complete"
  log_info ""
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 15. ФІНАЛЬНИЙ ЗВІТ
# -----------------------------------------------------------------------------
# generate_report() — формує коротке текстове резюме виконаних змін.
generate_report() {
  log_info "========================================"
  log_info "HARDENING COMPLETE — Summary Report"
  log_info "========================================"
  cat <<EOF | tee -a "$LOG_FILE"

  ╔══════════════════════════════════════════════════════════╗
  ║           HARDENING REPORT — $(date '+%Y-%m-%d %H:%M:%S')           ║
  ╚══════════════════════════════════════════════════════════╝

  Script version : ${SCRIPT_VERSION}
  Log file       : ${LOG_FILE}
  Backup dir     : ${BACKUP_DIR}

  MODULES APPLIED:
  ─────────────────────────────────────────────────────────
  [✓] Package verification and installation
  [✓] SSH hardening
        Port        : ${SSH_PORT}
        PermitRoot  : no
        MaxAuthTries: 3
        MaxStartups : 10:30:100
        LoginGrace  : 20s
        DebianBanner: no
  [✓] Web server hardening (${WEB_SERVER})
        server_tokens off / ServerTokens Prod
        Security headers enabled
        Directory listing disabled
  [$( [[ "$HAS_MYSQL" == "true" ]] && echo '✓' || echo '-' )] MySQL/MariaDB hardening
  [$( [[ "$HAS_VSFTPD" == "true" ]] && echo '✓' || echo '-' )] FTP (vsftpd) hardening
  [✓] UFW firewall
  [✓] Fail2Ban

  IMPORTANT: SSH is now on port ${SSH_PORT}
  Test in a new terminal before closing this session:
  ssh -p ${SSH_PORT} ${ADMIN_USER}@<server-ip>

  Quick verification commands:
  ufw status verbose
  fail2ban-client status sshd
  ssh -p ${SSH_PORT} ${ADMIN_USER}@<server-ip>
EOF
}

# -----------------------------------------------------------------------------
# РОЗДІЛ 16. ГОЛОВНИЙ КЕРУЮЧИЙ ПОТІК
# -----------------------------------------------------------------------------
# main() — оркеструє весь процес hardening у безпечному порядку.
main() {
  parse_args "$@"
  validate_args
  check_root
  show_first_run_notice
  log_info "============================================================"
  log_info "  hardening.sh v${SCRIPT_VERSION} started"
  log_info "  $(date)"
  log_info "  DRY_RUN=${DRY_RUN}"
  log_info "  SSH_PORT=${SSH_PORT}"
  log_info "  RESET_UFW=${RESET_UFW}"
  log_info "  RUN_UPGRADE=${RUN_UPGRADE}"
  log_info "============================================================"
  log_info ""
  check_and_install_all_packages
  detect_environment
  ensure_admin_user
  prepare_admin_ssh_access
  hardening_ssh
  apply_extra_ssh_policies
  configure_login_defs_hardening
  configure_shell_timeout
  configure_malware_scanner
  hardening_webserver
  hardening_mysql
  hardening_ftp
  hardening_perimeter
  generate_report
}

main "$@"
