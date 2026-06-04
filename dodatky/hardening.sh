#!/usr/bin/env bash
# =============================================================================
# hardening.sh — Автоматизований hardening веб-сервера (Ubuntu 24.04 LTS)
# =============================================================================
# Версія : 1.0
# Цільова ОС : Ubuntu 24.04 LTS
# Стек     : SSH + Nginx/Apache + MySQL + vsftpd
#
# Використання:
#   sudo bash hardening.sh [--ssh-port PORT] [--dry-run]
#
# Опції:
#   --ssh-port PORT   Новий порт SSH (за замовчуванням: 2222)
#   --dry-run         Показати, що буде змінено, без внесення змін
#
# Що робить скрипт:
#   1. Перевіряє (і за потреби встановлює) необхідні пакети
#   2. Робить резервну копію усіх конфігурацій перед змінами
#   3. Захищає SSH (Dead Man's Switch, без root-входу, без паролів)
#   4. Захищає веб-сервер (nginx або apache2)
#   5. Захищає MySQL (тільки localhost, без анонімних користувачів)
#   6. Захищає FTP (FTPS, chroot, обмежений PASV-діапазон)
#   7. Налаштовує UFW (default deny) + Fail2Ban
#   8. Генерує фінальний звіт
# =============================================================================

# -----------------------------------------------------------------------------
# РОЗДІЛ 1. РЕЖИМ СУВОРОГО ВИКОНАННЯ
# -----------------------------------------------------------------------------
# set -E  — обробник ERR успадковується функціями (необхідно для trap ERR)
# set -e  — зупиняти скрипт при першій команді з ненульовим кодом виходу
# set -u  — вважати посилання на невизначену змінну помилкою
# set -o pipefail — якщо будь-яка команда в конвеєрі (|) зазнала невдачі,
#           весь конвеєр вважається невдалим (без цього cmd1 | cmd2 маскує
#           помилку cmd1, якщо cmd2 завершилась успішно)
set -Eeuo pipefail

# -----------------------------------------------------------------------------
# РОЗДІЛ 2. ГЛОБАЛЬНІ КОНСТАНТИ ТА ЗМІННІ
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_NAME="$(basename "$0")"

# Мітка часу запуску — використовується в іменах лог-файлів і бекапів
readonly RUN_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Лог-файл: один файл на запуск
readonly LOG_FILE="/var/log/hardening_${RUN_TIMESTAMP}.log"

# Директорія для резервних копій конфігурацій
readonly BACKUP_DIR="/var/backups/hardening_${RUN_TIMESTAMP}"

# Порт SSH за замовчуванням (може бути перевизначений через --ssh-port)
SSH_PORT="${SSH_PORT:-2222}"

# Режим "dry run": якщо true — тільки показувати дії, нічого не змінювати
DRY_RUN=false

# Результат визначення веб-сервера (заповнюється функцією detect_webserver)
WEB_SERVER="none"

# Прапор наявності vsftpd
HAS_VSFTPD=false

# Прапор наявності MySQL/MariaDB
HAS_MYSQL=false

# Список усіх створених резервних копій (для відкату при помилці)
declare -a BACKUP_FILES=()

# -----------------------------------------------------------------------------
# РОЗДІЛ 3. ЖУРНАЛЮВАННЯ
# -----------------------------------------------------------------------------

# Функція log — виводить повідомлення в термінал і записує в лог-файл.
# Аргументи: $1 — текст повідомлення, $2 — рівень (INFO/WARN/ERROR), default INFO
log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Кольорове виведення в термінал (ANSI-коди; вимикаються при перенаправленні)
    local color=""
    local reset="\033[0m"
    if [[ -t 1 ]]; then
        case "$level" in
            INFO)  color="\033[0;32m" ;;   # зелений
            WARN)  color="\033[0;33m" ;;   # жовтий
            ERROR) color="\033[0;31m" ;;   # червоний
            *)     color="" ;;
        esac
    fi

    # Вивід у термінал з кольором
    printf "${color}[%s] [%-5s]  %s${reset}\n" "$timestamp" "$level" "$message" >&2

    # Вивід у лог-файл без кольорових кодів (якщо файл вже існує/доступний)
    if [[ -w "$(dirname "$LOG_FILE")" ]] || [[ -f "$LOG_FILE" ]]; then
        printf "[%s] [%-5s]  %s\n" "$timestamp" "$level" "$message" >> "$LOG_FILE"
    fi

    # Дублювання в системний syslog через logger
    logger -t "$SCRIPT_NAME" "[${level}] ${message}" 2>/dev/null || true
}

# Скорочення для рівнів
log_info()  { log "$1" "INFO"; }
log_warn()  { log "$1" "WARN"; }
log_error() { log "$1" "ERROR"; }

# -----------------------------------------------------------------------------
# РОЗДІЛ 4. ОБРОБКА ПОМИЛОК ТА ВІДКАТ
# -----------------------------------------------------------------------------

# restore_all_backups — відновлює усі зроблені резервні копії.
# Викликається обробником помилок або вручну у разі потреби.
restore_all_backups() {
    if [[ ${#BACKUP_FILES[@]} -eq 0 ]]; then
        log_warn "No backups to restore."
        return 0
    fi

    log_warn "Restoring all backed-up configurations..."
    for backup in "${BACKUP_FILES[@]}"; do
        # Ім'я оригінального файлу: відрізаємо суфікс .bak.TIMESTAMP
        local original="${backup%.bak.*}"
        if [[ -f "$backup" ]]; then
            cp -a "$backup" "$original"
            log_warn "Restored: $original (from $backup)"
        fi
    done
}

# cleanup_on_error — обробник trap ERR.
# Отримує номер рядка, де стався збій, фіксує це в журналі,
# намагається відновити бекапи і завершує скрипт із початковим кодом виходу.
cleanup_on_error() {
    local exit_code=$?
    local line_number="${1:-unknown}"
    log_error "Script failed at line ${line_number} with exit code ${exit_code}"
    log_error "Attempting to restore all backups..."
    restore_all_backups
    log_error "Hardening aborted. Review ${LOG_FILE} for details."
    exit "$exit_code"
}

# Реєстрація обробника: при будь-якій помилці (ненульовий exit code) — cleanup.
# $LINENO автоматично підставляється bash у момент спрацювання trap.
trap 'cleanup_on_error $LINENO' ERR

# Обробник виходу: повідомляє про завершення (успішне або ні)
trap_exit() {
    local code=$?
    if [[ $code -eq 0 ]]; then
        log_info "hardening.sh completed successfully. Log: ${LOG_FILE}"
    fi
}
trap 'trap_exit' EXIT

# -----------------------------------------------------------------------------
# РОЗДІЛ 5. ДОПОМІЖНІ ФУНКЦІЇ
# -----------------------------------------------------------------------------

# check_root — перевіряє наявність root-прав. Без root більшість операцій
# hardening-у неможлива (зміна системних конфігурацій, перезапуск служб тощо).
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo bash ${SCRIPT_NAME}"
        exit 1
    fi
}

# parse_args — розбирає аргументи командного рядка
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ssh-port)
                SSH_PORT="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                cat <<EOF
Usage: sudo bash ${SCRIPT_NAME} [OPTIONS]

Options:
  --ssh-port PORT   New SSH port (default: 2222)
  --dry-run         Show planned changes without applying them
  -h, --help        Show this help

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                exit 1
                ;;
        esac
    done
}

# run_cmd — виконує команду або лише виводить її (у dry-run режимі).
# Використання: run_cmd systemctl restart nginx
run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would execute: $*"
    else
        "$@"
    fi
}

# backup_config — робить резервну копію файлу перед змінами.
# Копія зберігається у BACKUP_DIR із оригінальним іменем + .bak.TIMESTAMP
# Прапор -a зберігає оригінальні права доступу, власника і мітки часу.
backup_config() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_warn "Backup skipped: file not found: $file"
        return 0
    fi

    # Створюємо директорію бекапів при першому виклику
    mkdir -p "$BACKUP_DIR"

    # Ім'я бекапу: /var/backups/hardening_TIMESTAMP/etc_ssh_sshd_config.bak
    local safe_name
    safe_name="$(echo "$file" | tr '/' '_').bak.${RUN_TIMESTAMP}"
    local backup_path="${BACKUP_DIR}/${safe_name}"

    cp -a "$file" "$backup_path"
    # Додаємо шлях до бекапу в масив для можливого відкату
    BACKUP_FILES+=("${backup_path}")
    log_info "Backup created: ${backup_path}"
}

# =============================================================================
# РОЗДІЛ 6. ПЕРЕВІРКА ТА ВСТАНОВЛЕННЯ НЕОБХІДНИХ ПАКЕТІВ
# =============================================================================
# Цей розділ є першим кроком після ініціалізації: скрипт перевіряє наявність
# кожного необхідного пакета і встановлює відсутні. Це гарантує, що всі
# наступні модулі hardening-у матимуть необхідні інструменти та сервіси.

# check_and_install_package — перевіряє наявність пакета через dpkg.
# Якщо пакет відсутній — встановлює його через apt-get.
# Аргументи: $1 — ім'я пакета, $2 (опц.) — ім'я бінарного файлу для перевірки
check_and_install_package() {
    local pkg="$1"
    local bin="${2:-}"   # бінарний файл/команда (якщо відрізняється від імені пакета)

    # Перевірка через dpkg: якщо пакет встановлений — ii означає "installed"
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        log_info "Package already installed: ${pkg}"
        return 0
    fi

    # Якщо вказано бінарний файл — додаткова перевірка через command -v
    if [[ -n "$bin" ]] && command -v "$bin" &>/dev/null; then
        log_info "Binary '${bin}' found, skipping package install: ${pkg}"
        return 0
    fi

    log_info "Package not found: ${pkg}. Installing..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would run: apt-get install -y ${pkg}"
        return 0
    fi

    # DEBIAN_FRONTEND=noninteractive: вимикає інтерактивні підказки debconf
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" \
        || { log_error "Failed to install package: ${pkg}"; return 1; }

    log_info "Package installed successfully: ${pkg}"
}

# check_and_install_all_packages — головна функція перевірки пакетів.
# Визначає, який веб-сервер потрібен (nginx чи apache2), і встановлює
# лише необхідні пакети, уникаючи конфліктів між nginx та apache2.
check_and_install_all_packages() {
    log_info "========================================"
    log_info "MODULE: Package verification & install"
    log_info "========================================"

    # Оновлення кешу apt (виконується один раз перед усіма встановленнями)
    log_info "Refreshing apt package cache..."
    if [[ "$DRY_RUN" != "true" ]]; then
        apt-get update -qq \
            || log_warn "apt-get update returned non-zero; continuing anyway."
    fi

    # ------------------------------------------------------------------
    # 6.1. SSH (openssh-server)
    # ------------------------------------------------------------------
    # openssh-server надає демон sshd, необхідний для hardening SSH.
    # Пакет openssh-client — це SSH-клієнт, він нас не цікавить як сервіс.
    log_info "--- Checking SSH ---"
    check_and_install_package "openssh-server" "sshd"

    # ------------------------------------------------------------------
    # 6.2. Веб-сервер (nginx або apache2)
    # ------------------------------------------------------------------
    # Логіка: якщо apache2 вже встановлений — використовуємо його.
    # Якщо nginx вже встановлений — використовуємо його.
    # Якщо жоден не встановлений — встановлюємо nginx як дефолт.
    # Встановлення обох одночасно уникається, бо вони конфліктують на порту 80.
    log_info "--- Checking web server ---"
    local apache_installed=false
    local nginx_installed=false

    dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -q "install ok installed" \
        && apache_installed=true
    dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -q "install ok installed" \
        && nginx_installed=true

    if [[ "$apache_installed" == "true" ]] && [[ "$nginx_installed" == "true" ]]; then
        # Обидва встановлені — залишаємо як є, detect_webserver вирішить активний
        log_warn "Both nginx and apache2 are installed. Will use whichever is active."
    elif [[ "$apache_installed" == "true" ]]; then
        log_info "apache2 is already installed."
    elif [[ "$nginx_installed" == "true" ]]; then
        log_info "nginx is already installed."
    else
        # Нічого не встановлено — ставимо nginx
        log_info "No web server found. Installing nginx..."
        check_and_install_package "nginx" "nginx"
    fi

    # ------------------------------------------------------------------
    # 6.3. MySQL / MariaDB
    # ------------------------------------------------------------------
    # Перевіряємо обидва варіанти: mysql-server (оригінальний MySQL)
    # та mariadb-server (сумісна заміна, часто дефолтна на Ubuntu 24.04).
    log_info "--- Checking MySQL/MariaDB ---"
    local mysql_pkg_installed=false

    if dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -q "install ok installed"; then
        log_info "mysql-server is already installed."
        mysql_pkg_installed=true
    elif dpkg-query -W -f='${Status}' mariadb-server 2>/dev/null | grep -q "install ok installed"; then
        log_info "mariadb-server is already installed."
        mysql_pkg_installed=true
    fi

    if [[ "$mysql_pkg_installed" == "false" ]]; then
        log_info "No MySQL/MariaDB found. Installing mariadb-server..."
        check_and_install_package "mariadb-server" "mysql"
    fi

    # ------------------------------------------------------------------
    # 6.4. FTP (vsftpd)
    # ------------------------------------------------------------------
    # vsftpd — Very Secure FTP Daemon, стандартний FTP-сервер для Ubuntu.
    # Встановлюємо лише якщо адміністратор явно підтвердить потребу,
    # оскільки FTP є застарілим протоколом і не завжди потрібен.
    log_info "--- Checking FTP (vsftpd) ---"
    if dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q "install ok installed"; then
        log_info "vsftpd is already installed."
    else
        log_warn "vsftpd is not installed."
        # Запитуємо підтвердження в інтерактивному режимі
        if [[ -t 0 ]] && [[ "$DRY_RUN" != "true" ]]; then
            read -rp "Install vsftpd (FTP server)? [y/N]: " answer
            if [[ "${answer,,}" == "y" ]]; then
                check_and_install_package "vsftpd" "vsftpd"
            else
                log_info "vsftpd installation skipped. FTP hardening module will be disabled."
            fi
        else
            log_info "Non-interactive mode: vsftpd installation skipped."
        fi
    fi

    # ------------------------------------------------------------------
    # 6.5. Інструменти периметра (ufw, fail2ban)
    # ------------------------------------------------------------------
    log_info "--- Checking perimeter tools (ufw, fail2ban) ---"
    check_and_install_package "ufw" "ufw"
    check_and_install_package "fail2ban" "fail2ban-server"

    # ------------------------------------------------------------------
    # 6.6. Системні утиліти (openssl, curl — для генерації сертифікатів)
    # ------------------------------------------------------------------
    log_info "--- Checking auxiliary tools ---"
    check_and_install_package "openssl" "openssl"

    log_info "Package verification complete."
    log_info ""
}

# =============================================================================
# РОЗДІЛ 7. ВИЗНАЧЕННЯ СЕРЕДОВИЩА
# =============================================================================

# detect_webserver — визначає активний веб-сервер через systemctl.
# systemctl is-active повертає код 0, якщо сервіс запущений.
# Повертає рядок: "nginx", "apache2" або "none".
detect_webserver() {
    if systemctl -q is-active nginx 2>/dev/null; then
        echo "nginx"
    elif systemctl -q is-active apache2 2>/dev/null; then
        echo "apache2"
    elif dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -q "install ok installed"; then
        # Встановлений але не запущений — спробуємо запустити
        systemctl start nginx 2>/dev/null && echo "nginx" || echo "none"
    elif dpkg-query -W -f='${Status}' apache2 2>/dev/null | grep -q "install ok installed"; then
        systemctl start apache2 2>/dev/null && echo "apache2" || echo "none"
    else
        echo "none"
    fi
}

# detect_environment — визначає весь стан системи та заповнює глобальні змінні.
detect_environment() {
    log_info "========================================"
    log_info "MODULE: Environment detection"
    log_info "========================================"

    # Веб-сервер
    WEB_SERVER="$(detect_webserver)"
    log_info "Active web server: ${WEB_SERVER}"

    # vsftpd
    if systemctl -q is-active vsftpd 2>/dev/null || \
       dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q "install ok installed"; then
        HAS_VSFTPD=true
        log_info "vsftpd: present"
    else
        log_info "vsftpd: not found (FTP module will be skipped)"
    fi

    # MySQL / MariaDB
    if systemctl -q is-active mysql 2>/dev/null || \
       systemctl -q is-active mariadb 2>/dev/null || \
       command -v mysql &>/dev/null; then
        HAS_MYSQL=true
        log_info "MySQL/MariaDB: present"
    else
        log_info "MySQL/MariaDB: not found (MySQL module will be skipped)"
    fi

    # Визначаємо користувача-адміністратора (той, хто запустив sudo)
    ADMIN_USER="${SUDO_USER:-${USER:-root}}"
    log_info "Admin user (for AllowUsers SSH): ${ADMIN_USER}"

    log_info ""
}

# =============================================================================
# РОЗДІЛ 8. HARDENING SSH
# =============================================================================
# Найвідповідальніший модуль: помилка тут може закрити доступ до сервера.
# Захищений Dead Man's Switch — watchdog-процесом, що автоматично відкатує
# конфігурацію через 60 секунд, якщо основний потік не скасував його явно.

# disable_password_auth — вимикає парольну автентифікацію SSH.
# ВАЖЛИВО: виконується лише якщо в системі знайдено хоча б один SSH-ключ.
# Без цієї перевірки адміністратор може заблокувати сам себе.
disable_password_auth() {
    local cfg="/etc/ssh/sshd_config"
    local has_keys=false

    # Перевіряємо authorized_keys для всіх системних користувачів з UID >= 1000
    # і для root (UID = 0)
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ "$uid" -ge 1000 ]] || [[ "$username" == "root" ]]; then
            local auth_keys="${home}/.ssh/authorized_keys"
            if [[ -s "$auth_keys" ]]; then
                has_keys=true
                log_info "SSH key found for user: ${username} (${auth_keys})"
                break
            fi
        fi
    done < /etc/passwd

    if [[ "$has_keys" == "false" ]]; then
        log_warn "No SSH authorized_keys found. Generating SSH key pair for ${ADMIN_USER}..."

        # Визначаємо домашню директорію адміністратора
        local admin_home
        admin_home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
        if [[ -z "$admin_home" ]]; then
            log_warn "Cannot determine home directory for ${ADMIN_USER}. Skipping key generation."
            log_warn "Action required: add your SSH public key manually, then re-run this module."
            return 0
        fi

        local ssh_dir="${admin_home}/.ssh"
        local key_file="${ssh_dir}/id_ed25519_hardening"

        # Створюємо директорію .ssh з правильними правами доступу
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"

        # Генеруємо пару ключів Ed25519 (без пароля для сумісності з автоматизацією).
        # Ed25519 обраний як сучасний стандарт: менший розмір, вища швидкість,
        # криптографічно стійкіший ніж RSA-2048.
        ssh-keygen -t ed25519 \
            -f "$key_file" \
            -N "" \
            -C "hardening-${ADMIN_USER}-$(date +%Y%m%d)" \
            2>/dev/null

        # Додаємо публічний ключ до authorized_keys
        cat "${key_file}.pub" >> "${ssh_dir}/authorized_keys"
        chmod 600 "${ssh_dir}/authorized_keys"

        # Встановлюємо власника (важливо якщо скрипт запущений від root, а ADMIN_USER — інший)
        local admin_group
        admin_group="$(id -gn "$ADMIN_USER" 2>/dev/null || echo "$ADMIN_USER")"
        chown -R "${ADMIN_USER}:${admin_group}" "$ssh_dir"

        # Зберігаємо копію приватного ключа у /root для зручного вилучення.
        # Права 600 — тільки root може прочитати.
        local key_export="/root/hardening_private_key_${RUN_TIMESTAMP}.pem"
        cp "$key_file" "$key_export"
        chmod 600 "$key_export"

        # Виводимо інструкції та вміст приватного ключа в термінал.
        # УВАГА: поточна SSH-сесія залишається активною навіть після перезапуску sshd,
        # тому ключ можна скопіювати з цього терміналу до закриття сесії.
        log_warn "========================================================"
        log_warn "  SSH KEY GENERATED — COPY PRIVATE KEY BEFORE PROCEEDING"
        log_warn "========================================================"
        log_warn "Private key also saved to: ${key_export}"
        log_warn ""
        log_warn "Option 1 — copy-paste from this terminal:"
        log_warn "  Select the key block below and save it locally as:"
        log_warn "  ~/.ssh/id_ed25519_server   (chmod 600)"
        log_warn ""
        log_warn "Option 2 — SCP from your local machine (open a NEW terminal NOW,"
        log_warn "  before password auth is disabled):"
        log_warn "  scp -P 22 root@<server-ip>:${key_export} ~/.ssh/id_ed25519_server"
        log_warn "  chmod 600 ~/.ssh/id_ed25519_server"
        log_warn ""
        log_warn "After saving, delete from server:"
        log_warn "  rm ${key_export}"
        log_warn "========================================================"
        # Виводимо вміст ключа напряму в термінал (без запису в лог-файл)
        printf '\n--- BEGIN PRIVATE KEY (copy everything between the markers) ---\n' >&2
        cat "$key_file" >&2
        printf '--- END PRIVATE KEY ---\n\n' >&2
        log_warn "========================================================"

        log_info "SSH key generated and added to authorized_keys for: ${ADMIN_USER}"
        has_keys=true
    fi

    # Знаходимо рядок незалежно від того, прокоментований він чи ні
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$cfg"
    log_info "SSH: PasswordAuthentication disabled (SSH keys confirmed present)"
}

# apply_ssh_hardening — застосовує всі директиви безпеки до sshd_config
apply_ssh_hardening() {
    local cfg="/etc/ssh/sshd_config"

    log_info "Applying SSH hardening directives..."

    # PermitRootLogin no — забороняє прямий вхід під root.
    # Навіть якщо зловмисник знає пароль root, він не зможе авторизуватися напряму.
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$cfg"
    log_info "SSH: PermitRootLogin -> no"

    # MaxAuthTries 3 — максимум 3 спроби автентифікації в рамках одного з'єднання.
    # Уповільнює brute-force: після 3 невдач SSH закриває з'єднання.
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$cfg"
    log_info "SSH: MaxAuthTries -> 3"

    # LoginGraceTime 20 — 20 секунд на автентифікацію (замість дефолтних 120).
    # Зменшує вікно для CVE-2024-6387 (regreSSHion) та атак типу "hold connection".
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 20/' "$cfg"
    log_info "SSH: LoginGraceTime -> 20"

    # X11Forwarding no — вимикає пробросування графіки через SSH.
    # На серверах без графічного інтерфейсу X11 — зайва поверхня атаки.
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$cfg"
    log_info "SSH: X11Forwarding -> no"

    # AllowAgentForwarding no — вимикає транзитивне використання SSH-ключів.
    # При компрометації проміжного сервера ключі не можуть бути "перенесені" далі.
    sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/' "$cfg"
    log_info "SSH: AllowAgentForwarding -> no"

    # ClientAliveInterval 300 + ClientAliveCountMax 2 — keepalive-механізм.
    # Якщо клієнт не відповідає 300 с і ігнорує 2 перевірки — з'єднання закривається.
    # Звільняє ресурси від "завислих" сесій.
    sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$cfg"
    sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' "$cfg"
    log_info "SSH: ClientAlive -> 300s interval, 2 max count"

    # Зміна порту SSH з дефолтного 22 на нестандартний.
    # Не є криптографічним захистом, але ефективно фільтрує 90%+ автоматизованих
    # сканерів, що перевіряють лише стандартний порт 22.
    sed -i "s/^#*Port.*/Port ${SSH_PORT}/" "$cfg"
    # Якщо рядок Port взагалі відсутній — додаємо на початок файлу
    grep -q "^Port " "$cfg" || sed -i "1s/^/Port ${SSH_PORT}\n/" "$cfg"
    log_info "SSH: Port -> ${SSH_PORT}"

    # AllowUsers — білий список: тільки явно вказані користувачі можуть входити.
    # Усі системні облікові записи (www-data, mysql тощо) автоматично блокуються.
    if grep -q "^AllowUsers" "$cfg"; then
        # Рядок вже є — перевіряємо, чи наш користувач включений
        if ! grep -q "^AllowUsers.*${ADMIN_USER}" "$cfg"; then
            sed -i "s/^AllowUsers.*/& ${ADMIN_USER}/" "$cfg"
            log_info "SSH: Added '${ADMIN_USER}' to existing AllowUsers"
        fi
    else
        echo "AllowUsers ${ADMIN_USER}" >> "$cfg"
        log_info "SSH: AllowUsers set to '${ADMIN_USER}'"
    fi

    # Безпечне вимкнення парольної автентифікації (з перевіркою наявності ключів)
    disable_password_auth
}

# hardening_ssh — головна функція SSH-модуля.
# Реалізує Dead Man's Switch: watchdog-процес автоматично відкатує конфіг
# через 60 секунд, якщо основний процес не скасував його явно.
hardening_ssh() {
    log_info "========================================"
    log_info "MODULE: SSH Hardening"
    log_info "========================================"

    local cfg="/etc/ssh/sshd_config"
    backup_config "$cfg"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would apply SSH hardening directives"
        log_info "[DRY-RUN] Would change SSH port to ${SSH_PORT}"
        return 0
    fi

    # ----- DEAD MAN'S SWITCH -----
    # Watchdog-процес запускається у фоні ДО внесення змін.
    # Через 60 секунд він автоматично відновить оригінальний конфіг і
    # перезапустить sshd — навіть якщо основний процес скрипта зависне або впаде.
    # Скасувати watchdog можна тільки через явний kill після успішної перевірки.
    local backup_cfg
    backup_cfg="${BACKUP_DIR}/$(echo "$cfg" | tr '/' '_').bak.${RUN_TIMESTAMP}"

    (
        sleep 60
        if cp -a "$backup_cfg" "$cfg" && systemctl restart sshd; then
            logger -t "hardening.sh" "[WARN] SSH config auto-reverted by Dead Man's Switch"
        fi
    ) &
    local watchdog_pid=$!
    log_info "SSH: Dead Man's Switch watchdog started (PID ${watchdog_pid}, timeout 60s)"

    # Вносимо зміни
    apply_ssh_hardening

    # Синтаксична перевірка ПЕРЕД перезапуском
    if sshd -t 2>/dev/null; then
        log_info "SSH: sshd -t syntax check PASSED"

        # Перезапускаємо SSH
        systemctl restart sshd

        # Невелика пауза для стабілізації
        sleep 3

        if systemctl -q is-active sshd 2>/dev/null; then
            # Усе добре — скасовуємо watchdog
            kill "$watchdog_pid" 2>/dev/null || true
            log_info "SSH: Dead Man's Switch cancelled (PID ${watchdog_pid})"
            log_info "SSH: sshd restarted and active on port ${SSH_PORT}"
        else
            log_error "SSH: sshd failed to stay active after restart"
            log_warn "SSH: watchdog will auto-revert config in remaining time"
            # Не скасовуємо watchdog — він відкатить конфіг
        fi
    else
        # Синтаксична помилка — негайний відкат без очікування watchdog
        log_error "SSH: sshd -t syntax check FAILED — reverting immediately"
        kill "$watchdog_pid" 2>/dev/null || true
        cp -a "$backup_cfg" "$cfg"
        systemctl restart sshd || true
        log_error "SSH: original config restored"
        return 1
    fi

    log_info "SSH hardening completed."
    log_info ""
}

# =============================================================================
# РОЗДІЛ 9. HARDENING ВЕБ-СЕРВЕРА
# =============================================================================

# hardening_nginx — hardening для Nginx
hardening_nginx() {
    local cfg="/etc/nginx/nginx.conf"
    local default_site="/etc/nginx/sites-available/default"
    local snippets_dir="/etc/nginx/snippets"

    backup_config "$cfg"
    [[ -f "$default_site" ]] && backup_config "$default_site"

    # ---- server_tokens off ----
    # За замовчуванням Nginx повідомляє точну версію у заголовку Server
    # і на сторінках помилок (наприклад: nginx/1.24.0).
    # server_tokens off залишає лише рядок "nginx" без версії.
    # grep-guard для ідемпотентності: не додаємо вдруге якщо вже є
    if grep -q 'server_tokens' "$cfg"; then
        sed -i 's/.*server_tokens.*/\tserver_tokens off;/' "$cfg"
    else
        # Додаємо всередину блоку http {}
        sed -i '/http\s*{/a\\tserver_tokens off;' "$cfg"
    fi
    log_info "Nginx: server_tokens off"

    # ---- Security Headers через snippets ----
    # Виносимо заголовки в окремий файл-сніпет, щоб підключати його
    # в будь-якому server{} блоці без дублювання.
    mkdir -p "$snippets_dir"
    cat > "${snippets_dir}/security-headers.conf" << 'NGINX_HEADERS'
# Захист від clickjacking: забороняє вбудовування у <iframe> зі сторонніх сайтів
add_header X-Frame-Options "SAMEORIGIN" always;

# Забороняє браузеру самостійно визначати MIME-тип (MIME sniffing)
add_header X-Content-Type-Options "nosniff" always;

# Контролює витік URL у заголовку Referer при зовнішніх переходах
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# CSP у режимі Report-Only: не блокує, але фіксує порушення.
# Змініть на Content-Security-Policy після налаштування під ваш застосунок.
add_header Content-Security-Policy-Report-Only "default-src 'self'" always;

# Забороняє доступ браузера до геолокації, камери та мікрофона
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
NGINX_HEADERS
    log_info "Nginx: security headers snippet created: ${snippets_dir}/security-headers.conf"

    # Підключення сніпета в дефолтний server block
    if [[ -f "$default_site" ]]; then
        # grep-guard: не додаємо двічі
        if ! grep -q 'security-headers' "$default_site"; then
            sed -i '/listen 80/a\\tinclude snippets/security-headers.conf;' "$default_site"
            log_info "Nginx: security-headers.conf included in default site"
        fi

        # ---- autoindex off ----
        # Вимикає автоматичне відображення вмісту директорії.
        # Без index-файлу Nginx поверне 403 замість списку файлів.
        sed -i 's/autoindex on/autoindex off/g' "$default_site"
        log_info "Nginx: autoindex disabled"
    fi

    # Синтаксична перевірка та перезавантаження (reload, не restart — без downtime)
    if nginx -t 2>/dev/null; then
        log_info "Nginx: nginx -t syntax check PASSED"
        run_cmd systemctl reload nginx
        log_info "Nginx: reloaded successfully"
    else
        log_error "Nginx: syntax check FAILED — reverting"
        restore_all_backups
        return 1
    fi
}

# hardening_apache — hardening для Apache2
hardening_apache() {
    local security_cfg="/etc/apache2/conf-available/security.conf"
    local apache_cfg="/etc/apache2/apache2.conf"

    [[ -f "$security_cfg" ]] && backup_config "$security_cfg"
    [[ -f "$apache_cfg" ]]   && backup_config "$apache_cfg"

    # ---- ServerTokens Prod ----
    # За замовчуванням Apache повідомляє ОС, дистрибутив і встановлені модулі
    # у заголовку Server (наприклад: Apache/2.4.58 (Ubuntu)).
    # ServerTokens Prod залишає лише рядок "Apache".
    if [[ -f "$security_cfg" ]]; then
        sed -i 's/^ServerTokens.*/ServerTokens Prod/'     "$security_cfg"
        sed -i 's/^ServerSignature.*/ServerSignature Off/' "$security_cfg"
        log_info "Apache: ServerTokens -> Prod, ServerSignature -> Off"
    fi

    # ---- Security Headers ----
    local headers_cfg="/etc/apache2/conf-available/security-headers.conf"
    cat > "$headers_cfg" << 'APACHE_HEADERS'
# Захист від clickjacking
Header always set X-Frame-Options "SAMEORIGIN"

# Захист від MIME sniffing
Header always set X-Content-Type-Options "nosniff"

# Контроль витоку Referer
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# CSP у режимі Report-Only
Header always set Content-Security-Policy-Report-Only "default-src 'self'"

# Обмеження браузерних API
Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
APACHE_HEADERS
    log_info "Apache: security headers config created"

    # Активуємо модуль headers та нову конфігурацію
    run_cmd a2enmod headers
    run_cmd a2enconf security-headers

    # ---- Options -Indexes ----
    # Вимикаємо директорійний лістинг глобально
    if [[ -f "$apache_cfg" ]]; then
        sed -i 's/Options Indexes/Options -Indexes/g' "$apache_cfg"
        log_info "Apache: directory listing disabled (Options -Indexes)"
    fi

    # Синтаксична перевірка
    if apache2ctl -t 2>/dev/null; then
        log_info "Apache: syntax check PASSED"
        run_cmd systemctl reload apache2
        log_info "Apache: reloaded successfully"
    else
        log_error "Apache: syntax check FAILED — reverting"
        restore_all_backups
        return 1
    fi
}

# hardening_webserver — диспетчер модуля веб-сервера
hardening_webserver() {
    log_info "========================================"
    log_info "MODULE: Web Server Hardening (${WEB_SERVER})"
    log_info "========================================"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would harden web server: ${WEB_SERVER}"
        return 0
    fi

    case "$WEB_SERVER" in
        nginx)   hardening_nginx ;;
        apache2) hardening_apache ;;
        none)
            log_warn "No active web server detected. Skipping web server module."
            ;;
    esac

    log_info ""
}

# =============================================================================
# РОЗДІЛ 10. HARDENING MySQL
# =============================================================================

# hardening_mysql — hardening бази даних MySQL/MariaDB.
# Два незалежних класи проблем:
#   1. Мережева доступність: MySQL не повинна слухати на зовнішньому інтерфейсі
#   2. Небезпечний стан після інсталяції: анонімні користувачі, тестова БД
hardening_mysql() {
    log_info "========================================"
    log_info "MODULE: MySQL/MariaDB Hardening"
    log_info "========================================"

    if [[ "$HAS_MYSQL" == "false" ]]; then
        log_info "MySQL/MariaDB not found. Skipping."
        log_info ""
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would set bind-address = 127.0.0.1"
        log_info "[DRY-RUN] Would remove anonymous users, test DB, remote root"
        return 0
    fi

    # Визначаємо правильний конфігураційний файл (різний для MySQL та MariaDB)
    local mysql_cfg=""
    for candidate in \
        "/etc/mysql/mysql.conf.d/mysqld.cnf" \
        "/etc/mysql/mariadb.conf.d/50-server.cnf" \
        "/etc/mysql/my.cnf"; do
        if [[ -f "$candidate" ]]; then
            mysql_cfg="$candidate"
            break
        fi
    done

    if [[ -z "$mysql_cfg" ]]; then
        log_warn "MySQL config file not found. Skipping network hardening."
    else
        backup_config "$mysql_cfg"

        # ---- bind-address = 127.0.0.1 ----
        # MySQL слухатиме ЛИШЕ на loopback-інтерфейсі.
        # Для веб-застосунків на тій самій машині це жодних обмежень не створює:
        # PHP/Python/Node.js підключаються через localhost і продовжують працювати.
        # Зате зовнішній порт 3306 стає недоступним без жодних правил файрволу.
        if grep -q "^bind-address" "$mysql_cfg"; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$mysql_cfg"
        elif grep -q "^\[mysqld\]" "$mysql_cfg"; then
            sed -i '/^\[mysqld\]/a bind-address = 127.0.0.1' "$mysql_cfg"
        else
            echo -e "\n[mysqld]\nbind-address = 127.0.0.1" >> "$mysql_cfg"
        fi
        log_info "MySQL: bind-address set to 127.0.0.1"

        # Валідація конфігурації перед перезапуском
        if mysqld --validate-config 2>/dev/null; then
            log_info "MySQL: config validation PASSED"
        else
            log_warn "MySQL: mysqld --validate-config returned non-zero (may be non-fatal)"
        fi

        run_cmd systemctl restart mysql 2>/dev/null || \
        run_cmd systemctl restart mariadb 2>/dev/null || \
            log_warn "Could not restart MySQL/MariaDB service"
    fi

    # ---- Програмний еквівалент mysql_secure_installation ----
    # mysql_secure_installation — інтерактивна утиліта, яку не можна викликати
    # в автоматизованому скрипті. Виконуємо ті самі SQL-операції напряму.

    log_info "MySQL: running security initialization (mysql_secure_installation equivalent)..."

    # Перевіряємо, чи MySQL доступна
    if ! mysql -u root -e "SELECT 1;" &>/dev/null; then
        log_warn "Cannot connect to MySQL as root without password."
        log_warn "Skipping SQL security init. Run mysql_secure_installation manually."
        log_info ""
        return 0
    fi

    # Видалення анонімних користувачів (User='').
    # Анонімний обліковий запис дозволяє підключитись без імені і пароля —
    # це вразливість у будь-якому продуктивному середовищі.
    mysql -u root << 'SQL'
DELETE FROM mysql.user WHERE User='';
SQL
    log_info "MySQL: anonymous users removed"

    # Заборона root-входу з будь-якого хоста, крім localhost/127.0.0.1/::1.
    # Навіть якщо root-пароль MySQL стане відомим — підключитися ззовні неможливо.
    mysql -u root << 'SQL'
DELETE FROM mysql.user
WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
SQL
    log_info "MySQL: remote root login blocked"

    # Видалення тестової бази даних.
    # База test із публічними дозволами на запис дозволяє будь-якому локальному
    # процесу записувати дані в MySQL без автентифікації.
    mysql -u root << 'SQL'
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
SQL
    log_info "MySQL: test database dropped"

    # Застосування всіх змін у таблицях привілеїв без перезапуску
    mysql -u root -e "FLUSH PRIVILEGES;" 2>/dev/null
    log_info "MySQL: privileges flushed"

    log_info "MySQL hardening completed."
    log_info ""
}

# =============================================================================
# РОЗДІЛ 11. HARDENING FTP (vsftpd)
# =============================================================================

# provision_ftp_certificate — забезпечує наявність TLS-сертифіката для vsftpd.
# Пріоритет: 1) існуючий Let's Encrypt, 2) генерація self-signed
provision_ftp_certificate() {
    local cfg="$1"

    # Шукаємо Let's Encrypt сертифікат
    local le_cert="" le_key=""
    if [[ -d "/etc/letsencrypt/live" ]]; then
        local domain
        domain="$(ls /etc/letsencrypt/live/ | head -1)"
        if [[ -n "$domain" ]]; then
            le_cert="/etc/letsencrypt/live/${domain}/fullchain.pem"
            le_key="/etc/letsencrypt/live/${domain}/privkey.pem"
        fi
    fi

    if [[ -f "${le_cert:-}" ]] && [[ -f "${le_key:-}" ]]; then
        # Використовуємо Let's Encrypt
        grep -q "^rsa_cert_file" "$cfg" \
            && sed -i "s|^rsa_cert_file.*|rsa_cert_file=${le_cert}|" "$cfg" \
            || echo "rsa_cert_file=${le_cert}" >> "$cfg"

        grep -q "^rsa_private_key_file" "$cfg" \
            && sed -i "s|^rsa_private_key_file.*|rsa_private_key_file=${le_key}|" "$cfg" \
            || echo "rsa_private_key_file=${le_key}" >> "$cfg"

        log_info "FTP: Using Let's Encrypt certificate: ${le_cert}"
    else
        # Генеруємо self-signed сертифікат (лише для тестового середовища)
        local ssl_dir="/etc/ssl/vsftpd"
        mkdir -p "$ssl_dir"

        openssl req -new -x509 -days 365 -nodes \
            -out "${ssl_dir}/vsftpd.pem" \
            -keyout "${ssl_dir}/vsftpd.key" \
            -subj "/CN=$(hostname -f)/O=Hardening/C=UA" \
            2>/dev/null

        grep -q "^rsa_cert_file" "$cfg" \
            && sed -i "s|^rsa_cert_file.*|rsa_cert_file=${ssl_dir}/vsftpd.pem|" "$cfg" \
            || echo "rsa_cert_file=${ssl_dir}/vsftpd.pem" >> "$cfg"

        grep -q "^rsa_private_key_file" "$cfg" \
            && sed -i "s|^rsa_private_key_file.*|rsa_private_key_file=${ssl_dir}/vsftpd.key|" "$cfg" \
            || echo "rsa_private_key_file=${ssl_dir}/vsftpd.key" >> "$cfg"

        log_warn "FTP: Self-signed certificate generated: ${ssl_dir}/vsftpd.pem"
        log_warn "FTP: Replace with a valid certificate for production!"
    fi
}

# hardening_ftp — hardening vsftpd
hardening_ftp() {
    log_info "========================================"
    log_info "MODULE: FTP (vsftpd) Hardening"
    log_info "========================================"

    if [[ "$HAS_VSFTPD" == "false" ]]; then
        log_info "vsftpd not found. Skipping FTP module."
        log_info ""
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would enable FTPS, chroot, restrict PASV to 40000-40099"
        return 0
    fi

    local cfg="/etc/vsftpd.conf"
    backup_config "$cfg"

    # ---- Увімкнення TLS (FTPS) ----
    # FTP без шифрування передає логін і пароль відкритим текстом.
    # ssl_enable=YES дозволяє TLS-з'єднання.
    sed -i 's/^#*ssl_enable.*/ssl_enable=YES/' "$cfg"
    log_info "FTP: ssl_enable=YES"

    # force_local_logins_ssl і force_local_data_ssl роблять TLS ОБОВ'ЯЗКОВИМ.
    # Без них TLS лише дозволений, але клієнт може підключитися без шифрування.
    sed -i 's/^#*force_local_logins_ssl.*/force_local_logins_ssl=YES/' "$cfg"
    sed -i 's/^#*force_local_data_ssl.*/force_local_data_ssl=YES/'     "$cfg"
    log_info "FTP: force_local_logins_ssl=YES, force_local_data_ssl=YES"

    # Вимикаємо застарілі протоколи SSLv2/SSLv3, лишаємо TLS 1.2+
    sed -i 's/^#*ssl_sslv2.*/ssl_sslv2=NO/'   "$cfg"
    sed -i 's/^#*ssl_sslv3.*/ssl_sslv3=NO/'   "$cfg"
    sed -i 's/^#*ssl_tlsv1_2.*/ssl_tlsv1_2=YES/' "$cfg"
    log_info "FTP: SSLv2/v3 disabled, TLSv1.2 enabled"

    # ---- chroot ізоляція ----
    # chroot_local_user=YES: кожен FTP-користувач бачить свою домашню директорію
    # як корінь файлової системи. Вийти за її межі неможливо.
    # Захищає від навмисного або випадкового доступу до системних файлів.
    sed -i 's/^#*chroot_local_user.*/chroot_local_user=YES/' "$cfg"
    log_info "FTP: chroot_local_user=YES"

    # allow_writeable_chroot=YES: необхідно для коректної роботи chroot,
    # якщо домашня директорія доступна для запису (типова ситуація для веб-хостингу)
    grep -q "^allow_writeable_chroot" "$cfg" \
        || echo "allow_writeable_chroot=YES" >> "$cfg"
    log_info "FTP: allow_writeable_chroot=YES"

    # ---- Детальне журналювання (контрзахід: Repudiation у матриці STRIDE) ----
    # xferlog_enable=YES: записує журнал усіх передач файлів (стандарт wu-ftpd).
    # log_ftp_protocol=YES: записує всі FTP-команди сесії (USER, PASS, RETR, STOR тощо).
    # Без цих директив vsftpd фіксує лише факт з'єднання, але не конкретні дії —
    # що унеможливлює ретроспективний аналіз після інциденту (Repudiation-загроза).
    sed -i 's/^#*xferlog_enable.*/xferlog_enable=YES/' "$cfg"
    grep -q "^xferlog_enable" "$cfg" || echo "xferlog_enable=YES" >> "$cfg"
    sed -i 's/^#*log_ftp_protocol.*/log_ftp_protocol=YES/' "$cfg"
    grep -q "^log_ftp_protocol" "$cfg" || echo "log_ftp_protocol=YES" >> "$cfg"
    log_info "FTP: xferlog_enable=YES, log_ftp_protocol=YES (Repudiation countermeasure)"

    # ---- Обмеження пасивного порт-діапазону ----
    # FTP у PASV-режимі відкриває динамічні порти для передачі даних.
    # Обмежуємо до 100 конкретних портів — це дозволяє точно налаштувати UFW.
    grep -q "^pasv_min_port" "$cfg" \
        || echo "pasv_min_port=40000" >> "$cfg"
    grep -q "^pasv_max_port" "$cfg" \
        || echo "pasv_max_port=40099" >> "$cfg"
    log_info "FTP: PASV range restricted to 40000-40099"

    # ---- TLS-сертифікат ----
    provision_ftp_certificate "$cfg"

    # Перезапуск vsftpd
    run_cmd systemctl restart vsftpd
    if systemctl -q is-active vsftpd; then
        log_info "FTP: vsftpd restarted and active"
    else
        log_error "FTP: vsftpd failed to start after configuration change"
        return 1
    fi

    log_info "FTP hardening completed."
    log_info ""
}

# =============================================================================
# РОЗДІЛ 12. ПЕРИМЕТР: UFW + FAIL2BAN
# =============================================================================

# hardening_ufw — налаштовує файрвол UFW (Uncomplicated Firewall)
hardening_ufw() {
    log_info "--- UFW Firewall ---"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would reset UFW and apply default deny + allow SSH:${SSH_PORT}, HTTP, HTTPS"
        return 0
    fi

    # ufw --force reset — скидає всі попередні правила.
    # Забезпечує передбачуваний стан незалежно від того, що було до нас.
    # --force відключає інтерактивне підтвердження для роботи в скрипті.
    ufw --force reset
    log_info "UFW: reset to clean state"

    # Стратегія "default deny incoming":
    # Забороняємо все вхідне і дозволяємо лише явно вказані порти.
    # Принципова відмінність від "default allow": кожен новий порт залишається
    # закритим до явного рішення адміністратора.
    ufw default deny incoming
    ufw default allow outgoing
    log_info "UFW: default deny incoming, allow outgoing"

    # SSH на нестандартному порті
    ufw allow "${SSH_PORT}/tcp" comment 'SSH hardened'
    log_info "UFW: allowed SSH on port ${SSH_PORT}/tcp"

    # HTTP і HTTPS — основний трафік веб-сервера
    ufw allow 80/tcp   comment 'HTTP'
    ufw allow 443/tcp  comment 'HTTPS'
    log_info "UFW: allowed HTTP (80/tcp) and HTTPS (443/tcp)"

    # FTP і PASV-діапазон — лише якщо vsftpd встановлений і активний
    if [[ "$HAS_VSFTPD" == "true" ]]; then
        ufw allow 21/tcp           comment 'FTP control'
        ufw allow 40000:40099/tcp  comment 'FTP PASV range'
        log_info "UFW: allowed FTP (21/tcp) and PASV range (40000-40099/tcp)"
    fi

    # Порт MySQL 3306 свідомо НЕ відкривається:
    # після hardening MySQL слухає лише на localhost (127.0.0.1),
    # тому зовнішній трафік до 3306 є підозрілим і небажаним.

    # Активуємо UFW
    ufw --force enable
    log_info "UFW: enabled and active"
    ufw status verbose | tee -a "$LOG_FILE"
}

# hardening_fail2ban — налаштовує Fail2Ban для динамічного блокування атак
hardening_fail2ban() {
    log_info "--- Fail2Ban ---"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would configure Fail2Ban jail.local for SSH, FTP, web"
        return 0
    fi

    local jail_local="/etc/fail2ban/jail.local"

    # Бекап якщо файл вже існує
    [[ -f "$jail_local" ]] && backup_config "$jail_local"

    # jail.local перевизначає значення з jail.conf.
    # Пряма зміна jail.conf — погана практика: оновлення пакета перезапишіть його.
    # Значення за замовчуванням [DEFAULT] застосовуються до всіх jail-ів.
    cat > "$jail_local" << EOF
[DEFAULT]
# Час блокування IP: 1 година (3600 секунд)
bantime  = 3600

# Часове вікно для підрахунку спроб: 10 хвилин (600 секунд)
findtime = 600

# Кількість невдалих спроб до блокування
maxretry = 5

# backend = systemd: читаємо логи через journald (рекомендовано для Ubuntu 24.04)
# Systemd є основним механізмом логування, текстові файли /var/log можуть бути вторинними
backend  = systemd

[sshd]
# Захист SSH від brute-force атак
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
# %(sshd_log)s — змінна Fail2Ban, автоматично вирішується в правильний шлях
# до лог-файлу SSH залежно від дистрибутива (Ubuntu 24.04: /var/log/auth.log)
logpath  = %(sshd_log)s
maxretry = 5
findtime = 600
bantime  = 3600

[vsftpd]
# Захист FTP від brute-force атак
enabled  = $(if [[ "$HAS_VSFTPD" == "true" ]]; then echo "true"; else echo "false"; fi)
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = %(vsftpd_log)s
maxretry = 5
findtime = 600
bantime  = 3600

[nginx-http-auth]
# Захист Nginx від brute-force HTTP-автентифікації та сканерів
enabled  = $(if [[ "$WEB_SERVER" == "nginx" ]]; then echo "true"; else echo "false"; fi)
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 600
bantime  = 1800

[apache-auth]
# Захист Apache від brute-force HTTP-автентифікації
enabled  = $(if [[ "$WEB_SERVER" == "apache2" ]]; then echo "true"; else echo "false"; fi)
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/error.log
maxretry = 10
findtime = 600
bantime  = 1800
EOF

    log_info "Fail2Ban: jail.local written"

    # Увімкнення та перезапуск Fail2Ban
    run_cmd systemctl enable fail2ban
    run_cmd systemctl restart fail2ban

    sleep 2
    if systemctl -q is-active fail2ban; then
        log_info "Fail2Ban: active and running"
    else
        log_warn "Fail2Ban: service may not have started properly"
    fi
}

# hardening_perimeter — головна функція модуля периметра
hardening_perimeter() {
    log_info "========================================"
    log_info "MODULE: Perimeter (UFW + Fail2Ban)"
    log_info "========================================"

    hardening_ufw
    hardening_fail2ban

    log_info "Perimeter hardening completed."
    log_info ""
}

# =============================================================================
# РОЗДІЛ 13. ФІНАЛЬНИЙ ЗВІТ
# =============================================================================

# generate_report — виводить підсумок усіх виконаних дій
generate_report() {
    log_info "========================================"
    log_info "HARDENING COMPLETE — Summary Report"
    log_info "========================================"

    cat << EOF | tee -a "$LOG_FILE"

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
        LoginGrace  : 20s
  [✓] Web server hardening (${WEB_SERVER})
        server_tokens off
        Security headers (X-Frame, XCTO, CSP-RO, RP, PP)
        Directory listing disabled
  [$(if [[ "$HAS_MYSQL" == "true" ]]; then echo "✓"; else echo "-"; fi)] MySQL/MariaDB hardening
        bind-address: 127.0.0.1
        Anonymous users removed
        Remote root blocked
        Test DB dropped
  [$(if [[ "$HAS_VSFTPD" == "true" ]]; then echo "✓"; else echo "-"; fi)] FTP (vsftpd) hardening
        FTPS (TLS) enabled
        chroot isolation enabled
        PASV range: 40000-40099
        xferlog + log_ftp_protocol enabled
  [✓] UFW firewall
        Default: deny incoming
        Open: SSH:${SSH_PORT}, HTTP:80, HTTPS:443$(if [[ "$HAS_VSFTPD" == "true" ]]; then echo ", FTP:21+PASV"; fi)
  [✓] Fail2Ban
        Jails: SSH$(if [[ "$HAS_VSFTPD" == "true" ]]; then echo ", FTP"; fi)$(if [[ "$WEB_SERVER" != "none" ]]; then echo ", ${WEB_SERVER}"; fi)

  ─────────────────────────────────────────────────────────
  IMPORTANT: SSH is now on port ${SSH_PORT}
  Update your SSH client configuration and any existing
  connections to use the new port!

  Next steps:
  1. Open a NEW terminal and test SSH connection BEFORE
     closing this session:
     ssh -p ${SSH_PORT} ${ADMIN_USER}@<server-ip>
  2. Run Lynis audit to measure the hardening score:
     sudo lynis audit system
  3. Review the log file for any warnings:
     ${LOG_FILE}
  ─────────────────────────────────────────────────────────

EOF
}

# =============================================================================
# РОЗДІЛ 14. ТОЧКА ВХОДУ (main)
# =============================================================================

main() {
    # Парсимо аргументи командного рядка
    parse_args "$@"

    # Перевіряємо root-права
    check_root

    # Ініціалізуємо лог-файл
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"   # лог може містити чутливу інформацію — тільки root

    log_info "============================================================"
    log_info "  hardening.sh v${SCRIPT_VERSION} started"
    log_info "  $(date)"
    log_info "  DRY_RUN=${DRY_RUN}"
    log_info "  SSH_PORT=${SSH_PORT}"
    log_info "============================================================"
    log_info ""

    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "DRY-RUN MODE: No changes will be made to the system"
        log_warn ""
    fi

    # ── Крок 1: Перевірка та встановлення пакетів ──
    check_and_install_all_packages

    # ── Крок 2: Визначення середовища ──
    detect_environment

    # ── Крок 3: Hardening SSH (найризикованіший модуль — виконується першим) ──
    hardening_ssh

    # ── Крок 4: Hardening веб-сервера ──
    hardening_webserver

    # ── Крок 5: Hardening MySQL ──
    hardening_mysql

    # ── Крок 6: Hardening FTP ──
    hardening_ftp

    # ── Крок 7: Периметр (UFW + Fail2Ban) ──
    hardening_perimeter

    # ── Крок 8: Фінальний звіт ──
    generate_report
}

# Викликаємо main і передаємо всі аргументи скрипта
main "$@"
