#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PROJECT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd)"
SERVICE_NAME="spdecode-telegram"
PYTHON="$PROJECT_DIR/.venv/bin/python"

run_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

lock_installation() {
    if [[ ! -O "$PROJECT_DIR" ]]; then
        echo "ERROR: run this command as the owner of the bot checkout at $PROJECT_DIR." >&2
        exit 2
    fi
    local git_dir
    git_dir="$(git -C "$PROJECT_DIR" rev-parse --absolute-git-dir)"
    exec 9>"$git_dir/spdecode-telegram.lock"
    if ! flock -n 9; then
        echo "ERROR: another bot maintenance command is running." >&2
        exit 1
    fi
}

configure_bot() (
    lock_installation
    exec 8</dev/tty
    if run_root systemctl is-active --quiet "$SERVICE_NAME"; then
        trap 'run_root systemctl start "$SERVICE_NAME"' EXIT
        run_root systemctl stop "$SERVICE_NAME"
    fi
    umask 077
    "$PYTHON" "$PROJECT_DIR/installers/configure.py" <&8
)

update_bot() (
    lock_installation
    cd "$PROJECT_DIR"
    if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
        echo "ERROR: commit or set aside your bot checkout changes before updating." >&2
        exit 1
    fi

    git fetch
    previous="$(git rev-parse HEAD)"
    target="$(git rev-parse '@{upstream}')"
    if [[ "$previous" == "$target" ]]; then
        echo "SP-DECODE Telegram is already up to date."
        exit 0
    fi
    if ! git merge-base --is-ancestor "$previous" "$target"; then
        echo "ERROR: the bot branch cannot be updated by fast-forward." >&2
        exit 1
    fi

    backup_dir="$(mktemp -d "$PROJECT_DIR/.telegram-update.XXXXXX")"
    was_active=0
    if run_root systemctl is-active --quiet "$SERVICE_NAME"; then
        was_active=1
    fi

    finish_update() {
        local status=$?
        local path restored=1
        if (( status != 0 )); then
            echo "Update failed. Restoring the previous bot version." >&2
            if (( was_active )) && ! run_root systemctl stop "$SERVICE_NAME"; then
                restored=0
            fi
            git reset --keep "$previous" || restored=0
            for path in .venv node_modules; do
                if [[ -d "$backup_dir/$path" ]]; then
                    rm -rf -- "$path" && mv -- "$backup_dir/$path" "$path" || restored=0
                fi
            done
            if (( ! restored )); then
                echo "ERROR: rollback incomplete. Update backups are in $backup_dir." >&2
                return "$status"
            fi
            if (( was_active )) && ! run_root systemctl start "$SERVICE_NAME"; then
                echo "ERROR: could not restart the previous version. Check spdecode-telegram logs." >&2
            fi
        fi
        rm -rf -- "$backup_dir"
        return "$status"
    }
    trap finish_update EXIT

    if (( was_active )); then
        run_root systemctl stop "$SERVICE_NAME"
    fi
    git merge --ff-only "$target"
    if ! git diff --quiet "$previous" "$target" -- requirements.txt; then
        mv -- .venv "$backup_dir/.venv"
        python3 -m venv .venv
        "$PYTHON" -m pip install -r requirements.txt
    fi
    if ! git diff --quiet "$previous" "$target" -- package.json package-lock.json; then
        mv -- node_modules "$backup_dir/node_modules"
        npm ci --omit=dev
    fi
    "$PYTHON" -c 'import main; main.validate_startup()'
    if (( was_active )); then
        run_root systemctl start "$SERVICE_NAME"
        run_root systemctl is-active --quiet "$SERVICE_NAME"
    fi
    echo "SP-DECODE Telegram updated to $(git rev-parse --short HEAD)."
)

case "${1:-status}" in
    start)
        run_root systemctl start "$SERVICE_NAME"
        run_root systemctl --no-pager --full status "$SERVICE_NAME"
        ;;
    stop)
        run_root systemctl stop "$SERVICE_NAME"
        ;;
    restart)
        run_root systemctl restart "$SERVICE_NAME"
        run_root systemctl --no-pager --full status "$SERVICE_NAME"
        ;;
    status)
        run_root systemctl --no-pager --full status "$SERVICE_NAME"
        ;;
    logs)
        run_root journalctl -u "$SERVICE_NAME" -n 100 -f
        ;;
    config|configure)
        configure_bot
        ;;
    update)
        update_bot
        ;;
    validate)
        cd "$PROJECT_DIR"
        "$PYTHON" validate_project.py
        "$PYTHON" -m unittest discover -s tests -v
        ;;
    *)
        echo "Usage: spdecode-telegram {start|stop|restart|status|logs|config|update|validate}"
        exit 2
        ;;
esac
