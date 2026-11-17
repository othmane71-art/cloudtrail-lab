#!/usr/bin/env bash
# Fonctions communes (a "sourcer" depuis les autres scripts). Executer DANS le conteneur lab.
LAB_ENDPOINT="${LAB_ENDPOINT:-http://floci:4566}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-eu-west-3}"
export AWS_PAGER=""
LOG_BUCKET="corp-cloudtrail-logs-synthetic"

# aws_ = AWS CLI pointe sur l'emulateur local (JAMAIS sur le vrai AWS)
aws_() { aws --endpoint-url "$LAB_ENDPOINT" "$@"; }
say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
ko()   { printf '\033[1;31m[KO]\033[0m %s\n' "$*"; }

# Garde-fou : refuse de tourner si le point d'acces n'est pas local
case "$LAB_ENDPOINT" in
  http://floci:*|http://localhost:*|http://127.0.0.1:*) ;;
  *) echo "Point d'acces non local ($LAB_ENDPOINT) : arret par securite."; exit 1;;
esac