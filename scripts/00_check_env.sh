#!/usr/bin/env bash
# 00_check_env.sh - Verifie l'environnement Floci (carte reel / emule / synthetique).
# Execution (dans le conteneur) :  bash scripts/00_check_env.sh
source "$(dirname "$0")/lib.sh"

say "Attente du point d'acces AWS local : $LAB_ENDPOINT"
for i in $(seq 1 30); do
  if aws_ sts get-caller-identity >/dev/null 2>&1; then ok "Point d'acces joignable (essai $i)"; break; fi
  sleep 2
  [ "$i" = 30 ] && { ko "Injoignable. Verifiez : docker compose logs floci"; exit 1; }
done

say "Identite (factice) vue par l'emulateur"
aws_ sts get-caller-identity

say "Etat de Floci (/_floci/health)"
if curl -sf "$LAB_ENDPOINT/_floci/health" >/tmp/health.json 2>/dev/null; then
  echo "  version : $(jq -r '.version' /tmp/health.json)"
  for s in s3 iam cloudtrail; do
    echo "  $s : $(jq -r --arg s "$s" '.services[$s] // "absent"' /tmp/health.json)"
  done
else
  warn "Endpoint /_floci/health injoignable."
fi

say "Test des fonctionnalites utilisees par le TP"
aws_ s3api list-buckets >/dev/null 2>&1 && ok "S3  : disponible" || ko "S3  : indisponible"
aws_ iam list-users     >/dev/null 2>&1 && ok "IAM : disponible" || ko "IAM : indisponible"

if aws_ cloudtrail describe-trails >/tmp/ct.out 2>&1; then
  ok "CloudTrail : EMULE par Floci (pas le vrai AWS)."
  warn "Les logs de generate_events.py restent SYNTHETIQUES."
else
  ko "CloudTrail : indisponible. $(head -c 300 /tmp/ct.out | tr '\n' ' ')"
fi