#!/usr/bin/env python3
"""
entra_log_parser.py

Outil de parsing et de recherche dans les fichiers d'export de logs Entra ID
(Azure AD) au format JSON exportés depuis le portail Azure ou via Microsoft Graph.

Types de logs gérés :
    - ApplicationSignIns_*.json   (connexions applicatives / service principals)
    - InteractiveSignIns_*.json   (connexions interactives utilisateur)
    - NonInteractiveSignIns_*.json(connexions non interactives)
    - AuditLogs_*.json            (journaux d'audit)

Le format d'un export est soit un tableau JSON [ {...}, {...} ], soit un objet
Graph { "value": [ {...} ] }, soit du JSON Lines (un objet par ligne). Les trois
cas sont gérés automatiquement.

Exemples d'utilisation :

    # Afficher un résumé statistique d'un ou plusieurs fichiers
    python3 entra_log_parser.py InteractiveSignIns_2026-09-14_2026-10-14.json --stats

    # Chercher toutes les connexions en échec pour un utilisateur
    python3 entra_log_parser.py InteractiveSignIns_*.json \
        --search userPrincipalName=jdupont --search status.errorCode!=0

    # Chercher les connexions depuis un pays, sur une période, format tableau
    python3 entra_log_parser.py *SignIns*.json \
        --search location.countryOrRegion=FR \
        --from 2026-10-01 --to 2026-10-14 \
        --field createdDateTime --field userPrincipalName --field ipAddress

    # Rechercher dans les logs d'audit par activité (regex)
    python3 entra_log_parser.py AuditLogs_2026-10-14.json \
        --search activityDisplayName=".*password.*" --regex --format json

    # Lister les champs disponibles pour construire ses recherches
    python3 entra_log_parser.py AuditLogs_2026-10-14.json --list-fields
"""

import argparse
import glob
import json
import re
import sys
from datetime import datetime, timezone


# --- Champs de date utilisés par chaque type de log (du plus au moins prioritaire)
CHAMPS_DATE = [
    "createdDateTime",      # SignIns
    "activityDateTime",     # AuditLogs
    "eventDateTime",
    "timeStamp",
]

# --- Opérateurs de comparaison acceptés dans --search (ordre important : ">=" avant "=")
OPERATEURS = ["!=", ">=", "<=", "=", ">", "<", "~"]


def _est_numerique(valeur):
    """Indique si une valeur peut être interprétée comme un nombre."""
    try:
        float(valeur)
        return True
    except (TypeError, ValueError):
        return False


class EntraLog:
    """Représente un ensemble de records de logs Entra ID chargés depuis un ou
    plusieurs fichiers JSON, avec des méthodes de recherche et de statistique."""

    def __init__(self):
        self.records = []

    # ------------------------------------------------------------------ chargement
    def charger(self, chemin):
        """Charge un fichier d'export et ajoute ses records à la collection.
        Gère le format tableau, le format Graph {"value": [...]} et le JSON Lines."""
        with open(chemin, "r", encoding="utf-8-sig") as f:
            contenu = f.read()

        records = self._decoder(contenu, chemin)

        # on garde une trace du fichier d'origine pour chaque record
        source = chemin.split("/")[-1]
        for r in records:
            if isinstance(r, dict):
                r.setdefault("_source", source)
                self.records.append(r)

        print(f"[+] {len(records):>6} records chargés depuis {source}", file=sys.stderr)
        return len(records)

    @staticmethod
    def _decoder(contenu, chemin):
        """Décode le contenu brut en liste de records, quel que soit le format."""
        contenu = contenu.strip()
        if not contenu:
            return []

        # 1) JSON standard (tableau ou objet Graph)
        try:
            data = json.loads(contenu)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                # format Microsoft Graph : {"value": [...]}
                if isinstance(data.get("value"), list):
                    return data["value"]
                # un objet unique
                return [data]
        except json.JSONDecodeError:
            pass

        # 2) JSON Lines (un objet JSON par ligne)
        records = []
        for num, ligne in enumerate(contenu.splitlines(), 1):
            ligne = ligne.strip().rstrip(",")
            if not ligne or ligne in ("[", "]"):
                continue
            try:
                records.append(json.loads(ligne))
            except json.JSONDecodeError:
                print(f"[!] {chemin}: ligne {num} ignorée (JSON invalide)", file=sys.stderr)
        return records

    # ------------------------------------------------------------------ accès champs
    @staticmethod
    def resoudre(record, chemin):
        """Résout un chemin en notation pointée (ex: 'status.errorCode' ou
        'location.countryOrRegion') et renvoie la LISTE des valeurs trouvées.
        Traverse automatiquement les listes (ex: 'targetResources.displayName'
        renvoie les valeurs de tous les éléments du tableau)."""
        valeurs = [record]
        for cle in chemin.split("."):
            suivantes = []
            for v in valeurs:
                if isinstance(v, dict) and cle in v:
                    suivantes.append(v[cle])
                elif isinstance(v, list):
                    # on applique la clé à chaque élément de la liste
                    for elem in v:
                        if isinstance(elem, dict) and cle in elem:
                            suivantes.append(elem[cle])
            valeurs = suivantes
            if not valeurs:
                return []
        return valeurs

    @classmethod
    def date_record(cls, record):
        """Renvoie la date (datetime tz-aware) d'un record, ou None si absente."""
        for champ in CHAMPS_DATE:
            vals = cls.resoudre(record, champ)
            if vals:
                dt = cls._parse_date(vals[0])
                if dt:
                    return dt
        return None

    @staticmethod
    def _parse_date(valeur):
        """Parse une date ISO 8601 (format Entra, ex: 2026-10-14T08:21:33Z)."""
        if not isinstance(valeur, str):
            return None
        txt = valeur.strip().replace("Z", "+00:00")
        # on tronque les fractions de seconde trop longues (> 6 chiffres)
        txt = re.sub(r"(\.\d{6})\d+", r"\1", txt)
        try:
            dt = datetime.fromisoformat(txt)
        except ValueError:
            # repli : on tente juste la partie date
            try:
                dt = datetime.fromisoformat(valeur.strip()[:10])
            except ValueError:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    # ------------------------------------------------------------------ recherche
    def filtrer(self, criteres, regex=False, dt_from=None, dt_to=None):
        """Renvoie les records qui satisfont TOUS les critères et la fenêtre de date.
        Chaque critère est un tuple (chemin, operateur, valeur)."""
        resultat = []
        for r in self.records:
            if dt_from or dt_to:
                d = self.date_record(r)
                if d is None:
                    continue
                if dt_from and d < dt_from:
                    continue
                if dt_to and d > dt_to:
                    continue
            if all(self._critere_ok(r, c, regex) for c in criteres):
                resultat.append(r)
        return resultat

    @classmethod
    def _critere_ok(cls, record, critere, regex):
        """Teste un critère (chemin, operateur, attendu) sur un record."""
        chemin, operateur, attendu = critere
        valeurs = cls.resoudre(record, chemin)
        if not valeurs:
            # un champ absent ne satisfait qu'un test de non-égalité
            return operateur == "!="

        # un record matche si AU MOINS une valeur du chemin satisfait le critère
        return any(cls._comparer(v, operateur, attendu, regex) for v in valeurs)

    @staticmethod
    def _comparer(valeur, operateur, attendu, regex):
        """Compare une valeur unique à la valeur attendue selon l'opérateur."""
        # opérateurs numériques
        if operateur in (">", "<", ">=", "<="):
            try:
                a, b = float(valeur), float(attendu)
            except (TypeError, ValueError):
                return False
            return {">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[operateur]

        texte = "" if valeur is None else str(valeur)

        # opérateur regex explicite
        if operateur == "~" or regex:
            try:
                trouve = re.search(attendu, texte, re.IGNORECASE) is not None
            except re.error:
                trouve = attendu.lower() in texte.lower()
        elif _est_numerique(attendu) and _est_numerique(texte):
            # deux nombres : égalité exacte (évite que "0" matche "50126")
            trouve = float(texte) == float(attendu)
        else:
            # égalité = correspondance de sous-chaîne, insensible à la casse
            trouve = attendu.lower() in texte.lower()

        return not trouve if operateur == "!=" else trouve

    # ------------------------------------------------------------------ statistiques
    def statistiques(self):
        """Affiche un résumé statistique de la collection chargée."""
        total = len(self.records)
        print(f"\n=== STATISTIQUES ({total} records) ===\n")
        if not total:
            return

        # fenêtre temporelle couverte
        dates = [d for d in (self.date_record(r) for r in self.records) if d]
        if dates:
            print(f"Période : {min(dates).isoformat()}  ->  {max(dates).isoformat()}\n")

        self._top("Source (fichier)", "_source")
        self._top("Utilisateur (userPrincipalName)", "userPrincipalName")
        self._top("Application (appDisplayName)", "appDisplayName")
        self._top("Adresse IP (ipAddress)", "ipAddress")
        self._top("Pays (location.countryOrRegion)", "location.countryOrRegion")
        self._top("Code erreur (status.errorCode)", "status.errorCode")
        self._top("Activité audit (activityDisplayName)", "activityDisplayName")
        self._top("Résultat audit (result)", "result")

    def _top(self, titre, chemin, n=10):
        """Affiche le décompte des n valeurs les plus fréquentes d'un champ."""
        compteur = {}
        for r in self.records:
            for v in self.resoudre(r, chemin):
                cle = "" if v is None else str(v)
                compteur[cle] = compteur.get(cle, 0) + 1
        if not compteur:
            return
        print(f"-- {titre} --")
        tri = sorted(compteur.items(), key=lambda kv: kv[1], reverse=True)
        for cle, nb in tri[:n]:
            affiche = cle if cle != "" else "(vide)"
            print(f"   {nb:>6}  {affiche}")
        if len(tri) > n:
            print(f"   ...   ({len(tri) - n} autres valeurs)")
        print()

    def lister_champs(self):
        """Liste tous les chemins de champs présents dans les records (échantillon)."""
        chemins = set()
        for r in self.records[:500]:
            self._parcourir(r, "", chemins)
        print("\n=== CHAMPS DISPONIBLES ===\n")
        for c in sorted(chemins):
            print(f"   {c}")

    @classmethod
    def _parcourir(cls, obj, prefixe, chemins):
        """Parcourt récursivement un record pour collecter les chemins pointés."""
        if isinstance(obj, dict):
            for cle, val in obj.items():
                nouveau = f"{prefixe}.{cle}" if prefixe else cle
                if isinstance(val, (dict, list)):
                    cls._parcourir(val, nouveau, chemins)
                else:
                    chemins.add(nouveau)
        elif isinstance(obj, list) and obj:
            cls._parcourir(obj[0], prefixe, chemins)


# ---------------------------------------------------------------------- affichage
def afficher(records, champs, fmt, limite):
    """Affiche les records selon le format demandé."""
    if limite:
        records = records[:limite]

    if fmt == "count":
        print(len(records))
        return

    if fmt == "json":
        nettoyes = [{k: v for k, v in r.items() if k != "_source"} for r in records]
        print(json.dumps(nettoyes, indent=2, ensure_ascii=False))
        return

    # format tableau : champs par défaut si non précisés
    if not champs:
        champs = ["createdDateTime", "activityDateTime", "userPrincipalName",
                  "appDisplayName", "ipAddress", "location.countryOrRegion",
                  "status.errorCode", "activityDisplayName", "result"]

    lignes = []
    for r in records:
        ligne = {}
        for c in champs:
            vals = EntraLog.resoudre(r, c)
            ligne[c] = ", ".join(str(v) for v in vals) if vals else ""
        lignes.append(ligne)

    # on ne garde que les colonnes qui ont au moins une valeur
    colonnes = [c for c in champs if any(l[c] for l in lignes)]
    if not colonnes:
        print("(aucune colonne à afficher)")
        return

    largeurs = {c: max(len(c), *(len(l[c]) for l in lignes)) if lignes else len(c)
                for c in colonnes}
    largeurs = {c: min(largeurs[c], 50) for c in colonnes}

    entete = " | ".join(c.ljust(largeurs[c])[:largeurs[c]] for c in colonnes)
    print(entete)
    print("-" * len(entete))
    for l in lignes:
        print(" | ".join(l[c].ljust(largeurs[c])[:largeurs[c]] for c in colonnes))
    print(f"\n({len(records)} record(s) affiché(s))")


def parser_critere(expr):
    """Transforme une expression 'champ OP valeur' en tuple (champ, operateur, valeur)."""
    for op in OPERATEURS:
        if op in expr:
            champ, valeur = expr.split(op, 1)
            return (champ.strip(), op, valeur.strip())
    raise argparse.ArgumentTypeError(
        f"Critère invalide : '{expr}'. Utilisez champ=valeur, champ!=valeur, "
        f"champ~regex, champ>valeur, etc.")


def parser_date(txt):
    """Parse une date de ligne de commande (YYYY-MM-DD ou ISO complet)."""
    dt = EntraLog._parse_date(txt)
    if dt is None:
        raise argparse.ArgumentTypeError(f"Date invalide : '{txt}' (attendu : YYYY-MM-DD)")
    return dt


def main():
    ap = argparse.ArgumentParser(
        description="Parser et moteur de recherche pour les exports de logs Entra ID (JSON).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Astuce : utilisez --list-fields pour découvrir les champs d'un fichier.")
    ap.add_argument("fichiers", nargs="+",
                    help="Fichiers d'export JSON (les motifs type *SignIns*.json sont acceptés).")
    ap.add_argument("-s", "--search", action="append", default=[], type=parser_critere,
                    metavar="CHAMP=VALEUR",
                    help="Critère de recherche (répétable). Opérateurs : = != ~ > < >= <=. "
                         "Notation pointée pour les champs imbriqués (status.errorCode).")
    ap.add_argument("--regex", action="store_true",
                    help="Interprète toutes les valeurs de --search comme des expressions régulières.")
    ap.add_argument("--from", dest="dt_from", type=parser_date, metavar="DATE",
                    help="Ne garder que les records à partir de cette date (YYYY-MM-DD).")
    ap.add_argument("--to", dest="dt_to", type=parser_date, metavar="DATE",
                    help="Ne garder que les records jusqu'à cette date (YYYY-MM-DD).")
    ap.add_argument("-f", "--field", action="append", default=[], dest="champs",
                    metavar="CHAMP", help="Colonne à afficher (répétable, format tableau).")
    ap.add_argument("--format", choices=["table", "json", "count"], default="table",
                    help="Format de sortie (défaut : table).")
    ap.add_argument("-n", "--limit", type=int, default=0, metavar="N",
                    help="Limiter le nombre de records affichés.")
    ap.add_argument("--stats", action="store_true",
                    help="Afficher un résumé statistique au lieu des records.")
    ap.add_argument("--list-fields", action="store_true",
                    help="Lister tous les champs disponibles puis quitter.")
    args = ap.parse_args()

    # expansion des motifs glob (utile si le shell ne le fait pas)
    chemins = []
    for motif in args.fichiers:
        trouves = sorted(glob.glob(motif))
        chemins.extend(trouves if trouves else [motif])

    log = EntraLog()
    for chemin in chemins:
        try:
            log.charger(chemin)
        except FileNotFoundError:
            print(f"[!] Fichier introuvable : {chemin}", file=sys.stderr)
        except OSError as e:
            print(f"[!] Erreur de lecture {chemin} : {e}", file=sys.stderr)

    if not log.records:
        print("[!] Aucun record chargé.", file=sys.stderr)
        sys.exit(1)

    if args.list_fields:
        log.lister_champs()
        return

    if args.stats:
        # on applique quand même les filtres avant de calculer les stats
        log.records = log.filtrer(args.search, args.regex, args.dt_from, args.dt_to)
        log.statistiques()
        return

    resultat = log.filtrer(args.search, args.regex, args.dt_from, args.dt_to)
    afficher(resultat, args.champs, args.format, args.limit)


if __name__ == "__main__":
    main()
