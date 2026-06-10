from flask import Flask, jsonify, request, render_template
import dns.resolver
import requests
import re
from datetime import datetime

app = Flask(__name__)

DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "s1",
    "s2",
    "smtp",
    "mail"
]


def get_txt_records(host):
    try:
        answers = dns.resolver.resolve(host, "TXT")

        records = []

        for answer in answers:
            txt = "".join(
                part.decode() if isinstance(part, bytes) else part
                for part in answer.strings
            )

            records.append(txt)

        return records

    except Exception:
        return []


def get_spf(domain):
    records = get_txt_records(domain)

    for record in records:
        if record.lower().startswith("v=spf1"):

            lookup_count = len(
                re.findall(
                    r'include:',
                    record,
                    re.IGNORECASE
                )
            )

            return record, lookup_count

    return "", 0


def get_dmarc(domain):
    records = get_txt_records(
        f"_dmarc.{domain}"
    )

    for record in records:
        if record.lower().startswith("v=dmarc1"):
            return record

    return ""


def get_dkim(domain):
    found = []

    for selector in DKIM_SELECTORS:

        try:
            host = (
                f"{selector}._domainkey."
                f"{domain}"
            )

            records = get_txt_records(host)

            for record in records:

                if (
                    "k=rsa" in record.lower()
                    or "p=" in record
                ):
                    found.append(selector)
                    break

        except Exception:
            pass

    return found


def get_mx(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "MX"
        )

        return sorted([
            str(mx.exchange).rstrip(".")
            for mx in answers
        ])

    except Exception:
        return []


def get_ns(domain):
    try:
        answers = dns.resolver.resolve(
            domain,
            "NS"
        )

        return sorted([
            str(ns.target).rstrip(".")
            for ns in answers
        ])

    except Exception:
        return []


def get_domain_age(domain):
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=10
        )

        if r.status_code != 200:
            return "Unknown", 0

        data = r.json()

        registrar = "Unknown"

        for entity in data.get("entities", []):

            if "registrar" in entity.get("roles", []):

                registrar = entity.get(
                    "handle",
                    "Unknown"
                )

                break

        age_days = 0

        for event in data.get("events", []):

            if event.get("eventAction") == "registration":

                created = datetime.fromisoformat(
                    event["eventDate"].replace(
                        "Z",
                        "+00:00"
                    )
                )

                age_days = (
                    datetime.now(created.tzinfo)
                    - created
                ).days

                break

        return registrar, age_days

    except Exception as e:

        print(
            f"RDAP ERROR ({domain}): {e}"
        )

        return "Unknown", 0


def detect_esp(
    spf_record,
    mx_records,
    dkim_selectors,
    nameservers
):
    data = " ".join([
        spf_record,
        " ".join(mx_records),
        " ".join(dkim_selectors),
        " ".join(nameservers)
    ]).lower()

    return {

        "mailgun": any(
            keyword in data
            for keyword in [
                "mailgun",
                "mailgun.org",
                "mailgun.us"
            ]
        ),

        "sendgrid": any(
            keyword in data
            for keyword in [
                "sendgrid",
                "sendgrid.net"
            ]
        ),

        "sparkpost": any(
            keyword in data
            for keyword in [
                "sparkpost",
                "sparkpostmail"
            ]
        )

    }


def calculate_score(data):
    score = 0

    if data["spf_record"]:
        score += 25

    if data["dmarc_record"]:
        score += 25

    if len(data["dkim_selectors"]) > 0:
        score += 20

    if len(data["mx_records"]) > 0:
        score += 10

    if len(data["nameservers"]) > 0:
        score += 5

    if data["domain_age"] > 365:
        score += 15

    return score


@app.route("/")
def home():
    return render_template(
        "index.html"
    )


@app.route("/check")
def check():

    domain = request.args.get(
        "domain",
        ""
    ).strip()

    if not domain:
        return jsonify({
            "error": "missing domain"
        })

    spf, lookups = get_spf(domain)

    dmarc = get_dmarc(domain)

    dkim = get_dkim(domain)

    mx = get_mx(domain)

    ns = get_ns(domain)

    registrar, age = get_domain_age(
        domain
    )

    esp = detect_esp(
        spf,
        mx,
        dkim,
        ns
    )

    result = {

        "domain": domain,

        "spf_record": spf,

        "spf_lookup_count": lookups,

        "dmarc_record": dmarc,

        "dkim_selectors": dkim,

        "mx_records": mx,

        "nameservers": ns,

        "registrar": registrar,

        "domain_age": age,

        "mailgun": esp["mailgun"],

        "sendgrid": esp["sendgrid"],

        "sparkpost": esp["sparkpost"]

    }

    result["score"] = calculate_score(
        result
    )

    print(f"""
====================================

Domain: {domain}

SPF:
{spf}

DMARC:
{dmarc}

DKIM:
{dkim}

MX:
{mx}

NS:
{ns}

Registrar:
{registrar}

Age:
{age}

Mailgun:
{esp['mailgun']}

SendGrid:
{esp['sendgrid']}

SparkPost:
{esp['sparkpost']}

Score:
{result['score']}

====================================
""")

    return jsonify(result)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

