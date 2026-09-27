# runner.Dockerfile — offensive Ausfuehrungsebene, isoliert (Deployment-
# Architektur Kap. 3.2). Laeuft NIE als Dauerdienst, sondern ephemer pro
# Auftrag (Kubernetes Job, s. deployment/k8s/job-tool-runner.yaml).
#
# Nur die Build-Zeit-Allowlist aus docs/spec/tool-allowlist.md
# (Kap. 2) wird installiert - NICHT HexStrikes volles 150+-Tool-Arsenal.
# Ein Tool, das nicht installiert ist, kann nicht missbraucht werden.

# REQ-SUPPLY-001: base pinned by digest for reproducibility/supply-chain. This
# is a ROLLING distro, so re-pin periodically (scripts/pin_images.sh) to pick up
# security updates; the apt-get below still fetches current packages at build.
FROM kalilinux/kali-rolling:latest@sha256:776d57c9d607faafef9957073b0b5a05b0d1115e5728777a8fc5588827cfd249

# GitHub issue #20: these three floated against a moving upstream target
# (default-branch HEAD / template-fetch-at-build-time) - rebuilding the SAME
# repo commit months apart produced different images, and there was no way
# to tie an incident to a known set of upstream code. Pinned via build ARGs
# so bumping any of them is a reviewed one-line diff (`docker build --build-arg
# HEXSTRIKE_SHA=... .` or edit the default below), not an implicit drift.
# Current values are simply "whatever HEAD/latest-release resolved to" at the
# time this was pinned (2026-08-12) - freezing the status quo, not a behavior
# change.
ARG HEXSTRIKE_SHA=d689933ff579d839c676c82b231f8e98326c5f04
ARG TESTSSL_SHA=06adbdccc546676ffa93c7a73d8741e8c4957a7e
ARG NUCLEI_TEMPLATES_TAG=v10.4.7

# 1. Nur die Tools der Allowlist (Kap. 2.1-2.4):
#    recon: subfinder, amass, dnsutils(dnsx-Ersatz), tlsx
#    fingerprint: httpx-toolkit, whatweb, nmap, sslscan/testssl, wafw00f
#    vuln: nuclei, nikto, ffuf (Content-Discovery/Enumeration)
#    cred: eigener Default-Cred-Check (kein hydra/medusa/patator)
# curl: agent-gesteuerter roher HTTP-Lesezugriff (http_request-Primitiv).
# ffuf + seclists: kuratierte Content-Discovery - der Vector Agent WAEHLT die
# passende Wortliste (aus /usr/share/seclists), ffuf leistet die Fleissarbeit.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip git ca-certificates curl \
      nmap nuclei httpx-toolkit dnsutils whatweb nikto sslscan wafw00f \
      subfinder amass ffuf seclists \
      build-essential python3-dev libcap2-bin \
      bsdextrautils openssl \
      chromium \
  && rm -rf /var/lib/apt/lists/*
# chromium: REQ-AGENT-018 - deliberate, explicit exception to this file's own
# "only the allowlisted tools" minimalism (a real dependency-surface increase,
# approved by johannes) - lets nuclei's -headless mode run its DOM-XSS/
# CSP-Bypass templates (dast/vulnerabilities/xss/csp-bypass, headless/*),
# which were previously silently never executed at all (they require a real
# browser; without one, nuclei just skips them). Nothing else in this image
# uses it - a browser that isn't installed can't be abused either.
# build-essential + python3-dev: HexStrikes requirements.txt zieht Pakete mit
# C-Extensions (u.a. msgpack), die Kali nicht vorkompiliert mitbringt.
# libcap2-bin: liefert setcap (Schritt 7).
# bsdextrautils (hexdump) + openssl: von testssl.sh zur Laufzeit benoetigt.
# seclists liegt unter /usr/share/seclists (Wortlisten fuer ffuf).

# 2. HexStrike installieren (Ausfuehrungs-Engine HINTER dem Scope Gateway,
#    niemals direkt vom LLM erreichbar - s. Deployment-Architektur Kap. 3.1).
#
#    pwntools/angr werden VOR dem pip install aus requirements.txt entfernt.
#    Quellcode-Analyse (nicht nur die Doku-Kommentare in requirements.txt)
#    bestaetigt: hexstrike_server.py importiert beide NICHT auf Modulebene.
#    Alle vier Fundstellen sind entweder (a) String-Eintraege einer
#    "ist Tool X verfuegbar?"-Prueftabelle oder (b) Teil eines f-string-
#    Templates, das HexStrike in eine Datei schreibt und als EIGENSTAENDIGEN
#    Kindprozess ausfuehrt (/tmp/pwntools_exploit.py, /tmp/angr_analysis.py) -
#    fuer die "Binary Exploitation"/"Binary Analysis"-Tool-Kategorien, die
#    ohnehin nicht in unserer tool_grant-Whitelist stehen. Der Hauptserver
#    (inkl. aller Kategorien, die wir tatsaechlich nutzen: recon, fingerprint,
#    vuln) startet und laeuft nachweislich ohne die beiden Pakete (getestet:
#    Server-Start + GET /health gegen ein Image ohne pwntools/angr).
WORKDIR /opt/hexstrike
COPY patch_hexstrike.py /tmp/patch_hexstrike.py
# REQ-HARDEN-001: the fail-closed shared-secret gate injected by the patch
# imports runner_auth at runtime; it must sit next to hexstrike_server.py.
# Staged via /tmp because `git clone . ` below requires an empty WORKDIR.
COPY runner_auth.py /tmp/runner_auth.py
RUN git clone https://github.com/0x4m4/hexstrike-ai.git . \
  && git checkout --detach "${HEXSTRIKE_SHA}" \
  && cp /tmp/runner_auth.py /opt/hexstrike/runner_auth.py \
  && rm /tmp/runner_auth.py \
  && sed -i '/^pwntools/d; /^angr/d' requirements.txt \
  && sed -i "s#logging.FileHandler('hexstrike.log')#logging.FileHandler('/tmp/hexstrike.log')#" hexstrike_server.py \
  && python3 /tmp/patch_hexstrike.py hexstrike_server.py \
  && rm /tmp/patch_hexstrike.py \
  && python3 -m venv venv \
  && ./venv/bin/pip install --no-cache-dir -r requirements.txt
# Log-Pfad auf /tmp umgebogen: hexstrike_server.py schreibt hart nach
# './hexstrike.log' (cwd-relativ, also /opt/hexstrike/) - kollidiert mit
# readOnlyRootFilesystem (Deployment-Architektur Kap. 7.1). HexStrikes eigener
# Fallback faengt nur PermissionError ab, nicht das hier tatsaechlich
# auftretende OSError(EROFS) - ohne diesen Patch crasht der Server beim
# Start unter read_only:true, noch bevor er ueberhaupt horcht.

# 3. Verifikation im Build: schlaegt fehl, wenn ein ausgeschlossenes Tool
#    doch installiert ist (Tool-Allowlist Kap. 4.2, Listing 2).
#    ZWEI Ebenen, nicht nur eine: reine `command -v`-Checks auf System-
#    Binaries sehen Python-Bibliotheken in HexStrikes venv nicht (so wurde
#    urspruenglich uebersehen, dass requirements.txt angr/pwntools UND deren
#    schwere transitive Deps - capstone, unicorn, z3-solver, ropgadget, ...
#    - zieht). Der zweite Check verifiziert das Fehlen direkt im venv.
RUN set -e; for bad in hydra john hashcat medusa patator ophcrack \
        responder netexec crackmapexec evil-winrm \
        metasploit msfconsole commix xsser sqlmap dalfox \
        ghidra radare2 gdb masscan; do \
      if command -v "$bad" >/dev/null 2>&1; then \
        echo "VERBOTEN: $bad ist als System-Binary installiert" && exit 1; fi; done
RUN set -e; for pkg in angr pwntools ropgadget capstone unicorn z3; do \
      if /opt/hexstrike/venv/bin/python3 -c "import $pkg" >/dev/null 2>&1; then \
        echo "VERBOTEN: $pkg ist als Python-Bibliothek in HexStrikes venv installiert" && exit 1; fi; done

# 3b. Weitere aktive Tools einsatzbereit machen (Registry-Kategorien vuln/
#     fingerprint). Diese drei Schritte bringen nuclei/httpx/testssl von
#     "installiert" zu "lauffaehig" (s. docs/kali-tools-capability-analysis-handoff.md):

# nuclei: Templates ZUR BUILD-ZEIT backen (Runtime-Fs ist read-only + isoliert;
# ein Update-Fetch waere dann unmoeglich), an einen stabilen, world-lesbaren
# Pfad, auf den nuclei zur Laufzeit per -t zeigt.
# GitHub issue #20: `nuclei -ut` fetched whatever the "latest released
# version" happened to be AT BUILD TIME - not just a provenance problem, but
# a correctness one: the benchmark suite's ground-truth scoring is not
# comparable across rebuilds if the template set silently changes under it.
# Cloning the pinned release tag directly makes the template set exactly as
# reproducible as the SHA pins above.
RUN set -e; git clone --depth 1 --branch "${NUCLEI_TEMPLATES_TAG}" \
      https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates \
  && rm -rf /opt/nuclei-templates/.git \
  && chmod -R a+rX /opt/nuclei-templates \
  && echo "nuclei-templates ${NUCLEI_TEMPLATES_TAG}: $(find /opt/nuclei-templates -name '*.yaml' | wc -l) Templates gebacken"

# httpx: das Kali-Paket installiert das Binary als 'httpx-toolkit'. HexStrike
# (und unser generischer Command-Aufruf) erwarten 'httpx' - Symlink davor.
RUN ln -sf "$(command -v httpx-toolkit)" /usr/local/bin/httpx

# testssl.sh: nicht als apt-Paket verfuegbar -> aus dem offiziellen Repo (ein
# Bash-Skript + etc/-Daten). Unterstuetzt --proxy (HTTP CONNECT), laeuft also
# durch den Egress-Proxy wie nikto.
# GitHub issue #20: pinned to an exact commit (git checkout --detach) instead
# of a --depth 1 clone of whatever the default branch's tip happened to be -
# a full (not shallow) clone is needed so an arbitrary historical SHA is
# actually reachable to check out; the repo is small enough that this costs
# nothing meaningful at build time.
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl \
  && cd /opt/testssl && git checkout --detach "${TESTSSL_SHA}" && cd / \
  && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl

# 4. Nicht-root Benutzer; Root-FS wird zur Laufzeit read-only (s. docker-
#    compose.yml / deployment/k8s Job-Manifest: readOnlyRootFilesystem).
RUN useradd -r -u 10001 -s /usr/sbin/nologin runner

# 5. Raw-Socket-Faehigkeit gezielt nur fuer nmap (statt root/CAP_ALL).
#    Kali installiert /usr/bin/nmap als Wrapper, der bei Nicht-root-Laeufen
#    eine privilegierte Re-Exec-Strategie versucht. Fuer den Runner wird
#    deshalb - falls vorhanden - das echte Binary direkt in /usr/local/bin
#    vor den Wrapper gelegt. HexStrike ruft weiterhin schlicht `nmap` auf.
RUN set -e; \
    if [ -x /usr/lib/nmap/nmap ]; then \
      setcap cap_net_raw+eip /usr/lib/nmap/nmap; \
      ln -sf /usr/lib/nmap/nmap /usr/local/bin/nmap; \
    else \
      setcap cap_net_raw+eip /usr/bin/nmap; \
    fi

USER runner
EXPOSE 8888
# HEXSTRIKE_PORT/HEXSTRIKE_HOST sind die einzigen vom echten Server
# gelesenen Env-Vars (verifiziert im Quellcode: os.environ.get(...) an
# genau zwei Stellen). app.run() bindet ohnehin hart auf 0.0.0.0 - HEXSTRIKE_HOST
# wird gelesen, aber nicht mehr verwendet (kein Problem fuer uns).
# HINWEIS: HEXSTRIKE_VALIDATE_COMMANDS/HEXSTRIKE_REQUIRE_API_KEY aus fruehen
# Entwuerfen dieser Datei existieren im echten HexStrike-Code NICHT - reine
# No-ops. Die tatsaechliche Kontrolle bleibt ausschliesslich das Scope
# Gateway (Deployment-Architektur Kap. 3.1) - siehe docs/security-model.md.
# HOME=/tmp: nuclei (und andere Tools) schreiben Config/Cache nach $HOME;
# unter readOnlyRootFilesystem ist nur das tmpfs /tmp beschreibbar. Ohne das
# scheitert nuclei beim Start (mkdir $HOME/.config/nuclei auf read-only fs).
ENV HOME=/tmp
ENV HEXSTRIKE_PORT=8888
# --debug ist die einzige echte Flag neben --port (argparse-Check im
# Quellcode); ein zuvor angenommenes --host existiert NICHT und haette den
# Serverstart mit "unrecognized arguments" abbrechen lassen.
ENTRYPOINT ["/opt/hexstrike/venv/bin/python3", "hexstrike_server.py"]
CMD ["--port", "8888"]
