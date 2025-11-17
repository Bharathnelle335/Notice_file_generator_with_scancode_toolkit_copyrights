#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, json, os, re, shutil, subprocess, sys, tempfile, tarfile, zipfile
from pathlib import Path
import requests
from packaging.version import parse as parse_version

# SBOM parsers (CycloneDX and SPDX)
# - CycloneDX Python lib: read/validate CycloneDX docs
# - SPDX tools: parse SPDX JSON
# Docs: CycloneDX python lib / SPDX tools-python.  [7](https://pypi.org/project/cyclonedx-python-lib/)[8](https://github.com/CycloneDX/cyclonedx-python-lib)[9](https://github.com/spdx/tools-python)

NOASSERT = {"NOASSERTION", "NONE", "", None}

def normalize(s):
    if s is None: return None
    s = str(s).strip()
    if not s or s.upper() in NOASSERT: return None
    return " ".join(s.split())

def read_cfg(path):
    cfg = {}
    for ln in Path(path).read_text(encoding="utf-8").splitlines():
        if "=" in ln:
            k,v = ln.split("=",1)
            cfg[k.strip()] = v.strip()
    return cfg

def detect_format(doc):
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
            return "cdx"
        if doc.get("spdxVersion") or doc.get("SPDXID") or "packages" in doc or "files" in doc:
            return "spdx"
    return "unknown"

def parse_spdx(doc):
    comps = []
    pkgs = doc.get("packages") or []
    for p in pkgs:
        name = normalize(p.get("name"))
        if not name: continue
        version = normalize(p.get("versionInfo"))
        license_str = normalize(p.get("licenseConcluded")) or normalize(p.get("licenseDeclared"))
        if not license_str:
            infos = p.get("licenseInfoFromFiles") or []
            toks = sorted(set([normalize(x) for x in infos if normalize(x)]))
            license_str = " AND ".join(toks) if toks else None
        homepage = normalize(p.get("homepage"))
        dl = normalize(p.get("downloadLocation"))
        url = dl or homepage
        purl = None
        for ref in p.get("externalRefs") or []:
            rtype = (ref.get("referenceType") or "").lower()
            loc = normalize(ref.get("referenceLocator"))
            if "purl" in rtype and loc:
                purl = loc; break
        comps.append({"name":name,"version":version,"license":license_str,"url":url,"purl":purl})
    return comps

def parse_cdx(doc):
    comps = []
    for c in doc.get("components") or []:
        name = normalize(c.get("name"))
        if not name: continue
        version = normalize(c.get("version"))
        purl = normalize(c.get("purl"))
        lic = None
        if c.get("licenses"):
            # prefer expression if present
            exprs = [normalize(x.get("expression")) for x in c["licenses"] if isinstance(x, dict) and x.get("expression")]
            if exprs and exprs[0]: lic = exprs[0]
            else:
                ids_or_names = []
                for entry in c["licenses"]:
                    licd = entry.get("license") if isinstance(entry, dict) else None
                    if isinstance(licd, dict):
                        lid = normalize(licd.get("id")); lname=normalize(licd.get("name"))
                        if lid: ids_or_names.append(lid)
                        elif lname: ids_or_names.append(lname)
                ids_or_names = sorted(set(ids_or_names))
                lic = " AND ".join(ids_or_names) if ids_or_names else None
        # pick one useful external reference as URL
        url = None
        for ref in c.get("externalReferences") or []:
            rtype = (ref.get("type") or "").lower()
            u = normalize(ref.get("url"))
            if rtype in {"website","vcs","distribution","documentation","release-notes"} and u:
                url = u; break
        comps.append({"name":name,"version":version,"license":lic,"url":url,"purl":purl})
    return comps

def load_sboms(list_path):
    comps = []
    for path in Path(list_path).read_text(encoding="utf-8").splitlines():
        if not path.strip(): continue
        with open(path.strip(), "r", encoding="utf-8") as f:
            doc = json.load(f)
        kind = detect_format(doc)
        if kind == "spdx": comps += parse_spdx(doc)
        elif kind == "cdx": comps += parse_cdx(doc)
    # de-dupe by purl else name@version
    out = {}
    for c in comps:
        k = ("purl", c["purl"]) if c.get("purl") else ("nv", f"{(c.get('name') or '').lower()}@{(c.get('version') or '').lower()}")
        if k not in out: out[k] = c
        else:
            # prefer non-empty fields
            for fld in ("license","url","version"):
                if not out[k].get(fld) and c.get(fld): out[k][fld]=c[fld]
    return list(out.values())

# ---------- Downloaders by PURL / URL ----------
REQ_TIMEOUT = 45

def ensure_dir(p): Path(p).mkdir(parents=True, exist_ok=True)

def download_npm(name, version, dest):
    # npm pack (tarball) approach
    # Doc: npm registry exposes dist.tarball in metadata; npm pack retrieves tarball. [10](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)[11](https://stackoverflow.com/questions/33530978/download-a-package-from-npm-as-a-tar-not-installing-it-to-a-module)
    if version:
        url = f"https://registry.npmjs.org/{name}/{version}"
    else:
        url = f"https://registry.npmjs.org/{name}/latest"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    r.raise_for_status()
    meta = r.json()
    tarball = meta["dist"]["tarball"]
    buf = requests.get(tarball, timeout=REQ_TIMEOUT).content
    fn = Path(dest)/f"{name}-{version or 'latest'}.tgz"
    fn.write_bytes(buf)
    return str(fn)

def download_pypi(name, version, dest):
    # Doc: PyPI JSON API exposes release file URLs incl. sdists/wheels. [12](https://docs.pypi.org/api/json/)
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    urls = data.get("urls", [])
    # prefer sdist else first file
    sdist = next((u for u in urls if u.get("packagetype")=="sdist"), None) or (urls[0] if urls else None)
    if not sdist: return None
    buf = requests.get(sdist["url"], timeout=REQ_TIMEOUT).content
    fn = Path(dest)/Path(sdist["filename"]).name
    fn.write_bytes(buf)
    return str(fn)

def download_maven(group, artifact, version, dest):
    # Maven Central layout: repo1.maven.org/maven2/<group>/<artifact>/<version>/<artifact>-<version>.jar. [13](https://codingtechroom.com/question/download-jars-maven-central-without-pom)
    base = f"https://repo1.maven.org/maven2/{group.replace('.','/')}/{artifact}/{version}"
    # try sources.jar then jar
    for suffix in (f"{artifact}-{version}-sources.jar", f"{artifact}-{version}.jar"):
        url = f"{base}/{suffix}"
        r = requests.get(url, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            fn = Path(dest)/suffix
            fn.write_bytes(r.content)
            return str(fn)
    return None

def download_nuget(name, version, dest):
    if not version: return None
    # NuGet v3 flat container: /v3-flatcontainer/<lower>/<version>/<lower>.<version>.nupkg. [14](https://eyindia-my.sharepoint.com/personal/bharath_n3_in_ey_com/Documents/Microsoft%20Copilot%20Chat%20Files/app%20(3).py).py).py)
    lower = name.lower()
    url = f"https://api.nuget.org/v3-flatcontainer/{lower}/{version}/{lower}.{version}.nupkgupkg"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    if  if r.status_code == 200:
        fn = Path(dest)/f"{lower}.{version}.nupkg"
       
        fn.write_bytes(r.content)
        return str(fn)
    return None

def
def download_rubygems(name, version, dest):
    if not version: return NoneNone
    url = f"https://rubygems.org/downloads/{name}-{version}.gem"
    r = requests.get(url, timeout=REQ_TIMEOUT)
   
    if r.status_code == 200:
        fn = Path(dest)/f"{name}-{version}.gem"
       gem"
        fn.write_bytes(r.content); return str(fn)
    return None

def download_golang(module, version, dest):
    if not version: return None
    url = f"https://proxy.golang.org/{moduledule}/@v/{version}.zip"
    r = requests.get(url, timeout=REQ_TIMEOUT)
   REQ_TIMEOUT)
    if r.status_code == 200:
        fn = Path(dest)/f"{module.replace('/','_')}@{version}.zip"
        fn.write_bytes(r.content); return str(fn)
    return None

def download_by_purl(purl, version, destdest):
    if not purl: return None
   None
    if purl.startswith("pkg:npm/"):
        pkg = purl.split("/",2)[-1].split2)[-1].split("@")[0]
        ver = version or (purl.split("@")[-1] if "@" in purl else None)
ne)
        return download_npm(pkg, ver, dest)
    if)
    if purl.startswith("pkg:pypi/"):
        pkg = purl.split("/",2)[-1].("/",2)[-1].split("@")[0]
        ver = version or (purl.split("@")[-1] if "@" in purl else None)
ne)
        return download_pypi(pkg, ver, dest)
    if)
    if purl.startswith("pkg:maven/"):
        rest = purl[len("pkg:maven/"):]
        coords  coords = rest.split("@")[0].split("/")
        if  if len(coords)>=2 and version:
            return download_maven(coordsn(coords[0], coords[1], version, dest)
    if purl.startswith("pkg:nuget/"):
       
        pkg = purl.split("/",2)[-1].split("@")[0]
        ver =   ver = version or (purl.split("@")[-1] if "@" in purl else None)
        return  return download_nuget(pkg, ver, dest)
    if purl.startswith("pkg:gem/"):
       
        pkg = purl.split("/",2)[-1].split("@")[0]
        ver =   ver = version or (purl.split("@")[-1] if "@" in purl else None)
        return download_rubload_rubygems(pkg, ver, dest)
    if purl.startswith("pkg:golang/"):
       
        mod = purl[len("pkg:golang/"):].split("@")[0]
        ver =   ver = version or (purl.split("@")[-1] if "@" in purl else None)
        returnturn download_golang(mod, ver, dest)
    return None

def extract extract_archive(path, outdir):
    ensure_dir(outdir)
    p   p = Path(path)
    try:
        # tar
            if p.suffix in (".tgz",".gz",".tar"):
            with    with tarfile.open(p, "r:*") as tf:
                tf.extractall(outdir)
            return outdir
        # zip/jar
        with    with zipfile.ZipFile(p) as zf:
            zf.extractall(outdir)
        return outdir
    except Exception:
        returnturn None

def run_scancode_scan(src_dir, out_json):
   on):
    # ScanCode CLI options:
    # -c (copyright), -l (license) plus --license-text to include matched texts; output JSON pretty. [6](https://scancode-toolkit.readthedocs.io/en/stable/tutorials/how_to_run_a_scan.html)[1](https://scancode-toolkit.readthedocs.io/en/latest/tutorials/how_to_set_what_will_be_detected_in_a_scan.html)
    cmd = [
        "scancode", "-cl", "--license-text",
        "--json-pp", out_json, src_dir
    ]
    subprocess.check_call(cmd)

def pick_copyrights(scan_json):
    data = json.loads(Path(scan_json).read_text(encoding="utf-8"))
    lines = []
    for f in data.get("files", []):
        for cp in f.get("copyrights", []):
            val = cp.get("value")
            if val:
                lines.append(val.strip())
    # de-dupe preserve order
    seen, uniq = set(), []
    for l in lines:
        if l not in seen:
            seen.add(l); uniq.append(l)
    # cap to reasonable length
    return "\n".join(uniq[:25]) if uniq else None

def collect_license_texts(scan_json):
    data = json.loads(Path(scan_json).read_text(encoding="utf-8"))
    texts = {}
    for f in data.get("files", []):
        for det in f.get("license_detections", []):
            key = det.get("license_expression_spdx") or det.get("license_expression") or det.get("license_key")
            if det.get("matches"):
                # concat match texts
                chunks = []
                for m in det["matches"]:
                    t = m.get("matched_text") or ""
                    t = t.strip()
                    if t: chunks.append(t)
                if chunks and key:
                    # store first big chunk per license key to keep NOTICE compact
                    texts.setdefault(key, chunks[0])
    return texts

def build_notice(title, rows, license_texts, include_spdx_texts):
    out = []
    out.append(f"# {title}\n")
    for r in rows:
        out.append(f"### {r['name']}" + (f" {r['version']}" if r.get('version') else ""))
        if r.get("url"): out.append(f"- **URL:** {r['url']}")
        if r.get("license"): out.append(f"- **License:** {r['license']}")
        if r.get("copyright"):
            out.append(f"- **Copyright:** {r['copyright']}")
        out.append("")  # blank

    # Append unique license texts (from ScanCode detections)
    if license_texts:
        out.append("\n## License Texts\n")
        # unique by key
        for lid, text in sorted(license_texts.items()):
            out.append(f"### {lid}\n```text\n{text.strip()}\n```\n")

    return ("\n".join(out)).rstrip() + "\n"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom-list", required=True)
    ap.add_argument("--cfg", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workdir", default=".work")
    args = ap.parse_args()

    cfg = read_cfg(args.cfg)
    include_spdx_texts = cfg.get("include_spdx_texts","true").lower() == "true"
    title = cfg.get("title","Open Source Notices")

    comps = load_sboms(args.sbom_list)
    ensure_dir(args.workdir)
    rows = []
    appendix_texts = {}

    for c in comps:
        name, version, url, purl, lic = c.get("name"), c.get("version"), c.get("url"), c.get("purl"), c.get("license")
        comp_dir = Path(args.workdir)/f"{(name or 'component').replace('/','_')}"
        ensure_dir(comp_dir)
        # 1) prefer download by PURL; else use URL (best-effort)
        archive = download_by_purl(purl, version, comp_dir)
        if not archive and url:
            # last resort: try to fetch repo zip if GitHub
            m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)", url or "")
            if m:
                org, repo = m.groups()
                zurl = f"https://codeload.github.com/{org}/{repo}/zip/refs/heads/main"
                r = requests.get(zurl, timeout=REQ_TIMEOUT)
                if r.status_code == 200:
                    zf = Path(comp_dir)/f"{repo}-main.zip"; zf.write_bytes(r.content)
                    archive = str(zf)

        # 2) extract, then run ScanCode
        scan_src = None
        if archive: scan_src = extract_archive(archive, Path(comp_dir)/"src")
        if not scan_src:
            # if we cannot download/extract, skip ScanCode
            rows.append({"name":name, "version":version, "url":url, "license":lic})
            continue

        out_json = str(Path(comp_dir)/"scan.json")
        run_scancode_scan(str(scan_src), out_json)

        # 3) collect copyrights & license texts
        cp = pick_copyrights(out_json)
        lt = collect_license_texts(out_json)
        if lt:
            for k,v in lt.items():
                appendix_texts.setdefault(k, v)

        rows.append({
            "name": name, "version": version, "url": url,
            "license": lic, "copyright": cp
        })

    notice = build_notice(title, rows, appendix_texts, include_spdx_texts)
    Path(args.out).write_text(notice, encoding="utf-8")

if __name__ == "__main__":
    main()
