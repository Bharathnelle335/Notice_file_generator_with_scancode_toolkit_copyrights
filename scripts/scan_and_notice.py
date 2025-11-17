#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, json, os, re, shutil, subprocess, sys, tarfile, zipfile
from pathlib import Path
import requests
from packaging.version import parse as parse_version

# NOASSERT handling consistent with SPDX/CycloneDX conventions
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
    # SPDX-Lite fallback (aggregate from files)
    if not pkgs and (doc.get("files") or []):
        doc_name = normalize(doc.get("name")) or normalize(doc.get("documentName")) or "SPDX-Document"
        files = doc.get("files") or []
        lic_tokens, cpr_lines = set(), []
        for f in files:
            v = normalize(f.get("licenseConcluded"))
            if v: lic_tokens.add(v)
            for vv in f.get("licenseInfoInFile") or []:
                v2 = normalize(vv)
                if v2: lic_tokens.add(v2)
            cpr = normalize(f.get("copyrightText"))
            if cpr and cpr not in NOASSERT:
                cpr_lines.append(cpr)
        license_str = " AND ".join(sorted(lic_tokens)) if lic_tokens else None
        cpr_agg = "\n".join(sorted(set(cpr_lines))) if cpr_lines else None
        comps.append({"name":doc_name,"version":None,"license":license_str,"url":None,"purl":None})
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
            for fld in ("license","url","version"):
                if not out[k].get(fld) and c.get(fld): out[k][fld]=c[fld]
    return list(out.values())

# ---------- Downloaders by PURL / URL ----------
REQ_TIMEOUT = 45

def ensure_dir(p): Path(p).mkdir(parents=True, exist_ok=True)

def download_npm(name, version, dest):
    # npm registry metadata → dist.tarball (or latest)
    url = f"https://registry.npmjs.org/{name}/{version}" if version else f"https://registry.npmjs.org/{name}/latest"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    r.raise_for_status()
    meta = r.json()
    tarball = meta["dist"]["tarball"]
    buf = requests.get(tarball, timeout=REQ_TIMEOUT).content
    fn = Path(dest)/f"{name}-{version or 'latest'}.tgz"
    fn.write_bytes(buf)
    return str(fn)

def download_pypi(name, version, dest):
    # PyPI JSON API → prefer sdist; else first file
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    urls = data.get("urls", [])
    sdist = next((u for u in urls if u.get("packagetype")=="sdist"), None) or (urls[0] if urls else None)
    if not sdist: return None
    buf = requests.get(sdist["url"], timeout=REQ_TIMEOUT).content
    fn = Path(dest)/Path(sdist["filename"]).name
    fn.write_bytes(buf)
    return str(fn)

def download_maven(group, artifact, version, dest):
    base = f"https://repo1.maven.org/maven2/{group.replace('.','/')}/{artifact}/{version}"
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
    lower = name.lower()
    url = f"https://api.nuget.org/v3-flatcontainer/{lower}/{version}/{lower}.{version}.nupkg"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    if r.status_code == 200:
        fn = Path(dest)/f"{lower}.{version}.nupkg"
        fn.write_bytes(r.content)
        return str(fn)
    return None

def download_rubygems(name, version, dest):
    if not version: return None
    url = f"https://rubygems.org/downloads/{name}-{version}.gem"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    if r.status_code == 200:
        fn = Path(dest)/f"{name}-{version}.gem"
        fn.write_bytes(r.content); return str(fn)
    return None

def download_golang(module, version, dest):
    if not version: return None
    url = f"https://proxy.golang.org/{module}/@v/{version}.zip"
    r = requests.get(url, timeout=REQ_TIMEOUT)
    if r.status_code == 200:
        fn = Path(dest)/f"{module.replace('/','_')}@{version}.zip"
        fn.write_bytes(r.content); return str(fn)
    return None

def download_by_purl(purl, version, dest):
    if not purl: return None
    if purl.startswith("pkg:npm/"):
        pkg = purl.split("/",2)[-1].split("@")[0]
        ver = version or (purl.split("@")[-1] if "@" in purl else None)
        return download_npm(pkg, ver, dest)
    if purl.startswith("pkg:pypi/"):
        pkg = purl.split("/",2)[-1].split("@")[0]
        ver = version or (purl.split("@")[-1] if "@" in purl else None)
        return download_pypi(pkg, ver, dest)
    if purl.startswith("pkg:maven/"):
        rest = purl[len("pkg:maven/"):]
        coords = rest.split("@")[0].split("/")
        if len(coords)>=2 and version:
            return download_maven(coords[0], coords[1], version, dest)
    if purl.startswith("pkg:nuget/"):
        pkg = purl.split("/",2)[-1].split("@")[0]
        ver = version or (purl.split("@")[-1] if "@" in purl else None)
        return download_nuget(pkg, ver, dest)
    if purl.startswith("pkg:gem/"):
        pkg = purl.split("/",2)[-1].split("@")[0]
        ver = version or (purl.split("@")[-1] if "@" in purl else None)
        return download_rubygems(pkg, ver, dest)
    if purl.startswith("pkg:golang/"):
        mod = purl[len("pkg:golang/"):].split("@")[0]
        ver = version or (purl.split("@")[-1] if "@" in purl else None)
        return download_golang(mod, ver, dest)
    return None

def extract_archive(path, outdir):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    p = Path(path)
    try:
        if p.suffix in (".tgz",".gz",".tar"):
            with tarfile.open(p, "r:*") as tf:
                tf.extractall(outdir)
            return outdir
        with zipfile.ZipFile(p) as zf:
            zf.extractall(outdir)
        return outdir
    except Exception:
        return None

def run_scancode_scan(src_dir, out_json):
    # Scan for licenses (+ license text) and copyrights; JSON pretty output
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
            if val: lines.append(val.strip())
    seen, uniq = set(), []
    for l in lines:
        if l not in seen:
            seen.add(l); uniq.append(l)
    return "\n".join(uniq[:25]) if uniq else None

def collect_license_texts(scan_json):
    data = json.loads(Path(scan_json).read_text(encoding="utf-8"))
    texts = {}
    for f in data.get("files", []):
        for det in f.get("license_detections", []):
            key = det.get("license_expression_spdx") or det.get("license_expression") or det.get("license_key")
            if det.get("matches"):
                chunks = []
                for m in det["matches"]:
                    t = m.get("matched_text") or ""
                    t = t.strip()
                    if t: chunks.append(t)
                if chunks and key:
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

    if license_texts:
        out.append("\n## License Texts\n")
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
    Path(args.workdir).mkdir(parents=True, exist_ok=True)
    rows = []
    appendix_texts = {}

    for c in comps:
        name, version, url, purl, lic = c.get("name"), c.get("version"), c.get("url"), c.get("purl"), c.get("license")
        comp_dir = Path(args.workdir)/f"{(name or 'component').replace('/','_')}"
        comp_dir.mkdir(parents=True, exist_ok=True)
        archive = download_by_purl(purl, version, comp_dir)
        if not archive and url:
            m = re.match(r"https?://github\.com/([^/]+)/([^/?#]+)", url or "")
            if m:
                org, repo = m.groups()
                zurl = f"https://codeload.github.com/{org}/{repo}/zip/refs/heads/main"
                r = requests.get(zurl, timeout=REQ_TIMEOUT)
                if r.status_code == 200:
                    zf = Path(comp_dir)/f"{repo}-main.zip"; zf.write_bytes(r.content)
                    archive = str(zf)

        scan_src = None
        if archive: scan_src = extract_archive(archive, comp_dir/"src")
        if not scan_src:
            rows.append({"name":name, "version":version, "url":url, "license":lic})
            continue

        out_json = str(comp_dir/"scan.json")
        run_scancode_scan(str(scan_src), out_json)

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
