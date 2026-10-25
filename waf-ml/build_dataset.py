"""T03 — bộ dataset v0 cho ML-WAF: SQLi (10 family mutation) + benign.

Sinh có chủ đích, không RNG: cùng một template tạo nhiều mutation; family là
một nhóm mutation cùng nguồn gốc. train.py tách train/test theo family
(GroupKFold) nên "anh em mutation" không lộ phép dò sang tập kiểm tra.
Families mô phỏng đúng 4 nhóm kỹ thuật trong giáo trình C4:
HPP/fragmentation, double-encoding, case/comment + tautology/union/stacked.
"""
import html

QUOTES = ["'", '"']


def sqli_tautology_string():
    rows = []
    for q in QUOTES:
        for tail in ["--", "#", "-- -", "/**/", " /*x*/", " /*x*/--"]:
            rows.append((f"{q} OR 1=1 {tail}", f"tautology-s.{q}.{tail.strip()}"))
        for rhs in ["2=2", "1=2 OR 1=1", "'a'='a", "2=3 OR 1=1"]:
            rows.append((f"{q} OR {rhs} ", f"tautology-s.{q}.{rhs[:3]}"))
    return rows


def sqli_tautology_numeric():
    rows = []
    for prefix, prefix_tip in [("1 OR", None), ("2 OR", None), ("-1 OR", None), ("1  OR", None), ("1\tOR", None)]:
        for rhs in ["1=1", "1=1 OR 2=2", "2=2", "0<>1", "1!=2"]:
            rows.append((f"{prefix} {rhs}", f"tautology-n.{prefix.split()[0]}.{rhs}"))
    for tail in ["--", "#", "/*x*/"]:
        rows.append((f"1 OR 1=1 {tail}", f"tautology-n.comm{tail.strip()}"))
    rows.append(("1 OR 1=1 OR 1=1#", "tautology-n.multi"))
    return rows


def sqli_union():
    rows = []
    for tail in ["--", "#", "-- -", "/**/", " /*z*/"]:
        rows.append((f"-1 UNION SELECT id,username FROM users {tail}".strip(),
                     f"union.sel{tail.strip()[:3]}"))
        rows.append((f"1 UNION ALL SELECT username,password FROM users {tail}".strip(),
                     f"union.all{tail.strip()[:3]}"))
        rows.append((f"-1 UNION SELECT version(),database() {tail}".strip(),
                     f"union.info{tail.strip()[:3]}"))
        rows.append((f"-1 UNION SELECT NULL,NULL,1 {tail}".strip(),
                     f"union.null{tail.strip()[:3]}"))
    for combo in ["uNiOn SeLeCt", "UNION    SELECT", "uNiOn/**/sElEcT", "UNION\tSELECT",
                  "UNION+SELECT", "UNION/**/ALL/**/SELECT"]:
        rows.append((f"-1 {combo} id,username,3 FROM users -- ", f"union.case.{combo[:6]}"))
    rows.append(("1 UNION SELECT user(),@@version -- ", "union.meta"))
    return rows


def sqli_error_based():
    rows = []
    for term, tag in [
        ("EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))", "extract-upper"),
        ("extractvalue(1,concat(0x7e,version()))", "extract-lower"),
        ("updatexml(1,concat(0x7e,version()),1)", "updatexml"),
        ("UPDATEXML(1,CONCAT(0x7e,database()),1)", "updatexml-up"),
    ]:
        rows.append((f"1 AND {term} -- ", f"error.{tag}"))
        rows.append((f"1 AND {term}", f"error.ntail.{tag}"))
    rows.append(("1' AND (SELECT 1 FROM (SELECT sleep(0))a) -- ", "error.subselect"))
    return rows


def sqli_stacked():
    rows = []
    for body, tag in [
        ("1; DROP TABLE users -- ", "drop"),
        ("1; DELETE FROM users; -- ", "delete"),
        ("1; SHOW TABLES; #", "show"),
        ("1;SELECT SLEEP(2) -- ", "sleep"),
        ("1 ; SHUTDOWN ; -- ", "shutdown"),  # gần miss: MySQL không có SHUTDOWN command
    ]:
        rows.append((body.strip(), f"stacked.{tag}"))
    return rows


def sqli_boolean():
    rows = []
    for q in QUOTES:
        for matcher, tag in [
            (f"1={q}1{q}", "eq-glue"),           # ' AND 1='1
            ("CHAR(97)=CHAR(97)", "char"),
            ("substring(username,1,1)='a", "substring"),
        ]:
            rows.append((f"{q} AND {matcher} -- ", f"boolean.{q}.{tag}"))
    rows.append(("admin' -- ", "boolean.login.admin"))
    rows.append(("alice' #", "boolean.login.hash"))
    rows.append(("alice' AND 1=1 -- ", "boolean.login.taut"))
    return rows


def sqli_time_based():
    rows = []
    for body, tag in [
        ("1 AND SLEEP(5)", "sleep5"),
        ("1 AND BENCHMARK(1000000,MD5('a'))", "benchmark"),
        ("1' AND (SELECT SLEEP(5)) -- ", "subsleep"),
        ("' OR SLEEP(4) -- ", "orsleep"),
        ("1 AND (SELECT * FROM (SELECT SLEEP(3))a)", "subsleep2"),
    ]:
        rows.append((body, f"time.{tag}"))
    return rows


def sqli_encoding():
    rows = []
    for space in ["%20", "+", "/**/", "%0a"]:
        rows.append((f"%27{space}OR{space}1=1{space}--", f"enc.wire{space[:3]}"))
    rows.append(("1%20OR%201%3D1", "enc.classic"))
    rows.append(("%27%20UNION%20SELECT%20id%20FROM%20users", "enc.union"))
    rows.append(("%22%3B%20SELECT%201%23", "enc.stacked"))
    rows.append((html.unescape("%27%20OR%201=1%20--"), "enc.resolved"))
    return rows


def sqli_double_encoding():
    rows = []
    for body, tag in [
        ("%2527%20OR%201=1%20--", "double-quote-plus"),
        ("%2527%2520OR%25201%253D1", "double-full"),
        ("%2527 OR 1=1 -- ", "double-half"),
        ("%2527%2520UNION%2520SELECT%2520id%2520FROM%2520users", "double-union"),
        ("%27%20%2527OR%201=1", "mixed"),
    ]:
        rows.append((body, f"doubleenc.{tag}"))
    return rows


def sqli_fragment():
    rows = []
    for body, tag in [
        ("UNION/**/SELECT/**/", "union"),
        ("SEL/**/ECT", "sel-split"),
        ("1/**/AND/**/1=1", "and-split"),
        ("1 UN/**/ION SE/**/LECT", "union-split"),
        ("-1/**/UNION/**/SELECT/**/user,pass/**/FROM/**/users--", "union-flatten"),
        ("AN/**/D 1=1", "and-split2"),
        ("1/**/OR/**/1=1--", "or-split"),
        ("1 /*&id=*/ OR 1=1", "hpp-style"),
    ]:
        rows.append((body.strip(), f"fragment.{tag}"))
    return rows


def sqli_casing():
    rows = []
    for kw in ["SeLeCt", "sElEcT", "SELECT", "select", "SeLeCt2"]:
        if kw.endswith("2"):
            continue
        rows.append((f"-1 {kw} id,username FROM users -- ", f"casing.select.{kw}"))
    for kw in ["UnIoN", "uNiOn", "UNION"]:
        rows.append((f"-1 {kw} SELECT id FROM users -- ", f"casing.union.{kw}"))
    rows.append(("-1 SeLeCt/**/FrOm users -- ", "casing.comment-mix"))
    rows.append(("1 OR/**/1=1--", "casing.or-comment"))
    return rows


SQLI_FAMILIES = {
    "tautology-s": sqli_tautology_string,
    "tautology-n": sqli_tautology_numeric,
    "union": sqli_union,
    "error": sqli_error_based,
    "stacked": sqli_stacked,
    "boolean": sqli_boolean,
    "time": sqli_time_based,
    "encoding": sqli_encoding,
    "double-encoding": sqli_double_encoding,
    "fragment": sqli_fragment,
    "casing": sqli_casing,
}


def search_terms():
    return [
        "laptop", "midi keyboard", "usb-c hub", "JBL? loud * speaker 40 W", "màn hình",
        "bàn phím cơ", "chuột gaming", "sạc nhanh OpAL 65 W", "tai nghe không dây",
        "USB-C cable", "adapter", "case máy tính", "loa Bluetooth", "lọc chọn đèn *",
        "C++ (beginner)", '"definition pdf"', "join them pristine", "page 17 (2nd ed.)",
        "scope làm 4 kênh", "bàn chải-ghế seat 45", "市长產品查詢", "450", "S", "%", "&",
        "—", "南ざ side", "3000 a", "6", "12-19-2026", "50% off", "1 liter *",
    ]


def benign_search():
    return [(t, "benign.search") for t in search_terms()]


def benign_notes():
    notes = [
        "price < 100 & stock > 0", "supplier: O'Reilly book", "title: C (object oriented) semantics.",
        "note\tshelf 3", "batch 224; shipment #732;", "== arrival 3 pm ==",
        "id-sticker 98A-12 (old)", "42", "wet floor 'wet' tag in place",
        "备注 & 价格 1800", "Nghi 'acid-coated rare' special", "<sup>regs</sup> ~1.3",
        "model-name / 3rd-gen / RFID",
    ]
    return [(n, "benign.notes") for n in notes]


def benign_code():
    values = [str(i) for i in range(1, 60)] + [
        "L-100", "SKU-2244", "SKU-1288", "PXL-751", "RGB2-021", "A-1", "item-7",
        "INV-2026-04", "12,4", "a2", "101,5", "0.5", "2.5", "1.2e3", "41973/2",
        "1,000,000", "5-2026",
    ]
    return [(c, "benign.code") for c in values]


def benign_login():
    creds = [("alice", "alice123"), ("bob", "bob123"), ("admin", "admin123"),
             ("test", "test123"), ("user1", "password1"), ("long", "longlab2026"),
             ("huy", "huylab2026"), ("hieu", "hieulab2026"), ("hoang", "hoang!lab"),
             ("hieuminh", "minh2026"), ("hnhoang", "autolab2"), ("nhs", "nhs.lab.2026"),
             ("pegawai_1", "sandbox"), ("legit-reviewer", "pw-9quite")]
    rows = [(f"{u} {p}", "benign.login.pair") for u, p in creds]
    rows += [(u, "benign.login.user") for u, p in creds]
    rows += [(p, "benign.login.pw") for u, p in creds]
    return rows


def benign_misc():
    misc = [
        "laptop bag", "search here", "q for query", "gaming chair", "e-scooter",
        "which monitor?", "search ? q", "poster A2", "tokina 11-16 f2.8",
        '"educ", "cdf"', "legit-user-level-4", "PRODUCT (2nd-hand)",
        "laptop; 97% out", "operation-line gas-type", "word = test",
        "a = 1 test", "value 1 OR 15-ton", "b == c sentence",
    ]
    return [(m, "benign.misc") for m in misc]


BENIGN_FAMILIES = {
    "benign.search": benign_search,
    "benign.notes": benign_notes,
    "benign.code": benign_code,
    "benign.login": benign_login,
    "benign.misc": benign_misc,
}


def row_values():
    """Trả về (text, label, family) không trùng lặp, thứ tự ổn định."""
    seen = set()
    out = [(text, "malicious", fam)
           for fam, gen in SQLI_FAMILIES.items()
           for text, variant in gen()
           if not (text in seen or seen.add(text))]
    out += [(text, "benign", fam)
            for fam, gen in BENIGN_FAMILIES.items()
            for text, variant in gen()
            if not (text in seen or seen.add(text))]
    return out


def main():
    import argparse
    import csv
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Xuất dataset CSV (tuỳ chọn)")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    rows = list(row_values())
    malicious = sum(1 for _, label, _ in rows if label == "malicious")
    benign = len(rows) - malicious
    families = len(SQLI_FAMILIES) + len(BENIGN_FAMILIES)
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["text", "label", "family"])
            writer.writerows(rows)
    print(f"n={len(rows)} malicious={malicious} benign={benign} families={families}")


if __name__ == "__main__":
    main()
