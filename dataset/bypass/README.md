# Corpus bypass SQLi — 4 nhóm kỹ thuật (schema per `docs/interfaces.md` §1)

Bốn thư mục, một file `cases.json` mỗi nhóm. **Quy tắc viết cặp**: mỗi nhóm đủ
benign (bảo chứng CRS không chặn nhầm) và malicious (bảo chứng app thực thi khi
đi direct), mọi case có ID duy nhất trên toàn bộ corpus, `technique` phải
khớp tên thư mục.

## Trường hợp đặc biệt schema

| Trường | Ý nghĩa |
|---|---|
| `transport: "chunked"` (tuỳ chọn) | runner gửi POST **Transfer-Encoding: chunked** (http.client encode_chunked); không có → form/urlencoded chuẩn |
| `control: "none"` (tuỳ chọn) | case cố ý NGHỊ designed mà app không thể thực thi payload (Flask bỏ ignore / literal-string) — runner yá như "hợp lệ control" khi `semantic_effect == False` và Không sql_error; các case này KHÔNG bao giờ tính true_bypass; ghi rõ ở note |
| không có control (mặc định) | benign phải `semantic_effect=false, sql_error=null`; malicious phải `semantic_effect=true, sql_error=null` |

Lý do thêm `control`: một số kỹ thuật (double-encoding, GET-with-body,
content-type confusion) chỉ tạo được khác nhau ở phía WAF vs app — nếu vẫn ép
"app chắc chắn phải thực thi", runner sẽ đánh fail nhầm. Thêm `control: none`
để ghi đúng chuẩn: WAF pass nhưng app không thực thi ==
"pass_without_effect", không phải bypass.

## Nhóm & vài viên đá chính

| Nhóm | Neutral | Malicious | ý nghĩa |
|---|---|---|---|
| hpp | 3 | 3 | Duplicate key; Flask first-value-wins vs CRS merge ARGS: CRS cộng điểm trên mọi occurrence nên HPP khó đủ hiệu (giả thuyết cần đo) |
| double-encoding | 2 | 4 | DE/triple-encoded/UTF-8 overlong; **vì Flask không decode lần nữa nên không thể true bypass** — đo coverage transform `t:urlDecodeUni` của CRS |
| case-comment | 3 | 5 | Case variation + `/**/` comment whítesspace — kỹ thuật mutation WAF-A-MoLE; app executible để có oracle đủ |
| parsing-discrepancy | 3 | 3 | Chunked TE, GET-with-form-body, Content-Type mismatch — vùng WAF thấy khác app |

## Đảm bảo chất lượng

- JSON hợp lệ, `label` in `benign/malicious`, `method` in `GET/POST`, path
  chỉ `/search`, `/product`, `/login` của lab web-app.
- Payload ở `params`/`form` là **danh sách cặp có thứ tự** — runner không được
  collapse thành dict, giữ nguyên trật tự (HPP cần).
- Mỗi file độc lập: có thể chạy chọn nhóm kỹ thuật nhờ `--technique`.
- Corpus chỉ gắn với các endpoints lab; KHÔNG dùng để tấn công bên ngoài.
- Ethical: payload chỉ ví dụ, không dùng đánh đổi tài khoản thật trong
  seed (`docker/db/init/02-seed.sql`).

## XSS corpus v2 (10 cases)

XSS fixtures extend the existing four technique files; the 26 SQLi fixtures
remain in their original v1 format. The combined corpus has 36 cases: 4 benign
and 6 malicious XSS cases use the v2 envelope (`request`, `vuln`, `family`,
`expected_waf_outcome`, and `expected_app_effect`).

Validate the complete corpus from the repository root:

```powershell
python dataset/bypass/validate_corpus.py
```

The validator uses only Python's standard library. It checks JSON syntax,
global ID uniqueness, technique-to-directory consistency, both schema versions,
ordered parameter/form pairs, endpoint and enum constraints, the independent
WAF/app expectation fields, and the required 26 v1 + 10 v2 / 4 benign + 6
malicious counts.

| Family | Payload mechanism | Cases |
|---|---|---:|
| `xss.tag` | Script/tag injection, including duplicate-parameter and body parsing cases | 3 |
| `xss.event` | Event-handler injection | 1 |
| `xss.encoding` | Percent-encoded and multiply encoded input | 2 |
| `xss.case-comment` | Case and comment mutation | 1 |
| `benign.html` | Harmless HTML and formatting text | 1 |
| `benign.lt` | Benign less-than/greater-than text | 2 |

The `technique` field describes wire construction (`hpp`, `double-encoding`,
`case-comment`, or `parsing-discrepancy`); `family` describes the payload
mechanism used for grouping and generalization. The two labels answer different
questions and should not be collapsed.

`expected_waf_outcome` records a test hypothesis about the WAF. It does not
describe application behavior. `expected_app_effect` describes the direct
`/comment` application control: `executed`, `not_executed`, or `none`; benign
cases always use `none`. A blocked WAF expectation may coexist with a direct
app effect of `executed`. Only observed browser verification can establish
JavaScript execution; corpus labels and HTTP reflection alone do not establish
a WAF bypass. Cases with a `control` also specify `/comment-escaped` and the
properties that the escaped control must not reflect or execute.

The XSS sink is intentionally vulnerable and exists only in the group's local
Docker lab. Use these cases only against the lab services owned by the group;
do not send them to public or third-party systems.
