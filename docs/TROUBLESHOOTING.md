# Diagnose a scanner without discarding its data

Use the existing approved scanner and its same-installation recovery material. Reserve maintenance before changing services. A public bug report should contain tool/engine versions, fixed error codes, sanitized counts, timestamps and artifact hashes; raw logs and exports can contain activation codes, session tokens, internal targets and account data. Keep those private.

## What a successful check establishes

| Evidence | Establishes | Still requires separate acceptance |
| --- | --- | --- |
| Official package SHA-256 and native version | The selected package/binary was installed and identified | Registration, library readiness, target scanning |
| Positive plugin/family counts and matching loaded set | A library is currently loaded | Every plugin runs, online feed delivery, scan accuracy |
| Native registration check | Its current eligibility classification | A new feed was actually downloaded or a target scan passed |
| Trusted HTTPS response from inside the scanner's network | That hostname/IP/port responds through that path | Discovery and vulnerability checks succeed in the Nessus scheduler |
| Standalone NASL compile/command exit | That exact command completed | Full discovery context, scheduler execution and report findings |
| Fresh native scan history plus terminal status and export | A specific managed run produced inspectable output | Coverage, completion reason and findings must still be reviewed |

`doctor` sets `targetScanAcceptanceProven=false` because it never launches target scans. A canceled run with only TCP scanner output is not a clean assessment, even when its ports were correctly detected. A native status of completed is also insufficient by itself if a run was stopped early, hosts were falsely marked dead or plugins did not run.

## Feed download failed while a library is loaded

Run `doctor` on a supported native host using the trusted certificate hostname and, if needed, your approved CA file:

```bash
sudo python3 -m nessus_safe doctor \
  --url https://scanner.example.org:8834 \
  --ca-file /secure-ca/nessus-ca.pem
```

From 0.2.3, the narrow diagnostic exception requires all of the following in the normal HTTPS JSON response:

- Native status `download-failed`.
- `detailed_status.login_status=allow`.
- Engine and database component statuses both `ready`.
- Feed component status `downloading-failed` or `download-failed`.

The tool can then read inventory and scan metadata, report `api.readiness.maintenanceReady=false`, retain a loaded compiled library and exit 3. Raw status messages are excluded. A missing or loading component, another unready status, TLS error, HTTP error or failed authenticated request still refuses. A JSON `code` field is not an HTTP status: an actual HTTP503 remains a refused HTTP request.

No maintenance snapshot accepts this diagnostic exception. Do not run an update or restore merely because the read-only diagnostic could log in. Distinguish upstream reachability, valid same-installation registration and the engine's library state. [Local reuse](LOCAL_REUSE.md) explains why another cache copy cannot establish registration validity.

## Narrow-port scans waiting on other ports

For an authorized assessment limited to specific TCP ports, inspect the saved scan configuration and current native progress. Some service checks may attempt their own ports when unscanned ports are considered unknown. In one operational reproduction, TCP connections outside the selected port range waited behind a deliberately narrow firewall.

If that behavior is confirmed for your run, stop only that authorized test through the normal interface, preserve its history/export, and review **Discovery → Port Scanning → Consider unscanned ports as closed** (`unscanned_closed=yes`). Read back the saved range and option. This is a candidate correction for observed out-of-range waits, not a universal cure and not permission to widen the assessment scope. It also makes unscanned ports unavailable to checks; describe that coverage limit in the assessment.

Keep safe checks on, use a bounded host/check concurrency suitable for the target, and keep UDP, brute force, denial-of-service and authenticated checks outside the run unless separately authorized. A large worker/thread ceiling does not justify overwhelming a target. This project does not configure scans or firewall rules automatically.

Establish a positive control from the same scanner network before retrying. Use the approved hostname/IP binding and full certificate validation. An HTTP200 from an operator workstation proves a different network path. If a temporary network allowance is authorized, limit its source/destinations/ports/duration, track its own objects, and verify their removal without replacing unrelated firewall state.

## `IP tracking irregularities detected`

This native Nessus refusal has been observed after a managed test run. A native log may also report `Potential IP limit abuse detected`. Treat that as a vendor integrity/licensing guard, not proof that a particular IP quota has been exceeded: the observed count can be below the advertised ceiling. Its internal cause is not established by that message alone.

Preserve the current scanner, registration/identity, users, results and backup. Capture the fixed error text, product/engine version, time, relevant counts and whether a fresh history was created. Do not repeatedly launch identical scans when the refusal is unchanged. Do not clear tracking databases/checkpoints, edit a signed preference, clone another installation's registration or patch the guard. This project does not implement a bypass or claim a source-level repair to the proprietary Nessus engine.

Check the legitimate product status through the owner's Tenable account and obtain the supported same-installation recovery procedure or vendor assistance. Tenable documents [activation management](https://docs.tenable.com/nessus/10_9/Content/ManageActivationCode.htm) and [account product management](https://docs.tenable.com/quick-reference/account-management/Content/products.htm); the general reset-activation procedure is not a verified cure for this exact error. Do not run it blindly or send activation codes in a public issue. The open-source operations tool itself has no activation-code requirement; the installed vendor product has its own registration rules.

## Resume and accept a real assessment

Once the native refusal is legitimately resolved and the operator has authorized scope and connectivity:

1. Reuse the existing approved scan, preserving its previous histories and results. Verify targets, safe checks, exact ports, concurrency and credentials before launch.
2. Verify scanner-network positive controls, then launch once through the product's supported interface. An edition with unavailable scan API must not be forced through hidden API flags.
3. Match a genuinely new history ID/UUID and native progress. Require the correct terminal completion reason and read back the exact history's native export.
4. Review host liveness, discovered services and actual plugin outputs. Separate low coverage, skipped prerequisites, canceled work and target vulnerabilities. An empty result is not automatically safe.
5. Use verified findings as inputs to later authorized stages. Keep compliance, cloud, credentialed and edition-gated capabilities explicitly pending when their prerequisites are absent.
6. Roll back temporary network/test changes and verify readback. Keep an assessment report separate from this tool's fixture-test report.

Do not restore an old snapshot over fresh work as an incidental troubleshooting step. Follow [recovery](RECOVERY.md), preserve the displaced current tree and review binary/package-manager compatibility before a selected rollback.

## خلاصهٔ فارسی

ابتدا وضعیت کتابخانه، ثبت محصول، مسیر شبکه و خروجی اسکن را جدا بررسی کنید. پاسخ API یا شمار زیاد افزونه‌ها به معنی تکمیل ارزیابی نیست. در خطای Feed، نسخهٔ ۰٫۲٫۳ فقط وقتی موتور و پایگاه آماده و ورود مجاز باشد تشخیص خواندنی انجام می‌دهد؛ مجوز نگهداری یا اسکن صادر نمی‌کند.

برای انتظار روی پورت‌های خارج از محدوده، پس از تأیید شاهد و حفظ تاریخچه، گزینهٔ بسته‌محسوب‌کردن پورت‌های بررسی‌نشده را در همان اسکن بازبینی و ذخیره کنید. اثر واقعی آن باید در اجرای تازه سنجیده شود. خطای `IP tracking irregularities detected` کنترل بومی Nessus است؛ پاک‌کردن پایگاه ردیابی یا تغییر امضا راه بازیابی این ابزار نیست. ثبت و هویت نصب حفظ و مسیر پشتیبانی‌شدهٔ مالک/سازنده دنبال شود.

پس از رفع معتبر مانع، اجرای تازه باید تاریخچهٔ جدید، پایان درست و export قابل بررسی با خروجی واقعی افزونه‌ها داشته باشد؛ سپس مراحل بعد بر اساس همان خروجی‌ها ادامه پیدا کنند. اعتبارنامه، کد فعال‌سازی، گزارش خام و نشانی‌های داخلی را وارد Git عمومی نکنید.
