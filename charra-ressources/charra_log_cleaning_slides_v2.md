# Cleaning an IMA log entry: before and after

Real entries from one run — `ima_test_logs.txt` through `charra_sdk_redact_ima_log()`. Nothing here is illustrative.

An `ima-ng` entry has five parts:

    PCR | template_digest | template_name | file-content digest | pathname

## Example 1

    log_a  10 b82f92690571eb8f0b739e3ff99d21dd625d680cf7c976ae48824e04ad8bc104 ima-ng sha256:61cee375b05e8f2666a441322163788f470b2499d785d8d434ae5d68becfd541 /usr/lib/systemd/systemd
    log_r  10 b0c30a6d73544cf2d346fd8ef81a8f1a4a6324a60559c4f1d820068932fa7e6f ima-ng sha256:61cee375b05e8f2666a441322163788f470b2499d785d8d434ae5d68becfd541 4c28124bd3c470c77a11aaccda2ce1dd8c3eae8ca974830ad6988e690616dea8

+—————--+—————————————————————————--+—————————————————————————--+
|                 | `log_a` — Attester → RP                                                   | `log_r` — RP → Verifier                                                   |
+=================+=============================================================================+=============================================================================+
| PCR             | `10`                                                                        | `10`                                                                        |
+—————--+—————————————————————————--+—————————————————————————--+
| template_digest | `b82f92690571eb8f0b739e3ff99d21dd``625d680cf7c976ae48824e04ad8bc104`        | `b0c30a6d73544cf2d346fd8ef81a8f1a``4a6324a60559c4f1d820068932fa7e6f`        |
+—————--+—————————————————————————--+—————————————————————————--+
| template_name   | `ima-ng`                                                                    | `ima-ng`                                                                    |
+—————--+—————————————————————————--+—————————————————————————--+
| file digest     | `sha256:61cee375b05e8f2666a441322163788f``470b2499d785d8d434ae5d68becfd541` | `sha256:61cee375b05e8f2666a441322163788f``470b2499d785d8d434ae5d68becfd541` |
+—————--+—————————————————————————--+—————————————————————————--+
| **pathname**    | `/usr/lib/systemd/systemd`                                                  | `4c28124bd3c470c77a11aaccda2ce1dd``8c3eae8ca974830ad6988e690616dea8`        |
+—————--+—————————————————————————--+—————————————————————————--+
| pathname size   | 25 B                                                                        | 32 B                                                                        |
+—————--+—————————————————————————--+—————————————————————————--+

## Example 2

    log_a  10 c13322eacf6125ad462e483c199560ebf0ff04a02c387810a4752a2c232a4504 ima-ng sha256:0059699e84d5101ceb4c2f1535b2acfe59868f454eca4886cc29ddb69a772be6 /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
    log_r  10 9f606dca98d2c76b007e6ebf8284d089bdf1ef23334a4901b90b30a8ee38bd52 ima-ng sha256:0059699e84d5101ceb4c2f1535b2acfe59868f454eca4886cc29ddb69a772be6 a7676318ee3c6c12ad1fce0b024403f542c3a663f834ec0df0bb841e1303b21d

+—————--+—————————————————————————--+—————————————————————————--+
|                 | `log_a` — Attester → RP                                                   | `log_r` — RP → Verifier                                                   |
+=================+=============================================================================+=============================================================================+
| PCR             | `10`                                                                        | `10`                                                                        |
+—————--+—————————————————————————--+—————————————————————————--+
| template_digest | `c13322eacf6125ad462e483c199560eb``f0ff04a02c387810a4752a2c232a4504`        | `9f606dca98d2c76b007e6ebf8284d089``bdf1ef23334a4901b90b30a8ee38bd52`        |
+—————--+—————————————————————————--+—————————————————————————--+
| template_name   | `ima-ng`                                                                    | `ima-ng`                                                                    |
+—————--+—————————————————————————--+—————————————————————————--+
| file digest     | `sha256:0059699e84d5101ceb4c2f1535b2acfe``59868f454eca4886cc29ddb69a772be6` | `sha256:0059699e84d5101ceb4c2f1535b2acfe``59868f454eca4886cc29ddb69a772be6` |
+—————--+—————————————————————————--+—————————————————————————--+
| **pathname**    | `/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`                          | `a7676318ee3c6c12ad1fce0b024403f5``42c3a663f834ec0df0bb841e1303b21d`        |
+—————--+—————————————————————————--+—————————————————————————--+
| pathname size   | 49 B                                                                        | 32 B                                                                        |
+—————--+—————————————————————————--+—————————————————————————--+

## What changed, and what did not

+————————————-+———————————————————--+
| **PCR, template_name, file digest** | **identical** — the redaction does not touch them       |
+————————————-+———————————————————--+
| **pathname**                        | replaced by `SHA256(pathname ‖ salt)`, always 32 B        |
+————————————-+———————————————————--+
| **template_digest**                 | recomputed, because it must equal `SHA256(template_data)` |
+————————————-+———————————————————--+
