---
description: Safely fingerprint and decompile an Android artifact through the sandboxed MCP server.
argument-hint: <relative-path-to-apk|xapk|apks|apkm|jar|aar>
---

Analyze `$ARGUMENTS` using only the `safe-android-reverser` MCP server.

1. Call `health`. If the sandbox image/runtime is unavailable, stop and explain the setup step.
2. For APK/XAPK/APKS/APKM, call `fingerprint` first.
3. If the fingerprint identifies Flutter, React Native, Cordova/Capacitor, or Xamarin/.NET MAUI,
   explain that Java/Kotlin decompilation is not the primary path and do not wastefully continue.
4. Otherwise call `decompile` with the appropriate engine (`jadx` for Android packages,
   `vineflower` for JAR/AAR unless comparison is useful).
5. Call `extract_api` on the returned `job_id`.
6. Use `search_source` and `read_source_file` to investigate the highest-signal findings.
7. If Kotlin + moderate/high obfuscation is present, call `recover_kotlin_names` and treat results
   as confidence-scored candidates.
8. Return a concise architecture summary, API inventory, notable auth/network behavior, and the
   strongest source evidence.

Never call the legacy installer or reverse tools directly on the host.
