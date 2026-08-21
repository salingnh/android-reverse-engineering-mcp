from __future__ import annotations

from copy import deepcopy
from typing import Any

ROUTER_SCHEMA_VERSION = 1

PROFILE_REGISTRY: dict[str, dict[str, Any]] = {
    "static-core": {
        "status": "available",
        "trust_boundary": "static",
        "representation": "APK/DEX/Java/Kotlin/resources",
    },
    "framework-flutter": {
        "status": "planned",
        "trust_boundary": "framework-static",
        "representation": "Dart AOT/libapp.so/flutter_assets",
    },
    "framework-hermes": {
        "status": "planned",
        "trust_boundary": "framework-static",
        "representation": "Hermes/JavaScript bundle",
    },
    "framework-il2cpp": {
        "status": "planned",
        "trust_boundary": "framework-static",
        "representation": "IL2CPP metadata/native code",
    },
    "framework-dotnet": {
        "status": "planned",
        "trust_boundary": "framework-static",
        "representation": ".NET managed assemblies",
    },
    "web-assets": {
        "status": "planned",
        "trust_boundary": "framework-static",
        "representation": "HTML/JavaScript/web assets",
    },
    "native": {
        "status": "planned",
        "trust_boundary": "native-static",
        "representation": "ELF/JNI/native code",
    },
    "dynamic": {
        "status": "planned",
        "trust_boundary": "dynamic-opt-in",
        "representation": "runtime observations",
    },
}


def profile_registry() -> dict[str, dict[str, Any]]:
    return deepcopy(PROFILE_REGISTRY)


def _contains_native_library(fingerprint: dict[str, Any], basename: str) -> bool:
    suffix = "/" + basename
    return any(str(item).endswith(suffix) for item in fingerprint.get("native_libraries", []))


def _secondary(profile: str, purpose: str) -> dict[str, str]:
    return {
        "profile": profile,
        "status": PROFILE_REGISTRY[profile]["status"],
        "purpose": purpose,
    }


def _route(
    *,
    framework_id: str,
    framework_type: str,
    primary_profile: str,
    primary_representation: list[str],
    strategy: str,
    secondary_profiles: list[dict[str, str]],
    allow_java_decompile_as_primary: bool,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    primary = PROFILE_REGISTRY[primary_profile]
    return {
        "schema_version": ROUTER_SCHEMA_VERSION,
        "framework_id": framework_id,
        "framework_type": framework_type,
        "primary_profile": primary_profile,
        "primary_profile_status": primary["status"],
        "primary_representation": primary_representation,
        "secondary_profiles": secondary_profiles,
        "allow_java_decompile_as_primary": allow_java_decompile_as_primary,
        "strategy": strategy,
        "limitations": limitations or [],
    }


def route_fingerprint(fingerprint: dict[str, Any]) -> dict[str, Any]:
    """Choose an analysis profile from bounded fingerprint evidence.

    The router deliberately distinguishes framework identification from analyzer
    availability. A planned framework profile is returned as planned instead of
    silently falling back to JADX and pretending that host-shell code is the
    application's primary business logic.
    """

    framework = fingerprint.get("framework") or {}
    framework_type = str(framework.get("type") or "Unknown")
    normalized = framework_type.lower()

    # IL2CPP can otherwise look like a native Android shell when only DEX
    # descriptors are considered. Native-library evidence is strong enough to
    # route it explicitly even before the dedicated IL2CPP analyzer exists.
    if _contains_native_library(fingerprint, "libil2cpp.so"):
        return _route(
            framework_id="unity-il2cpp",
            framework_type="Unity IL2CPP",
            primary_profile="framework-il2cpp",
            primary_representation=["global-metadata.dat", "libil2cpp.so"],
            strategy="Recover IL2CPP metadata first, then correlate recovered methods with localized native code.",
            secondary_profiles=[
                _secondary("native", "localized native CFG/XREF/decompilation"),
                _secondary("static-core", "Android host shell, manifest, resources and components"),
            ],
            allow_java_decompile_as_primary=False,
            limitations=["The framework-il2cpp profile is not bundled in the current static image."],
        )

    if normalized.startswith("flutter") or _contains_native_library(fingerprint, "libflutter.so"):
        return _route(
            framework_id="flutter",
            framework_type=framework_type,
            primary_profile="framework-flutter",
            primary_representation=["libapp.so", "libflutter.so", "assets/flutter_assets"],
            strategy="Use Dart AOT-aware analysis of libapp.so and Flutter assets; inspect Java/Kotlin only as host-shell evidence.",
            secondary_profiles=[
                _secondary("static-core", "Android host shell, manifest, resources and plugin bridges"),
                _secondary("native", "localized native analysis after Dart-level recovery"),
                _secondary("dynamic", "targeted runtime verification when explicitly enabled"),
            ],
            allow_java_decompile_as_primary=False,
            limitations=["The framework-flutter analyzer profile is the next P0 capability and may not yet be available in this release."],
        )

    if normalized.startswith("react native") or "hermes" in normalized:
        return _route(
            framework_id="react-native-hermes",
            framework_type=framework_type,
            primary_profile="framework-hermes",
            primary_representation=["assets/index.android.bundle", "Hermes bytecode", "source maps"],
            strategy="Analyze Hermes/JavaScript representation first and use DEX only for host/native bridge evidence.",
            secondary_profiles=[
                _secondary("static-core", "Android host shell and bridge code"),
                _secondary("native", "localized React Native/Hermes native bridge analysis"),
            ],
            allow_java_decompile_as_primary=False,
            limitations=["The framework-hermes profile is planned and not bundled in the current static image."],
        )

    if normalized.startswith("xamarin") or ".net maui" in normalized:
        return _route(
            framework_id="dotnet-android",
            framework_type=framework_type,
            primary_profile="framework-dotnet",
            primary_representation=["managed assemblies", "Mono/.NET runtime metadata"],
            strategy="Analyze managed assemblies with an IL-aware backend; use JADX only for the Android host shell.",
            secondary_profiles=[
                _secondary("static-core", "Android host shell, manifest and resources"),
                _secondary("native", "localized runtime/JNI analysis"),
            ],
            allow_java_decompile_as_primary=False,
            limitations=["The framework-dotnet profile is planned and not bundled in the current static image."],
        )

    if normalized.startswith("cordova") or normalized.startswith("capacitor"):
        return _route(
            framework_id="cordova-capacitor",
            framework_type=framework_type,
            primary_profile="web-assets",
            primary_representation=["assets/www", "assets/public", "JavaScript/HTML"],
            strategy="Inspect packaged web assets first; use Java/Kotlin for WebView host and plugin bridge evidence.",
            secondary_profiles=[_secondary("static-core", "Android host shell, WebView and plugin bridges")],
            allow_java_decompile_as_primary=False,
            limitations=["A dedicated web-assets semantic index is planned."],
        )

    if normalized.startswith("native android"):
        return _route(
            framework_id="native-android",
            framework_type=framework_type,
            primary_profile="static-core",
            primary_representation=["DEX", "Java/Kotlin", "Android resources"],
            strategy="Proceed with DEX semantic indexing and targeted JADX/Vineflower decompilation.",
            secondary_profiles=[_secondary("native", "JNI/native libraries when localized evidence requires it")],
            allow_java_decompile_as_primary=True,
        )

    return _route(
        framework_id="unknown",
        framework_type=framework_type,
        primary_profile="static-core",
        primary_representation=["APK/DEX/resources"],
        strategy="Use bounded static-core triage, preserve uncertainty, and avoid assuming Java/Kotlin contains all business logic.",
        secondary_profiles=[_secondary("native", "native libraries when present")],
        allow_java_decompile_as_primary=True,
        limitations=["Framework fingerprint did not match a dedicated route."],
    )
