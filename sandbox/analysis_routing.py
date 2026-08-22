from __future__ import annotations

from copy import deepcopy
from typing import Any

ROUTER_SCHEMA_VERSION = 2

PROFILE_REGISTRY: dict[str, dict[str, Any]] = {
    "static-core": {
        "status": "available",
        "capability_id": "static-core",
        "trust_boundary": "static",
        "representation": "APK/DEX/Java/Kotlin/resources",
    },
    "framework-flutter": {
        "status": "declared",
        "capability_id": "framework-flutter",
        "trust_boundary": "framework-static",
        "representation": "Dart AOT/libapp.so/flutter_assets",
        "available_capabilities": [
            "artifact-inventory",
            "asset-inventory",
            "bounded-runtime-marker-scan",
            "dart-aot-index",
            "dart-xrefs",
            "dart-to-native-map",
            "flutter-network-model",
            "verified-runtime-cache-dispatch",
        ],
        "planned_capabilities": ["true-data-flow"],
    },
    "framework-react-native": {
        "status": "planned",
        "capability_id": "framework-react-native",
        "trust_boundary": "framework-static",
        "representation": "React Native JavaScript bundle/source maps/native bridge",
    },
    "framework-hermes": {
        "status": "planned",
        "capability_id": "framework-hermes",
        "trust_boundary": "framework-static",
        "representation": "Hermes bytecode/JavaScript bundle",
    },
    "framework-il2cpp": {
        "status": "planned",
        "capability_id": "framework-il2cpp",
        "trust_boundary": "framework-static",
        "representation": "IL2CPP metadata/native code",
    },
    "framework-dotnet": {
        "status": "planned",
        "capability_id": "framework-dotnet",
        "trust_boundary": "framework-static",
        "representation": ".NET managed assemblies",
    },
    "web-assets": {
        "status": "planned",
        "capability_id": "web-assets",
        "trust_boundary": "framework-static",
        "representation": "HTML/JavaScript/web assets",
    },
    "native": {
        "status": "planned",
        "capability_id": "native",
        "trust_boundary": "native-static",
        "representation": "ELF/JNI/native code",
    },
    "dynamic": {
        "status": "planned",
        "capability_id": "dynamic",
        "trust_boundary": "dynamic-opt-in",
        "representation": "runtime observations",
    },
}


def profile_registry() -> dict[str, dict[str, Any]]:
    return deepcopy(PROFILE_REGISTRY)


def _contains_native_library(fingerprint: dict[str, Any], basename: str) -> bool:
    suffix = "/" + basename
    return any(
        str(item).endswith(suffix) for item in fingerprint.get("native_libraries", [])
    )


def _secondary(profile: str, purpose: str) -> dict[str, str]:
    return {
        "profile": profile,
        "status": PROFILE_REGISTRY[profile]["status"],
        "capability_id": PROFILE_REGISTRY[profile]["capability_id"],
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
        "primary_capability_id": primary["capability_id"],
        "primary_profile_status": primary["status"],
        "primary_representation": primary_representation,
        "secondary_profiles": secondary_profiles,
        "allow_java_decompile_as_primary": allow_java_decompile_as_primary,
        "strategy": strategy,
        "limitations": limitations or [],
    }


def route_fingerprint(fingerprint: dict[str, Any]) -> dict[str, Any]:
    """Choose an analysis capability from bounded fingerprint evidence.

    This router describes deterministic topology only. Runtime readiness is a
    host control-plane concern and must be discovered separately. A declared or
    planned framework capability remains primary instead of silently falling
    back to JADX and pretending host-shell code contains business logic.
    """

    framework = fingerprint.get("framework") or {}
    framework_type = str(framework.get("type") or "Unknown")
    normalized = framework_type.lower()

    if _contains_native_library(fingerprint, "libil2cpp.so"):
        return _route(
            framework_id="unity-il2cpp",
            framework_type="Unity IL2CPP",
            primary_profile="framework-il2cpp",
            primary_representation=["global-metadata.dat", "libil2cpp.so"],
            strategy=(
                "Recover IL2CPP metadata first, then correlate recovered methods "
                "with localized native code."
            ),
            secondary_profiles=[
                _secondary("native", "localized native CFG/XREF/decompilation"),
                _secondary(
                    "static-core",
                    "Android host shell, manifest, resources and components",
                ),
            ],
            allow_java_decompile_as_primary=False,
            limitations=["The framework-il2cpp capability is planned."],
        )

    if normalized.startswith("flutter") or _contains_native_library(
        fingerprint, "libflutter.so"
    ):
        return _route(
            framework_id="flutter",
            framework_type=framework_type,
            primary_profile="framework-flutter",
            primary_representation=[
                "libapp.so",
                "libflutter.so",
                "assets/flutter_assets",
            ],
            strategy=(
                "Inspect Flutter artifacts/runtime first, then let the host control "
                "plane dispatch the framework-flutter capability for bounded Dart "
                "AOT analysis of libapp.so; Java/Kotlin remains host-shell evidence only."
            ),
            secondary_profiles=[
                _secondary(
                    "static-core",
                    "Android host shell, manifest, resources and plugin bridges",
                ),
                _secondary(
                    "native", "localized native analysis after Dart-level recovery"
                ),
                _secondary(
                    "dynamic", "targeted runtime verification when explicitly enabled"
                ),
            ],
            allow_java_decompile_as_primary=False,
            limitations=[
                "Runtime readiness is discovered by the host control plane; the router only declares the framework-flutter capability.",
                "Exact Dart AOT analysis requires a matching immutable runtime-cache image; a cache miss never triggers an in-sandbox build or download.",
                "Dart call/XREF adjacency is not proof of interprocedural value flow; true data-flow analysis remains a later capability.",
            ],
        )

    if normalized.startswith("react native") or "hermes" in normalized:
        hermes_proven = _contains_native_library(fingerprint, "libhermes.so") or (
            "hermes" in normalized
        )
        if hermes_proven:
            return _route(
                framework_id="react-native-hermes",
                framework_type=framework_type,
                primary_profile="framework-hermes",
                primary_representation=[
                    "Hermes bytecode",
                    "assets/index.android.bundle",
                    "source maps",
                ],
                strategy=(
                    "Analyze Hermes bytecode/JavaScript representation first and "
                    "use DEX only for host/native bridge evidence."
                ),
                secondary_profiles=[
                    _secondary("static-core", "Android host shell and bridge code"),
                    _secondary(
                        "native", "localized React Native/Hermes native bridge analysis"
                    ),
                ],
                allow_java_decompile_as_primary=False,
                limitations=["The framework-hermes capability is planned."],
            )

        return _route(
            framework_id="react-native",
            framework_type=framework_type,
            primary_profile="framework-react-native",
            primary_representation=[
                "assets/index.android.bundle",
                "JavaScript bundle",
                "source maps",
            ],
            strategy=(
                "Inspect the React Native JavaScript representation and identify "
                "the runtime before selecting a Hermes-specific analyzer."
            ),
            secondary_profiles=[
                _secondary("static-core", "Android host shell and bridge code"),
                _secondary("native", "localized React Native native bridge analysis"),
            ],
            allow_java_decompile_as_primary=False,
            limitations=[
                "Hermes was not proven by the current fingerprint; do not assume Hermes bytecode."
            ],
        )

    if normalized.startswith("xamarin") or ".net maui" in normalized:
        return _route(
            framework_id="dotnet-android",
            framework_type=framework_type,
            primary_profile="framework-dotnet",
            primary_representation=["managed assemblies", "Mono/.NET runtime metadata"],
            strategy=(
                "Analyze managed assemblies with an IL-aware backend; use JADX "
                "only for the Android host shell."
            ),
            secondary_profiles=[
                _secondary(
                    "static-core", "Android host shell, manifest and resources"
                ),
                _secondary("native", "localized runtime/JNI analysis"),
            ],
            allow_java_decompile_as_primary=False,
            limitations=["The framework-dotnet capability is planned."],
        )

    if normalized.startswith("cordova") or normalized.startswith("capacitor"):
        return _route(
            framework_id="cordova-capacitor",
            framework_type=framework_type,
            primary_profile="web-assets",
            primary_representation=[
                "assets/www",
                "assets/public",
                "JavaScript/HTML",
            ],
            strategy=(
                "Inspect packaged web assets first; use Java/Kotlin for WebView "
                "host and plugin bridge evidence."
            ),
            secondary_profiles=[
                _secondary(
                    "static-core", "Android host shell, WebView and plugin bridges"
                )
            ],
            allow_java_decompile_as_primary=False,
            limitations=["The web-assets semantic capability is planned."],
        )

    if normalized.startswith("native android"):
        return _route(
            framework_id="native-android",
            framework_type=framework_type,
            primary_profile="static-core",
            primary_representation=["DEX", "Java/Kotlin", "Android resources"],
            strategy=(
                "Proceed with DEX semantic indexing and targeted JADX/Vineflower "
                "decompilation."
            ),
            secondary_profiles=[
                _secondary(
                    "native", "JNI/native libraries when localized evidence requires it"
                )
            ],
            allow_java_decompile_as_primary=True,
        )

    return _route(
        framework_id="unknown",
        framework_type=framework_type,
        primary_profile="static-core",
        primary_representation=["APK/DEX/resources"],
        strategy=(
            "Use bounded static-core triage, preserve uncertainty, and do not "
            "treat Java/Kotlin decompilation as proof of the primary business-logic representation."
        ),
        secondary_profiles=[_secondary("native", "native libraries when present")],
        allow_java_decompile_as_primary=False,
        limitations=["Framework fingerprint did not match a dedicated route."],
    )
