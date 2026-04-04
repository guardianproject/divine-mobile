// ABOUTME: Configuration for ProofSign device-authenticated C2PA signing server
// ABOUTME: Provides server URL, GCP project number, and optional dev bearer token

/// Configuration for the ProofSign device-authenticated signing service.
///
/// ProofSign enables C2PA content credential signing with device attestation
/// (App Attest on iOS, Play Integrity / Key Attestation on Android).
class ProofSignConfig {
  const ProofSignConfig({
    required this.serverUrl,
    required this.gcpProjectNumber,
    required this.appleAppId,
    this.bearerToken,
  });

  /// ProofSign server URL
  final String serverUrl;

  /// Google Cloud project number for Play Integrity verification
  final String gcpProjectNumber;

  /// Apple Team ID + Bundle ID for App Attest (e.g., "XXXXXXXXXX.co.example.app")
  final String appleAppId;

  /// Optional bearer token for development/testing (bypasses device auth).
  /// When set, C2paSigningService uses CallbackSigner with this token in
  /// the Authorization header instead of requiring a registered device.
  final String? bearerToken;

  /// Whether a bearer token is configured for dev/testing
  bool get hasDevToken => bearerToken != null && bearerToken!.isNotEmpty;

  /// Environment-based configuration using compile-time constants.
  static const ProofSignConfig fromEnvironment = ProofSignConfig(
    serverUrl: String.fromEnvironment('PROOFSIGN_SERVER_URL'),
    gcpProjectNumber: String.fromEnvironment(
      'PROOFSIGN_GCP_PROJECT_NUMBER',
    ),
    appleAppId: String.fromEnvironment('PROOFSIGN_APPLE_APP_ID'),
    bearerToken: String.fromEnvironment('PROOFSIGN_BEARER_TOKEN'),
  );

  /// When true, forces the Android client to use hardware Key Attestation
  /// even on devices with Play Services. Useful for testing the Key
  /// Attestation path on normal Android devices without degoogling them.
  static const bool forceKeyAttestation = bool.fromEnvironment(
    'PROOFSIGN_FORCE_KEY_ATTESTATION',
  );

  /// Whether ProofSign is configured (server URL is set)
  bool get isConfigured => serverUrl.isNotEmpty;
}
