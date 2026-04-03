// ABOUTME: Abstract interface for platform-specific device authentication providers
// ABOUTME: Used by C2paSigningService to add device attestation to signing requests

import 'package:http/http.dart' as http;

/// Abstract interface for device authentication providers.
///
/// Each platform implements this differently:
/// - iOS: App Attest (DCAppAttestService via Secure Enclave)
/// - Android with Play Services: Play Integrity API
/// - Android without Play Services: Hardware Key Attestation
abstract class DeviceAuthProvider {
  /// Build the JSON body for a C2PA signing request with device auth fields.
  ///
  /// The [claim] is the base64-encoded data to sign.
  /// The [platform] is 'ios' or 'android'.
  Future<Map<String, dynamic>> buildSigningRequest({
    required String claim,
    required String platform,
  });

  /// Additional HTTP headers for signing requests (e.g., bearer tokens).
  Map<String, String> additionalHeaders();

  /// Register this device with the ProofSign server (one-time setup).
  ///
  /// Throws on failure. Call [isRegistered] to check status before calling.
  Future<void> register(String serverUrl, http.Client client);

  /// Refresh device verification (called when server returns 428).
  Future<void> refreshVerification();

  /// Whether this device has completed registration with the server.
  bool get isRegistered;
}

/// Exception thrown by device authentication providers.
class DeviceAuthException implements Exception {
  const DeviceAuthException(this.message);

  final String message;

  @override
  String toString() => 'DeviceAuthException: $message';
}
