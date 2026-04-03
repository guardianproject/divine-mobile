// ABOUTME: iOS App Attest device authentication provider for ProofSign
// ABOUTME: Uses DCAppAttestService via method channel for Secure Enclave attestation

import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:openvine/services/device_auth/device_auth_provider.dart';
import 'package:openvine/utils/unified_logger.dart';

/// iOS App Attest device authentication provider.
///
/// Uses DCAppAttestService (Secure Enclave) to generate attestations and
/// assertions that prove the request comes from a genuine app on genuine
/// Apple hardware.
///
/// Flow:
/// 1. [register]: Generate key -> attest key -> register with server
/// 2. [buildSigningRequest]: Generate assertion bound to signing data
class AppAttestProvider implements DeviceAuthProvider {
  AppAttestProvider({required this.appId});

  static const _channel = MethodChannel('com.openvine/app_attest');
  static const _tag = 'AppAttestProvider';
  static const _registrationTimeout = Duration(seconds: 30);

  /// Apple Team ID + Bundle ID (e.g., "XXXXXXXXXX.co.example.app")
  final String appId;

  String? _keyId;

  /// The App Attest key ID, or null if not registered.
  String? get keyId => _keyId;

  @override
  bool get isRegistered => _keyId != null;

  @override
  Future<void> register(String serverUrl, http.Client client) async {
    Log.info('Registering device with App Attest', name: _tag);

    // 1. Generate key in Secure Enclave
    final keyId = await _channel.invokeMethod<String>('generateKey');
    if (keyId == null) {
      throw const DeviceAuthException('App Attest key generation returned null');
    }

    // 2. Create challenge for attestation
    // The App Attest registration endpoint validates the challenge
    // by verifying the attestation object which embeds the challenge hash.
    // The server stores the key_id and public key extracted from the
    // attestation for later assertion verification.
    final challenge = _generateChallenge();
    final challengeHash = sha256.convert(utf8.encode(challenge)).bytes;

    // 3. Get attestation from Secure Enclave using server challenge
    final attestation = await _channel.invokeMethod<Uint8List>(
      'attestKey',
      {'keyId': keyId, 'clientDataHash': Uint8List.fromList(challengeHash)},
    );
    if (attestation == null) {
      throw const DeviceAuthException('App Attest attestation returned null');
    }

    // 4. Register attestation with ProofSign server
    final response = await client
        .post(
          Uri.parse('$serverUrl/api/v1/app_attest/register'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'key_id': keyId,
            'attestation_object': base64Encode(attestation),
            'challenge': challenge,
            'bundle_id': appId,
          }),
        )
        .timeout(_registrationTimeout);

    if (response.statusCode != 200) {
      throw DeviceAuthException(
        'App Attest registration failed: '
        '${response.statusCode} ${response.body}',
      );
    }

    _keyId = keyId;
    Log.info('App Attest registration complete', name: _tag);
  }

  @override
  Future<Map<String, dynamic>> buildSigningRequest({
    required String claim,
    required String platform,
  }) async {
    if (_keyId == null) {
      throw const DeviceAuthException(
        'Device not registered. Call register() first.',
      );
    }

    final dataBytes = base64Decode(claim);
    final challengeBase64 = base64Encode(sha256.convert(dataBytes).bytes);

    // Build client data JSON that binds the assertion to the data being signed
    final clientDataJson = jsonEncode({'challenge': challengeBase64});
    final clientDataHash = sha256.convert(utf8.encode(clientDataJson)).bytes;

    // Generate assertion bound to this data via Secure Enclave
    final assertion = await _channel.invokeMethod<Uint8List>(
      'generateAssertion',
      {'keyId': _keyId, 'clientDataHash': Uint8List.fromList(clientDataHash)},
    );
    if (assertion == null) {
      throw const DeviceAuthException('App Attest assertion returned null');
    }

    return {
      'claim': claim,
      'platform': 'ios',
      'key_id': _keyId,
      'assertion': base64Encode(assertion),
      'client_data_hash': challengeBase64,
      'client_data_json': clientDataJson,
    };
  }

  @override
  Map<String, String> additionalHeaders() => {};

  @override
  Future<void> refreshVerification() async {
    // App Attest generates a fresh assertion per request, no refresh needed
  }

  /// Restore a previously registered key ID (e.g., from persistent storage).
  void restoreKeyId(String keyId) {
    _keyId = keyId;
  }

  /// Generate a challenge string for App Attest attestation.
  ///
  /// The challenge is embedded in the attestation object which the server
  /// validates. It binds the attestation to this specific registration attempt.
  static String _generateChallenge() {
    final rng = Random.secure();
    final randomBytes = List<int>.generate(32, (_) => rng.nextInt(256));
    return base64Encode(
      sha256.convert(randomBytes).bytes,
    );
  }
}
