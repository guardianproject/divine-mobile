// ABOUTME: Android Play Integrity device authentication provider for ProofSign
// ABOUTME: Uses Play Integrity API via method channel for device attestation

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:openvine/services/device_auth/device_auth_provider.dart';
import 'package:unified_logger/unified_logger.dart';
import 'package:uuid/uuid.dart';

/// Android Play Integrity device authentication provider.
///
/// Uses the Play Integrity API to generate integrity tokens that prove the
/// request comes from a genuine app on a genuine Android device with
/// Google Play Services.
class PlayIntegrityProvider implements DeviceAuthProvider {
  PlayIntegrityProvider({
    required this.gcpProjectNumber,
    required this.packageName,
  });

  static const _channel = MethodChannel('com.openvine/play_integrity');
  static const _tag = 'PlayIntegrityProvider';
  static const _uuid = Uuid();

  /// Google Cloud project number for Play Integrity verification
  final String gcpProjectNumber;

  /// Android package name (read from PackageInfo at runtime)
  final String packageName;

  String? _deviceId;

  /// The device ID, or null if not registered.
  String? get deviceId => _deviceId;

  @override
  bool get isRegistered => _deviceId != null;

  @override
  Future<void> register(String serverUrl, http.Client client) async {
    Log.info('Registering device with Play Integrity', name: _tag);

    // Play Integrity does not have a separate registration endpoint.
    // Device verification happens inline with each signing request via
    // the /api/v1/c2pa/sign endpoint which calls /api/v1/play_integrity/verify.
    // We just generate a local device ID for tracking.
    _deviceId = _uuid.v4();

    Log.debug(
      'Play Integrity device ID generated',
      name: _tag,
    );
  }

  @override
  Future<Map<String, dynamic>> buildSigningRequest({
    required String claim,
    required String platform,
  }) async {
    if (_deviceId == null) {
      throw const DeviceAuthException(
        'Device not registered. Call register() first.',
      );
    }

    final dataBytes = base64Decode(claim);
    final clientDataHash = base64Encode(sha256.convert(dataBytes).bytes);
    final nonce = _generateNonce(_deviceId!, clientDataHash);

    // Request a fresh Play Integrity token via method channel
    final integrityToken = await _requestIntegrityToken(nonce);

    return {
      'claim': claim,
      'platform': 'android',
      'device_id': _deviceId,
      'integrity_token': integrityToken,
      'client_data_hash': clientDataHash,
      'nonce': nonce,
      'package_name': packageName,
    };
  }

  @override
  Map<String, String> additionalHeaders() => {};

  @override
  Future<void> refreshVerification() async {
    // Play Integrity generates a fresh token per request, no refresh needed
  }

  /// Restore a previously registered device ID (e.g., from persistent storage).
  void restoreDeviceId(String deviceId) {
    _deviceId = deviceId;
  }

  /// Generate a nonce binding the device ID and claim data together.
  ///
  /// Play Integrity requires base64url encoding without padding.
  String _generateNonce(String deviceId, String clientDataHash) {
    final combined =
        '$deviceId:${DateTime.now().millisecondsSinceEpoch}:'
        '${_uuid.v4()}:$clientDataHash';
    final hash = sha256.convert(utf8.encode(combined)).bytes;
    return base64Url.encode(hash).replaceAll('=', '');
  }

  /// Request an integrity token from the Play Integrity API via method channel.
  Future<String> _requestIntegrityToken(String nonce) async {
    final token = await _channel.invokeMethod<String>(
      'requestIntegrityToken',
      {
        'nonce': nonce,
        'cloudProjectNumber': gcpProjectNumber,
      },
    );
    if (token == null) {
      throw const DeviceAuthException(
        'Play Integrity token request returned null',
      );
    }
    return token;
  }
}
