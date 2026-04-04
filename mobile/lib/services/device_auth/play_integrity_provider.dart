// ABOUTME: Android Play Integrity device authentication provider for ProofSign
// ABOUTME: Uses Play Integrity API via method channel for device attestation

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:openvine/services/device_auth/device_auth_provider.dart';
import 'package:openvine/utils/unified_logger.dart';
import 'package:uuid/uuid.dart';

/// Android Play Integrity device authentication provider.
///
/// Uses the Play Integrity API to generate integrity tokens that prove the
/// request comes from a genuine app on a genuine Android device with
/// Google Play Services.
///
/// Flow:
/// 1. [register]: Generate device ID -> request integrity token ->
///    POST to /api/v1/play_integrity/verify (creates verification record)
/// 2. [buildSigningRequest]: Send just device_id -- the server's middleware
///    validates the existing verification record created during [register].
/// 3. Server verification records expire after 7 days. [refreshVerification]
///    re-runs the verify flow when the server returns 428.
class PlayIntegrityProvider implements DeviceAuthProvider {
  PlayIntegrityProvider({
    required this.gcpProjectNumber,
    required this.packageName,
  });

  static const _channel = MethodChannel('com.openvine/play_integrity');
  static const _tag = 'PlayIntegrityProvider';
  static const _uuid = Uuid();
  static const _registrationTimeout = Duration(seconds: 30);

  /// Google Cloud project number for Play Integrity verification
  final String gcpProjectNumber;

  /// Android package name (read from PackageInfo at runtime)
  final String packageName;

  String? _deviceId;
  String? _serverUrl;
  http.Client? _client;

  /// The device ID, or null if not registered.
  String? get deviceId => _deviceId;

  @override
  bool get isRegistered => _deviceId != null;

  @override
  Future<void> register(String serverUrl, http.Client client) async {
    Log.info('Registering device with Play Integrity', name: _tag);

    _serverUrl = serverUrl;
    _client = client;
    _deviceId = _uuid.v4();

    await _verifyWithServer();

    Log.info('Play Integrity registration complete', name: _tag);
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

    // The server's device_auth middleware validates the existing
    // verification record created during register(). No need to send
    // integrity_token/nonce/client_data_hash again.
    return {
      'claim': claim,
      'platform': 'android',
      'device_id': _deviceId,
    };
  }

  @override
  Map<String, String> additionalHeaders() => {};

  @override
  Future<void> refreshVerification() async {
    Log.info('Refreshing Play Integrity verification', name: _tag);
    await _verifyWithServer();
  }

  /// Restore a previously registered device ID (e.g., from persistent storage).
  void restoreDeviceId(String deviceId) {
    _deviceId = deviceId;
  }

  /// Request a fresh integrity token and POST it to the server's
  /// /api/v1/play_integrity/verify endpoint to create or refresh the
  /// device verification record.
  Future<void> _verifyWithServer() async {
    final serverUrl = _serverUrl;
    final client = _client;
    final deviceId = _deviceId;
    if (serverUrl == null || client == null || deviceId == null) {
      throw const DeviceAuthException(
        'Play Integrity verification requires register() to be called first',
      );
    }

    final nonce = _generateNonce(deviceId);
    final integrityToken = await _requestIntegrityToken(nonce);

    final response = await client
        .post(
          Uri.parse('$serverUrl/api/v1/play_integrity/verify'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'device_id': deviceId,
            'integrity_token': integrityToken,
            'nonce': nonce,
            'package_name': packageName,
          }),
        )
        .timeout(_registrationTimeout);

    if (response.statusCode != 200) {
      throw DeviceAuthException(
        'Play Integrity verification failed: '
        '${response.statusCode} ${response.body}',
      );
    }
  }

  /// Generate a nonce for Play Integrity token binding.
  ///
  /// Play Integrity requires base64url encoding without padding.
  String _generateNonce(String deviceId) {
    final combined = '$deviceId:${DateTime.now().millisecondsSinceEpoch}:'
        '${_uuid.v4()}';
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
