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
/// Combines Play Integrity (one-time, Google-verified device + app identity)
/// with per-request EC P-256 signing (replay protection equivalent to iOS App
/// Attest). This mirrors the Android device-signing protocol implemented by
/// `proofsign-server`.
///
/// Flow:
/// 1. [register]: generate device ID -> generate EC P-256 keypair in Android
///    Keystore -> request integrity token -> POST to
///    `/api/v1/play_integrity/verify` with `{integrity_token, public_key, ...}`.
///    The server validates the token with Google and stores the public key
///    against the device ID.
/// 2. [buildSigningRequest]: increment a strictly-monotonic counter, persist
///    it via [onCounterChanged], and sign `deviceId|counter|timestamp|claim`
///    with the Keystore private key. The server verifies the signature
///    against the registered public key, enforces strictly-increasing counter,
///    and rejects replays.
/// 3. Server verification records expire after 7 days. [refreshVerification]
///    re-runs the verify flow when the server returns 428, reusing the
///    existing keypair so the registered public key stays valid.
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
  int _counter = 0;
  String? _serverUrl;
  http.Client? _client;

  /// Called after each signing request with the new counter value.
  ///
  /// The signer awaits this future before transmitting the signed request,
  /// so the persisted counter is durable even if the app is killed mid-flight.
  Future<void> Function(int counter)? onCounterChanged;

  /// The device ID, or null if not registered.
  String? get deviceId => _deviceId;

  /// Current per-request counter value (visible for tests).
  int get counter => _counter;

  @override
  bool get isRegistered => _deviceId != null;

  @override
  Future<void> register(String serverUrl, http.Client client) async {
    Log.info('Registering device with Play Integrity', name: _tag);

    _serverUrl = serverUrl;
    _client = client;
    _deviceId = _uuid.v4();
    _counter = 0;

    // Generate the per-request signing key BEFORE talking to the server,
    // so the public key we register matches the private key we'll use.
    final publicKey = await _generateSigningKey();

    await _verifyWithServer(publicKey: publicKey);

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

    // Snapshot the counter into a local BEFORE awaiting persistence, so two
    // concurrent buildSigningRequest calls don't both end up signing with
    // whichever counter happens to be last after the await yields.
    final requestCounter = ++_counter;
    // Persist the new counter BEFORE we use it to sign the outgoing request,
    // so a crash between increment and signing can't leave the server with a
    // counter higher than what we'll present on next launch.
    await onCounterChanged?.call(requestCounter);
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final signPayload = '$_deviceId|$requestCounter|$timestamp|$claim';

    final signature = await _channel.invokeMethod<String>(
      'signWithSigningKey',
      {'data': signPayload},
    );
    if (signature == null) {
      throw const DeviceAuthException(
        'Play Integrity signing returned null',
      );
    }

    return {
      'claim': claim,
      'platform': 'android',
      'device_id': _deviceId,
      'counter': requestCounter,
      'timestamp': timestamp,
      'request_signature': signature,
    };
  }

  @override
  Map<String, String> additionalHeaders() => {};

  @override
  Future<void> refreshVerification() async {
    Log.info('Refreshing Play Integrity verification', name: _tag);
    // Reuse the existing keypair so the registered public key stays valid.
    // If it's gone (rare: app data cleared without uninstall), generate fresh.
    final existingPublicKey = await _channel.invokeMethod<String>(
      'getSigningKeyPublicKey',
    );
    final publicKey = existingPublicKey ?? await _generateSigningKey();
    await _verifyWithServer(publicKey: publicKey);
  }

  /// Restore a previously registered device ID and counter from persistent
  /// storage. Counter must be the last persisted value to preserve the
  /// strictly-monotonic guarantee against the server's stored counter.
  void restoreDeviceId(String deviceId, {int counter = 0}) {
    _deviceId = deviceId;
    _counter = counter;
  }

  Future<String> _generateSigningKey() async {
    final publicKey = await _channel.invokeMethod<String>('generateSigningKey');
    if (publicKey == null) {
      throw const DeviceAuthException(
        'Play Integrity signing key generation returned null',
      );
    }
    return publicKey;
  }

  /// Request a fresh integrity token and POST it to the server's
  /// /api/v1/play_integrity/verify endpoint to create or refresh the
  /// device verification record.
  Future<void> _verifyWithServer({required String publicKey}) async {
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
            'public_key': publicKey,
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
    final combined =
        '$deviceId:${DateTime.now().millisecondsSinceEpoch}:'
        '${_uuid.v4()}';
    final hash = sha256.convert(utf8.encode(combined)).bytes;
    return base64Url.encode(hash).replaceAll('=', '');
  }

  /// Request an integrity token from the Play Integrity API via method channel.
  Future<String> _requestIntegrityToken(String nonce) async {
    final token = await _channel.invokeMethod<String>(
      'requestIntegrityToken',
      {'nonce': nonce, 'cloudProjectNumber': gcpProjectNumber},
    );
    if (token == null) {
      throw const DeviceAuthException(
        'Play Integrity token request returned null',
      );
    }
    return token;
  }
}
