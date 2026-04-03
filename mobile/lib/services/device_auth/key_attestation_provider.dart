// ABOUTME: Android Key Attestation device authentication provider for ProofSign
// ABOUTME: Uses hardware-backed KeyStore attestation for devices without Play Services

import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:openvine/services/device_auth/device_auth_provider.dart';
import 'package:unified_logger/unified_logger.dart';
import 'package:uuid/uuid.dart';

/// Android Key Attestation device authentication provider.
///
/// For devices without Google Play Services (e.g., GrapheneOS, CalyxOS),
/// uses Android Keystore hardware-backed key attestation to prove the request
/// comes from a device with a Trusted Execution Environment (TEE).
///
/// Flow:
/// 1. [register]: Get challenge -> generate attested key -> register cert chain
/// 2. [buildSigningRequest]: Sign request payload with hardware-backed key
class KeyAttestationProvider implements DeviceAuthProvider {
  static const _channel = MethodChannel('com.openvine/key_attestation');
  static const _tag = 'KeyAttestationProvider';
  static const _uuid = Uuid();
  static const _registrationTimeout = Duration(seconds: 30);

  String? _deviceId;
  int _counter = 0;

  /// Called after each signing request with the new counter value.
  /// Used by the provider to persist the counter to SharedPreferences.
  void Function(int counter)? onCounterChanged;

  /// The device ID, or null if not registered.
  String? get deviceId => _deviceId;

  /// Current counter value for replay protection.
  int get counter => _counter;

  @override
  bool get isRegistered => _deviceId != null;

  @override
  Future<void> register(String serverUrl, http.Client client) async {
    Log.info('Registering device with Key Attestation', name: _tag);

    _deviceId = _uuid.v4();

    // 1. Get challenge from server
    final challengeResponse = await client
        .post(
          Uri.parse('$serverUrl/api/v1/key_attestation/challenge'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'device_id': _deviceId}),
        )
        .timeout(_registrationTimeout);
    if (challengeResponse.statusCode != 200) {
      _deviceId = null;
      throw DeviceAuthException(
        'Key Attestation challenge request failed: '
        '${challengeResponse.statusCode} ${challengeResponse.body}',
      );
    }
    final challenge = jsonDecode(challengeResponse.body)['challenge'] as String;

    // 2. Generate hardware-backed key with challenge embedded in attestation
    final certChain = await _channel.invokeMethod<List<dynamic>>(
      'generateAttestationKey',
      {'challenge': challenge, 'deviceId': _deviceId},
    );
    if (certChain == null || certChain.isEmpty) {
      _deviceId = null;
      throw const DeviceAuthException(
        'Key Attestation key generation returned null or empty cert chain',
      );
    }

    // 3. Register the attestation certificate chain with server
    final registerResponse = await client
        .post(
          Uri.parse('$serverUrl/api/v1/key_attestation/register'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'device_id': _deviceId,
            'challenge': challenge,
            'certificate_chain': certChain.cast<String>(),
          }),
        )
        .timeout(_registrationTimeout);

    if (registerResponse.statusCode != 200) {
      _deviceId = null;
      throw DeviceAuthException(
        'Key Attestation registration failed: '
        '${registerResponse.statusCode} ${registerResponse.body}',
      );
    }

    Log.info('Key Attestation registration complete', name: _tag);
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

    _counter++;
    onCounterChanged?.call(_counter);
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final signPayload = '$_deviceId|$_counter|$timestamp|$claim';

    // Sign the payload with the hardware-backed key
    final signature = await _channel.invokeMethod<String>(
      'signWithDeviceKey',
      {'data': signPayload},
    );
    if (signature == null) {
      throw const DeviceAuthException(
        'Key Attestation signing returned null',
      );
    }

    return {
      'claim': claim,
      'platform': 'android',
      'device_id': _deviceId,
      'counter': _counter,
      'timestamp': timestamp,
      'request_signature': signature,
    };
  }

  @override
  Map<String, String> additionalHeaders() => {};

  @override
  Future<void> refreshVerification() async {
    // Key attestation is persistent, no refresh needed
  }

  /// Restore a previously registered device ID and counter from storage.
  void restoreDeviceId(String deviceId, {int counter = 0}) {
    _deviceId = deviceId;
    _counter = counter;
  }
}
