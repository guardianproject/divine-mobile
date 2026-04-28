// ABOUTME: Riverpod provider for ProofSign device authentication
// ABOUTME: Handles platform detection, device auth provider selection, and registration

import 'dart:io';

import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:openvine/config/proofsign_config.dart';
import 'package:openvine/features/feature_flags/models/feature_flag.dart';
import 'package:openvine/features/feature_flags/providers/feature_flag_providers.dart';
import 'package:openvine/services/device_auth/app_attest_provider.dart';
import 'package:openvine/services/device_auth/device_auth_provider.dart';
import 'package:openvine/services/device_auth/key_attestation_provider.dart';
import 'package:openvine/services/device_auth/play_integrity_provider.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:unified_logger/unified_logger.dart';

part 'proofsign_provider.g.dart';

/// Shared preferences keys for persisting device auth state
const _keyDeviceAuthType = 'proofsign_device_auth_type';
const _keyDeviceAuthId = 'proofsign_device_auth_id';
const _keyDeviceAuthCounter = 'proofsign_device_auth_counter';

const _tag = 'ProofSignProvider';

/// Provides a registered [DeviceAuthProvider] if ProofSign is configured,
/// null otherwise.
///
/// Handles platform detection, device auth provider selection, and
/// one-time device registration. Returns null if configuration is missing
/// or registration fails.
@Riverpod(keepAlive: true)
Future<DeviceAuthProvider?> proofSignAuth(Ref ref) async {
  final flagEnabled = ref.watch(
    isFeatureEnabledProvider(FeatureFlag.proofSignDeviceAuth),
  );
  if (!flagEnabled) {
    Log.info(
      'ProofSign device auth disabled by feature flag — '
      'signing will use bearer token',
      name: _tag,
    );
    return null;
  }

  const config = ProofSignConfig.fromEnvironment;
  if (!config.isConfigured) {
    Log.info(
      'ProofSign not configured (PROOFSIGN_SERVER_URL not set)',
      name: _tag,
    );
    return null;
  }

  final authProvider = await _createAuthProvider(config);
  if (authProvider == null) {
    Log.warning('No device auth provider available', name: _tag);
    return null;
  }

  // Register device if not already registered
  if (!authProvider.isRegistered) {
    final client = http.Client();
    try {
      await authProvider.register(config.serverUrl, client);
      await _persistRegistration(authProvider);
      Log.info('Device registered with ProofSign', name: _tag);
    } catch (e, stackTrace) {
      Log.error(
        'Device registration failed (signing will fall back to legacy)',
        name: _tag,
        error: e,
        stackTrace: stackTrace,
      );
      return null;
    } finally {
      client.close();
    }
  }

  return authProvider;
}

/// Select and create the appropriate device auth provider for this platform.
Future<DeviceAuthProvider?> _createAuthProvider(
  ProofSignConfig config,
) async {
  if (Platform.isIOS) {
    return _createIosProvider(config);
  } else if (Platform.isAndroid) {
    return _createAndroidProvider(config);
  }
  return null;
}

/// Create iOS App Attest provider, restoring key ID from storage if available.
Future<DeviceAuthProvider?> _createIosProvider(
  ProofSignConfig config,
) async {
  final provider = AppAttestProvider(appId: config.appleAppId);

  // Restore registration state from persistent storage
  final prefs = await SharedPreferences.getInstance();
  final savedType = prefs.getString(_keyDeviceAuthType);
  final savedId = prefs.getString(_keyDeviceAuthId);
  if (savedType == 'app_attest' && savedId != null) {
    provider.restoreKeyId(savedId);
    Log.debug('Restored App Attest registration from storage', name: _tag);
  }

  return provider;
}

/// Create Android provider: try Play Integrity first, fall back to
/// Key Attestation for devices without Play Services.
Future<DeviceAuthProvider?> _createAndroidProvider(
  ProofSignConfig config,
) async {
  // Check if Play Services is available (can be forced off for testing)
  final hasPlayServices =
      !ProofSignConfig.forceKeyAttestation && await _checkPlayServices();

  // Restore registration state from persistent storage
  final prefs = await SharedPreferences.getInstance();
  final savedType = prefs.getString(_keyDeviceAuthType);
  final savedId = prefs.getString(_keyDeviceAuthId);

  if (hasPlayServices) {
    final packageInfo = await PackageInfo.fromPlatform();
    final provider = PlayIntegrityProvider(
      gcpProjectNumber: config.gcpProjectNumber,
      packageName: packageInfo.packageName,
    );
    if (savedType == 'play_integrity' && savedId != null) {
      provider.restoreDeviceId(savedId);
      Log.debug(
        'Restored Play Integrity registration from storage',
        name: _tag,
      );
    }
    return provider;
  }

  // Fall back to Key Attestation
  final provider = KeyAttestationProvider();
  if (savedType == 'key_attestation' && savedId != null) {
    final savedCounter = prefs.getInt(_keyDeviceAuthCounter) ?? 0;
    provider.restoreDeviceId(savedId, counter: savedCounter);
    Log.debug(
      'Restored Key Attestation device ID from storage '
      '(counter: $savedCounter)',
      name: _tag,
    );
  }
  // Persist counter after each signing request
  provider.onCounterChanged = (counter) async {
    final p = await SharedPreferences.getInstance();
    await p.setInt(_keyDeviceAuthCounter, counter);
  };
  return provider;
}

/// Check if Google Play Services is available via method channel.
Future<bool> _checkPlayServices() async {
  try {
    const channel = MethodChannel('com.openvine/play_integrity');
    final result = await channel.invokeMethod<bool>('isAvailable');
    return result ?? false;
  } catch (_) {
    return false;
  }
}

/// Persist the device auth registration state so it survives app restarts.
Future<void> _persistRegistration(DeviceAuthProvider provider) async {
  final prefs = await SharedPreferences.getInstance();

  if (provider is AppAttestProvider) {
    await prefs.setString(_keyDeviceAuthType, 'app_attest');
    await prefs.setString(_keyDeviceAuthId, provider.keyId ?? '');
  } else if (provider is PlayIntegrityProvider) {
    await prefs.setString(_keyDeviceAuthType, 'play_integrity');
    await prefs.setString(_keyDeviceAuthId, provider.deviceId ?? '');
  } else if (provider is KeyAttestationProvider) {
    await prefs.setString(_keyDeviceAuthType, 'key_attestation');
    await prefs.setString(_keyDeviceAuthId, provider.deviceId ?? '');
    await prefs.setInt(_keyDeviceAuthCounter, provider.counter);
  }
}
