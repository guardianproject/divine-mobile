// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'proofsign_provider.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning
/// Provides a registered [DeviceAuthProvider] if ProofSign is configured,
/// null otherwise.
///
/// Handles platform detection, device auth provider selection, and
/// one-time device registration. Returns null if configuration is missing
/// or registration fails.

@ProviderFor(proofSignAuth)
const proofSignAuthProvider = ProofSignAuthProvider._();

/// Provides a registered [DeviceAuthProvider] if ProofSign is configured,
/// null otherwise.
///
/// Handles platform detection, device auth provider selection, and
/// one-time device registration. Returns null if configuration is missing
/// or registration fails.

final class ProofSignAuthProvider
    extends
        $FunctionalProvider<
          AsyncValue<DeviceAuthProvider?>,
          DeviceAuthProvider?,
          FutureOr<DeviceAuthProvider?>
        >
    with
        $FutureModifier<DeviceAuthProvider?>,
        $FutureProvider<DeviceAuthProvider?> {
  /// Provides a registered [DeviceAuthProvider] if ProofSign is configured,
  /// null otherwise.
  ///
  /// Handles platform detection, device auth provider selection, and
  /// one-time device registration. Returns null if configuration is missing
  /// or registration fails.
  const ProofSignAuthProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'proofSignAuthProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$proofSignAuthHash();

  @$internal
  @override
  $FutureProviderElement<DeviceAuthProvider?> $createElement(
    $ProviderPointer pointer,
  ) => $FutureProviderElement(pointer);

  @override
  FutureOr<DeviceAuthProvider?> create(Ref ref) {
    return proofSignAuth(ref);
  }
}

String _$proofSignAuthHash() => r'378654665efdacb76a942f8a575d46438f6edbf9';
