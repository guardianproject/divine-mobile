// ABOUTME: Flutter platform channel for native ProofMode library integration
// ABOUTME: Bridges Dart to native Android/iOS libProofMode implementations

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:openvine/utils/unified_logger.dart';
import 'package:models/models.dart' show NativeProofData;
import 'package:openvine/services/c2pa_signing_service.dart';

/// Service for generating cryptographic proof using native ProofMode libraries
///
/// Uses platform channels to call:
/// - Android: org.witness:android-libproofmode
/// - iOS: ProofMode iOS library (from Guardian Project GitLab)
class NativeProofModeService {
  static const MethodChannel _channel = MethodChannel('org.openvine/proofmode');

  /// Generate native ProofMode proof for a video file.
  ///
  /// Returns [NativeProofData] if proof generation succeeds, null otherwise.
  /// Handles platform availability checks and graceful fallback if ProofMode
  /// is not supported.
  static Future<NativeProofData?> proofFile(File videoFile) async {
    try {

      // Check if native ProofMode/C2PA is available on this platform
      final isAvailable = await NativeProofModeService.isAvailable();
      if (!isAvailable) {
        Log.info(
          '🔐 Native ProofMode not available on this platform',
          name: 'VideoRecorderProofService',
          category: .video,
        );
        return null;
      }

      final C2paSigningService _c2paSigningService = C2paSigningService();

      // First, sign/embed video with C2PA content credentials
      Log.info(
        'Signing video with C2PA...',
        name: 'VideoRecorderProofService',
        category: LogCategory.video,
      );
      final c2paResult = await _c2paSigningService.signVideo(
        videoPath: videoFile.path,
      );

      if (c2paResult.success) {
        Log.info(
          'C2PA signing complete: $c2paResult.signedFilePath',
          name: 'VideoRecorderProofService',
          category: LogCategory.video,
        );
      } else {
        Log.warning(
          'C2PA signing failed (continuing without): ${c2paResult.error}',
          name: 'VideoRecorderProofService',
          category: LogCategory.video,
        );
      }
      
      final manifestInfo = await _c2paSigningService.readManifest(c2paResult.signedFilePath);

      if (manifestInfo?.validationStatus != null) {

          /**
          Log.debug("C2PA Validation Status: ${manifestInfo?.validationStatus}");
          manifestInfo?.validationErrors
              .forEach((error) => Log.debug("C2PA Validation Error: $error"));
          **/

          Log.debug("C2PA Active Manifest ID: ${manifestInfo?.activeManifest}");

          /**
          manifestInfo?.manifests.forEach((manifestId, manifest)
          {

            Log.debug("C2PA Manifest: $manifestId");

            Log.debug(
                "C2PA Claim Generator: ${manifest?.claimGenerator.toString()}");
            Log.debug("C2PA Claim Format: ${manifest?.format}");
            Log.debug("C2PA Claim Title: ${manifest?.title}");

            manifest?.assertions.forEach((assertion) {
              Log.debug("C2PA Assertion Label: ${assertion.label}");
              Log.debug("C2PA Assertion Data: ${assertion.data}");
            });

            manifest?.ingredients.forEach((ingredient) {
              Log.debug("C2PA Ingredient Data: ${ingredient.title}");
              Log.debug("C2PA Ingredient Format: ${ingredient.format}");
            });


            Log.debug("C2PA Claim Signature: ${manifest?.signature?.issuer}");
            Log.debug(
                "C2PA Claim Serial: ${manifest?.signature?.serialNumber}");
          });**/

      }


      Log.info(
        '🔐 Generating native ProofMode proof for: ${videoFile.path}',
        name: 'VideoRecorderProofService',
        category: .video,
      );

      // Generate proof using native library
      final proofHash = await NativeProofModeService.generateProof(
        videoFile.path,
      );
      if (proofHash == null) {
        Log.warning(
          '🔐 Native proof generation returned null',
          name: 'VideoRecorderProofService',
          category: .video,
        );
        return null;
      }

      Log.info(
        '🔐 Native proof hash: $proofHash',
        name: 'VideoRecorderProofService',
        category: .video,
      );

      // Read proof metadata from native library
      final metadata = await NativeProofModeService.readProofMetadata(
        proofHash,
      );
      if (metadata == null) {
        Log.warning(
          '🔐 Could not read native proof metadata',
          name: 'VideoRecorderProofService',
          category: .video,
        );
        return null;
      }

      Log.info(
        '🔐 Native proof metadata fields: ${metadata.keys.join(", ")}',
        name: 'VideoRecorderProofService',
        category: .video,
      );

      if (manifestInfo?.activeManifest != null) {
        String activeManifestId = manifestInfo!.activeManifest!;
        metadata.putIfAbsent("c2paManifestId", () => activeManifestId);
      }

      // Create NativeProofData from metadata
      final proofData = NativeProofData.fromMetadata(metadata);

      Log.info(
        '🔐 Native proof data created: ${proofData.verificationLevel}',
        name: 'VideoRecorderProofService',
        category: .video,
      );

      return proofData;
    } catch (e) {
      Log.error(
        '🔐 Native proof generation failed: $e',
        name: 'VideoRecorderProofService',
        category: .video,
      );
      return null;
    }
  }

  /// Generate proof for a media file using native ProofMode library
  ///
  /// Returns the SHA256 hash of the media file, which is used as the key
  /// to retrieve proof data from the native library's storage.
  ///
  /// Throws [PlatformException] if proof generation fails.
  static Future<String?> generateProof(String mediaPath) async {
    try {
      Log.info(
        '🔐 Generating native ProofMode proof for: $mediaPath',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );

      if (!File(mediaPath).existsSync()) {
        Log.error(
          '🔐 Media file does not exist: $mediaPath',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
        return null;
      }

      final String? proofHash = await _channel.invokeMethod('generateProof', {
        'mediaPath': mediaPath,
      });

      if (proofHash != null) {
        Log.info(
          '🔐 Native ProofMode proof generated: $proofHash',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
      } else {
        Log.warning(
          '🔐 Native ProofMode proof generation returned null',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
      }

      return proofHash;
    } on PlatformException catch (e) {
      Log.error(
        '🔐 Native ProofMode proof generation failed: ${e.code} - ${e.message}',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );
      return null;
    } catch (e) {
      Log.error(
        '🔐 Unexpected error generating native ProofMode proof: $e',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );
      return null;
    }
  }

  /// Get the directory containing proof files for a given media hash
  ///
  /// Returns the path to the directory containing:
  /// - .csv file with sensor data
  /// - .asc file with OpenPGP signature
  /// - .sig file with additional signatures
  /// - timestamp and other metadata files
  static Future<String?> getProofDir(String proofHash) async {
    try {
      Log.debug(
        '🔐 Getting native ProofMode proof directory for hash: $proofHash',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );

      final String? proofDir = await _channel.invokeMethod('getProofDir', {
        'proofHash': proofHash,
      });

      if (proofDir != null) {
        Log.debug(
          '🔐 Native ProofMode proof directory: $proofDir',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
      }

      return proofDir;
    } on PlatformException catch (e) {
      Log.error(
        '🔐 Failed to get native ProofMode proof directory: ${e.code} - ${e.message}',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );
      return null;
    } catch (e) {
      Log.error(
        '🔐 Unexpected error getting native ProofMode proof directory: $e',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );
      return null;
    }
  }

  /// Read proof metadata from the native proof directory
  ///
  /// Returns a map containing:
  /// - 'csv': Sensor data CSV content
  /// - 'signature': OpenPGP signature
  /// - 'hash': SHA256 hash of media file
  /// - 'timestamp': Timestamp data
  static Future<Map<String, String>?> readProofMetadata(
    String proofHash,
  ) async {
    try {
      final proofDir = await getProofDir(proofHash);
      if (proofDir == null) {
        Log.warning(
          '🔐 No proof directory found for hash: $proofHash',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
        return null;
      }

      final dir = Directory(proofDir);
      if (!dir.existsSync()) {
        Log.warning(
          '🔐 Proof directory does not exist: $proofDir',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
        return null;
      }

      final metadata = <String, String>{};

      // Read CSV sensor data
      final csvFile = File('$proofDir/$proofHash.csv');
      if (csvFile.existsSync()) {
        metadata['csv'] = await csvFile.readAsString();
        Log.debug(
          '🔐 Read CSV metadata (${metadata['csv']!.length} bytes)',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
      }

      // Read OpenPGP signature
      final sigFile = File('$proofDir/$proofHash.asc');
      if (sigFile.existsSync()) {
        metadata['signature'] = await sigFile.readAsString();
        Log.debug(
          '🔐 Read signature (${metadata['signature']!.length} bytes)',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
      }

      // Read proof public key
      final pubkeyFile = File('$proofDir/$proofHash-pubkey.asc');
      if (pubkeyFile.existsSync()) {
        metadata['publicKey'] = await pubkeyFile.readAsString();
        Log.debug(
          '🔐 Read public key (${metadata['publicKey']!.length} bytes)',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
      }

      // Read local device attestation info
      final deviceAttestation = File('$proofDir/$proofHash.attest');
      if (deviceAttestation.existsSync()) {
        metadata['deviceAttestation'] = await deviceAttestation.readAsString();
        Log.debug(
          '🔐 Read device attestation (${metadata['deviceAttestation']!.length} bytes)',
          name: 'NativeProofMode',
          category: LogCategory.system,
        );
      }

      metadata['hash'] = proofHash;

      Log.info(
        '🔐 Read native ProofMode metadata (${metadata.length} fields)',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );

      return metadata;
    } catch (e) {
      Log.error(
        '🔐 Failed to read native ProofMode metadata: $e',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );
      return null;
    }
  }

  /// Check if native ProofMode is available on this platform
  static Future<bool> isAvailable() async {
    try {
      final bool? available = await _channel.invokeMethod('isAvailable');
      return available ?? false;
    } on PlatformException catch (e) {
      Log.warning(
        '🔐 Native ProofMode not available: ${e.code} - ${e.message}',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );
      return false;
    } catch (e) {
      Log.warning(
        '🔐 Error checking native ProofMode availability: $e',
        name: 'NativeProofMode',
        category: LogCategory.system,
      );
      return false;
    }
  }
}
