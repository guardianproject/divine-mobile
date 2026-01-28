// ABOUTME: Service for signing videos with C2PA content credentials
// ABOUTME: Embeds provenance information into video files before upload

import 'dart:io';

import 'package:c2pa_flutter/c2pa.dart';
import 'package:openvine/utils/unified_logger.dart';
import 'package:package_info_plus/package_info_plus.dart';

/// Result of a C2PA signing operation
class C2paSigningResult {
  const C2paSigningResult({
    required this.signedFilePath,
    required this.success,
    this.error,
  });

  /// Path to the signed video file
  final String signedFilePath;

  /// Whether signing was successful
  final bool success;

  /// Error message if signing failed
  final String? error;
}

/// Service for signing videos with C2PA content credentials.
///
/// C2PA (Coalition for Content Provenance and Authenticity) embeds
/// cryptographic provenance information directly into media files,
/// establishing the origin and history of digital content.
class C2paSigningService {
  C2paSigningService();

  final C2pa _c2pa = C2pa();
  static const String CLAIM_GENERATOR = "DiVine/1.0";

  /// Signs a video file with C2PA content credentials.
  ///
  /// [videoPath] - Path to the video file to sign
  /// [claimGenerator] - Identifier for the app/tool creating the claim
  ///
  /// Returns the path to the signed video file, or the original path if
  /// signing fails (signing is best-effort, not blocking).
  Future<C2paSigningResult> signVideo({
    required String videoPath
  }) async {
    try {
      Log.info(
        'Starting C2PA signing for video: $videoPath',
        name: 'C2paSigningService',
        category: LogCategory.video,
      );

      // Verify input file exists
      final inputFile = File(videoPath);
      if (!await inputFile.exists()) {
        return C2paSigningResult(
          signedFilePath: videoPath,
          success: false,
          error: 'Input file does not exist',
        );
      }

      PackageInfo packageInfo = await PackageInfo.fromPlatform();
      String claimGenerator = "${packageInfo.appName}/${packageInfo.version}";

      // Generate output path for signed video
      final directory = inputFile.parent.path;
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      final signedPath = '$directory/c2pa_signed_$timestamp.mp4';

      // Build manifest JSON for digital capture
      final manifestJsonSource = _buildManifestJson(claimGenerator, inputFile.uri.path, DigitalSourceType.digitalCapture.url);
      Log.info("prepared C2PA manifest json: $manifestJsonSource");

      // Create signer using PEM credentials (test certificates for now)
      final signer = _createSigner();

      // Sign the file
      await _c2pa.signFile(
        sourcePath: videoPath,
        destPath: signedPath,
        manifestJson: manifestJsonSource,
        signer: signer,
      );

      // Verify signed file was created
      final signedFile = File(signedPath);
      if (!await signedFile.exists()) {
        return C2paSigningResult(
          signedFilePath: videoPath,
          success: false,
          error: 'Signed file was not created',
        );
      }

      Log.debug("replacing original video $videoPath with signed file $signedFile");
      var iFileNew = inputFile.renameSync(inputFile.path + ".old");
      Log.debug("original file renamed: ${iFileNew.path} ");
      var sFileNew = signedFile.renameSync(inputFile.path);
      Log.debug("signed file renamed: ${sFileNew.path} ");

      final signedSize = await sFileNew.length();
      Log.info(
        'C2PA signing complete: $sFileNew (${signedSize ~/ 1024} KB)',
        name: 'C2paSigningService',
        category: LogCategory.video,
      );

      return C2paSigningResult(
        signedFilePath: sFileNew.path,
        success: true,
      );
    } catch (e, stackTrace) {
      Log.error(
        'C2PA signing failed: $e',
        name: 'C2paSigningService',
        category: LogCategory.video,
        error: e,
        stackTrace: stackTrace,
      );

      // Return original path - signing is best-effort, not blocking
      return C2paSigningResult(
        signedFilePath: videoPath,
        success: false,
        error: e.toString(),
      );
    }
  }

  /// Reads and validates C2PA manifest from a signed file.
  ///
  /// Returns a [ManifestStoreInfo] with parsed manifest data and validation
  /// info, or null if no manifest is found.
  Future<ManifestStoreInfo?> readManifest(String filePath) async {
    try {
      return await _c2pa.readManifestFromFile(filePath);
    } catch (e) {
      Log.warning(
        'Failed to read C2PA manifest: $e',
        name: 'C2paSigningService',
        category: LogCategory.video,
      );
      return null;
    }
  }

  /// Gets the C2PA library version.
  Future<String?> getVersion() async {
    return _c2pa.getVersion();
  }

  /// Checks if hardware-backed signing is available on this device.
  ///
  /// Returns true if:
  /// - Android: StrongBox is available (Android 9.0+ with hardware support)
  /// - iOS: Secure Enclave is available (iPhone 5s+, not in Simulator)
  Future<bool> isHardwareSigningAvailable() async {
    return _c2pa.isHardwareSigningAvailable();
  }

  /// Builds the manifest JSON for a freshly captured video.
  String _buildManifestJson(String claimGenerator, String title, String digitalSourceUrl) {
    // Using digitalCapture source type for in-app recorded content
    // DigitalSourceType.digitalCapture.url provides the IPTC URL
    //final digitalSourceUrl = DigitalSourceType.digitalCapture.url;
    return '''
{
  "claim_generator": "$claimGenerator",
  "title": "$title",
  "format": "video/mp4",
  "assertions": [
    {
      "label": "c2pa.actions.v2",
      "data": {
        "actions": [
          {
            "action": "c2pa.created",
            "digitalSourceType": "$digitalSourceUrl",
            "softwareAgent": "$claimGenerator"
          }
        ]
      }
    }
  ]
}
''';
  }


  /// Creates a signer for C2PA operations.
  ///
  /// TODO: Replace with proper key management:
  /// - Use HardwareSigner for Secure Enclave (iOS) / StrongBox (Android)
  /// - Generate per-user keys during onboarding
  /// - Store certificates securely
  /// - Support user-provided certificates via enrollment API
  C2paSigner _createSigner() {

    /**
    return PemSigner(
      algorithm: SigningAlgorithm.es256,
      certificatePem: _testCertificate,
      privateKeyPem: _testPrivateKey,
      tsaUrl: _timeStampAuthority
    );**/

    return RemoteSigner(configurationUrl: DEFAULT_SIGNING_SERVER_ENDPOINT, bearerToken: DEFAULT_SIGNING_SERVER_TOKEN);
  }
  static const DEFAULT_SIGNING_SERVER_ENDPOINT = "https://zbjspd6jfv.us-east-2.awsapprunner.com/api/v1/c2pa/configuration?platform=android";
  static const DEFAULT_SIGNING_SERVER_TOKEN = "2d0c8b6b66c47c3b215976cc808296269322558c6d533d9ce6f3c45a9ccfe811";

  static const String _timeStampAuthority = 'http://timestamp.digicert.com';
  // Test certificate chain for development - NOT FOR PRODUCTION
  // These are the official C2PA test certificates from c2pa-flutter.
  // They will show as "untrusted" when verified since they're not from
  // a recognized C2PA trust list. Production requires proper PKI certificates.
  static const String _testCertificate = '''-----BEGIN CERTIFICATE-----
MIIChzCCAi6gAwIBAgIUcCTmJHYF8dZfG0d1UdT6/LXtkeYwCgYIKoZIzj0EAwIw
gYwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdoZXJl
MScwJQYDVQQKDB5DMlBBIFRlc3QgSW50ZXJtZWRpYXRlIFJvb3QgQ0ExGTAXBgNV
BAsMEEZPUiBURVNUSU5HX09OTFkxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBDQTAe
Fw0yMjA2MTAxODQ2NDBaFw0zMDA4MjYxODQ2NDBaMIGAMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNvbWV3aGVyZTEfMB0GA1UECgwWQzJQQSBU
ZXN0IFNpZ25pbmcgQ2VydDEZMBcGA1UECwwQRk9SIFRFU1RJTkdfT05MWTEUMBIG
A1UEAwwLQzJQQSBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQPaL6R
kAkYkKU4+IryBSYxJM3h77sFiMrbvbI8fG7w2Bbl9otNG/cch3DAw5rGAPV7NWky
l3QGuV/wt0MrAPDoo3gwdjAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
AQUFBwMEMA4GA1UdDwEB/wQEAwIGwDAdBgNVHQ4EFgQUFznP0y83joiNOCedQkxT
tAMyNcowHwYDVR0jBBgwFoAUDnyNcma/osnlAJTvtW6A4rYOL2swCgYIKoZIzj0E
AwIDRwAwRAIgOY/2szXjslg/MyJFZ2y7OH8giPYTsvS7UPRP9GI9NgICIDQPMKrE
LQUJEtipZ0TqvI/4mieoyRCeIiQtyuS0LACz
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICajCCAg+gAwIBAgIUfXDXHH+6GtA2QEBX2IvJ2YnGMnUwCgYIKoZIzj0EAwIw
dzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlTb21ld2hlcmUx
GjAYBgNVBAoMEUMyUEEgVGVzdCBSb290IENBMRkwFwYDVQQLDBBGT1IgVEVTVElO
R19PTkxZMRAwDgYDVQQDDAdSb290IENBMB4XDTIyMDYxMDE4NDY0MFoXDTMwMDgy
NzE4NDY0MFowgYwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJ
U29tZXdoZXJlMScwJQYDVQQKDB5DMlBBIFRlc3QgSW50ZXJtZWRpYXRlIFJvb3Qg
Q0ExGTAXBgNVBAsMEEZPUiBURVNUSU5HX09OTFkxGDAWBgNVBAMMD0ludGVybWVk
aWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHllI4O7a0EkpTYAWfPM
D6Rnfk9iqhEmCQKMOR6J47Rvh2GGjUw4CS+aLT89ySukPTnzGsMQ4jK9d3V4Aq4Q
LsOjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQW
BBQOfI1yZr+iyeUAlO+1boDitg4vazAfBgNVHSMEGDAWgBRembiG4Xgb2VcVWnUA
UrYpDsuojDAKBggqhkjOPQQDAgNJADBGAiEAtdZ3+05CzFo90fWeZ4woeJcNQC4B
84Ill3YeZVvR8ZECIQDVRdha1xEDKuNTAManY0zthSosfXcvLnZui1A/y/DYeg==
-----END CERTIFICATE-----''';

  static const String _testPrivateKey = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfNJBsaRLSeHizv0m
GL+gcn78QmtfLSm+n+qG9veC2W2hRANCAAQPaL6RkAkYkKU4+IryBSYxJM3h77sF
iMrbvbI8fG7w2Bbl9otNG/cch3DAw5rGAPV7NWkyl3QGuV/wt0MrAPDo
-----END PRIVATE KEY-----''';
}
