// ABOUTME: Service for signing videos with C2PA content credentials
// ABOUTME: Embeds provenance information into video files before upload

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:c2pa_flutter/c2pa.dart';
import 'package:http/http.dart' as http;
import 'package:openvine/config/proofsign_config.dart';
import 'package:openvine/services/device_auth/device_auth_provider.dart';
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
///
/// Signer selection:
/// 1. ProofSign CallbackSigner with device attestation -- if [authProvider]
///    is registered (App Attest / Play Integrity / Key Attestation)
/// 2. ProofSign CallbackSigner with dev bearer token -- for CI/testing
class C2paSigningService {
  C2paSigningService({this.authProvider});

  /// Optional device auth provider for ProofSign-backed signing.
  /// When provided and registered, uses CallbackSigner with device
  /// attestation. Otherwise falls back to bearer token if configured.
  final DeviceAuthProvider? authProvider;

  final C2pa _c2pa = C2pa();
  http.Client? _httpClient;

  static const _signingTimeout = Duration(seconds: 15);
  static const _tag = 'C2paSigningService';

  /// Signs a video file with C2PA content credentials.
  ///
  /// Returns the path to the signed video file, or the original path if
  /// signing fails (signing is best-effort, not blocking).
  Future<C2paSigningResult> signVideo({required String videoPath}) async {
    try {
      Log.info(
        'Starting C2PA signing for video: $videoPath',
        name: _tag,
        category: LogCategory.video,
      );

      // Verify input file exists
      final inputFile = File(videoPath);
      if (!inputFile.existsSync()) {
        return C2paSigningResult(
          signedFilePath: videoPath,
          success: false,
          error: 'Input file does not exist',
        );
      }

      final PackageInfo packageInfo = await PackageInfo.fromPlatform();
      final String claimGenerator =
          '${packageInfo.appName}/${packageInfo.version}';

      // Generate output path for signed video
      final directory = inputFile.parent.path;
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      final signedPath = '$directory/c2pa_signed_$timestamp.mp4';

      final filename = inputFile.path.split('/').last;
      // Build manifest JSON for digital capture
      final manifestJsonSource = _buildManifestJson(
        claimGenerator,
        filename,
        DigitalSourceType.digitalCapture.url,
      );
      Log.info('prepared C2PA manifest json: $manifestJsonSource');

      // Create signer
      final signer = await _createSigner();

      // Sign the file
      await _c2pa.signFile(
        sourcePath: videoPath,
        destPath: signedPath,
        manifestJson: manifestJsonSource,
        signer: signer,
      );

      // Verify signed file was created
      final signedFile = File(signedPath);
      if (!signedFile.existsSync()) {
        return C2paSigningResult(
          signedFilePath: videoPath,
          success: false,
          error: 'Signed file was not created',
        );
      }

      inputFile.renameSync('${inputFile.path}.old');
      final sFileNew = signedFile.renameSync(inputFile.path);
      Log.debug('signed file renamed: ${sFileNew.path} ');

      final signedSize = await sFileNew.length();
      Log.info(
        'C2PA signing complete: $sFileNew (${signedSize ~/ 1024} KB)',
        name: _tag,
        category: LogCategory.video,
      );

      return C2paSigningResult(signedFilePath: sFileNew.path, success: true);
    } catch (e, stackTrace) {
      Log.error(
        'C2PA signing failed: $e',
        name: _tag,
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
        name: _tag,
        category: LogCategory.video,
      );
      return null;
    }
  }

  /// Gets the C2PA library version.
  Future<String?> getVersion() async {
    return _c2pa.getVersion();
  }

  /// Get or create the HTTP client (lazy -- only allocated for ProofSign path).
  http.Client get _client => _httpClient ??= http.Client();

  /// Close the internal HTTP client. Call when done signing.
  void dispose() {
    _httpClient?.close();
    _httpClient = null;
  }

  // ---------------------------------------------------------------------------
  // Signer creation
  // ---------------------------------------------------------------------------

  /// Creates a signer for C2PA operations.
  ///
  /// Uses ProofSign CallbackSigner with either device attestation or a
  /// dev bearer token. Throws if ProofSign is not configured.
  Future<C2paSigner> _createSigner() async {
    final platform = Platform.isIOS ? 'ios' : 'android';
    const proofSignConfig = ProofSignConfig.fromEnvironment;

    if (!proofSignConfig.isConfigured) {
      throw const DeviceAuthException(
        'ProofSign not configured (PROOFSIGN_SERVER_URL not set)',
      );
    }

    // 1. Use ProofSign CallbackSigner with device auth
    if (authProvider != null && authProvider!.isRegistered) {
      Log.info(
        'Using ProofSign CallbackSigner with device auth',
        name: _tag,
        category: LogCategory.video,
      );
      return _createProofSignCallbackSigner(platform);
    }

    // 2. Use ProofSign CallbackSigner with dev bearer token (CI/testing)
    if (proofSignConfig.hasDevToken) {
      Log.info(
        'Using ProofSign CallbackSigner with dev bearer token',
        name: _tag,
        category: LogCategory.video,
      );
      return _createProofSignCallbackSigner(platform);
    }

    throw const DeviceAuthException(
      'ProofSign is configured but no device auth provider is registered '
      'and no dev bearer token is set',
    );
  }

  /// Creates a CallbackSigner that delegates signing to ProofSign with
  /// device attestation.
  Future<CallbackSigner> _createProofSignCallbackSigner(
    String platform,
  ) async {
    final config = await _getProofSignConfiguration(platform: platform);

    return CallbackSigner(
      algorithm: _parseAlgorithm(config.algorithm),
      certificateChainPem: config.certificateChain,
      signCallback: (data) async {
        return _signWithDeviceAuth(
          dataToSign: data,
          signingUrl: config.signingUrl,
          platform: platform,
        );
      },
      tsaUrl: config.timestampUrl,
    );
  }

  // ---------------------------------------------------------------------------
  // ProofSign HTTP methods
  // ---------------------------------------------------------------------------

  /// Fetch C2PA signing configuration from the ProofSign server.
  Future<_ProofSignSigningConfig> _getProofSignConfiguration({
    required String platform,
  }) async {
    const config = ProofSignConfig.fromEnvironment;
    final url = '${config.serverUrl}/api/v1/c2pa/configuration'
        '?platform=$platform';
    Log.info('Fetching ProofSign configuration: $url', name: _tag);

    final response = await _client
        .get(Uri.parse(url), headers: {'Accept': 'application/json'})
        .timeout(_signingTimeout);

    if (response.statusCode != 200) {
      throw DeviceAuthException(
        'Failed to fetch ProofSign config: ${response.statusCode}',
      );
    }

    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return _ProofSignSigningConfig(
      algorithm: json['algorithm'] as String,
      signingUrl: json['signing_url'] as String,
      timestampUrl: json['timestamp_url'] as String?,
      certificateChain: utf8.decode(
        base64Decode(json['certificate_chain'] as String),
      ),
    );
  }

  /// Sign data via the ProofSign server.
  ///
  /// Uses device auth headers when [authProvider] is available, or a dev
  /// bearer token from [ProofSignConfig] for CI/testing.
  ///
  /// Handles HTTP 428 (server requests fresh device verification) with
  /// automatic retry when using device auth.
  Future<Uint8List> _signWithDeviceAuth({
    required Uint8List dataToSign,
    required String signingUrl,
    required String platform,
  }) async {
    final claim = base64Encode(dataToSign);
    final useDeviceAuth = authProvider != null && authProvider!.isRegistered;

    Map<String, String> buildHeaders() {
      final headers = <String, String>{'Content-Type': 'application/json'};
      if (useDeviceAuth) {
        headers.addAll(authProvider!.additionalHeaders());
      } else {
        const config = ProofSignConfig.fromEnvironment;
        if (config.hasDevToken) {
          headers['Authorization'] = 'Bearer ${config.bearerToken}';
        }
      }
      return headers;
    }

    // Build request body (with device auth fields if available)
    final body = useDeviceAuth
        ? await authProvider!.buildSigningRequest(
            claim: claim,
            platform: platform,
          )
        : <String, dynamic>{'claim': claim, 'platform': platform};

    final response = await _client
        .post(
          Uri.parse(signingUrl),
          headers: buildHeaders(),
          body: jsonEncode(body),
        )
        .timeout(_signingTimeout);

    // Handle 428: server requests fresh device verification
    if (response.statusCode == 428 && useDeviceAuth) {
      Log.info(
        'Server requested fresh device verification (428), retrying',
        name: _tag,
      );
      await authProvider!.refreshVerification();

      final retryBody = await authProvider!.buildSigningRequest(
        claim: claim,
        platform: platform,
      );
      final retryResponse = await _client
          .post(
            Uri.parse(signingUrl),
            headers: buildHeaders(),
            body: jsonEncode(retryBody),
          )
          .timeout(_signingTimeout);

      if (retryResponse.statusCode != 200) {
        throw DeviceAuthException(
          'Signing failed after retry: '
          '${retryResponse.statusCode} ${retryResponse.body}',
        );
      }
      return _extractSignature(retryResponse.body);
    }

    if (response.statusCode != 200) {
      throw DeviceAuthException(
        'Signing failed: ${response.statusCode} ${response.body}',
      );
    }

    return _extractSignature(response.body);
  }

  /// Extract and validate the signature from a server response body.
  Uint8List _extractSignature(String responseBody) {
    final json = jsonDecode(responseBody) as Map<String, dynamic>;
    final signature = json['signature'];
    if (signature is! String) {
      throw const DeviceAuthException(
        'Server response missing or invalid "signature" field',
      );
    }
    return base64Decode(signature);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// Builds the manifest JSON for a freshly captured video.
  String _buildManifestJson(
    String claimGenerator,
    String title,
    String digitalSourceUrl,
  ) {
    return '''
{
  "claim_generator": "$claimGenerator",
  "title": "$title",
  "format": "video/mp4",
  "ingredients": [
        {
          "title": "$title",
          "format": "video/mp4",
          "relationship": "parentOf",
          "label": "c2pa.ingredient.v2"
        }
      ],
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

  /// Parse a signing algorithm string into the c2pa_flutter enum.
  static SigningAlgorithm _parseAlgorithm(String algorithm) {
    switch (algorithm.toLowerCase()) {
      case 'es256':
        return SigningAlgorithm.es256;
      case 'es384':
        return SigningAlgorithm.es384;
      case 'es512':
        return SigningAlgorithm.es512;
      case 'ps256':
        return SigningAlgorithm.ps256;
      case 'ps384':
        return SigningAlgorithm.ps384;
      case 'ps512':
        return SigningAlgorithm.ps512;
      case 'ed25519':
        return SigningAlgorithm.ed25519;
      default:
        return SigningAlgorithm.es256;
    }
  }

}

/// Signing configuration returned by the ProofSign server.
class _ProofSignSigningConfig {
  const _ProofSignSigningConfig({
    required this.algorithm,
    required this.signingUrl,
    required this.certificateChain,
    this.timestampUrl,
  });

  final String algorithm;
  final String signingUrl;
  final String? timestampUrl;
  final String certificateChain;
}
