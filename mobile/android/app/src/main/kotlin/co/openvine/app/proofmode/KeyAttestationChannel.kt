package co.openvine.app.proofmode

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Flutter method channel for Android Key Attestation.
 *
 * Provides hardware-backed key generation with attestation certificates
 * and signing operations for devices without Google Play Services.
 */
class KeyAttestationChannel {
    companion object {
        private const val CHANNEL_NAME = "com.openvine/key_attestation"
        private const val TAG = "KeyAttestationChannel"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "proofsign_key_attestation_key"
    }

    fun register(flutterEngine: FlutterEngine) {
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            CHANNEL_NAME
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "generateAttestationKey" -> {
                    val challenge = call.argument<String>("challenge")
                    val deviceId = call.argument<String>("deviceId")
                    if (challenge == null || deviceId == null) {
                        result.error(
                            "INVALID_ARGUMENT",
                            "challenge and deviceId are required",
                            null
                        )
                        return@setMethodCallHandler
                    }

                    try {
                        val certChain = generateAttestationKey(challenge)
                        result.success(certChain)
                    } catch (e: Exception) {
                        Log.e(TAG, "Key attestation generation failed", e)
                        result.error(
                            "KEY_GENERATION_FAILED",
                            e.message,
                            null
                        )
                    }
                }

                "signWithDeviceKey" -> {
                    val data = call.argument<String>("data")
                    if (data == null) {
                        result.error(
                            "INVALID_ARGUMENT",
                            "data is required",
                            null
                        )
                        return@setMethodCallHandler
                    }

                    try {
                        val signature = signWithDeviceKey(data)
                        result.success(signature)
                    } catch (e: Exception) {
                        Log.e(TAG, "Device key signing failed", e)
                        result.error("SIGNING_FAILED", e.message, null)
                    }
                }

                else -> result.notImplemented()
            }
        }

        Log.d(TAG, "Key Attestation platform channel registered")
    }

    /**
     * Generate a hardware-backed key with attestation.
     *
     * The attestation challenge is embedded in the key's certificate,
     * allowing the server to verify the key was generated on genuine hardware.
     *
     * Returns the certificate chain as a list of Base64-encoded DER certificates.
     */
    private fun generateAttestationKey(challenge: String): List<String> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        // Delete any existing key
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }

        // Server sends challenge as hex-encoded string; the attestation
        // extension must contain the raw decoded bytes, not the UTF-8
        // bytes of the hex string.
        val challengeBytes = hexDecode(challenge)

        // Try StrongBox first (Android 9+), fall back to TEE
        val useStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        if (useStrongBox) {
            try {
                generateKeyPairWithParams(challengeBytes, strongBox = true)
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox key generation failed, falling back to TEE", e)
                // Clean up failed key before retry
                if (keyStore.containsAlias(KEY_ALIAS)) {
                    keyStore.deleteEntry(KEY_ALIAS)
                }
                generateKeyPairWithParams(challengeBytes, strongBox = false)
            }
        } else {
            generateKeyPairWithParams(challengeBytes, strongBox = false)
        }

        // Extract certificate chain with attestation extension
        val certChain = keyStore.getCertificateChain(KEY_ALIAS)
        return certChain.map { cert ->
            Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
        }
    }

    private fun generateKeyPairWithParams(challengeBytes: ByteArray, strongBox: Boolean) {
        val paramSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).apply {
            setDigests(KeyProperties.DIGEST_SHA256)
            setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            setAttestationChallenge(challengeBytes)
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(true)
            }
        }.build()

        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        keyPairGenerator.initialize(paramSpec)
        keyPairGenerator.generateKeyPair()
    }

    /**
     * Decode a hex-encoded string into its raw bytes.
     */
    private fun hexDecode(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    /**
     * Sign data with the hardware-backed device key.
     *
     * Returns the signature as a Base64-encoded string.
     */
    private fun signWithDeviceKey(data: String): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val privateKey = keyStore.getKey(KEY_ALIAS, null)
            ?: throw IllegalStateException("Device key not found. Call generateAttestationKey first.")

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey as java.security.PrivateKey)
        signature.update(data.toByteArray(Charsets.UTF_8))
        val signedBytes = signature.sign()

        return Base64.encodeToString(signedBytes, Base64.NO_WRAP)
    }
}
