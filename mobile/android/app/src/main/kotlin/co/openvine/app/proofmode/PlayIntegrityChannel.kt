package co.openvine.app.proofmode

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Flutter method channel for Google Play Integrity API.
 *
 * Requests integrity tokens that the ProofSign server can verify to confirm
 * the request comes from a genuine app on a genuine device with Play Services.
 *
 * Also provides the per-request EC P-256 signing key used to bind C2PA
 * signing requests to this device after Play Integrity registration. The
 * keypair lives in Android Keystore under a Play-Integrity-specific alias
 * (separate from the Key Attestation alias) so the two paths can coexist.
 */
class PlayIntegrityChannel(private val context: Context) {
    companion object {
        private const val CHANNEL_NAME = "com.openvine/play_integrity"
        private const val TAG = "PlayIntegrityChannel"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGNING_KEY_ALIAS = "proofsign_play_integrity_key"
    }

    fun register(flutterEngine: FlutterEngine) {
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            CHANNEL_NAME
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "requestIntegrityToken" -> {
                    val nonce = call.argument<String>("nonce")
                    val cloudProjectNumber = call.argument<String>("cloudProjectNumber")
                    if (nonce == null) {
                        result.error(
                            "INVALID_ARGUMENT",
                            "nonce is required",
                            null
                        )
                        return@setMethodCallHandler
                    }

                    requestIntegrityToken(nonce, cloudProjectNumber?.toLongOrNull(), result)
                }

                "isAvailable" -> {
                    // Play Integrity is available if Play Services is present
                    result.success(isPlayServicesAvailable())
                }

                "generateSigningKey" -> {
                    try {
                        val publicKey = generateSigningKey()
                        result.success(publicKey)
                    } catch (e: Exception) {
                        Log.e(TAG, "Signing key generation failed", e)
                        result.error("KEY_GENERATION_FAILED", e.message, null)
                    }
                }

                "getSigningKeyPublicKey" -> {
                    try {
                        result.success(getSigningKeyPublicKey())
                    } catch (e: Exception) {
                        Log.e(TAG, "Reading signing key public key failed", e)
                        result.error("KEY_READ_FAILED", e.message, null)
                    }
                }

                "signWithSigningKey" -> {
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
                        result.success(signWithSigningKey(data))
                    } catch (e: Exception) {
                        Log.e(TAG, "Device key signing failed", e)
                        result.error("SIGNING_FAILED", e.message, null)
                    }
                }

                else -> result.notImplemented()
            }
        }

        Log.d(TAG, "Play Integrity platform channel registered")
    }

    /**
     * Generate a fresh EC P-256 keypair in Android Keystore (overwriting any
     * existing one for the Play Integrity alias) and return the public key as
     * a base64-encoded X.509 SubjectPublicKeyInfo DER blob — the form the
     * ProofSign server expects in `/play_integrity/verify`.
     */
    private fun generateSigningKey(): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (keyStore.containsAlias(SIGNING_KEY_ALIAS)) {
            keyStore.deleteEntry(SIGNING_KEY_ALIAS)
        }

        val paramSpec = KeyGenParameterSpec.Builder(
            SIGNING_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).apply {
            setDigests(KeyProperties.DIGEST_SHA256)
            setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        }.build()

        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        keyPairGenerator.initialize(paramSpec)
        keyPairGenerator.generateKeyPair()

        val publicKey = keyStore.getCertificate(SIGNING_KEY_ALIAS).publicKey
        return Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
    }

    /**
     * Return the public key of the existing Play-Integrity signing keypair as
     * a base64-encoded SubjectPublicKeyInfo DER blob, or null if no keypair
     * has been generated yet.
     */
    private fun getSigningKeyPublicKey(): String? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        if (!keyStore.containsAlias(SIGNING_KEY_ALIAS)) {
            return null
        }
        val publicKey = keyStore.getCertificate(SIGNING_KEY_ALIAS).publicKey
        return Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
    }

    /**
     * Sign data with the Play-Integrity signing key. Returns the signature as
     * a base64-encoded ASN.1/DER ECDSA blob — the form the server expects.
     */
    private fun signWithSigningKey(data: String): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(SIGNING_KEY_ALIAS, null)
            ?: throw IllegalStateException(
                "Play Integrity signing key not found. Call generateSigningKey first."
            )

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey as PrivateKey)
        signature.update(data.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    private fun requestIntegrityToken(
        nonce: String,
        cloudProjectNumber: Long?,
        result: MethodChannel.Result
    ) {
        val integrityManager = IntegrityManagerFactory.create(context)

        val requestBuilder = IntegrityTokenRequest.builder()
            .setNonce(nonce)

        if (cloudProjectNumber != null) {
            requestBuilder.setCloudProjectNumber(cloudProjectNumber)
        }

        val integrityTokenResponse = integrityManager.requestIntegrityToken(
            requestBuilder.build()
        )

        integrityTokenResponse.addOnSuccessListener { response ->
            val token = response.token()
            Log.d(TAG, "Integrity token received (length: ${token.length})")
            result.success(token)
        }

        integrityTokenResponse.addOnFailureListener { exception ->
            Log.e(TAG, "Integrity token request failed", exception)
            result.error(
                "INTEGRITY_TOKEN_FAILED",
                exception.message,
                null
            )
        }
    }

    private fun isPlayServicesAvailable(): Boolean {
        return try {
            val clazz = Class.forName(
                "com.google.android.gms.common.GoogleApiAvailability"
            )
            val getInstance = clazz.getMethod("getInstance")
            val instance = getInstance.invoke(null)
            val isAvailable = clazz.getMethod(
                "isGooglePlayServicesAvailable",
                Context::class.java
            )
            val result = isAvailable.invoke(instance, context) as Int
            // ConnectionResult.SUCCESS == 0
            result == 0
        } catch (e: Exception) {
            false
        }
    }
}
