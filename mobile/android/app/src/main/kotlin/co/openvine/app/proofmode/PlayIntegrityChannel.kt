package co.openvine.app.proofmode

import android.content.Context
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Flutter method channel for Google Play Integrity API.
 *
 * Requests integrity tokens that the ProofSign server can verify to confirm
 * the request comes from a genuine app on a genuine device with Play Services.
 */
class PlayIntegrityChannel(private val context: Context) {
    companion object {
        private const val CHANNEL_NAME = "com.openvine/play_integrity"
        private const val TAG = "PlayIntegrityChannel"
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

                else -> result.notImplemented()
            }
        }

        Log.d(TAG, "Play Integrity platform channel registered")
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
