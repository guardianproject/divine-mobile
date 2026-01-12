package co.openvine.app.proofmode

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.location.Location
import android.os.Build
import android.os.Environment
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.contentauth.c2pa.Builder
import org.contentauth.c2pa.ByteArrayStream
import org.contentauth.c2pa.C2PA
import org.contentauth.c2pa.DataStream
import org.contentauth.c2pa.FileStream
import org.contentauth.c2pa.Signer
import org.contentauth.c2pa.Stream
import org.contentauth.c2pa.WebServiceSigner
import org.contentauth.c2pa.manifest.Action
import org.contentauth.c2pa.manifest.AttestationBuilder
import org.contentauth.c2pa.manifest.C2PAActions
import org.contentauth.c2pa.manifest.C2PAFormats
import org.contentauth.c2pa.manifest.C2PARelationships
import org.contentauth.c2pa.manifest.DigitalSourceTypes
import org.contentauth.c2pa.manifest.Ingredient
import org.contentauth.c2pa.manifest.ManifestBuilder
import org.contentauth.c2pa.manifest.SoftwareAgent
import org.contentauth.c2pa.manifest.TimestampAuthorities
import org.json.JSONObject
import org.witness.proofmode.c2pa.SigningMode
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.security.auth.x500.X500Principal

class C2PAManager(private val context: Context) {
    companion object {
        private const val TAG = "C2PAManager"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS_PREFIX = "C2PA_KEY_"

        private const val DEFAULT_SIGNING_SERVER_ENDPOINT = "https://zbjspd6jfv.us-east-2.awsapprunner.com/api/v1/c2pa/configuration?platform=android"
        private const val DEFAULT_SIGNING_SERVER_TOKEN = "2d0c8b6b66c47c3b215976cc808296269322558c6d533d9ce6f3c45a9ccfe811"

        private val iso8601 = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
    }

    private lateinit var defaultSigner:Signer

    suspend fun signMediaFile(inFile: File, contentType: String, outFile: File, doEmbed: Boolean = true): Result<Stream> =
        withContext(Dispatchers.IO) {
            try {


                Log.d(TAG, "Original file size: ${inFile.length()} bytes")

                // Get current signing mode
                //val signingMode = preferencesManager.signingMode.first()
                val signingMode = SigningMode.REMOTE

                Log.d(TAG, "Using signing mode: $signingMode")

                var creator = "diVineUserId"

                // Create manifest JSON
                val manifestJSON =
                    createManifestJSON(context, creator, inFile.name, contentType, null, true)
                //Timber.tag(TAG).d("Media manifest file:\n\n$manifestJSON")

                // Create appropriate signer based on mode
                if (!::defaultSigner.isInitialized)
                    defaultSigner = createRemoteSigner()

                // Sign the image using C2PA library
                val fileStream = FileStream(inFile)
                val outStream = FileStream(outFile)

                signStream(fileStream, contentType, outStream, manifestJSON, defaultSigner, doEmbed)
                Log.d(TAG, "Signed file size: ${outFile.length()} bytes")

                // Verify the signed image
                var isVerified = verifySignedImage(outFile.absolutePath)
                Log.d(TAG, "isVerified=$isVerified")

                Result.success(outStream)
            } catch (e: Exception) {
                Log.e(TAG, "Error signing image", e)
                e.printStackTrace();
                Result.failure(e)
            }
        }


    /**
    private fun createDefaultSigner(tsaUrl: String): Signer {
        requireNotNull(defaultCertificate) { "Default certificate not available" }
        requireNotNull(defaultPrivateKey) { "Default private key not available" }

        Log.d(TAG, "Creating default signer with test certificates")
        Log.d(TAG, "Certificate length: ${defaultCertificate!!.length} chars")
        Log.d(TAG, "Private key length: ${defaultPrivateKey!!.length} chars")


        return try {
            Signer.fromKeys(
                certsPEM = defaultCertificate!!,
                privateKeyPEM = defaultPrivateKey!!,
                algorithm = SigningAlgorithm.ES256,
                tsaURL = tsaUrl,
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create default signer", e)
            throw e
        }
    }**/





    private suspend fun createRemoteSigner(): Signer {
        /**
        val remoteUrl =
            preferencesManager.remoteUrl.first()
                ?: throw IllegalStateException("Remote signing URL not configured")
        val bearerToken = preferencesManager.remoteToken.first()

        val configUrl =
            if (remoteUrl.contains("/api/v1/c2pa/configuration")) {
                remoteUrl
            } else {
                "$remoteUrl/api/v1/c2pa/configuration"
            }**/

        val configUrl = DEFAULT_SIGNING_SERVER_ENDPOINT
        val bearerToken = DEFAULT_SIGNING_SERVER_TOKEN

        Log.d(TAG, "Creating WebServiceSigner with URL: $configUrl")

        // Use the new WebServiceSigner class
        val webServiceSigner =
            WebServiceSigner(configurationURL = configUrl, bearerToken = bearerToken)

        return webServiceSigner.createSigner()
    }

    private fun createKeystoreKey(alias: String, useHardware: Boolean) {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

        val paramSpec =
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .apply {
                    setDigests(KeyProperties.DIGEST_SHA256)
                    setAlgorithmParameterSpec(
                        ECGenParameterSpec("secp256r1"),
                    )

                    if (useHardware) {
                        // Request hardware backing (StrongBox if available, TEE otherwise)
                        if (Build.VERSION.SDK_INT >=
                            Build.VERSION_CODES.P
                        ) {
                            setIsStrongBoxBacked(true)
                        }
                    }

                    // Self-signed certificate validity
                    setCertificateSubject(
                        X500Principal("CN=C2PA Android User, O=C2PA Example, C=US"),
                    )
                    setCertificateSerialNumber(
                        BigInteger.valueOf(System.currentTimeMillis()),
                    )
                    setCertificateNotBefore(Date())
                    setCertificateNotAfter(
                        Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                    )
                }
                .build()

        keyPairGenerator.initialize(paramSpec)
        keyPairGenerator.generateKeyPair()
    }



    private fun signImageData(imageData: ByteArray, manifestJSON: String, signer: Signer): ByteArray {
        Log.d(TAG, "Starting signImageData")
        Log.d(TAG, "Input image size: ${imageData.size} bytes")
        Log.d(TAG, "Manifest JSON: ${manifestJSON.take(200)}...") // First 200 chars

        // Create Builder with manifest
        Log.d(TAG, "Creating Builder from JSON")
        val builder = Builder.fromJson(manifestJSON)

        // Use ByteArrayStream which is designed for this purpose
        Log.d(TAG, "Creating streams")
        val sourceStream = DataStream(imageData)
        val destStream = ByteArrayStream()

        try {
            // Sign the image
            Log.d(TAG, "Calling builder.sign()")
            builder.sign(
                format = "image/jpeg",
                source = sourceStream,
                dest = destStream,
                signer = signer,
            )

            Log.d(TAG, "builder.sign() completed successfully")
            val result = destStream.getData()
            Log.d(TAG, "Output size: ${result.size} bytes")
            return result
        } catch (e: Exception) {
            Log.e(TAG, "Error in signImageData", e)
            Log.e(TAG, "Error message: ${e.message}")
            Log.e(TAG, "Error cause: ${e.cause}")
            throw e
        } finally {
            // Make sure to close streams
            Log.d(TAG, "Closing streams")
            sourceStream.close()
            destStream.close()
        }
    }

    private fun signStream(sourceStream: Stream, contentType: String, destStream: Stream, manifestJSON: String, signer: Signer, embed: Boolean = true) {
        Log.d(TAG, "Starting signImageData")
        Log.d(TAG, "Manifest JSON: ${manifestJSON.take(200)}...") // First 200 chars

        // Create Builder with manifest
        Log.d(TAG, "Creating Builder from JSON")
        val builder = Builder.fromJson(manifestJSON)

        if (!embed)
            builder.setNoEmbed()

        try {
            // Sign the image
            Log.d(TAG, "Calling builder.sign()")
            builder.sign(
                format = contentType,
                source = sourceStream,
                dest = destStream,
                signer = signer,
            )

            Log.d(TAG, "builder.sign() completed successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Error in signImageData", e)
            Log.e(TAG, "Error message: ${e.message}")
            Log.e(TAG, "Error cause: ${e.cause}")
            throw e
        } finally {
            // Make sure to close streams
            Log.d(TAG, "Closing streams")
            sourceStream.close()
            destStream.close()
        }
    }

    private fun createManifestJSON(context: Context, creator: String, fileName: String, contentType: String, location: Location?, isDirectCapture: Boolean): String {

        val appLabel = getAppName(context)
        val appVersion = getAppVersionName(context)

        //val appInfo = ApplicationInfo(appLabel, appVersion, APP_ICON_URI)

        //  val mediaFile = FileData(fileImageIn.absolutePath, null, fileImageIn.name)
        //val contentCreds = userCert?.let { ContentCredentials(it,mediaFile, appInfo) }

        val exifMake = Build.MANUFACTURER
        val exifModel = Build.MODEL
        val exifTimestamp = Date().toGMTString()

        var softwareAgent = SoftwareAgent("$appLabel $appVersion", Build.VERSION.SDK_INT.toString(), Build.VERSION.CODENAME)

        val currentTs = iso8601.format(Date())
        val thumbnailId = fileName + "-thumb.jpg"

        var mb = ManifestBuilder()
        mb.claimGenerator(appLabel, version = appVersion)
        mb.timestampAuthorityUrl(TimestampAuthorities.DIGICERT)

        mb.title(fileName)
        mb.format(contentType)
        //   mb.addThumbnail(Thumbnail(C2PAFormats.JPEG, thumbnailId))

        val sAgent = SoftwareAgent(appLabel, appVersion, Build.PRODUCT)

        if (isDirectCapture)
        {
            //add created
            mb.addAction(Action(C2PAActions.CREATED, currentTs, softwareAgent, digitalSourceType = DigitalSourceTypes.DIGITAL_CAPTURE))
        }
        else
        {
            //add placed
            mb.addAction(Action(C2PAActions.PLACED, currentTs, softwareAgent))

        }

        val ingredient = Ingredient(
            title = fileName,
            format = C2PAFormats.JPEG,
            relationship = C2PARelationships.PARENT_OF,
            //         thumbnail = Thumbnail(C2PAFormats.JPEG, thumbnailId)
        )

        mb.addIngredient(ingredient)

        val attestationBuilder = AttestationBuilder()

        /**
        attestationBuilder.addCreativeWork {
            addAuthor(creator)
            dateCreated(Date())
        }**/





        /**
        val customAttestationJson = JSONObject().apply {
        put("@type", "Integrity")
        put("nonce", "something")
        put("response", "b64encodedresponse")
        }

        attestationBuilder.addCustomAttestation("app.integrity", customAttestationJson)

        attestationBuilder.addCAWGIdentity {
            validFromNow()
            addSocialMediaIdentity(pgpFingerprint, webLink, currentTs, appLabel, appLabel)
        }
         **/



        attestationBuilder.buildForManifest(mb)

        val manifestJson = mb.buildJson()


        return manifestJson
    }

    private fun verifySignedImage(filePath: String): Boolean {
        try {

            // Read and verify using C2PA
            val manifestJSON = C2PA.readFile(filePath, null)

            Log.d(TAG, "C2PA VERIFICATION SUCCESS")
            Log.d(TAG, "Manifest JSON length: ${manifestJSON.length} characters")
            Log.d(TAG,"Menifest JSON:\n${manifestJSON}")

            // Parse and log key information
            val manifest = JSONObject(manifestJSON)
            manifest.optJSONObject("active_manifest").let { activeManifest ->
                Log.d(TAG, "Active manifest found")
                activeManifest?.optString("claim_generator").let {
                    Log.d(TAG, "Claim generator: $it")
                }
                activeManifest?.optString("title")?.let { Log.d(TAG, "Title: $it") }
                activeManifest?.optJSONObject("signature_info")?.let { sigInfo ->
                    Log.d(TAG, "Signature info present")
                    sigInfo.optString("alg").let { Log.d(TAG, "Algorithm: $it") }
                    sigInfo.optString("issuer").let { Log.d(TAG, "Issuer: $it") }
                    return true
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "C2PA VERIFICATION FAILED", e)


        }

        return false
    }

    private fun createLocationAssertion(location: Location): JSONObject {
        val timestamp = formatIsoTimestamp(Date(location.time))
        val metadata =
            JSONObject().apply {
                put("exif:GPSLatitude", location.latitude.toString())
                put("exif:GPSLongitude", location.longitude.toString())
                put("exif:GPSAltitude", location.altitude.toString())
                put("exif:GPSTimeStamp", timestamp)
                put(
                    "@context",
                    JSONObject().apply { put("exif", "http://ns.adobe.com/exif/1.0/") },
                )
            }
        return JSONObject().apply {
            put("label", "c2pa.metadata")
            put("data", metadata)
        }
    }

    private fun formatIsoTimestamp(date: Date): String {
        val formatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        formatter.timeZone = TimeZone.getTimeZone("UTC")
        return formatter.format(date)
    }

    fun saveImageToGallery(imageData: ByteArray): Result<String> = try {
        // Implementation depends on Android version
        // For simplicity, saving to app's external files directory
        val photosDir =
            File(
                context.getExternalFilesDir(
                    Environment.DIRECTORY_PICTURES,
                ),
                "C2PA",
            )
        Log.d(TAG, "Gallery directory: ${photosDir.absolutePath}")
        Log.d(TAG, "Directory exists: ${photosDir.exists()}")

        if (!photosDir.exists()) {
            val created = photosDir.mkdirs()
            Log.d(TAG, "Directory created: $created")
        }

        val fileName = "C2PA_${System.currentTimeMillis()}.jpg"
        val file = File(photosDir, fileName)
        file.writeBytes(imageData)

        Log.d(TAG, "Image saved to: ${file.absolutePath}")
        Log.d(TAG, "File exists: ${file.exists()}")
        Log.d(TAG, "File size: ${file.length()} bytes")

        // Verify the file can be read back
        if (file.exists() && file.canRead()) {
            Log.d(TAG, "File successfully saved and readable")
        } else {
            Log.e(TAG, "File saved but cannot be read")
        }

        Result.success(file.absolutePath)
    } catch (e: Exception) {
        Log.e(TAG, "Error saving image", e)
        Result.failure(e)
    }

    /**
     * Helper functions for getting app name and version
     */
    fun getAppVersionName(context: Context): String {

        var appVersionName = ""
        try {
            appVersionName =
                context.packageManager.getPackageInfo(context.packageName, 0).versionName?:""

        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
        }
        return appVersionName
    }

    fun getAppName(context: Context): String {
        var applicationInfo: ApplicationInfo? = null
        try {
            applicationInfo = context.packageManager.getApplicationInfo(context.applicationInfo.packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            Log.d("TAG", "The package with the given name cannot be found on the system.", e)
        }
        return (if (applicationInfo != null) context.packageManager.getApplicationLabel(applicationInfo) else "Unknown") as String

    }
}
