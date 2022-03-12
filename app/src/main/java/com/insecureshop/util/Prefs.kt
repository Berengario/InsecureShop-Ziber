package com.insecureshop.util

import android.annotation.SuppressLint
import android.content.Context
import android.icu.util.Calendar
import android.os.Build
import android.preference.PreferenceManager
import android.security.KeyPairGeneratorSpec
import android.text.TextUtils
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.security.auth.x500.X500Principal


@SuppressLint("StaticFieldLeak")
@RequiresApi(Build.VERSION_CODES.N)
object Prefs {

    private const val TAG: String = "InsecureShop_APP"
    private const val KEYSTORE: String = "AndroidKeyStore"
    private const val ALIAS: String = "InsecureShop_APP"
    private const val TYPE_RSA = "RSA"
    private const val CYPHER = "RSA/ECB/PKCS1Padding"
    private val ENCODING = Charsets.UTF_8
    var prefs: Prefs? = null
    var ctx: Context? = null

    fun getInstance(context: Context): Prefs {
        if (prefs == null) {
            ctx = context
            prefs = this
        }
        return prefs!!
    }

    var data: String?
        get() = get(ctx, "data")
        set(value) {
            put(ctx, "data", value)
        }

    var username: String?
        get() = get(ctx, "username")
        set(value) {
            put(ctx, "username", value)
        }

    var password: String?
        get() = get(ctx, "password")
        set(value) {
            put(ctx, "password", value)
        }

//    var productList: String?
//        get() = get(ctx, "productList")
//        set(value) {
//            put(ctx, "productList", value)
//        }

    var productList: String?
        get() = PreferenceManager.getDefaultSharedPreferences(ctx).getString("productList", "")
        set(value) {
            PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putString("productList", value).apply()
        }

    fun clearAll() {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().clear().apply()
    }


    fun put(ctx: Context?, key: String?, value: String?) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(Prefs.ctx)
        if (value == null) {
            prefs.edit().putString(key, null).apply()
        } else {
            try {
                prefs.edit().putString(key, encryptString(ctx, value)).apply()
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }


    fun get(ctx: Context?, key: String?): String? {
        val prefs = PreferenceManager.getDefaultSharedPreferences(ctx)
        val pref = prefs.getString(key, "")
        return if (!TextUtils.isEmpty(pref)) {
            decryptString(ctx, pref)
        } else null
    }


    private fun encryptString(context: Context?, toEncrypt: String): String? {
        try {
            val privateKeyEntry: KeyStore.PrivateKeyEntry? = getPrivateKey(context)
            if (privateKeyEntry != null) {
                val publicKey: PublicKey = privateKeyEntry.certificate.publicKey

                // Encrypt the text
                val input: Cipher = Cipher.getInstance(CYPHER)
                input.init(Cipher.ENCRYPT_MODE, publicKey)
                val outputStream = ByteArrayOutputStream()
                val cipherOutputStream = CipherOutputStream(
                    outputStream, input
                )
                cipherOutputStream.write(toEncrypt.toByteArray(ENCODING))
                cipherOutputStream.close()
                val vals: ByteArray = outputStream.toByteArray()
                return Base64.encodeToString(vals, Base64.DEFAULT)
            }
        } catch (e: Exception) {
            Log.e(TAG, Log.getStackTraceString(e))
            return null
        }
        return null
    }


    private fun decryptString(context: Context?, encrypted: String?): String? {
        try {
            val privateKeyEntry: KeyStore.PrivateKeyEntry? = getPrivateKey(context)
            if (privateKeyEntry != null) {
                val privateKey: PrivateKey = privateKeyEntry.privateKey
                val output: Cipher = Cipher.getInstance(CYPHER)
                output.init(Cipher.DECRYPT_MODE, privateKey)
                val cipherInputStream = CipherInputStream(
                    ByteArrayInputStream(Base64.decode(encrypted, Base64.DEFAULT)), output
                )
                val values: ArrayList<Byte> = ArrayList()
                var nextByte: Int
                while (cipherInputStream.read().also { nextByte = it } != -1) {
                    values.add(nextByte.toByte())
                }
                val bytes = ByteArray(values.size)
                for (i in bytes.indices) {
                    bytes[i] = values[i]
                }
                return String(bytes, 0, bytes.size, ENCODING)
            }
        } catch (e: Exception) {
            Log.e(TAG, Log.getStackTraceString(e))
            return null
        }
        return null
    }


    private fun getPrivateKey(context: Context?): KeyStore.PrivateKeyEntry? {
        var ks: KeyStore = KeyStore.getInstance(KEYSTORE)
        val protParam: KeyStore.ProtectionParameter =
            KeyStore.PasswordProtection("@dm1n!".toCharArray())

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null)

        // Load the key pair from the Android Key Store
        var entry: KeyStore.Entry? = ks.getEntry(ALIAS, protParam)

        // If the entry is null, keys were never stored under this alias.

        if (entry == null) {
            Log.w(TAG, "No key found under alias: $ALIAS")
            Log.w(TAG, "Generating new key...")
            try {
                createKeys(context)

                // reload keystore
                ks = KeyStore.getInstance(KEYSTORE)
                ks.load(null)

                // reload key pair
                entry = ks.getEntry(ALIAS, null)
                if (entry == null) {
                    Log.w(TAG, "Generating new key failed...")
                    return null
                }
            } catch (e: NoSuchProviderException) {
                Log.w(TAG, "Generating new key failed...")
                e.printStackTrace()
                return null
            } catch (e: InvalidAlgorithmParameterException) {
                Log.w(TAG, "Generating new key failed...")
                e.printStackTrace()
                return null
            }
        }

        /* If entry is not a KeyStore.PrivateKeyEntry, it might have gotten stored in a previous
         * iteration of your application that was using some other mechanism, or been overwritten
         * by something else using the same keystore with the same alias.
         * You can determine the type using entry.getClass() and debug from there.
         */
        if (entry !is KeyStore.PrivateKeyEntry) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry")
            Log.w(TAG, "Exiting signData()...")
            return null
        }
        return entry
    }

    /**
     * Creates a public and private key and stores it using the Android Key Store, so that only
     * this application will be able to access the keys.
     */

    private fun createKeys(context: Context?) {
        // Create a start and end time, for the validity range of the key pair that's about to be
        // generated.
        val start: Calendar = Calendar.getInstance()
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 25)

        // The KeyPairGeneratorSpec object is how parameters for your key pair are passed
        // to the KeyPairGenerator.  For a fun home game, count how many classes in this sample
        // start with the phrase "KeyPair".
        val spec =
            KeyPairGeneratorSpec.Builder(context!!) // You'll use the alias later to retrieve the key.  It's a key for the key!
                .setAlias(ALIAS) // The subject used for the self-signed certificate of the generated pair
                .setSubject(X500Principal("CN=$ALIAS")) // The serial number used for the self-signed certificate of the
                // generated pair.
                .setSerialNumber(BigInteger.valueOf(1337)) // Date range of validity for the generated pair.
                .setStartDate(start.time)
                .setEndDate(end.time)
                .build()

        // Initialize a KeyPair generator using the the intended algorithm (in this example, RSA
        // and the KeyStore.  This example uses the AndroidKeyStore.
        val kpGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(TYPE_RSA, KEYSTORE)

        kpGenerator.initialize(spec)

        val kp: KeyPair = kpGenerator.generateKeyPair()
        Log.d(TAG, "Public Key is: " + kp.public.toString())
    }
}