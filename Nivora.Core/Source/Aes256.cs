using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Nivora.Core;

public class Aes256
{
                  /// <summary>
        /// Encrypts plain text as a string using AES-256 CBC with PKCS7 padding.
        /// </summary>
        /// <param name="plainText">Input string to encrypt (UTF8 encoded).</param>
        /// <param name="key">The encryption key (32 bytes for AES-256).</param>
        /// <param name="iv">The initialization vector (16 bytes).</param>
        /// <returns>Base64 encoded ciphertext string.</returns>
        public static string Encrypt(string plainText, byte[] key, byte[] iv)
        {
            // Convert the input string to bytes (UTF8)
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = Encrypt(plainBytes, key, iv);
            // Convert to base64 for transport/safe output
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// Decrypts a base64 encoded ciphertext string using AES-256 CBC with PKCS7 padding.
        /// </summary>
        /// <param name="cipherTextBase64">Base64 encoded ciphertext string.</param>
        /// <param name="key">The decryption key (32 bytes for AES-256).</param>
        /// <param name="iv">The initialization vector (16 bytes).</param>
        /// <returns>Decrypted plain text as string (UTF8).</returns>
        public static string Decrypt(string cipherTextBase64, byte[] key, byte[] iv)
        {
            // Convert base64 input to bytes
            var cipherBytes = Convert.FromBase64String(cipherTextBase64);
            var plainBytes = Decrypt(cipherBytes, key, iv);
            // Convert bytes to UTF8 string
            return Encoding.UTF8.GetString(plainBytes);
        }

        /// <summary>
        /// Encrypts plain bytes using AES-256 CBC with PKCS7 padding.
        /// </summary>
        /// <param name="plainBytes">Plain byte array.</param>
        /// <param name="key">The encryption key (32 bytes for AES-256).</param>
        /// <param name="iv">The initialization vector (16 bytes).</param>
        /// <returns>Encrypted bytes.</returns>
        public static byte[] Encrypt(byte[] plainBytes, byte[] key, byte[] iv)
        {
            if (key is not { Length: 32 })
                throw new ArgumentException("Key must be 32 bytes for AES-256.");
            if (iv is not { Length: 16 })
                throw new ArgumentException("IV must be 16 bytes.");

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            var output = new byte[cipher.GetOutputSize(plainBytes.Length)];
            var length = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, output, 0);
            length += cipher.DoFinal(output, length);

            // Copy only the valid bytes
            var encrypted = new byte[length];
            Array.Copy(output, 0, encrypted, 0, length);

            return encrypted;
        }

        /// <summary>
        /// Decrypts AES-256 CBC encrypted bytes with PKCS7 padding.
        /// </summary>
        /// <param name="cipherBytes">Encrypted byte array.</param>
        /// <param name="key">The decryption key (32 bytes for AES-256).</param>
        /// <param name="iv">The initialization vector (16 bytes).</param>
        /// <returns>Decrypted plain byte array.</returns>
        public static byte[] Decrypt(byte[] cipherBytes, byte[] key, byte[] iv)
        {
            if (key is not { Length: 32 })
                throw new ArgumentException("Key must be 32 bytes for AES-256.");
            if (iv is not { Length: 16 })
                throw new ArgumentException("IV must be 16 bytes.");

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            var output = new byte[cipher.GetOutputSize(cipherBytes.Length)];
            var length = cipher.ProcessBytes(cipherBytes, 0, cipherBytes.Length, output, 0);
            length += cipher.DoFinal(output, length);

            // Copy only the valid bytes
            var decrypted = new byte[length];
            Array.Copy(output, 0, decrypted, 0, length);

            return decrypted;
        }
        
        /// <summary>
        /// Encrypts the data from a source stream and writes the encrypted data to a destination stream using AES-256 CBC with PKCS7 padding.
        /// </summary>
        /// <param name="inputStream">Source stream with plain data.</param>
        /// <param name="outputStream">Destination stream to receive encrypted data.</param>
        /// <param name="key">Encryption key (32 bytes).</param>
        /// <param name="iv">Initialization vector (16 bytes).</param>
        /// <param name="bufferSize">Buffer size for reading/writing (default: 4096 bytes).</param>
        public static async Task EncryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv, int bufferSize = 4096, CancellationToken token = default)
        {
            if (key is not { Length: 32 })
                throw new ArgumentException("Key must be 32 bytes for AES-256.", nameof(key));
            if (iv is not { Length: 16 })
                throw new ArgumentException("IV must be 16 bytes.", nameof(iv));
            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable.", nameof(inputStream));
            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable.", nameof(outputStream));

            // Create cipher for AES-256 CBC with PKCS7 padding
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            var inputBuffer = new byte[bufferSize];
            var outputBuffer = new byte[cipher.GetOutputSize(bufferSize)];
            int bytesRead;
            int outputLen;
            while ((bytesRead = await inputStream.ReadAsync(inputBuffer, token)) > 0)
            {
                outputLen = cipher.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                if (outputLen > 0)
                    await outputStream.WriteAsync(outputBuffer.AsMemory(0, outputLen), token);
            }
            // Finalize encryption and write any remaining bytes
            outputLen = cipher.DoFinal(outputBuffer, 0);
            if (outputLen > 0)
                await outputStream.WriteAsync(outputBuffer.AsMemory(0, outputLen), token);
        }

        /// <summary>
        /// Decrypts the data from a source stream and writes the decrypted data to a destination stream using AES-256 CBC with PKCS7 padding.
        /// </summary>
        /// <param name="inputStream">Source stream with encrypted data.</param>
        /// <param name="outputStream">Destination stream for decrypted data.</param>
        /// <param name="key">Decryption key (32 bytes).</param>
        /// <param name="iv">Initialization vector (16 bytes).</param>
        /// <param name="bufferSize">Buffer size for reading/writing (default: 4096 bytes).</param>
        public static async Task DecryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv, int bufferSize = 4096, CancellationToken token = default)
        {
            if (key is not { Length: 32 })
                throw new ArgumentException("Key must be 32 bytes for AES-256.", nameof(key));
            if (iv is not { Length: 16 })
                throw new ArgumentException("IV must be 16 bytes.", nameof(iv));
            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable.", nameof(inputStream));
            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable.", nameof(outputStream));

            // Create cipher for AES-256 CBC with PKCS7 padding
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            var inputBuffer = new byte[bufferSize];
            var outputBuffer = new byte[cipher.GetOutputSize(bufferSize)];
            int bytesRead;
            int outputLen;
            while ((bytesRead = await inputStream.ReadAsync(inputBuffer, token)) > 0)
            {
                outputLen = cipher.ProcessBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
                if (outputLen > 0)
                    await outputStream.WriteAsync(outputBuffer.AsMemory(0, outputLen), token);
            }
            // Finalize decryption and write any remaining bytes
            outputLen = cipher.DoFinal(outputBuffer, 0);
            if (outputLen > 0)
                await outputStream.WriteAsync(outputBuffer.AsMemory(0, outputLen), token);
        }

        /// <summary>
        /// Generates a random key for AES encryption.
        /// </summary>
        /// <param name="keySizeInBits">The key size in bits (256 only for AES-256).</param>
        /// <returns>Random key as byte array.</returns>
        public static byte[] GenerateRandomKey(int keySizeInBits = 256)
        {
            if (keySizeInBits != 256)
                throw new ArgumentException("Only 256-bit keys are supported by AES.");
            var random = new SecureRandom();
            var key = new byte[keySizeInBits / 8];
            random.NextBytes(key);
            return key;
        }

        /// <summary>
        /// Generates a random IV for AES encryption.
        /// </summary>
        /// <returns>Random IV as byte array (16 bytes).</returns>
        public static byte[] GenerateRandomIv()
        {
            var random = new SecureRandom();
            var iv = new byte[16];
            random.NextBytes(iv);
            return iv;
        }
}