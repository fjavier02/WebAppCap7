using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace WebAppCap7.Helpers
{

    public static class EncryptionHelper
    {
        private static readonly byte[] StaticSalt = Convert.FromBase64String("aGVsbG90aGlzYXBvd2VyZnVsYmFzZTY0c3RyaW5n"); // Ejemplo

        public static string HashPassword(string password)
        {
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: StaticSalt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));
        }

        public static bool VerifyPassword(string password, string storedHash)
        {
            string hash = HashPassword(password);
            return hash == storedHash;
        }
    }

}
