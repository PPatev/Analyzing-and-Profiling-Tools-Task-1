using System.Security.Cryptography;

namespace Analyzing_and_Profiling_Tools
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var password = "password";


            var salt = new byte[16];
            var random = new Random();
            random.NextBytes(salt);

            var passwordHash = GeneratePasswordHashUsingSalt(password, salt);

            Console.WriteLine($"PaswordHash: {passwordHash}");
        }

        public static string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
        {
            var iterate = 10_000;
            var pbkdf2 = new CustomRfc2898DeriveBytes(passwordText, salt, iterate);
            byte[] hash = pbkdf2.GetBytes(20);

            byte[] hashBytes = new byte[36];

            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            var passwordHash = Convert.ToBase64String(hashBytes);

            return passwordHash;
        }
    }
}