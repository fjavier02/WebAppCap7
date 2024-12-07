using Oracle.ManagedDataAccess.Client;

namespace WebAppCap7.Tests
{
    public class OracleConnectionTest
    {
        public static void TestConnection()
        {
            string connectionString = "User Id=cap10;Password=cap10;Data Source=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=XEPDB1)))";

            try
            {
                using (var connection = new OracleConnection(connectionString))
                {
                    connection.Open();
                    Console.WriteLine("Conexión exitosa a Oracle.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al conectar a Oracle: {ex.Message}");
            }
        }
    }
}
