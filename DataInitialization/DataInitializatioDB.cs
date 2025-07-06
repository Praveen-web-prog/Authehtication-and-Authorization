using Microsoft.Data.SqlClient;

namespace MyAuthentication.DataInitialization
{
    public class DataInitializatioDB
    {
        IConfiguration configuration;
        public DataInitializatioDB(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void InitializeDatabase()
        {
            using (SqlConnection sqlConnection =
                new SqlConnection(configuration["DefaultConnection"]))
            {
                sqlConnection.Open();

                string sqlString = @"
                      IF NOT EXSIST (SELEC * FROM sys.database WHERE name = AuthDb)
                      BEGIN 
                       CREATE DATABASE AuthdB
                      END
                     ";
                       
                using (SqlCommand cmd = new SqlCommand(sqlString,sqlConnection))
                {
                    cmd.ExecuteNonQuery();
                }

            }

        }
    }
    
}
