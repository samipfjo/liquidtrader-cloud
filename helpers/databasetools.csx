#r "System.Data"
#r "Microsoft.WindowsAzure.Storage"
#r "System.Configuration"

using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Threading.Tasks;


public static void WriteDatabase(string queryString, List<string> paramNames, List<object> paramValues)
{
    string connectionInfo = ConfigurationManager.ConnectionStrings["LICENSE_SERVER_CONNECTION"].ConnectionString;

    using (SqlConnection connection = new SqlConnection(connectionInfo)) {
        connection.Open();

        using (var tran = connection.BeginTransaction()) {
            using (SqlCommand command = new SqlCommand(queryString, connection, tran)) {
                for (int i=0; i < paramNames.Count; i++) {
                    command.Parameters.AddWithValue(paramNames[i], paramValues[i]);
                }

                try {
                    command.ExecuteNonQuery();

                } catch {
                    tran.Rollback();
                    throw;
                }

                tran.Commit();
            }
        }
    }
}


public static List<string> ReadDatabase(String queryString, List<string> paramNames, List<object> paramValues, TraceWriter log)
{
    string connectionInfo = ConfigurationManager.ConnectionStrings["LICENSE_SERVER_CONNECTION"].ConnectionString;
    List<string> output = new List<string>();

    using (SqlConnection connection = new SqlConnection(connectionInfo)) {
        connection.Open();

        using (SqlCommand command = new SqlCommand(queryString, connection)) {
            for (int i=0; i < paramNames.Count; i++) {
                command.Parameters.AddWithValue(paramNames[i], paramValues[i]);
            }

            using (var reader = command.ExecuteReader()) {
                int columnCount = reader.FieldCount;

                try {
                    while (reader.Read()) {
                        for (int columnIndex=0; columnIndex < columnCount; columnIndex++) {
                            if (!reader.IsDBNull(columnIndex)) {
                                output.Add(reader.GetValue(columnIndex).ToString());
                            }
                        }
                    }

                } catch (Exception ex) {
                    log.Error(ex.ToString());
                }
            }
        }
    }

    return output;
}

