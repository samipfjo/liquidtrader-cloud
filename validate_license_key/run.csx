#r "Microsoft.WindowsAzure.Storage"
#r "Newtonsoft.Json"
#r "System.Data"
#r "System.Configuration"
#r "System.ServiceModel"
#r "System.Web"

#load "CryptoHelper.csx"
#load "D:/home/site/wwwroot/helpers/databasetools.csx"
#load "D:/home/site/wwwroot/helpers/bantool.csx"

using System.Net;
using System.Net.Http;

using System.Web;
using System.ServiceModel.Channels;

using System.Text;
using System.Text.RegularExpressions;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.Security.Cryptography;

using Newtonsoft.Json;


// ---------------
public static TraceWriter logger;

public static string CONNECTED_CLIENT;


// RSA keys for use with verfication process
public static RSACryptoServiceProvider SERVER_CRYPTO_ENGINE = PrivateKeyFromPemFile(@"D:\home\site\wwwroot\validate_license_key\keys\server.pem");
public static RSACryptoServiceProvider LIQUITRADER_CRYPTO_ENGINE = PublicKeyFromPemFile(@"D:\home\site\wwwroot\validate_license_key\keys\liquitrader.pem");

// ---------------
public static bool IsValidLicenseKeyFormat(string licenseKey)
{
    return (new Regex("^([ACDEFGHJKLMNPQRTVWXYZ23479]{5}-){4}[ACDEFGHJKLMNPQRTVWXYZ23479]{5}$")).IsMatch(licenseKey);
}


public static string Base64Encode(string plainText, byte[] plainTextBytes=null)
{
  if (plainTextBytes == null) {
    plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
  }

  return System.Convert.ToBase64String(plainTextBytes);
}

public static byte[] Base64Decode(string base64EncodedData)
{
  return System.Convert.FromBase64String(base64EncodedData);
}


public static string RSAEncrypt(string data)
{
    byte []dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
    byte []encryptedDataBytes = LIQUITRADER_CRYPTO_ENGINE.Encrypt(dataBytes, true);

    return Convert.ToBase64String(encryptedDataBytes);
}

public static byte[] RSADecrypt(byte []encrypted, TraceWriter log)
{
    return SERVER_CRYPTO_ENGINE.Decrypt(encrypted, true);
}

public static bool RSAVerify(byte[] signedData, byte[] signature)
{   
    return LIQUITRADER_CRYPTO_ENGINE.VerifyData(signedData, "SHA256", signature);
}

public static string RSASign(string data) {
    byte []dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
    return Convert.ToBase64String(SERVER_CRYPTO_ENGINE.SignData(dataBytes, "SHA256"));
}


public static (bool success, string error_msg, string license_key, string api_key, string data_b64) DecryptVerifierData(string data, TraceWriter log)
{
    string []data_parts = data.Split(' ');

    byte []signature = Base64Decode(data_parts[0]);
    byte []encrypted_payload_data = Base64Decode(data_parts[1]);

    byte []decrypted_payload_data;

    // Decrypt data using server's private key
    try {
        decrypted_payload_data = RSADecrypt(encrypted_payload_data, log);
    
    } catch (Exception ex) {
        return (false, "Invalid request (2)", "", "", "");
    }

    // Split timestamp and data apart 
    string decrypted_payload_string = System.Text.Encoding.UTF8.GetString(decrypted_payload_data);
    string []decrypted_payload_parts = decrypted_payload_string.Split(' ');
    
    // Incorrect number of spaces
    if (decrypted_payload_parts.Count() < 4) {
        return (false, "Invalid request (3)", "", "", "");
    }

    // Check timestamp for being within 30s of current UTC time
    float timestamp = float.Parse(decrypted_payload_parts[0]);
    float utcNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    if ((utcNow - timestamp) > 30f) {
        return (false, "Verification timeout", "", "", "");
    }

    // Verify recieved signature using LIQUITRADER public key
    if (!RSAVerify(decrypted_payload_data, signature)) {
        return (false, "Invalid request (4)", "", "", "");
    }

    byte []data_bytes = new byte[300];
    int spaceCount = 0;
    int spaceLoc = -2;

    // 32 is the byte representation of the space character
    for (int i = 0; i < decrypted_payload_data.Count(); i++) {
        if (decrypted_payload_data[i].ToString() == "32") {
            spaceCount += 1;
            if (spaceCount == 3) {
                spaceLoc = i;
                break;
            }
        }
    }
    
    try {
        Buffer.BlockCopy(decrypted_payload_data, spaceLoc + 1, data_bytes, 0, decrypted_payload_data.Count() - spaceLoc - 1);
    
    } catch (Exception ex) {
        logger.Error(ex.ToString());
        return (false, "Invalid request (5)", "", "", "");
    }
    
    Array.Resize(ref data_bytes, decrypted_payload_data.Count() - spaceLoc - 1);

    string licenseKey = decrypted_payload_parts[1];
    string apiKey = decrypted_payload_parts[2];

    return (true, "", licenseKey, apiKey, Base64Encode("", data_bytes));
}


public static string GenerateVerifierData(string data, TraceWriter log)
{
    string verifierData = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString() + " " + data;

    try {
        return RSASign(verifierData) + " " + RSAEncrypt(verifierData);

    } catch (Exception ex) {
        log.Error(ex.ToString());
        return string.Empty;
    }
}


public static HttpResponseMessage GenerateFailureResponse(string msg, HttpRequestMessage request, HttpStatusCode status=HttpStatusCode.Forbidden)
{
    FailureResponse response = new FailureResponse();
    response.error = msg;

    return request.CreateResponse(status, JsonConvert.SerializeObject(response));
}


public static string ExtractHeaderParameter(string parameter, HttpRequestMessage request) {
    IEnumerable<string> extractedValue;

    string result;

    try {
        request.Headers.TryGetValues(parameter, out extractedValue);
        result = extractedValue == null ? string.Empty : extractedValue.First();
    
    } catch (Exception ex) {
        result = string.Empty;
        // logger.Error(ex.ToString());
    }

    return result;
}


public static async Task<HttpResponseMessage> Run(HttpRequestMessage request, TraceWriter log)
{
    string _parseData = await request.Content.ReadAsStringAsync();
    dynamic _data = await request.Content.ReadAsAsync<object>();


    HttpResponseMessage ban_message = GenerateFailureResponse("Too many invalid requests; try again in 10 minutes.", request);

    if (IsHostBannedInDatabase(request, log)) {
        return ban_message;
    }

    string authKey = string.Empty;
    string licenseKey = string.Empty;
    string apiKey = string.Empty;

    string payload = string.Empty;

    string failureMessage = string.Empty;
    string correctAuthKey = "aAgTQITwDdEv1xobEwQmhvjPZ4W/Jl26HWc2pnNwXNEZYpd4VEouEQ==";

    // =======
    // Basic auth check to save processing time on simple evil requests
    authKey = ExtractHeaderParameter("auth_key", request);
    if (authKey != correctAuthKey) {
        if (await MaybeBan(request, log)) {
            return ban_message;
        }

         return GenerateFailureResponse("Invalid request", request);
    }

    // =======
    // Contains encrypted timestamp, license key, api key, and verifier data
    payload = ExtractHeaderParameter("data", request);

    if (payload == string.Empty) {
        if (await MaybeBan(request, log)) {
            return ban_message;
        }

        return GenerateFailureResponse("Invalid request", request);
    }

    // Decrypt data    
    var decryptionResponse = (false, "", "", "", "");

    try {
        decryptionResponse = DecryptVerifierData(payload, log);

    } catch (Exception ex) {
        log.Error(ex.ToString());

        if (await MaybeBan(request, log)) {
            return ban_message;
        }

        return GenerateFailureResponse("Invalid request (err 1)", request);
    }

    // Decrypter signaled a failure
    if (!decryptionResponse.Item1) {
        if (await MaybeBan(request, log)) {
            return ban_message;
        }

        return GenerateFailureResponse(decryptionResponse.Item2, request);
    }

    licenseKey = decryptionResponse.Item3;
    apiKey = decryptionResponse.Item4;
    string decryptedVerifierData = decryptionResponse.Item5;
    
    // =======
    // Check basic format of provided license key to prevent needless DB queries for junk spammers
    if (licenseKey.Length != 29 && !IsValidLicenseKeyFormat(licenseKey)) {
        if (await MaybeBan(request, log)) {
            return ban_message;
        }

        return GenerateFailureResponse("Invalid request (7)", request);
    }

    // =======
    // Check the database for the given license
    var query = "SELECT license, api_key_1, api_key_2, expires FROM awmobvie_licenses WHERE license=@license;";
    var paramNameList = new List<string>(){ "@license" };
    var paramValueList = new List<object>(){ licenseKey };

    List<string> licenseEntryColumns = ReadDatabase(query, paramNameList, paramValueList, log);
    // Did not find license key in database
    if (licenseEntryColumns.Count == 0) {
        if (await MaybeBan(request, log)) {
            return ban_message;
        }

        return GenerateFailureResponse("Invalid request (8)", request);
    }

    // =======
    // Check if API key is associated with the license
    bool hasTwoAPIKeys = licenseEntryColumns.Count == 4;

    if (apiKey != licenseEntryColumns[1] || (hasTwoAPIKeys && apiKey != licenseEntryColumns[2])) {
        if (await MaybeBan(request, log)) {
            return ban_message;
        }
        
        return GenerateFailureResponse("API key is not permitted for use with the provided license", request);
    }

    // =======
    // Make sure the license key hasn't expired
    long utcNow = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    long expiresIn = long.Parse(hasTwoAPIKeys ? licenseEntryColumns[3] : licenseEntryColumns[2]) - utcNow;

    if (expiresIn <= 0f) {
        return GenerateFailureResponse("License key is expired", request);
    }

    // =======
    // Everything's dandy, go ahead and generate a success response
    string verifierDataOutput = GenerateVerifierData(decryptedVerifierData, log);

    if (verifierDataOutput == string.Empty) {
        if (await MaybeBan(request, log)) {
            return ban_message;
        }

        return GenerateFailureResponse("Invalid request (9)", request);
    }

    SuccessResponse response = new SuccessResponse();
    response.expires_in = expiresIn.ToString();
    response.verifier_data = verifierDataOutput;

    return request.CreateResponse(HttpStatusCode.OK, JsonConvert.SerializeObject(response));
}


public class RequestJSON
{
    public string auth_key { get; set; }
    public string data { get; set; }
}

public class FailureResponse
{
    public string error { get; set; }
}

public class SuccessResponse
{
    public string expires_in { get; set; }
    public string verifier_data { get; set; }
}
