#r "Microsoft.WindowsAzure.Storage"
#r "System.Web"
#r "System.ServiceModel"
#r "Newtonsoft.Json"
#r "System.Data"
#r "System.Configuration"

#load "D:/home/site/wwwroot/helpers/bantool.csx"
#load "D:/home/site/wwwroot/helpers/databasetools.csx"
 
using System.Net;
using System.Text;
using System.Configuration;

using System.Web;
using System.ServiceModel.Channels;

using System.Data;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.Security.Cryptography;

using Newtonsoft.Json;


// ---------------
public static string CreateLicenseKey()
{
    char[] chars = new char[26];
    chars = "ACDEFGHJKLMNPQRTVWXYZ23479".ToCharArray();

    byte[] data = new byte[1];

    using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider()) {
        crypto.GetNonZeroBytes(data);
        data = new byte[25];
        crypto.GetNonZeroBytes(data);
    }

    StringBuilder result = new StringBuilder(25);
    int strpos = 0;
    foreach (byte b in data) {
        if (strpos != 0 && strpos % 5 == 0) {
            result.Append("-");
        }

        result.Append(chars[b % (chars.Length)]);
        strpos++;
    }

    return result.ToString();
}


public static string SerializeResponse(string msg, bool success) {
    if (success) {
        SuccessResponse response = new SuccessResponse();
        response.license = msg;
        return JsonConvert.SerializeObject(response);

    } else {
        FailureResponse response = new FailureResponse();
        response.error = msg;
        return JsonConvert.SerializeObject(response);
    }
}


public static async Task<HttpResponseMessage> Run(HttpRequestMessage request, TraceWriter log)
{
    string parseData = await request.Content.ReadAsStringAsync();
    dynamic data = await request.Content.ReadAsAsync<object>();

    List<string> IPWhitelist = new List<string> {
        Dns.GetHostAddresses("liquitrader.com")[0].ToString(),
        "108.7.61.77",
        // "173.244.44.78"  // Set to your IP for testing -- MAKE SURE YOU COMMENT IT BACK OUT!
    };

    string clientIP = GetClientIpAddress(request);

    // Run before deserializing for security purposes
    if (!IPWhitelist.Contains(clientIP)) {
        log.Warning(clientIP + " attempted to create a license key!");

        await MaybeBan(request, log);

        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      SerializeResponse("Did you really think it would be that easy?", false));
    }

    RequestJSON input = JsonConvert.DeserializeObject<RequestJSON>(parseData);

    // Check to make sure the api keys haven't been registered to another license key
    var query = "SELECT api_key_1, api_key_2 FROM awmobvie_licenses WHERE api_key_1=@api_key OR api_key_2=@api_key;";
    var paramNameList = new List<string>(){ "@api_key" };
    var paramValueList = new List<object>(){ input.api_key };

    List<string> apiKeyQueryList = ReadDatabase(query, paramNameList, paramValueList, log);

    if (apiKeyQueryList.Count != 0) {
        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      SerializeResponse("api key already registered", false));
    }

    // Make sure our license key does not exist
    // Extremely statisically unlikely, but sanity check nonetheless
    string licenseKey;
    char checkChar;

    try {
        checkChar = input.api_key[6];

    } catch (IndexOutOfRangeException) {
        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      SerializeResponse("invalid api key", false));
    }

    while (true) {
        licenseKey = CreateLicenseKey();

        for (int i=6; i < input.api_key.Count(); i++) {
            checkChar = input.api_key[i];
            if ("ACDEFGHJKLMNPQRTVWXYZ23479".Contains(checkChar)) {
                break;
            }
        }

        licenseKey = licenseKey.Substring(0, 9) + char.ToUpper(checkChar) + licenseKey.Substring(10);

        if (ReadDatabase("SELECT license FROM awmobvie_licenses WHERE license=@license;",
                         new List<string>(){ "@license" },
                         new List<object>(){ licenseKey },
                         log).Count == 0) {
            break;
        }
    }

    long now_utc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    // Once we switch to a subscription model we will use one year or something like it
    // Until then, 200 years will work fine for a lifetime subscription
    long one_year = 31536000;  // One year in seconds
    long one_year_from_now = now_utc + one_year;
    long many_years_from_now = now_utc + (200 * one_year);

    WriteDatabase("INSERT INTO awmobvie_licenses (license, email, api_key_1, created, expires) VALUES (@license, @email, @apiKey1, @created, @expires);",
                  new List<string>() { "@license", "@email", "apiKey1", "@created", "@expires"},
                  new List<object>() { licenseKey, input.email, input.api_key, now_utc, many_years_from_now });

    return request.CreateResponse(HttpStatusCode.OK, SerializeResponse(licenseKey, true));
}


public class RequestJSON
{
    public string api_key { get; set; }
    public string email { get; set; }
}

public class FailureResponse
{
    public string error { get; set; }
}

public class SuccessResponse
{
    public string license { get; set; }
}
