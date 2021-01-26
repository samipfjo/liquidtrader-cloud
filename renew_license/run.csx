#r "Microsoft.WindowsAzure.Storage"
#r "Newtonsoft.Json"
#r "System.Web"
#r "System.Data"
#r "System.Configuration"
#r "System.ServiceModel"

#load "D:/home/site/wwwroot/helpers/databasetools.csx"
 
using System.Web;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Configuration;
using System.ServiceModel.Channels;

using System.Data;
using System.Data.SqlClient;
using System.Threading.Tasks;
using System.Security.Cryptography;

using Newtonsoft.Json;


public static async Task<HttpResponseMessage> Run(HttpRequestMessage request, TraceWriter log)
{
    string parseData = await request.Content.ReadAsStringAsync();
    dynamic data = await request.Content.ReadAsAsync<object>();

    List<string> IPWhitelist = new List<string> {
        Dns.GetHostAddresses("liquitrader.com")[0].ToString(),
        /*string azureIP = Dns.GetHostAddresses("liquitrader-auth.azurewebsites.net")[0].ToString();*/
    };

    string clientIP = GetClientIpAddress(request);

    // Run before deserializing for security purposes
    if (!IPWhitelist.Contains(clientIP)) {
        log.Warning(clientIP + " attempted to create a license key!");

        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      SerializeResponse("Did you really think it would be that easy?", false));
    }

    RequestJSON input = JsonConvert.DeserializeObject<RequestJSON>(parseData);

    // Check to make sure the api keys haven't been registered to another license key
    var query = "SELECT license, email FROM awmobvie_licenses WHERE license=@license AND email=@email";
    var paramNameList = new List<string>(){ "@license", "@email" };
    var paramValueList = new List<object>(){ input.license_key, input.email };

    List<string> apiKeyQueryList = ReadDatabase(query, paramNameList, paramValueList, log);

    if (apiKeyQueryList.Count != 0) {
        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      SerializeResponse("Invalid license key or email", false));
    }

    long now_utc = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    // Once we switch to a subscription model we will use one year or something like it
    // Until then, 200 years will work fine for a lifetime subscription
    long one_year = 31536000;  // One year in seconds
    long one_year_from_now = now_utc + one_year;
    long many_years_from_now = now_utc + (200 * one_year);

    WriteDatabase(@"UPDATE awmobvie_licenses
                    SET expires=@expires
                    WHERE license=@license;",
                  new List<string>() { "@license", "@expires"},
                  new List<object>() { input.license_key, many_years_from_now });

    return request.CreateResponse(HttpStatusCode.OK, SerializeResponse(many_years_from_now.ToString(), true));
}

public static string GetClientIpAddress(HttpRequestMessage request)
{
    if (request.Properties.ContainsKey("MS_HttpContext")) {
        return ((HttpContextBase)request.Properties["MS_HttpContext"]).Request.UserHostAddress;
   
    } else if (request.Properties.ContainsKey(RemoteEndpointMessageProperty.Name)) {
        return ((RemoteEndpointMessageProperty)request.Properties[RemoteEndpointMessageProperty.Name]).Address;
    }

    return string.Empty;
}

public static string SerializeResponse(string msg, bool success)
{
    if (success) {
        SuccessResponse response = new SuccessResponse();
        response.new_expire_date = msg;
        return JsonConvert.SerializeObject(response);
    
    } else {
        FailureResponse response = new FailureResponse();
        response.error = msg;
        return JsonConvert.SerializeObject(response);
    }
}


public class RequestJSON
{
    public string license_key { get; set; }
    public string email { get; set; }
}

public class FailureResponse
{
    public string error { get; set; }
}

public class SuccessResponse
{
    public string new_expire_date { get; set; }
}
