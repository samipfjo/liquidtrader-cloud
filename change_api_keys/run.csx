#r "Microsoft.WindowsAzure.Storage"
#r "Newtonsoft.Json"
#r "System.Web"
#r "System.Data"
#r "System.Configuration"
#r "System.ServiceModel"

#load "D:/home/site/wwwroot/helpers/bantool.csx"
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


// ---------------
public static async Task<HttpResponseMessage> Run(HttpRequestMessage request, TraceWriter log)
{
    string parseData = await request.Content.ReadAsStringAsync();
    dynamic data = await request.Content.ReadAsAsync<object>();

    if (IsHostBannedInDatabase(request, log)) {
        return request.CreateResponse(HttpStatusCode.Forbidden, CreateFailureMessage("Too many invalid requests; try again in 10 minutes."));
    }

    RequestJSON input = JsonConvert.DeserializeObject<RequestJSON>(parseData);

    if (input.license_key == null || input.email == null) {
        if (await MaybeBan(request, log)) {
            return request.CreateResponse(HttpStatusCode.Forbidden, CreateFailureMessage("Too many invalid requests; try again in 10 minutes."));
        }

        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      CreateFailureMessage("Missing license key or email"));
    }

    if (input.api_key_1 == null && input.api_key_2 == null) {
        if (await MaybeBan(request, log)) {
            return request.CreateResponse(HttpStatusCode.Forbidden, CreateFailureMessage("Too many invalid requests; try again in 10 minutes."));
        }

        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      CreateFailureMessage("No api key provided"));
    }

    // Get old API keys
    var query = "SELECT api_key_1, api_key_2, license, email FROM awmobvie_licenses WHERE license=@license AND email=@email";
    var paramNameList = new List<string>(){ "@license", "@email" };
    var paramValueList = new List<object>(){ input.license_key, input.email };

    List<string> apiKeyQueryList = ReadDatabase(query, paramNameList, paramValueList, log);

    // No such license/email pair
    if (apiKeyQueryList.Count == 0) {
        if (await MaybeBan(request, log)) {
            return request.CreateResponse(HttpStatusCode.Forbidden, CreateFailureMessage("Too many invalid requests; try again in 10 minutes."));
        }

        return request.CreateResponse(System.Net.HttpStatusCode.Forbidden,
                                      CreateFailureMessage("Invalid request"));
    }

    string oldApiKey1 = apiKeyQueryList[0];
    string oldApiKey2 = apiKeyQueryList.Count == 3 ? null : apiKeyQueryList[1];

    string newApiKey1 = input.api_key_1 != null ? input.api_key_1 : oldApiKey1;
    string newApiKey2 = input.api_key_2 != null ? input.api_key_2 : oldApiKey2;

    // Set key 2
    if (newApiKey1 == null) {
        WriteDatabase(@"UPDATE awmobvie_licenses
                        SET api_key_2=@api_key_2
                        WHERE license=@license;",
                    new List<string>() { "@api_key_2", "@license" },
                    new List<object>() { newApiKey2, input.license_key });
    
    // Set key 1
    } else if (newApiKey2 == null) {
        WriteDatabase(@"UPDATE awmobvie_licenses
                SET api_key_1=@api_key_1
                WHERE license=@license;",
            new List<string>() { "@api_key_1", "@license" },
            new List<object>() { newApiKey1, input.license_key });

    // Set both
    } else {
        WriteDatabase(@"UPDATE awmobvie_licenses
                SET api_key_1=@api_key_1, api_key_2=@api_key_2
                WHERE license=@license;",
            new List<string>() { "@api_key_1", "@api_key_2", "@license" },
            new List<object>() { newApiKey1, newApiKey2, input.license_key });
    }

    return request.CreateResponse(HttpStatusCode.OK);
}

// -----
public static string CreateFailureMessage(string msg)
{
    FailureResponse response = new FailureResponse();
    response.error = msg;
    return JsonConvert.SerializeObject(response);
}

// -----
public class RequestJSON
{
    public string license_key { get; set; }
    public string email { get; set; }
    public string api_key_1 { get; set; }
    public string api_key_2 { get; set; }
}

// -----
public class FailureResponse
{
    public string error { get; set; }
}
