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

using Newtonsoft.Json;


// ----
public static string SerializeResponse(bool success, string msg="", string api_key1="", string api_key2="") {
    if (success) {
        SuccessResponse response = new SuccessResponse();
        response.api_key1 = api_key1;
        response.api_key2 = api_key2;
        return JsonConvert.SerializeObject(response);
    
    } else {
        FailureResponse response = new FailureResponse();
        response.error = msg;
        return JsonConvert.SerializeObject(response);
    }
}

// ----
public static string ExtractHeaderParameter(string parameter, HttpRequestMessage request, TraceWriter logger) {
    IEnumerable<string> extractedValue;

    string result = string.Empty;

    try {
        request.Headers.TryGetValues(parameter, out extractedValue);
        result = extractedValue == null ? string.Empty : extractedValue.First();
    
    } catch (Exception ex) {
        logger.Error(ex.ToString());
    }

    return result;
}

// ----
public static async Task<HttpResponseMessage> Run(HttpRequestMessage request, TraceWriter log)
{
    string parseData = await request.Content.ReadAsStringAsync();
    dynamic data = await request.Content.ReadAsAsync<object>();

    if (IsHostBannedInDatabase(request, log)) {
        return request.CreateResponse(HttpStatusCode.Forbidden,
                                      SerializeResponse(false, "Too many invalid requests; try again in 10 minutes."));
    }

    string licenseKey = ExtractHeaderParameter("license", request, log);
    string email = ExtractHeaderParameter("email", request, log);

    if (licenseKey == string.Empty || email == string.Empty) {
        if (await MaybeBan(request, log)) {
            return request.CreateResponse(HttpStatusCode.Forbidden, SerializeResponse(false, "Too many invalid requests; try again in 10 minutes."));
        }
        return request.CreateResponse(HttpStatusCode.Forbidden, SerializeResponse(false, "Bad request"));
    }

    List<string> result = ReadDatabase("SELECT api_key_1, api_key_2, license FROM awmobvie_licenses WHERE license=@license AND email=@email;",
                                        new List<string>(){ "@license", "@email" },
                                        new List<object>(){ licenseKey, email },
                                        log);

    string api_key1 = "";
    string api_key2 = "";

    if (result.Count == 0) {
        if (await MaybeBan(request, log)) {
            return request.CreateResponse(HttpStatusCode.Forbidden, SerializeResponse(false, "Too many invalid requests; try again in 10 minutes."));
        }
        return request.CreateResponse(HttpStatusCode.Forbidden, SerializeResponse(false, "License or email incorrect"));
    
    } else if (result.Count == 2) {
        api_key1 = result[0];
    
    } else if (result.Count == 3) {
        api_key1 = result[0];
        api_key2 = result[1];
    }

    return request.CreateResponse(HttpStatusCode.OK, SerializeResponse(true, "", api_key1, api_key2));
}


public class RequestJSON
{
    public string license { get; set; }
    public string email { get; set; }
}

public class FailureResponse
{
    public string error { get; set; }
}

public class SuccessResponse
{
    public string api_key1 { get; set; }
    public string api_key2 { get; set; }
}
