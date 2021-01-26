#r "System.Web"
#r "System.ServiceModel"
#r "Newtonsoft.Json"

#load "D:/home/site/wwwroot/helpers/managementresponse.csx"
#load "D:/home/site/wwwroot/helpers/databasetools.csx"

using System.Web;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Linq;
using System.ServiceModel.Channels;

using Newtonsoft.Json;
using Newtonsoft.Json.Schema; 
using Newtonsoft.Json.Linq;


public static class AuthenticationHelpers
{
    const string TokenEndpoint = "https://login.windows.net/{0}/oauth2/token";
    const string SPNPayload = "resource={0}&client_id={1}&grant_type=client_credentials&client_secret={2}";
    const string ARMResource = "https://management.core.windows.net/";

    public static async Task<string> AcquireTokenBySPN(string tenantId, string clientId, string clientSecret)
    {
        var payload = String.Format(SPNPayload,
                                    WebUtility.UrlEncode(ARMResource),
                                    WebUtility.UrlEncode(clientId),
                                    WebUtility.UrlEncode(clientSecret));

        var body = await HttpPost(tenantId, payload);
        return body.access_token;
    } 

    static async Task<dynamic> HttpPost(string tenantId, string payload)
    {
        using (var client = new HttpClient())
        {
            var address = String.Format(TokenEndpoint, tenantId);
            var content = new StringContent(payload, Encoding.UTF8, "application/x-www-form-urlencoded");
            using (var response = await client.PostAsync(address, content))
            {
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine("Status:  {0}", response.StatusCode);
                    Console.WriteLine("Content: {0}", await response.Content.ReadAsStringAsync());
                }

                response.EnsureSuccessStatusCode();

                return await response.Content.ReadAsAsync<dynamic>();
            }
        }
    }
}

public class BanEntry {
    public string ipAddress { get; set; }
    public string action { get; set; }
    public int priority { get; set; }
    public string name { get; set; }
};

public static class BanManager
{
    static HttpClient client = new HttpClient();
    
    static string managementURL = "https://management.azure.com/subscriptions/<snip>/resourceGroups/liquitrader-auth-group/providers/Microsoft.Web/sites/liquitrader-auth/config/web?api-version=2018-02-01";
    static string tenentID = "<snip>";
    static string applicationID = "<snip>";

    static string oAuthToken;

    static IList<JToken> existingBans = null;

    public static TraceWriter logger;

    // =============
    public static async Task Initialize(TraceWriter log) 
    {
        oAuthToken = await AuthenticationHelpers.AcquireTokenBySPN(tenentID, applicationID, "<snip>");
        existingBans = await GetExistingBans();

        logger = log;
    }

    // =============
    public static async Task<IList<JToken>>GetExistingBans()
    {
        using (var client = new HttpClient())
        {
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + oAuthToken);

            using (var response = await client.GetAsync(managementURL))
            {
                if (!response.IsSuccessStatusCode) {
                    logger.Warning("Unsuccessful network request while trying to get existing bans, " + response.StatusCode.ToString());
                    return null;
                }

                response.EnsureSuccessStatusCode();

                string jsonResponse = await response.Content.ReadAsStringAsync();

                return JObject.Parse(jsonResponse).SelectToken("properties.ipSecurityRestrictions").Children().ToList();
            }
        }
    }

    // =============
    public static async Task _AddManagementBan(string host)
    {
        IList<BanEntry> banEntries = new List<BanEntry>();

        foreach (JToken banToken in existingBans)
        {
            BanEntry banEntry = banToken.ToObject<BanEntry>();

            if (banEntry.name == host) {
                logger.Error("Attempted to re-ban " + banEntry.ipAddress + " -- This should not have happened");
                return;
            }

            banEntries.Add(banEntry);
        }

        banEntries.Add(new BanEntry() {
            ipAddress = host,
            action = "Deny",
            priority = 100,
            name = host
        });
        
        await _UpdateManagement(banEntries);
    }

    public static async Task _UpdateManagement(IList<BanEntry> hosts, string task="ban") {
        JObject jsonData = JObject.FromObject( 
            new {
                properties = new {
                    ipSecurityRestrictions = hosts
                }
            }
        );

        string requestJSON = JsonConvert.SerializeObject(jsonData);

        var content = new StringContent(requestJSON, Encoding.UTF8, "application/json");
        using (var client = new HttpClient())
        {
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + oAuthToken);

            using (var response = await client.PutAsync(managementURL, content))
            {
                if (!response.IsSuccessStatusCode) {
                    logger.Warning("Unsuccessful network request during " + task + ", " + response.StatusCode.ToString());
                }

                response.EnsureSuccessStatusCode();

                string jsonResponse = await response.Content.ReadAsStringAsync();
            }
        }
    }

    // =============
    public static async Task<bool> MaybeBanHost(string host)
    {
        if (!host.Contains("/")) {
            host = host + "/32";
        }

        string query = @"
DECLARE @attempt_modulus int;

UPDATE zvyuwc_banlist
SET attempts = attempts + 1,
    @attempt_modulus = (attempts + 1) % 10,
    last_attempt = GETUTCDATE(),
    ban_active = CASE WHEN @attempt_modulus = 0 OR ban_expires >= GETUTCDATE() THEN 1 ELSE 0 END,
    ban_expires = CASE WHEN @attempt_modulus = 0 THEN DATEADD(mi, 10, GETUTCDATE()) ELSE ban_expires END
WHERE host=@host;

IF @@ROWCOUNT = 0
    BEGIN
    INSERT INTO zvyuwc_banlist (host) VALUES (@host);
    SET @attempt_modulus = 9;
    END

SELECT @attempt_modulus;";

        int attempt_modulus = -1;

        try {
            List<string> results = ReadDatabase(query, new List<string>() {"@host"}, new List<object> {host}, logger);
            attempt_modulus = Convert.ToInt32(results[0]);
        
        } catch (Exception ex) {
            logger.Error(ex.ToString());
            throw;
        }

        if (attempt_modulus == 0) {
            try {
                await _AddManagementBan(host);
                return true;

            } catch (Exception ex) {
                logger.Error(ex.ToString());
                throw;
            }
        }

        return false;
    }

    public static async Task UnbanHosts(List<string> hosts)
    {
        IList<BanEntry> banEntries = new List<BanEntry>();

        foreach (JToken banToken in existingBans)
        {
            BanEntry banEntry = banToken.ToObject<BanEntry>();

            if (!hosts.Contains(banEntry.name)) {
                banEntries.Add(banEntry);
            }
        }

        await _UpdateManagement(banEntries, "unban");
    }
}

// ---------------
public static async Task<bool> MaybeBan(HttpRequestMessage request, TraceWriter logger) {
    // Gets the latest bans
    await BanManager.Initialize(logger);

    try {
        string client = GetClientIpAddress(request);

        if (await BanManager.MaybeBanHost(client)) {
            return true;
        }
    
    } catch (Exception ex) {
        logger.Error(ex.ToString());
    }

    return false;
}

// -----
public static bool IsHostBannedInDatabase(HttpRequestMessage request, TraceWriter logger) {
    string host = GetClientIpAddress(request);

    if (!host.Contains("/")) {
        host = host + "/32";
    }

    List<string> banActiveResults = ReadDatabase("SELECT ban_active FROM zvyuwc_banlist WHERE host=@host",
                                                    new List<string>() {"@host"},
                                                    new List<object> {host},
                                                    logger);
    
    // Not in database yet
    if (banActiveResults.Count == 0) {
        return false;
    }

    return banActiveResults[0] == "True";
}

// -----
public static string GetClientIpAddress(HttpRequestMessage request)
{
    if (request.Properties.ContainsKey("MS_HttpContext")) {
        return ((HttpContextBase)request.Properties["MS_HttpContext"]).Request.UserHostAddress;
   
    } else if (request.Properties.ContainsKey(RemoteEndpointMessageProperty.Name)) {
        return ((RemoteEndpointMessageProperty)request.Properties[RemoteEndpointMessageProperty.Name]).Address;
    }

    return string.Empty;
}