#load "D:/home/site/wwwroot/helpers/databasetools.csx"
#load "D:/home/site/wwwroot/helpers/bantool.csx"

using System;
using System.Threading.Tasks;

public static void Run(TimerInfo myTimer, TraceWriter log)
{
    Task _initializeTask = Task.Run(async () => await BanManager.Initialize(log));

    // Get all expired bans
    string expired_bans_query = @"
    SELECT * FROM zvyuwc_banlist
    WHERE ban_active = 1
          AND ban_expires <= GETUTCDATE();";

    List<string> expired_bans = ReadDatabase(expired_bans_query, new List<string>(), new List<object>(), log);

    if (expired_bans.Count > 0) {
        // Removes entries via management API
        Task _unbanHostsTask = Task.Run(async () => await BanManager.UnbanHosts(expired_bans));

        // Set ban_active to false for all expired bans
        string set_expired_bans_inactive_query = @"
        UPDATE zvyuwc_banlist
        SET ban_active = 0
        WHERE ban_expires <= GETUTCDATE();";

        WriteDatabase(set_expired_bans_inactive_query, new List<string>(), new List<object>());
    }

    // Reset ban count to last increment for users that haven't been naughty in 15m
    string reset_ban_counter = @"
        UPDATE zvyuwc_banlist
        SET attempts=(attempts - (attempts % 10))
        WHERE ban_active = 0
              AND DATEADD(mi, -(15), last_attempt) <= GETUTCDATE();";

    WriteDatabase(reset_ban_counter, new List<string>(), new List<object>());

    // Delete all database entries > 1w old
    string destroy_old_bans = "DELETE FROM zvyuwc_banlist WHERE DATEADD(wk, 1, last_attempt) <= GETUTCDATE()";
    WriteDatabase(destroy_old_bans, new List<string>(), new List<object>());
}
