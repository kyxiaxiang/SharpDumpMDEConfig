using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;

class Program
{
    static void Main(string[] args)
    {
        bool tableOutput = args.Contains("--TableOutput");
        string tableOutputFile = args.Contains("--TableOutputFile") ? args[Array.IndexOf(args, "--TableOutputFile") + 1] : "MDEConfig.txt";
        bool csvOutput = args.Contains("--CSVOutput");

        Console.WriteLine("[+] Dumping Defender Excluded Paths");
        QueryExclusionPaths(tableOutput, tableOutputFile, csvOutput);

        Console.WriteLine("[+] Dumping Enabled ASR Rules");
        QueryRegASRRules(tableOutput, tableOutputFile, csvOutput);

        Console.WriteLine("[+] Dumping Allowed Threats");
        QueryAllowedThreats(tableOutput, tableOutputFile, csvOutput);

        Console.WriteLine("[+] Dumping Defender Protection History");
        QueryProtectionHistory(tableOutput, tableOutputFile, csvOutput);

        Console.WriteLine("[+] Dumping Exploit Guard Protection History");
        QueryExploitGuardProtectionHistory(tableOutput, tableOutputFile, csvOutput);

        Console.WriteLine("[+] Dumping Windows Firewall Exclusions");
        QueryFirewallExclusions(tableOutput, tableOutputFile, csvOutput);

        if (tableOutput)
        {
            Console.WriteLine($"[+] Defender Config Dumped to {tableOutputFile}");
        }
    }

    static void QueryExclusionPaths(bool tableOutput, string tableOutputFile, bool csvOutput)
    {
        try
        {
            string logName = "Microsoft-Windows-Windows Defender/Operational";
            string query = "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=5007)]]";
            EventLogQuery eventsQuery = new EventLogQuery(logName, PathType.LogName, query);
            EventLogReader logReader = new EventLogReader(eventsQuery);

            var exclusionPaths = new List<dynamic>();

            for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
            {
                string message = eventInstance.FormatDescription();
                var match = System.Text.RegularExpressions.Regex.Match(message, @"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\([^\s]+)");
                if (match.Success)
                {
                    exclusionPaths.Add(new { Path = match.Groups[1].Value, TimeCreated = eventInstance.TimeCreated });
                }
            }

            if (tableOutput)
            {
                File.AppendAllText(tableOutputFile, "[+] Exclusion Paths:\n");
                File.AppendAllText(tableOutputFile, string.Join("\n", exclusionPaths.Select(e => e.ToString())));
            }
            else if (csvOutput)
            {
                File.WriteAllText("ExclusionPaths.csv", "Path,TimeCreated\n" + string.Join("\n", exclusionPaths.Select(e => $"{e.Path},{e.TimeCreated}")));
                Console.WriteLine("[+] Dumped Exclusion Paths to ExclusionPaths.csv");
            }
            else
            {
                foreach (var path in exclusionPaths)
                {
                    Console.WriteLine($"{path.Path} - {path.TimeCreated}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to query exclusion paths: {ex}");
        }
    }

    static void QueryRegASRRules(bool tableOutput, string tableOutputFile, bool csvOutput)
    {
        try
        {
            string logName = "Microsoft-Windows-Windows Defender/Operational";
            string query = "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=5007)]]";
            EventLogQuery eventsQuery = new EventLogQuery(logName, PathType.LogName, query);
            EventLogReader logReader = new EventLogReader(eventsQuery);
            var asrDescriptions = GetASRRuleDescriptions();

            var asrRules = new List<dynamic>();

            for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
            {
                string message = eventInstance.FormatDescription();
                var match = System.Text.RegularExpressions.Regex.Match(message, @"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules\\([0-9A-Fa-f-]+)");
                if (match.Success)
                {
                    string asrRuleId = match.Groups[1].Value.ToLower();
                    string description = asrDescriptions.ContainsKey(asrRuleId) ? asrDescriptions[asrRuleId] : "Unknown ASR Rule";
                    asrRules.Add(new { RuleId = asrRuleId, Description = description, TimeCreated = eventInstance.TimeCreated });
                }
            }

            if (tableOutput)
            {
                File.AppendAllText(tableOutputFile, "[+] Enabled ASR Rules:\n");
                File.AppendAllText(tableOutputFile, string.Join("\n", asrRules.Select(r => r.ToString())));
            }
            else if (csvOutput)
            {
                File.WriteAllText("ASRRules.csv", "RuleId,Description,TimeCreated\n" + string.Join("\n", asrRules.Select(r => $"{r.RuleId},{r.Description},{r.TimeCreated}")));
                Console.WriteLine("[+] Dumped Enabled ASR Rules to ASRRules.csv");
            }
            else
            {
                foreach (var rule in asrRules)
                {
                    Console.WriteLine($"{rule.RuleId} - {rule.Description} - {rule.TimeCreated}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to query ASR rules: {ex}");
        }
    }

    static void QueryAllowedThreats(bool tableOutput, string tableOutputFile, bool csvOutput)
    {
        try
        {
            string logName = "Microsoft-Windows-Windows Defender/Operational";
            string query = "*[System[(EventID=1117 or EventID=5007)]]";
            EventLogQuery eventsQuery = new EventLogQuery(logName, PathType.LogName, query);
            EventLogReader logReader = new EventLogReader(eventsQuery);

            var threatDetails = new Dictionary<string, dynamic>();
            var allowedThreats = new List<dynamic>();

            for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
            {
                string message = eventInstance.ToXml();
                int eventId = eventInstance.Id;

                if (eventId == 1117)
                {
                    var threatIdMatch = System.Text.RegularExpressions.Regex.Match(message, @"threatid=(.+?)&");
                    var toolNameMatch = System.Text.RegularExpressions.Regex.Match(message, @"<Data Name='Threat Name'>(.+?)</Data>");
                    var pathMatch = System.Text.RegularExpressions.Regex.Match(message, @"<Data Name='Path'>(.+?)</Data>");

                    if (threatIdMatch.Success)
                    {
                        string threatId = threatIdMatch.Groups[1].Value;
                        string toolName = toolNameMatch.Success ? toolNameMatch.Groups[1].Value : "";
                        string path = pathMatch.Success ? pathMatch.Groups[1].Value : "";

                        threatDetails[threatId] = new { ToolName = toolName, Path = path };
                    }
                }
                else if (eventId == 5007)
                {
                    var newValueMatch = System.Text.RegularExpressions.Regex.Match(message, @"<Data Name='New Value'>(.+?)</Data>");
                    if (newValueMatch.Success && newValueMatch.Groups[1].Value.Contains("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Threats\\ThreatIDDefaultAction") && newValueMatch.Groups[1].Value.EndsWith("= 0x6"))
                    {
                        var threatIdMatch = System.Text.RegularExpressions.Regex.Match(newValueMatch.Groups[1].Value, @"ThreatIDDefaultAction\\(.+?) ");
                        if (threatIdMatch.Success && threatDetails.ContainsKey(threatIdMatch.Groups[1].Value))
                        {
                            string threatId = threatIdMatch.Groups[1].Value;
                            string timeCreatedStr = System.Text.RegularExpressions.Regex.Match(message, @"<TimeCreated SystemTime='(.+?)'").Groups[1].Value;
                            DateTime timeCreatedUtc = DateTime.ParseExact(timeCreatedStr, "yyyy-MM-ddTHH:mm:ss.fffffffK", null, System.Globalization.DateTimeStyles.AssumeUniversal).ToUniversalTime();

                            allowedThreats.Add(new { ThreatID = threatId, ToolName = threatDetails[threatId].ToolName, Path = threatDetails[threatId].Path, TimeCreated = timeCreatedUtc });
                        }
                    }
                }
            }

            if (tableOutput)
            {
                File.AppendAllText(tableOutputFile, "[+] Allowed Threats:\n");
                File.AppendAllText(tableOutputFile, string.Join("\n", allowedThreats.Select(t => t.ToString())));
            }
            else if (csvOutput)
            {
                File.WriteAllText("AllowedThreats.csv", "ThreatID,ToolName,Path,TimeCreated\n" + string.Join("\n", allowedThreats.Select(t => $"{t.ThreatID},{t.ToolName},{t.Path},{t.TimeCreated}")));
                Console.WriteLine("[+] Dumped Allowed Threats to AllowedThreats.csv");
            }
            else
            {
                foreach (var threat in allowedThreats)
                {
                    Console.WriteLine($"{threat.ThreatID} - {threat.ToolName} - {threat.Path} - {threat.TimeCreated}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to query allowed threats: {ex}");
        }
    }

    static void QueryProtectionHistory(bool tableOutput, string tableOutputFile, bool csvOutput)
    {
        try
        {
            string logName = "Microsoft-Windows-Windows Defender/Operational";
            string query = "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=1116)]]";
            EventLogQuery eventsQuery = new EventLogQuery(logName, PathType.LogName, query);
            EventLogReader logReader = new EventLogReader(eventsQuery);

            var protectionHistory = new List<dynamic>();

            for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
            {
                string message = eventInstance.FormatDescription();
                var match = System.Text.RegularExpressions.Regex.Match(message, @"Threat Name: ([^\r\n]+)");
                if (match.Success)
                {
                    string threatName = match.Groups[1].Value;
                    string timeCreatedStr = eventInstance.TimeCreated.ToString();
                    protectionHistory.Add(new { ThreatName = threatName, TimeCreated = eventInstance.TimeCreated });
                }
            }

            if (tableOutput)
            {
                File.AppendAllText(tableOutputFile, "[+] Protection History:\n");
                File.AppendAllText(tableOutputFile, string.Join("\n", protectionHistory.Select(h => h.ToString())));
            }
            else if (csvOutput)
            {
                File.WriteAllText("ProtectionHistory.csv", "ThreatName,TimeCreated\n" + string.Join("\n", protectionHistory.Select(h => $"{h.ThreatName},{h.TimeCreated}")));
                Console.WriteLine("[+] Dumped Protection History to ProtectionHistory.csv");
            }
            else
            {
                foreach (var entry in protectionHistory)
                {
                    Console.WriteLine($"{entry.ThreatName} - {entry.TimeCreated}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to query protection history: {ex}");
        }
    }

    static void QueryExploitGuardProtectionHistory(bool tableOutput, string tableOutputFile, bool csvOutput)
    {
        try
        {
            string logName = "Microsoft-Windows-Windows Defender/Operational";
            string query = "*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and (EventID=1120)]]";
            EventLogQuery eventsQuery = new EventLogQuery(logName, PathType.LogName, query);
            EventLogReader logReader = new EventLogReader(eventsQuery);

            var protectionHistory = new List<dynamic>();

            for (EventRecord eventInstance = logReader.ReadEvent(); eventInstance != null; eventInstance = logReader.ReadEvent())
            {
                string message = eventInstance.FormatDescription();
                var match = System.Text.RegularExpressions.Regex.Match(message, @"Exploit Guard rule ([^\r\n]+) was triggered");
                if (match.Success)
                {
                    string ruleName = match.Groups[1].Value;
                    string timeCreatedStr = eventInstance.TimeCreated.ToString();
                    protectionHistory.Add(new { RuleName = ruleName, TimeCreated = eventInstance.TimeCreated });
                }
            }

            if (tableOutput)
            {
                File.AppendAllText(tableOutputFile, "[+] Exploit Guard Protection History:\n");
                File.AppendAllText(tableOutputFile, string.Join("\n", protectionHistory.Select(h => h.ToString())));
            }
            else if (csvOutput)
            {
                File.WriteAllText("ExploitGuardProtectionHistory.csv", "RuleName,TimeCreated\n" + string.Join("\n", protectionHistory.Select(h => $"{h.RuleName},{h.TimeCreated}")));
                Console.WriteLine("[+] Dumped Exploit Guard Protection History to ExploitGuardProtectionHistory.csv");
            }
            else
            {
                foreach (var entry in protectionHistory)
                {
                    Console.WriteLine($"{entry.RuleName} - {entry.TimeCreated}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to query exploit guard protection history: {ex}");
        }
    }

    static void QueryFirewallExclusions(bool tableOutput, string tableOutputFile, bool csvOutput)
    {
        try
        {
            var exclusionPaths = new List<dynamic>();

            string firewallRules = ExecuteCommand("netsh advfirewall firewall show rule name=all");

            var matches = System.Text.RegularExpressions.Regex.Matches(firewallRules, @"Rule Name:\s*(.*?)\r\n", System.Text.RegularExpressions.RegexOptions.Multiline);
            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                if (match.Success)
                {
                    string ruleName = match.Groups[1].Value;
                    string timeCreated = DateTime.Now.ToString();
                    exclusionPaths.Add(new { RuleName = ruleName, TimeCreated = timeCreated });
                }
            }

            if (tableOutput)
            {
                File.AppendAllText(tableOutputFile, "[+] Firewall Exclusions:\n");
                File.AppendAllText(tableOutputFile, string.Join("\n", exclusionPaths.Select(e => e.ToString())));
            }
            else if (csvOutput)
            {
                File.WriteAllText("FirewallExclusions.csv", "RuleName,TimeCreated\n" + string.Join("\n", exclusionPaths.Select(e => $"{e.RuleName},{e.TimeCreated}")));
                Console.WriteLine("[+] Dumped Firewall Exclusions to FirewallExclusions.csv");
            }
            else
            {
                foreach (var path in exclusionPaths)
                {
                    Console.WriteLine($"{path.RuleName} - {path.TimeCreated}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to query firewall exclusions: {ex}");
        }
    }

    static string ExecuteCommand(string command)
    {
        var process = new System.Diagnostics.Process
        {
            StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };
        process.Start();
        string result = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return result;
    }

    static Dictionary<string, string> GetASRRuleDescriptions()
    {
        return new Dictionary<string, string>
        {
            { "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block Exploit of Vulnerable Signed Drivers" },
            { "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Prevent Adobe Reader from creating child processes" },
            { "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Prevent all Office applications from creating child processes" },
            { "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem" },
            { "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail" },
            { "01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files unless they meet a prevalence, age, or trusted list criterion" },
            { "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially hidden scripts" },
            { "d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content" },
            { "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content" },
            { "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Prevent Office applications from injecting code into other processes" },
            { "26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office Communication Application from Creating Child Processes" },
            { "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence via WMI event subscription" },
            { "d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block Process Creations from PSExec and WMI Commands" },
            { "33ddedf1-c6e0-47cb-833e-de6133960387", "Block computer restarting in safe mode (preview)" },
            { "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes running from USB" },
            { "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block the use of copied or imitated system utilities (preview)" },
            { "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block the creation of web shells for servers" },
            { "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API Calls from Office Macros" },
            { "c1db55ab-c21a-4637-bb3f-a12568109d35", "How to use advanced ransomware protection" },
        };
    }

}
