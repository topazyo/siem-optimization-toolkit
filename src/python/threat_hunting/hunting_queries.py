# src/kql/threat_hunting/hunting_queries.py

from typing import Dict, List
from dataclasses import dataclass

@dataclass
class HuntingQueryCollection:
    """Collection of advanced hunting queries."""

    @staticmethod
    def get_privileged_access_queries() -> Dict[str, str]:
        """Queries for detecting privileged access abuse."""
        return {
            "golden_ticket_detection": """
            let timeframe = 1d;
            let known_services = dynamic(["krbtgt", "kadmin"]);
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4769
            | extend TicketOptions = extract("Ticket Options:(.*)", 1, tostring(EventData))
            | extend TicketEncryption = extract("Ticket Encryption Type:(.*)", 1, tostring(EventData))
            | where TicketOptions has "0x40810000" // Forwardable, Renewable, Initial
                or TicketEncryption has "0x17" // RC4-HMAC
            | where Account has_any (known_services)
            | summarize
                TicketCount = count(),
                ServiceAccounts = make_set(Account),
                SourceIPs = make_set(IpAddress),
                ComputerTargets = make_set(Computer)
            by bin(TimeGenerated, 1h)
            | where TicketCount > 2
            """,
            
            "dcsync_detection": """
            let timeframe = 12h;
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID in (4662, 4624)
            | where OperationType has "DS-Replication-Get-Changes"
                or OperationType has "DS-Replication-Get-Changes-All"
            | summarize
                ReplicationEvents = count(),
                Accounts = make_set(Account),
                SourceIPs = make_set(IpAddress)
            by bin(TimeGenerated, 1h), Computer
            | where ReplicationEvents > 5
            """,
            
            "domain_admin_abuse": """
            let timeframe = 24h;
            let admin_groups = dynamic(["Domain Admins", "Enterprise Admins"]);
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID in (4728, 4732, 4756) // Group membership changes
            | where TargetUserName has_any (admin_groups)
            | extend ModifiedGroup = TargetUserName
            | extend ModifiedAccount = extract("Account Name:\\s+(.+?)\n", 1, tostring(EventData))
            | project
                TimeGenerated,
                Activity,
                ModifiedGroup,
                ModifiedAccount,
                Actor = SubjectUserName,
                Computer
            """
        }

    @staticmethod
    def get_lateral_movement_queries() -> Dict[str, str]:
        """Queries for detecting lateral movement."""
        return {
            "pass_the_hash_detection": """
            let timeframe = 24h;
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4624 // Successful logon
            | where LogonType == 3 // Network logon
            | where AuthenticationPackageName == "NTLM"
                and IpAddress != "-"
                and IpAddress != "::1"
                and IpAddress != "127.0.0.1"
            | summarize
                LogonCount = count(),
                TargetAccounts = make_set(TargetUserName),
                SourceIPs = make_set(IpAddress),
                LogonTypes = make_set(LogonType)
            by bin(TimeGenerated, 1h), Computer
            | where LogonCount > 10
            """,
            
            "suspicious_service_creation": """
            let timeframe = 12h;
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 7045 // Service installation
            | extend ServiceName = extract("Service Name:\\s+(.+?)\n", 1, tostring(EventData))
            | extend ServiceFile = extract("Service File Name:\\s+(.+?)\n", 1, tostring(EventData))
            | where ServiceFile has_any ("admin", "PAExec", "pwdump", "mimikatz")
                or ServiceFile matches regex @"\\\\[0-9a-fA-F]{8}\\.*"
            | project
                TimeGenerated,
                Computer,
                ServiceName,
                ServiceFile,
                Account
            """
        }

    @staticmethod
    def get_persistence_queries() -> Dict[str, str]:
        """Queries for detecting persistence mechanisms."""
        return {
            "scheduled_task_abuse": """
            let timeframe = 24h;
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4698 // Scheduled task creation
            | extend TaskName = extract("Task Name:\\s+(.+?)\n", 1, tostring(EventData))
            | extend TaskContent = extract("Task Content:\\s+(.+?)\n", 1, tostring(EventData))
            | where TaskContent has_any ("powershell", "cmd.exe", "rundll32", "regsvr32")
                and isnotempty(TaskContent)
            | project
                TimeGenerated,
                Computer,
                TaskName,
                TaskContent,
                Account = SubjectUserName
            """,
            
            "startup_folder_modification": """
            let timeframe = 12h;
            let startup_paths = dynamic([
                "\\Windows\\Start Menu\\Programs\\Startup",
                "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            ]);
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4663 // File system object access
            | where ObjectName has_any (startup_paths)
            | extend FileName = extract(@"([^\\]+)$", 1, ObjectName)
            | project
                TimeGenerated,
                Computer,
                Account = SubjectUserName,
                FileName,
                ObjectName,
                AccessMask
            """
        }

    @staticmethod
    def get_defense_evasion_queries() -> Dict[str, str]:
        """Queries for detecting defense evasion techniques."""
        return {
            "security_tool_deletion": """
            let timeframe = 6h;
            let security_services = dynamic([
                "MsMpEng.exe", // Windows Defender
                "nsudo.exe", // Norton
                "mcshield.exe", // McAfee
                "360tray.exe", // 360 Safeguard
                "avguard.exe", // Avira
                "egui.exe" // ESET
            ]);
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4688 // Process creation
            | where ProcessName has_any (security_services)
                or CommandLine has "net stop"
                or CommandLine has "sc stop"
            | project
                TimeGenerated,
                Computer,
                Account = SubjectUserName,
                ProcessName,
                CommandLine,
                ParentProcessName
            """,
            
            "powershell_encoding_detection": """
            let timeframe = 24h;
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4688 // Process creation
            | where ProcessName has "powershell.exe"
                and CommandLine has_any ("-enc", "-encodedcommand", "-e")
            | extend DecodedCommand = base64_decode_tostring(
                extract("[A-Za-z0-9+/]{20,}[=]{0,3}", 0, CommandLine)
            )
            | project
                TimeGenerated,
                Computer,
                Account = SubjectUserName,
                CommandLine,
                DecodedCommand,
                ParentProcessName
            """
        }

    @staticmethod
    def get_credential_access_queries() -> Dict[str, str]:
        """Queries for detecting credential access attempts."""
        return {
            "lsass_access_detection": """
            let timeframe = 12h;
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4656 // Handle to an object requested
            | where ObjectName has "lsass.exe"
                and AccessMask == "0x1410" // PROCESS_VM_READ and PROCESS_QUERY_INFORMATION
            | project
                TimeGenerated,
                Computer,
                Account = SubjectUserName,
                ProcessName,
                AccessMask,
                ObjectName
            """,
            
            "credential_dumping_detection": """
            let timeframe = 24h;
            let dump_tools = dynamic([
                "mimikatz",
                "pwdump",
                "gsecdump",
                "wce.exe",
                "procdump.exe",
                "ntdsutil"
            ]);
            SecurityEvent
            | where TimeGenerated > ago(timeframe)
            | where EventID == 4688 // Process creation
            | where ProcessName has_any (dump_tools)
                or CommandLine has_any (dump_tools)
                or CommandLine has "sekurlsa::"
            | project
                TimeGenerated,
                Computer,
                Account = SubjectUserName,
                ProcessName,
                CommandLine,
                ParentProcessName
            """
        }
