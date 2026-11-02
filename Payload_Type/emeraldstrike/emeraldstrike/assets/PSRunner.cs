using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

// PSRunner: CLR-hosted PowerShell execution for EmeraldStrike powerpick.
// Invoked via _MethodInfo::Invoke_3 with args[0] = base64-free script text.
// Console.SetOut/SetError re-read the current Win32 std handles on every run,
// so output capture keeps working after SetStdHandle redirection regardless
// of what earlier managed code cached.
class PSRunner
{
    static int Main(string[] args)
    {
        try
        {
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("\nNo script provided");
                return 1;
            }
            return RunScript(args[0]);
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nEXCEPTION: " + ex.Message);
            return 1;
        }
    }

    static int RunScript(string script)
    {
        try
        {
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
        }
        catch { /* non-console process; pipeline output below still works */ }

        using (var runspace = RunspaceFactory.CreateRunspace())
        {
            runspace.Open();
            using (var ps = PowerShell.Create())
            {
                ps.Runspace = runspace;
                ps.AddScript(script);
                var output = ps.Invoke();
                var sb = new StringBuilder();
                foreach (var item in output)
                    sb.AppendLine(item == null ? "" : item.ToString());
                if (ps.Streams.Error.Count > 0)
                    foreach (var err in ps.Streams.Error)
                        sb.AppendLine("ERROR: " + err.ToString());
                if (ps.Streams.Warning.Count > 0)
                    foreach (var warn in ps.Streams.Warning)
                        sb.AppendLine("WARNING: " + warn.ToString());
                Console.Write(sb.ToString());
            }
        }
        return 0;
    }
}
