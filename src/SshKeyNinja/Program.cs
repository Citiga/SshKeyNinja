using System.Diagnostics;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using SshKeyNinja;

internal class Program
{
    private static int Main(string[] args)
    {
        var comment = $"{Environment.UserName}@{Environment.MachineName}";
        var outputPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".ssh", "id_ed25519");
        string? passphrase = null;
        bool askPassphrase = true;
        bool addToAgent = true;
        bool removeMode = false;
        bool noKeygen = false;
        int generatePassphraseWords = 0;
        bool showPassphrase = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-x":
                    removeMode = true;
                    break;
                case "-PP" when i + 1 < args.Length:
                    showPassphrase = true;
                    if (int.TryParse(args[i + 1], out int ppCount) && ppCount is >= 1 and <= 16)
                    {
                        generatePassphraseWords = ppCount;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine($"  Error: -PP requires a number between 1 and 16.");
                        return 1;
                    }
                    break;
                case "-P" when i + 1 < args.Length:
                    if (int.TryParse(args[i + 1], out int pCount) && pCount is >= 1 and <= 16)
                    {
                        generatePassphraseWords = pCount;
                        i++;
                    }
                    else
                    {
                        Console.WriteLine($"  Error: -P requires a number between 1 and 16.");
                        return 1;
                    }
                    break;
                case "-C" when i + 1 < args.Length:
                    comment = args[++i];
                    break;
                case "-f" when i + 1 < args.Length:
                    outputPath = args[++i];
                    break;
                case "-N" when i + 1 < args.Length && !args[i + 1].StartsWith('-'):
                    passphrase = args[++i];
                    askPassphrase = false;
                    break;
                case "-N":
                    passphrase = "";
                    askPassphrase = false;
                    break;
                case "--no-agent":
                    addToAgent = false;
                    break;
                case "--no-keygen":
                    noKeygen = true;
                    break;
                case "-h" or "--help":
                    PrintUsage();
                    return 0;
            }
        }

        if (removeMode)
            return RemoveKeysFromAgent();

        if (generatePassphraseWords > 0 && noKeygen)
            return GeneratePassphraseOnly(generatePassphraseWords, showPassphrase);

        return GenerateKey(
            outputPath, comment, passphrase, askPassphrase,
            addToAgent, generatePassphraseWords, showPassphrase);
    }

    private static int GenerateKey(
        string outputPath, string comment,
        string? passphrase, bool askPassphrase,
        bool addToAgent, int generatePassphraseWords, bool showPassphrase)
    {
        Console.WriteLine();
        Console.WriteLine("  SshKeyNinja - ED25519 Key Generator");
        Console.WriteLine("  ====================================");
        Console.WriteLine();

        var fullPath = Path.GetFullPath(ExpandHome(outputPath));
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        if (File.Exists(fullPath))
        {
            Console.Write($"  '{fullPath}' exists. Overwrite? [y/N]: ");
            if (Console.ReadLine()?.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) != true)
            {
                Console.WriteLine("  Aborted.");
                return 1;
            }
            Console.WriteLine();
        }

        bool passphraseGenerated = false;
        if (generatePassphraseWords > 0 && askPassphrase)
        {
            try
            {
                passphrase = PassphraseGenerator.Generate(generatePassphraseWords);
                askPassphrase = false;
                passphraseGenerated = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Error generating passphrase: {ex.Message}");
                return 1;
            }
        }

        if (askPassphrase)
        {
            Console.Write("  Enter passphrase (empty for no passphrase): ");
            passphrase = ReadPassphrase();
            Console.WriteLine();

            if (!string.IsNullOrEmpty(passphrase))
            {
                Console.Write("  Enter same passphrase again: ");
                string? confirm = ReadPassphrase();
                Console.WriteLine();

                if (passphrase != confirm)
                {
                    Console.WriteLine("  Passphrases do not match. Aborted.");
                    return 1;
                }
            }

            Console.WriteLine();
        }

        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();

        var privateKeyParams = (Ed25519PrivateKeyParameters)keyPair.Private;
        var publicKeyParams = (Ed25519PublicKeyParameters)keyPair.Public;

        string privateKeyPem = OpenSshKeyWriter.FormatPrivateKey(
            privateKeyParams, publicKeyParams, comment,
            string.IsNullOrEmpty(passphrase) ? null : passphrase);
        string publicKeyLine = OpenSshKeyWriter.FormatPublicKey(publicKeyParams, comment);
        string fingerprint = OpenSshKeyWriter.ComputeFingerprint(publicKeyParams);

        File.WriteAllBytes(fullPath, System.Text.Encoding.UTF8.GetBytes(privateKeyPem));
        File.WriteAllBytes(fullPath + ".pub", System.Text.Encoding.UTF8.GetBytes(publicKeyLine + "\n"));

        bool encrypted = !string.IsNullOrEmpty(passphrase);
        Console.WriteLine($"  Private key : {fullPath}");
        Console.WriteLine($"  Public key  : {fullPath}.pub");
        Console.WriteLine($"  Fingerprint : SHA256:{fingerprint}");
        Console.WriteLine($"  Comment     : {comment}");
        Console.WriteLine($"  Encrypted   : {(encrypted ? "yes (aes256-ctr, bcrypt)" : "no")}");

        if (encrypted && passphraseGenerated)
        {
            if (CopyToClipboard(passphrase!))
                Console.WriteLine("  Passphrase  : copied to clipboard");
            else
                showPassphrase = true;

            if (showPassphrase)
                Console.WriteLine($"  Passphrase  : {passphrase}");
        }

        if (addToAgent)
        {
            var existingKeys = SshAgentClient.ListKeys(out string? listErr);
            AgentKey? duplicate = listErr == null
                ? existingKeys.Find(k => k.Comment.Equals(comment, StringComparison.Ordinal))
                : null;

            if (duplicate != null)
            {
                Console.Write($"  SSH Agent already has a key with comment '{comment}'. Replace? [y/N]: ");
                if (Console.ReadLine()?.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) != true)
                {
                    Console.WriteLine("  SSH Agent   : skipped (existing key kept)");
                }
                else if (!SshAgentClient.RemoveKey(duplicate.Blob, out string? removeErr))
                {
                    Console.WriteLine($"  SSH Agent   : failed to remove old key ({removeErr})");
                }
                else if (SshAgentClient.TryAddKey(privateKeyParams, publicKeyParams, comment, out string? addErr))
                {
                    Console.WriteLine("  SSH Agent   : key replaced");
                }
                else
                {
                    Console.WriteLine($"  SSH Agent   : old key removed but adding new key failed ({addErr})");
                }
            }
            else if (SshAgentClient.TryAddKey(privateKeyParams, publicKeyParams, comment, out string? agentError))
            {
                Console.WriteLine("  SSH Agent   : key added");
            }
            else
            {
                Console.WriteLine($"  SSH Agent   : failed ({agentError})");
            }
        }

        Console.WriteLine();
        Console.WriteLine("  Public key:");
        Console.WriteLine($"  {publicKeyLine}");
        Console.WriteLine();

        return 0;
    }

    private static int GeneratePassphraseOnly(int wordCount, bool show)
    {
        Console.WriteLine();
        Console.WriteLine("  SshKeyNinja - Passphrase Generator");
        Console.WriteLine("  ===================================");
        Console.WriteLine();

        string passphrase;
        try
        {
            passphrase = PassphraseGenerator.Generate(wordCount);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Error: {ex.Message}");
            return 1;
        }

        Console.WriteLine($"  Words       : {wordCount}");

        if (CopyToClipboard(passphrase))
        {
            Console.WriteLine("  Clipboard   : copied");
        }
        else
        {
            Console.WriteLine("  Clipboard   : failed (not available)");
            show = true;
        }

        if (show)
            Console.WriteLine($"  Passphrase  : {passphrase}");

        Console.WriteLine();
        return 0;
    }

    private static string ReadPassphrase()
    {
        var passphrase = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (passphrase.Length > 0)
                {
                    passphrase.Length--;
                    Console.Write("\b \b");
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                passphrase.Append(key.KeyChar);
                Console.Write('*');
            }
        }
        return passphrase.ToString();
    }

    private static int RemoveKeysFromAgent()
    {
        Console.WriteLine();
        Console.WriteLine("  SshKeyNinja - Remove Keys from SSH Agent");
        Console.WriteLine("  =========================================");
        Console.WriteLine();

        var keys = SshAgentClient.ListKeys(out string? listError);

        if (listError != null)
        {
            Console.WriteLine($"  Could not list keys: {listError}");
            return 1;
        }

        if (keys.Count == 0)
        {
            Console.WriteLine("  No keys loaded in the SSH agent.");
            return 0;
        }

        int idxWidth = keys.Count.ToString().Length;

        for (int i = 0; i < keys.Count; i++)
        {
            string idx = (i + 1).ToString().PadLeft(idxWidth);
            Console.WriteLine($"  [{idx}] {keys[i].KeyType}");
            Console.WriteLine($"  {new string(' ', idxWidth + 2)} SHA256:{keys[i].Fingerprint}");
            Console.WriteLine($"  {new string(' ', idxWidth + 2)} {keys[i].Comment}");
        }

        Console.WriteLine();
        Console.Write("  Keys to remove (comma-separated, e.g. 1,3): ");
        string? input = Console.ReadLine()?.Trim();

        if (string.IsNullOrEmpty(input))
        {
            Console.WriteLine("  No keys selected. Aborted.");
            return 0;
        }

        var indices = new List<int>();
        foreach (string part in input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, out int num) && num >= 1 && num <= keys.Count)
            {
                if (!indices.Contains(num))
                    indices.Add(num);
            }
            else
            {
                Console.WriteLine($"  Invalid selection: '{part}'. Aborted.");
                return 1;
            }
        }

        indices.Sort();

        Console.WriteLine();
        Console.WriteLine($"  Removing {indices.Count} key(s)...");
        Console.WriteLine();

        int removed = 0;
        foreach (int idx in indices)
        {
            var key = keys[idx - 1];
            if (SshAgentClient.RemoveKey(key.Blob, out string? removeError))
            {
                Console.WriteLine($"  Removed: {key.KeyType} SHA256:{key.Fingerprint} {key.Comment}");
                removed++;
            }
            else
            {
                Console.WriteLine($"  Failed:  {key.KeyType} SHA256:{key.Fingerprint} ({removeError})");
            }
        }

        Console.WriteLine();
        Console.WriteLine($"  Done. {removed}/{indices.Count} key(s) removed.");
        Console.WriteLine();

        return 0;
    }

    private static string ExpandHome(string path)
    {
        if (path == "~")
            return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (path.StartsWith("~/") || path.StartsWith("~\\"))
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                path[2..]);

        return path;
    }

    private static bool CopyToClipboard(string text)
    {
        try
        {
            string exe;
            string args;

            if (OperatingSystem.IsWindows())
            {
                exe = "cmd";
                args = "/c clip";
            }
            else if (OperatingSystem.IsMacOS())
            {
                exe = "pbcopy";
                args = "";
            }
            else
            {
                exe = "xclip";
                args = "-selection clipboard";
            }

            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                RedirectStandardInput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.Start();
            process.StandardInput.Write(text);
            process.StandardInput.Close();
            process.WaitForExit(3000);

            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine();
        Console.WriteLine("  SshKeyNinja - SSH ED25519 Key Generator");
        Console.WriteLine();
        Console.WriteLine("  Usage: SshKeyNinja [options]");
        Console.WriteLine();
        Console.WriteLine("  Key generation:");
        Console.WriteLine("    -C <comment>      Key comment (default: user@hostname)");
        Console.WriteLine("    -f <path>         Output file path (default: ~/.ssh/id_ed25519)");
        Console.WriteLine("    -N <passphrase>   Passphrase for private key (default: prompt)");
        Console.WriteLine("    -P <1-16>         Generate a Diceware passphrase and encrypt the key");
        Console.WriteLine("    -PP <1-16>        Same as -P but also displays the passphrase");
        Console.WriteLine("    --no-agent        Don't add the key to the SSH agent");
        Console.WriteLine();
        Console.WriteLine("  Passphrase only:");
        Console.WriteLine("    -P <1-16> --no-keygen   Generate passphrase only (copy to clipboard)");
        Console.WriteLine("    -PP <1-16> --no-keygen   Same but also displays the passphrase");
        Console.WriteLine();
        Console.WriteLine("  Agent management:");
        Console.WriteLine("    -x                Remove keys from the SSH agent interactively");
        Console.WriteLine();
        Console.WriteLine("  General:");
        Console.WriteLine("    -h, --help        Show this help message");
        Console.WriteLine();
        Console.WriteLine("  Passphrases are generated using the EFF Large Wordlist (CC-BY 3.0).");
        Console.WriteLine("  More info: https://www.eff.org/dice");
        Console.WriteLine();
    }
}
