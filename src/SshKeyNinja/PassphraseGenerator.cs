// This file uses the EFF Large Wordlist (CC-BY 3.0):
// https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
// License: https://creativecommons.org/licenses/by/3.0/
using System.Security.Cryptography;

namespace SshKeyNinja;

internal static class PassphraseGenerator
{
    private static readonly string[] Words = LoadWordlist();

    public static string Generate(int wordCount)
    {
        if (wordCount is < 1 or > 16)
            throw new ArgumentOutOfRangeException(nameof(wordCount), "Word count must be between 1 and 16.");

        var chosen = new string[wordCount];
        for (int i = 0; i < wordCount; i++)
            chosen[i] = Words[RandomNumberGenerator.GetInt32(Words.Length)];

        return string.Join('-', chosen);
    }

    private static string[] LoadWordlist()
    {
        using var stream = typeof(PassphraseGenerator).Assembly
            .GetManifestResourceStream("eff_large_wordlist.txt")
            ?? throw new InvalidOperationException("Embedded wordlist resource not found.");

        using var reader = new StreamReader(stream);
        var words = new List<string>(7776);
        string? line;

        while ((line = reader.ReadLine()) != null)
        {
            int tab = line.IndexOf('\t');
            if (tab >= 0 && tab + 1 < line.Length)
                words.Add(line[(tab + 1)..]);
        }

        return words.ToArray();
    }
}
