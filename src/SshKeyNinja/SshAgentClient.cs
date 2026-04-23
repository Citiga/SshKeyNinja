using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace SshKeyNinja;

internal sealed record AgentKey(byte[] Blob, string Comment, string KeyType, string Fingerprint);

/// <summary>
/// Communicates with the SSH agent via the agent protocol (RFC draft-miller-ssh-agent).
/// Supports adding, listing, and removing identities.
/// Connects via named pipe on Windows, Unix domain socket on Linux/macOS.
/// </summary>
internal static class SshAgentClient
{
    private const byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
    private const byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
    private const byte SSH_AGENTC_ADD_IDENTITY = 17;
    private const byte SSH_AGENTC_REMOVE_IDENTITY = 18;
    private const byte SSH_AGENT_SUCCESS = 6;

    public static bool TryAddKey(
        Ed25519PrivateKeyParameters privateKey,
        Ed25519PublicKeyParameters publicKey,
        string comment,
        out string? errorMessage)
    {
        try
        {
            byte[] request = BuildAddIdentityMessage(privateKey, publicKey, comment);
            byte[] response = SendToAgent(request);

            if (response.Length >= 1 && response[0] == SSH_AGENT_SUCCESS)
            {
                errorMessage = null;
                return true;
            }

            errorMessage = "SSH agent refused the key.";
            return false;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return false;
        }
    }

    public static List<AgentKey> ListKeys(out string? errorMessage)
    {
        try
        {
            using var msg = new MemoryStream();
            WriteBigEndianU32(msg, 1);
            msg.WriteByte(SSH_AGENTC_REQUEST_IDENTITIES);

            byte[] response = SendToAgent(msg.ToArray());

            if (response.Length < 5 || response[0] != SSH2_AGENT_IDENTITIES_ANSWER)
                throw new InvalidOperationException("Unexpected response from SSH agent.");

            int nkeys = (response[1] << 24) | (response[2] << 16) | (response[3] << 8) | response[4];
            var keys = new List<AgentKey>(nkeys);
            int offset = 5;

            for (int i = 0; i < nkeys; i++)
            {
                byte[] blob = ReadSshBytes(response, ref offset);
                string comment = ReadSshString(response, ref offset);

                string keyType = ExtractKeyType(blob);
                string fingerprint = ComputeFingerprint(blob);
                keys.Add(new AgentKey(blob, comment, keyType, fingerprint));
            }

            errorMessage = null;
            return keys;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return [];
        }
    }

    public static bool RemoveKey(byte[] keyBlob, out string? errorMessage)
    {
        try
        {
            using var body = new MemoryStream();
            body.WriteByte(SSH_AGENTC_REMOVE_IDENTITY);
            WriteBytes(body, keyBlob);

            byte[] bodyBytes = body.ToArray();

            using var message = new MemoryStream();
            WriteBigEndianU32(message, (uint)bodyBytes.Length);
            message.Write(bodyBytes);

            byte[] response = SendToAgent(message.ToArray());

            if (response.Length >= 1 && response[0] == SSH_AGENT_SUCCESS)
            {
                errorMessage = null;
                return true;
            }

            errorMessage = "SSH agent refused to remove the key.";
            return false;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return false;
        }
    }

    private static byte[] ReadSshBytes(byte[] data, ref int offset)
    {
        if (offset + 4 > data.Length)
            throw new InvalidOperationException("Truncated SSH agent response.");

        int len = (data[offset] << 24) | (data[offset + 1] << 16)
                | (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (len < 0 || offset + len > data.Length)
            throw new InvalidOperationException("Invalid length in SSH agent response.");

        byte[] result = new byte[len];
        Buffer.BlockCopy(data, offset, result, 0, len);
        offset += len;
        return result;
    }

    private static string ReadSshString(byte[] data, ref int offset)
    {
        byte[] bytes = ReadSshBytes(data, ref offset);
        return Encoding.UTF8.GetString(bytes);
    }

    private static string ExtractKeyType(byte[] blob)
    {
        int offset = 0;
        return ReadSshString(blob, ref offset);
    }

    private static string ComputeFingerprint(byte[] blob)
    {
        byte[] hash = SHA256.HashData(blob);
        return Convert.ToBase64String(hash).TrimEnd('=');
    }

    private static byte[] BuildAddIdentityMessage(
        Ed25519PrivateKeyParameters privateKey,
        Ed25519PublicKeyParameters publicKey,
        string comment)
    {
        using var body = new MemoryStream();

        body.WriteByte(SSH_AGENTC_ADD_IDENTITY);

        WriteString(body, "ssh-ed25519");
        WriteBytes(body, publicKey.GetEncoded());

        byte[] privEncoded = privateKey.GetEncoded();
        byte[] pubEncoded = publicKey.GetEncoded();
        byte[] combined = new byte[privEncoded.Length + pubEncoded.Length];
        Buffer.BlockCopy(privEncoded, 0, combined, 0, privEncoded.Length);
        Buffer.BlockCopy(pubEncoded, 0, combined, privEncoded.Length, pubEncoded.Length);
        WriteBytes(body, combined);

        WriteString(body, comment);

        byte[] bodyBytes = body.ToArray();

        using var message = new MemoryStream();
        WriteBigEndianU32(message, (uint)bodyBytes.Length);
        message.Write(bodyBytes);

        return message.ToArray();
    }

    private static byte[] SendToAgent(byte[] message)
    {
        using var stream = ConnectToAgent();

        stream.Write(message);
        stream.Flush();

        byte[] lengthBuf = new byte[4];
        ReadExact(stream, lengthBuf);
        int responseLength = (lengthBuf[0] << 24) | (lengthBuf[1] << 16) | (lengthBuf[2] << 8) | lengthBuf[3];

        if (responseLength is <= 0 or > 16384)
            throw new InvalidOperationException($"Invalid response length from SSH agent: {responseLength}");

        byte[] response = new byte[responseLength];
        ReadExact(stream, response);

        return response;
    }

    private static Stream ConnectToAgent()
    {
        if (OperatingSystem.IsWindows())
            return ConnectWindowsAgent();

        string? authSock = Environment.GetEnvironmentVariable("SSH_AUTH_SOCK");
        if (string.IsNullOrEmpty(authSock))
            throw new InvalidOperationException(
                "SSH_AUTH_SOCK is not set. Is the ssh-agent running?");

        return ConnectUnixAgent(authSock);
    }

    private static Stream ConnectWindowsAgent()
    {
        var pipe = new NamedPipeClientStream(".", "openssh-ssh-agent", PipeDirection.InOut);
        try
        {
            pipe.Connect(timeout: 3000);
            return pipe;
        }
        catch (TimeoutException)
        {
            pipe.Dispose();
            throw new InvalidOperationException(
                "Could not connect to SSH agent. Is the OpenSSH Authentication Agent service running?");
        }
    }

    private static Stream ConnectUnixAgent(string socketPath)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            socket.Connect(new UnixDomainSocketEndPoint(socketPath));
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static void ReadExact(Stream stream, byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read == 0)
                throw new EndOfStreamException("SSH agent closed the connection.");
            offset += read;
        }
    }

    private static void WriteString(Stream stream, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        WriteBytes(stream, bytes);
    }

    private static void WriteBytes(Stream stream, byte[] data)
    {
        WriteBigEndianU32(stream, (uint)data.Length);
        stream.Write(data);
    }

    private static void WriteBigEndianU32(Stream stream, uint value)
    {
        stream.WriteByte((byte)((value >> 24) & 0xFF));
        stream.WriteByte((byte)((value >> 16) & 0xFF));
        stream.WriteByte((byte)((value >> 8) & 0xFF));
        stream.WriteByte((byte)(value & 0xFF));
    }
}
