using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class NetDiagStatusServer : IDisposable {
    private readonly Dictionary<string, byte[]> assets = new Dictionary<string, byte[]>();
    private readonly object stateLock = new object();
    private string state = "{\"schemaVersion\":1,\"lifecycle\":\"STARTING\"}";
    private long stateTick = Stopwatch.GetTimestamp();
    private TcpListener listener;
    private Thread worker;
    private volatile bool stop;
    private int port;
    public string Error { get; private set; }
    public bool IsAlive { get { return worker != null && worker.IsAlive; } }
    public void AddAsset(string path, byte[] bytes) { assets.Add(path, bytes); }
    public void Publish(string json) {
        if (Encoding.UTF8.GetByteCount(json) > 262144) throw new InvalidOperationException("Status payload exceeds 256 KiB.");
        lock (stateLock) { state = json.Trim(); stateTick = Stopwatch.GetTimestamp(); }
    }
    public void Start(int number) {
        port = number;
        listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start(8);
        worker = new Thread(Serve); worker.IsBackground = true; worker.Name = "NetDiag local status"; worker.Start();
    }
    private void Serve() {
        try {
            while (!stop) {
                using (TcpClient client = listener.AcceptTcpClient()) {
                    client.ReceiveTimeout = 1000; client.SendTimeout = 1000;
                    try { Handle(client.GetStream()); } catch (IOException) {} catch (SocketException) {}
                }
            }
        } catch (Exception ex) { if (!stop) Error = ex.GetType().Name + ": " + ex.Message; }
    }
    private void Handle(NetworkStream stream) {
        byte[] buffer = new byte[8192]; int count = 0;
        long started = Stopwatch.GetTimestamp();
        while (count < buffer.Length) {
            if ((Stopwatch.GetTimestamp() - started) / (double)Stopwatch.Frequency > 2.0) return;
            int next = stream.ReadByte(); if (next < 0) return;
            buffer[count++] = (byte)next;
            if (count >= 4 && buffer[count-4] == 13 && buffer[count-3] == 10 && buffer[count-2] == 13 && buffer[count-1] == 10) break;
        }
        if (count == buffer.Length) { Reply(stream, 431, "text/plain", Encoding.UTF8.GetBytes("Headers too large")); return; }
        string[] lines = Encoding.ASCII.GetString(buffer, 0, count).Split(new string[] {"\r\n"}, StringSplitOptions.None);
        string[] request = lines[0].Split(' ');
        if (request.Length != 3 || request[2] != "HTTP/1.1") { Reply(stream, 400, "text/plain", new byte[0]); return; }
        string host = null; int hostCount = 0;
        for (int i=1; i<lines.Length; i++) {
            if (lines[i].StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) { host = lines[i].Substring(5).Trim(); hostCount++; }
        }
        if (hostCount != 1 || (host != "127.0.0.1:"+port && host != "localhost:"+port)) { Reply(stream, 403, "text/plain", new byte[0]); return; }
        if (request[0] != "GET") { Reply(stream, 405, "text/plain", new byte[0]); return; }
        string path = request[1];
        if (path == "/api/status") {
            string snapshot; long tick;
            lock (stateLock) { snapshot = state; tick = stateTick; }
            long age = Math.Max(0L,(long)((Stopwatch.GetTimestamp()-tick)*1000.0/Stopwatch.Frequency));
            if (!snapshot.EndsWith("}")) { Reply(stream, 503, "text/plain", new byte[0]); return; }
            snapshot = snapshot.Substring(0,snapshot.Length-1)+",\"snapshotAgeMs\":"+age.ToString(System.Globalization.CultureInfo.InvariantCulture)+"}";
            Reply(stream, 200, "application/json; charset=utf-8", Encoding.UTF8.GetBytes(snapshot)); return;
        }
        if (path == "/") path = "/index.html";
        byte[] data;
        if (!assets.TryGetValue(path, out data)) { Reply(stream, 404, "text/plain", new byte[0]); return; }
        string type = path.EndsWith(".js") ? "text/javascript; charset=utf-8" : path.EndsWith(".css") ? "text/css; charset=utf-8" : "text/html; charset=utf-8";
        Reply(stream, 200, type, data);
    }
    private void Reply(NetworkStream stream, int code, string type, byte[] body) {
        string reason = code == 200 ? "OK" : "Rejected";
        string header = "HTTP/1.1 "+code+" "+reason+"\r\nContent-Type: "+type+"\r\nContent-Length: "+body.Length+"\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n\r\n";
        byte[] bytes = Encoding.ASCII.GetBytes(header); stream.Write(bytes,0,bytes.Length); stream.Write(body,0,body.Length);
    }
    public void Dispose() { stop = true; if (listener != null) listener.Stop(); if (worker != null) worker.Join(3500); }
}
