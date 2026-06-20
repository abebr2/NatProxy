package com.natproxy.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class Socks5ProxyService : Service() {

    companion object {
        const val TAG = "NatProxy"
        const val CHANNEL_ID = "natproxy_channel"
        const val NOTIF_ID = 1
        const val ACTION_START = "START"
        const val ACTION_STOP = "STOP"
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"

        private const val TCP_BUF = 32768
        private const val SELECT_TIMEOUT = 60_000
        private const val BACKLOG = 64
        private const val MAX_WORKERS = 64
    }

    inner class LocalBinder : Binder() {
        fun getService() = this@Socks5ProxyService
    }

    private val binder = LocalBinder()
    private val running = AtomicBoolean(false)
    val activeConnections = AtomicInteger(0)
    val totalConnections = AtomicInteger(0)

    private var serverSocket: ServerSocket? = null
    private val executor = Executors.newFixedThreadPool(MAX_WORKERS)
    private val acceptThread = Executors.newSingleThreadExecutor()

    var statusCallback: ((String) -> Unit)? = null

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val host = intent.getStringExtra(EXTRA_HOST) ?: detectLocalIp()
                val port = intent.getIntExtra(EXTRA_PORT, 9898)
                startProxy(host, port)
            }
            ACTION_STOP -> stopProxy()
        }
        return START_NOT_STICKY
    }

    fun startProxy(host: String, port: Int) {
        if (running.get()) return
        running.set(true)

        startForeground(NOTIF_ID, buildNotification("در حال اجرا — $host:$port"))

        acceptThread.execute {
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(host, port))
                }
                log("پروکسی SOCKS5 روی $host:$port شروع به کار کرد")
                statusCallback?.invoke("running:$host:$port")

                while (running.get()) {
                    try {
                        val client = serverSocket!!.accept()
                        executor.execute { handleClient(client) }
                    } catch (e: IOException) {
                        if (running.get()) log("خطای accept: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                log("خطا در شروع سرور: ${e.message}")
                statusCallback?.invoke("error:${e.message}")
                running.set(false)
            }
        }
    }

    fun stopProxy() {
        running.set(false)
        try { serverSocket?.close() } catch (_: Exception) {}
        statusCallback?.invoke("stopped")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        log("پروکسی متوقف شد")
    }

    fun isRunning() = running.get()

    // ── IP detection ──────────────────────────────────────────────────────────

    fun detectLocalIp(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            for (iface in interfaces) {
                val name = iface.name.lowercase()
                if (!name.startsWith("wlan") && !name.startsWith("ap") &&
                    !name.startsWith("rmnet")) continue
                for (addr in iface.inetAddresses) {
                    if (addr.isLoopbackAddress || addr !is InetAddress) continue
                    val ip = addr.hostAddress ?: continue
                    if (ip.startsWith("192.168.") || ip.startsWith("10.")) return ip
                }
            }
        } catch (e: Exception) {
            log("نمیتوان IP را تشخیص داد: ${e.message}")
        }
        return "0.0.0.0"
    }

    // ── Client handler ────────────────────────────────────────────────────────

    private fun handleClient(client: Socket) {
        totalConnections.incrementAndGet()
        activeConnections.incrementAndGet()
        try {
            client.soTimeout = 15_000
            if (!doHandshake(client)) return

            val (cmd, destIp, destPort) = parseRequest(client) ?: return

            if (cmd == 0x01) {
                handleTcpConnect(client, destIp, destPort)
            }
            // UDP ASSOCIATE (0x03) — اندروید معمولاً UDP را سیستمی مدیریت می‌کند
        } catch (e: Exception) {
            Log.d(TAG, "خطای کلاینت: ${e.message}")
        } finally {
            try { client.close() } catch (_: Exception) {}
            activeConnections.decrementAndGet()
        }
    }

    // ── SOCKS5 handshake ──────────────────────────────────────────────────────

    private fun doHandshake(sock: Socket): Boolean {
        val input = sock.getInputStream()
        val output = sock.getOutputStream()

        val hdr = readExact(input, 2) ?: return false
        if (hdr[0] != 0x05.toByte()) return false

        val methods = readExact(input, hdr[1].toInt() and 0xFF) ?: return false
        output.write(byteArrayOf(0x05, 0x00)) // no auth
        return true
    }

    // ── SOCKS5 request parser ─────────────────────────────────────────────────

    private data class Request(val cmd: Int, val destIp: String, val destPort: Int)

    private fun parseRequest(sock: Socket): Request? {
        val input = sock.getInputStream()
        val hdr = readExact(input, 4) ?: return null
        if (hdr[0] != 0x05.toByte()) return null

        val cmd = hdr[1].toInt() and 0xFF
        val atyp = hdr[3].toInt() and 0xFF

        val destIp = when (atyp) {
            0x01 -> { // IPv4
                val raw = readExact(input, 4) ?: return null
                raw.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }
            0x03 -> { // domain
                val len = input.read()
                if (len < 0) return null
                val domain = readExact(input, len)?.toString(Charsets.UTF_8) ?: return null
                try { InetAddress.getByName(domain).hostAddress ?: return null }
                catch (e: Exception) { return null }
            }
            else -> return null
        }

        val portBytes = readExact(input, 2) ?: return null
        val destPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

        return Request(cmd, destIp, destPort)
    }

    // ── TCP CONNECT relay ─────────────────────────────────────────────────────

    private fun handleTcpConnect(client: Socket, destIp: String, destPort: Int) {
        val output = client.getOutputStream()
        val remote: Socket
        try {
            remote = Socket()
            remote.connect(InetSocketAddress(destIp, destPort), 15_000)
            remote.tcpNoDelay = true
            client.tcpNoDelay = true
        } catch (e: Exception) {
            output.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            return
        }

        // Success reply
        val ipBytes = InetAddress.getByName(destIp).address
        output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01) + ipBytes +
                byteArrayOf((destPort shr 8).toByte(), destPort.toByte()))

        // Relay both directions
        val done = AtomicBoolean(false)
        val t1 = Thread { relay(client.getInputStream(), remote.getOutputStream(), done) }
        val t2 = Thread { relay(remote.getInputStream(), client.getOutputStream(), done) }
        t1.isDaemon = true; t2.isDaemon = true
        t1.start(); t2.start()
        t1.join(SELECT_TIMEOUT.toLong())
        done.set(true)
        try { remote.close() } catch (_: Exception) {}
    }

    private fun relay(input: java.io.InputStream, output: java.io.OutputStream, done: AtomicBoolean) {
        val buf = ByteArray(TCP_BUF)
        try {
            while (!done.get()) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
            }
        } catch (_: Exception) {}
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun readExact(input: java.io.InputStream, n: Int): ByteArray? {
        if (n <= 0) return ByteArray(0)
        val buf = ByteArray(n)
        var offset = 0
        while (offset < n) {
            val read = input.read(buf, offset, n - offset)
            if (read < 0) return null
            offset += read
        }
        return buf
    }

    private fun log(msg: String) {
        Log.i(TAG, msg)
        statusCallback?.invoke("log:$msg")
    }

    // ── Notification ──────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "NatProxy Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "پروکسی SOCKS5 در حال اجرا" }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = Intent(this, Socks5ProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NatProxy")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .addAction(android.R.drawable.ic_delete, "توقف", stopPending)
            .setOngoing(true)
            .build()
    }
}
