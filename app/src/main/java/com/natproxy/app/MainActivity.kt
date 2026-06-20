package com.natproxy.app

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private var proxyService: Socks5ProxyService? = null
    private var bound = false

    private lateinit var tvIp: TextView
    private lateinit var tvStatus: TextView
    private lateinit var tvLog: TextView
    private lateinit var etPort: EditText
    private lateinit var btnToggle: Button
    private lateinit var btnDetect: Button
    private lateinit var etHost: EditText

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            proxyService = (binder as Socks5ProxyService.LocalBinder).getService()
            bound = true
            proxyService!!.statusCallback = { msg -> runOnUiThread { handleStatus(msg) } }
            updateUI()
        }
        override fun onServiceDisconnected(name: ComponentName) {
            bound = false
            proxyService = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvIp      = findViewById(R.id.tvIp)
        tvStatus  = findViewById(R.id.tvStatus)
        tvLog     = findViewById(R.id.tvLog)
        etPort    = findViewById(R.id.etPort)
        etHost    = findViewById(R.id.etHost)
        btnToggle = findViewById(R.id.btnToggle)
        btnDetect = findViewById(R.id.btnDetect)

        btnDetect.setOnClickListener {
            val ip = Socks5ProxyService().detectLocalIp()
                .ifEmpty { "شناسایی نشد" }
            etHost.setText(ip)
            tvIp.text = "IP شناسایی شده: $ip"
        }

        btnToggle.setOnClickListener {
            if (proxyService?.isRunning() == true) {
                stopProxy()
            } else {
                startProxy()
            }
        }

        // Auto-detect IP on start
        btnDetect.performClick()
    }

    override fun onStart() {
        super.onStart()
        Intent(this, Socks5ProxyService::class.java).also {
            bindService(it, connection, Context.BIND_AUTO_CREATE)
        }
    }

    override fun onStop() {
        super.onStop()
        if (bound) {
            unbindService(connection)
            bound = false
        }
    }

    private fun startProxy() {
        val host = etHost.text.toString().trim().ifEmpty {
            toast("لطفاً IP را وارد کنید"); return
        }
        val port = etPort.text.toString().toIntOrNull() ?: run {
            toast("پورت نامعتبر است"); return
        }

        Intent(this, Socks5ProxyService::class.java).apply {
            action = Socks5ProxyService.ACTION_START
            putExtra(Socks5ProxyService.EXTRA_HOST, host)
            putExtra(Socks5ProxyService.EXTRA_PORT, port)
        }.also { startService(it) }
    }

    private fun stopProxy() {
        Intent(this, Socks5ProxyService::class.java).apply {
            action = Socks5ProxyService.ACTION_STOP
        }.also { startService(it) }
    }

    private fun handleStatus(msg: String) {
        when {
            msg.startsWith("running:") -> {
                val addr = msg.removePrefix("running:")
                tvStatus.text = "✅ در حال اجرا: $addr"
                tvStatus.setTextColor(getColor(R.color.green))
                btnToggle.text = "⏹ توقف پروکسی"
                appendLog("پروکسی شروع به کار کرد روی $addr")
            }
            msg == "stopped" -> {
                tvStatus.text = "⏸ متوقف"
                tvStatus.setTextColor(getColor(R.color.gray))
                btnToggle.text = "▶ شروع پروکسی"
                appendLog("پروکسی متوقف شد")
                updateUI()
            }
            msg.startsWith("error:") -> {
                tvStatus.text = "❌ خطا: ${msg.removePrefix("error:")}"
                tvStatus.setTextColor(getColor(android.R.color.holo_red_light))
            }
            msg.startsWith("log:") -> appendLog(msg.removePrefix("log:"))
        }
    }

    private fun updateUI() {
        val running = proxyService?.isRunning() == true
        btnToggle.text = if (running) "⏹ توقف پروکسی" else "▶ شروع پروکسی"
        if (!running) {
            tvStatus.text = "⏸ متوقف"
            tvStatus.setTextColor(getColor(R.color.gray))
        }
    }

    private fun appendLog(msg: String) {
        val current = tvLog.text.toString()
        val lines = current.split("\n").takeLast(50)
        tvLog.text = (lines + msg).joinToString("\n")
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}
