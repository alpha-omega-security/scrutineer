package com.example.notes

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlin.concurrent.thread

const val LOGIN_URL = "https://api.example.com/login"

class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val username = EditText(this)
        val password = EditText(this)
        val signIn = Button(this).apply { text = "Sign in" }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(username)
            addView(password)
            addView(signIn)
        })
        signIn.setOnClickListener {
            val user = username.text.toString()
            val pass = password.text.toString()
            thread {
                val token = signIn(user, pass)
                TokenStore(this).save(token)
                runOnUiThread { finish() }
            }
        }
    }

    private fun signIn(username: String, password: String): String {
        val conn = URL(LOGIN_URL).openConnection() as HttpsURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            val body = JSONObject().put("username", username).put("password", password)
            conn.outputStream.use { it.write(body.toString().toByteArray()) }
            val response = conn.inputStream.bufferedReader().use { it.readText() }
            return JSONObject(response).getString("token")
        } finally {
            conn.disconnect()
        }
    }
}
