package com.example.notes

import android.annotation.SuppressLint
import android.app.Activity
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView

class SessionBridge(private val store: TokenStore) {
    @JavascriptInterface
    fun token(): String = store.load()
}

class DeepLinkActivity : Activity() {
    @SuppressLint("SetJavaScriptEnabled", "AddJavascriptInterface")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(SessionBridge(TokenStore(this)), "Session")
        setContentView(webView)
        val url = intent.data?.getQueryParameter("url") ?: return
        webView.loadUrl(url)
    }
}
