package com.example.notes

import android.app.Activity
import android.net.Uri
import android.os.Bundle
import android.webkit.WebView

const val HELP_HOST = "help.example.com"

class HelpActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)
        val target = Uri.parse(intent.data?.getQueryParameter("page") ?: return)
        if (target.scheme == "https" && target.host == HELP_HOST) {
            webView.loadUrl(target.toString())
        }
    }
}
