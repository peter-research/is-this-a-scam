package com.isthisascam;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.ViewGroup;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Is This A Scam? — one screen, one input.
 *
 * The UI is the shared HTML/CSS/JS in assets/www, served over an https://
 * base URL so the page has a normal origin. Requests the page makes to
 * app.local/proxy?u=<url> are answered by fetching the real site from Java,
 * which sidesteps the CORS headers those reputation sites do not send.
 */
public class MainActivity extends Activity {

    private static final String BASE = "https://app.local/";
    private static final String[] ALLOWED = {
            "www.scamadviser.com", "scamadviser.com",
            "rdap.org", "dns.google",
            "openphish.com", "www.openphish.com",
            "archive.org", "web.archive.org",
    };

    private WebView web;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        web = new WebView(this);
        web.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        web.setBackgroundColor(0xFF0E1117);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        s.setSupportZoom(false);
        s.setBuiltInZoomControls(false);

        web.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(
                    WebView view, WebResourceRequest request) {
                Uri u = request.getUrl();
                if (u == null || !"app.local".equals(u.getHost())) return null;

                String path = u.getPath() == null ? "/" : u.getPath();
                if (path.startsWith("/proxy")) {
                    return proxy(u.getQueryParameter("u"));
                }
                String asset = "www" + (path.equals("/") ? "/index.html" : path);
                try {
                    InputStream in = getAssets().open(asset);
                    return new WebResourceResponse(mimeFor(asset), "UTF-8", 200, "OK",
                            Collections.<String, String>emptyMap(), in);
                } catch (IOException e) {
                    return new WebResourceResponse("text/plain", "UTF-8", 404, "Not Found",
                            Collections.<String, String>emptyMap(),
                            new ByteArrayInputStream(new byte[0]));
                }
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri u = request.getUrl();
                if (u != null && "app.local".equals(u.getHost())) return false;
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, u));
                } catch (Exception ignored) { }
                return true;
            }
        });

        setContentView(web);
        load(extractSharedText(getIntent()));
    }

    /** Fetch a reputation URL server-side and hand the body back to the page. */
    private WebResourceResponse proxy(String encoded) {
        Map<String, String> cors = new HashMap<>();
        cors.put("Access-Control-Allow-Origin", "*");
        if (encoded == null) {
            return new WebResourceResponse("text/plain", "UTF-8", 400, "Bad Request",
                    cors, new ByteArrayInputStream(new byte[0]));
        }
        String target = URLDecoder.decode(encoded, StandardCharsets.UTF_8);
        try {
            URL url = new URL(target);
            if (!"https".equals(url.getProtocol()) || !isAllowed(url.getHost())) {
                return new WebResourceResponse("text/plain", "UTF-8", 403, "Forbidden", cors,
                        new ByteArrayInputStream(
                                "host not allowed".getBytes(StandardCharsets.UTF_8)));
            }
            HttpURLConnection c = (HttpURLConnection) url.openConnection();
            c.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; IsThisAScam/1.0)");
            c.setConnectTimeout(20000);
            c.setReadTimeout(25000);
            c.setInstanceFollowRedirects(true);
            int code = c.getResponseCode();
            InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (in != null) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
                in.close();
            }
            String body = bos.toString("UTF-8");
            return new WebResourceResponse(mimeFor(target), "UTF-8", code,
                    code >= 400 ? "Error" : "OK", cors,
                    new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return new WebResourceResponse("text/plain", "UTF-8", 502, "Bad Gateway", cors,
                    new ByteArrayInputStream(String.valueOf(e.getMessage())
                            .getBytes(StandardCharsets.UTF_8)));
        }
    }

    private boolean isAllowed(String host) {
        for (String h : ALLOWED) if (h.equalsIgnoreCase(host)) return true;
        return false;
    }

    private static String mimeFor(String name) {
        if (name.endsWith(".html")) return "text/html";
        if (name.endsWith(".js")) return "application/javascript";
        if (name.endsWith(".css")) return "text/css";
        if (name.endsWith(".json")) return "application/json";
        return "application/octet-stream";
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        load(extractSharedText(intent));
    }

    /** Support Android share intents: share a link from any app into the checker. */
    private String extractSharedText(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) return null;
        String t = intent.getStringExtra(Intent.EXTRA_TEXT);
        if (t == null) return null;
        java.util.regex.Matcher m =
                java.util.regex.Pattern.compile("https?://\\S+").matcher(t);
        return m.find() ? m.group() : t.trim();
    }

    private void load(String query) {
        String url = BASE;
        if (query != null && !query.isEmpty()) url = BASE + "?q=" + Uri.encode(query);
        web.loadUrl(url);
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK && web.canGoBack()) {
            web.goBack();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }
}
