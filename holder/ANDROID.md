# Holder Android wrapper (agency: mobile-app-builder)
- Option 1 (demo): open `holder/index.html` in Chrome on the phone. Zero build.
- Option 2 (native feel, same code): Android Studio → Empty Views Activity →
  WebView loading the holder page (or the Render URL):
```kotlin
webView.settings.javaScriptEnabled = true
webView.loadUrl("https://your-holder.onrender.com/holder/")
```
- Verifier scan uses camera via `getUserMedia` in `verifier/` page, or manual
  paste of JSON for projector demos. No PII ever rendered on holder screen
  besides the opaque QR blob.
